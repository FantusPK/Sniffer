"""Application layer -- wires the sniffing engine to the GUI."""

from __future__ import annotations

import os
import re
import sys
import threading
import tkinter as tk
import xml.etree.ElementTree as ET
from importlib.metadata import PackageNotFoundError, version as _pkg_version
from datetime import datetime
from tkinter import filedialog, messagebox
from typing import Any

import serial.tools.list_ports

from sniffer.core.bacnet_client import BACnetClient
from sniffer.core.engine import EngineCallbacks, SnifferEngine
from sniffer.core.exporter import export_csv, export_presence_csv
from sniffer.core.npcap_source import NpcapSource, list_interfaces
from sniffer.gui.main_window import MainWindow
from sniffer.protocols import get_decoders, get_decoders_for
from sniffer.sim.serial_sim import SimulatedSerial
from sniffer.sim.traffic import make_generator


def _app_version() -> str:
    try:
        return _pkg_version("sniffer")
    except PackageNotFoundError:
        try:
            from sniffer import __version__
            return __version__
        except (ImportError, AttributeError):
            return "dev"


def _default_log_dir() -> str:
    """Return a ``Logs`` folder next to the exe / script."""
    if getattr(sys, "frozen", False):
        base = os.path.dirname(sys.executable)
    else:
        base = os.path.dirname(os.path.abspath(__file__))
    log_dir = os.path.join(base, "Logs")
    os.makedirs(log_dir, exist_ok=True)
    return log_dir


class SnifferApp:
    """Top-level application object.

    Owns all Tk state variables, creates the engine and the window, and
    bridges engine callbacks (sniff thread) to GUI updates (main thread)
    via ``root.after``.
    """

    def __init__(self) -> None:
        self.root = tk.Tk()

        # ── state variables ───────────────────────────────────────────
        self.selected_port = tk.StringVar()
        self.device_address = tk.StringVar(value="1")
        self.save_dir = tk.StringVar(value=_default_log_dir())
        self.packet_count_all = tk.IntVar(value=0)
        self.packet_count_target = tk.IntVar(value=0)
        self.protocol_detected = tk.StringVar(value="\u2014")
        self.current_baud = tk.StringVar(value="9600")
        self.status_text = tk.StringVar(value="Idle")
        self.sim_protocol = tk.StringVar(value="BACnet-MSTP")
        self.selected_protocol = tk.StringVar(value="Auto-detect")
        self.selected_baud = tk.StringVar(value="Auto-detect")
        self.source_type = tk.StringVar(value="Serial (COM)")
        self.udp_host = tk.StringVar(value="192.168.142.1")
        self.udp_port = tk.StringVar(value="47808")
        self.who_is_on_connect = tk.BooleanVar(value=True)
        self.jace_ip = tk.StringVar(value="192.168.142.1")

        self.target_address: int = 1
        self._rows_lock = threading.Lock()
        self.all_log_rows: list[list] = []
        self.target_log_rows: list[list] = []
        self._iface_map: dict[str, tuple[Any, str]] = {}  # label → (iface, ip)
        self._query_client: BACnetClient | None = None

        # engine is created fresh on each launch with the selected decoder(s)
        self.engine = SnifferEngine(get_decoders())

        # ── GUI ───────────────────────────────────────────────────────
        self.window = MainWindow(
            self.root,
            app_title=f"Bus Sniffer v{_app_version()}",
            subtitle="Field Diagnostic  //  Auto-Detect Protocols",
            port_var=self.selected_port,
            addr_var=self.device_address,
            dir_var=self.save_dir,
            all_count_var=self.packet_count_all,
            target_count_var=self.packet_count_target,
            protocol_var=self.protocol_detected,
            baud_var=self.current_baud,
            status_var=self.status_text,
            sim_protocol_var=self.sim_protocol,
            selected_protocol_var=self.selected_protocol,
            selected_baud_var=self.selected_baud,
            source_type_var=self.source_type,
            udp_host_var=self.udp_host,
            udp_port_var=self.udp_port,
            who_is_var=self.who_is_on_connect,
            jace_ip_var=self.jace_ip,
            on_refresh_ports=self._refresh_ports,
            on_refresh_ifaces=self._refresh_interfaces,
            on_start=self._start,
            on_stop=self._stop,
            on_simulate=self._simulate,
            on_export=self._export,
            on_clear=self._clear,
            on_query=self._query,
            on_import_roster=self._import_roster,
            on_export_presence=self._export_presence,
            on_rebuild=self._rebuild,
        )

        self._refresh_ports()
        self._refresh_interfaces()
        self.window.config.force_display("1", _default_log_dir())

    # ── roster import ─────────────────────────────────────────────────

    def _import_roster(self) -> None:
        path = filedialog.askopenfilename(
            title="Import Device Roster",
            filetypes=[("oBIX / XML files", "*.obix *.xml"), ("All files", "*.*")],
        )
        if not path:
            return
        try:
            devices = _parse_obix(path)
        except Exception as exc:
            messagebox.showerror("Import failed", str(exc))
            return
        self.window.logs.import_roster(devices)
        self._log_all(
            f"[{self._ts()}] ── Roster imported: "
            f"{len(devices)} devices from {os.path.basename(path)} ──",
        )

    def _export_presence(self) -> None:
        save_dir = self.save_dir.get().strip()
        if not save_dir or not os.path.isdir(save_dir):
            self._log_all(
                f"[{self._ts()}] !! Please select a valid save directory.",
            )
            return
        rows = self.window.logs.get_presence_rows()
        if not rows:
            self._log_all(f"[{self._ts()}] !! No presence data to export.")
            return
        path = export_presence_csv(save_dir, rows)
        self._log_all(
            f"[{self._ts()}] ── Presence exported: {len(rows)} devices → {path} ──",
        )

    # ── port helpers ──────────────────────────────────────────────────

    def _refresh_ports(self) -> None:
        ports = [p.device for p in serial.tools.list_ports.comports()]
        self.window.config.set_ports(ports)

    def _refresh_interfaces(self) -> None:
        ifaces = list_interfaces()
        self._iface_map = {label: (iface, ip) for label, iface, ip in ifaces}
        self.window.config.set_interfaces(list(self._iface_map.keys()))

    # ── start / stop ──────────────────────────────────────────────────

    def _start(self) -> None:
        addr_str = self.device_address.get().strip()
        save_dir = self.save_dir.get().strip()

        if not addr_str.isdigit() or not (1 <= int(addr_str) <= 255):
            self._log_all(f"[{self._ts()}] !! Device address must be 1\u2013255.")
            return
        if not save_dir or not os.path.isdir(save_dir):
            self._log_all(
                f"[{self._ts()}] !! Please select a valid save directory.",
            )
            return

        if self.source_type.get() == "Network (BACnet/IP)":
            iface_label = self.udp_host.get().strip()
            udp_port_str = self.udp_port.get().strip()
            if not iface_label:
                self._log_all(f"[{self._ts()}] !! No network interface selected. Click \u27f3 to refresh.")
                return
            if not udp_port_str.isdigit() or not (1 <= int(udp_port_str) <= 65535):
                self._log_all(f"[{self._ts()}] !! UDP port must be 1\u201365535.")
                return
            entry = self._iface_map.get(iface_label)
            if entry is None:
                self._log_all(f"[{self._ts()}] !! Interface not found \u2014 click \u27f3 to refresh.")
                return
            iface, host_ip = entry
            try:
                npcap_source = NpcapSource(iface=iface, port=int(udp_port_str), host_ip=host_ip)
            except Exception as exc:
                self._log_all(f"[{self._ts()}] !! Failed to start capture: {exc}")
                self._log_all(f"[{self._ts()}] !! Ensure Npcap is installed and try running as Administrator.")
                return
            self._launch(
                port=f"UDP {host_ip}:{udp_port_str}",
                addr_str=addr_str,
                sim_serial=npcap_source,
            )
            if self.who_is_on_connect.get():
                npcap_source.send_who_is()
        else:
            port = self.selected_port.get()
            if not port:
                self._log_all(f"[{self._ts()}] !! No COM port selected.")
                return
            self._launch(port=port, addr_str=addr_str, sim_serial=None)

    def _simulate(self) -> None:
        """Start the engine with a simulated serial port."""
        addr_str = self.device_address.get().strip()
        save_dir = self.save_dir.get().strip()

        if not addr_str.isdigit() or not (1 <= int(addr_str) <= 255):
            self._log_all(f"[{self._ts()}] !! Device address must be 1\u2013255.")
            return
        if not save_dir or not os.path.isdir(save_dir):
            self._log_all(
                f"[{self._ts()}] !! Please select a valid save directory.",
            )
            return

        proto = self.sim_protocol.get() or "BACnet-MSTP"
        gen = make_generator(proto)
        sim_serial = SimulatedSerial(gen, packets_per_second=5.0)

        self._log_all(
            f"[{self._ts()}] \u2500\u2500 Starting SIMULATION "
            f"(\u00b7 Protocol: {proto} \u00b7 5 pkt/s) \u2500\u2500",
        )
        self._launch(port="SIM", addr_str=addr_str, sim_serial=sim_serial)

    def _launch(
        self,
        *,
        port: str,
        addr_str: str,
        sim_serial: object | None,
    ) -> None:
        """Shared start logic for both real and simulated sessions."""
        self.target_address = int(addr_str)
        self.status_text.set("LIVE")
        self.protocol_detected.set("detecting\u2026")
        self.window.logs.set_paused(False)
        self.window.controls.set_sniffing(True)

        # recreate engine with only the selected protocol's decoder(s)
        if isinstance(sim_serial, NpcapSource):
            decoders = get_decoders_for("BACnet-IP")
        else:
            decoders = get_decoders_for(self.selected_protocol.get())
        self.engine = SnifferEngine(decoders)

        callbacks = EngineCallbacks(
            on_packet=lambda d, r: self.root.after(
                0, self._handle_packet, d, r,
            ),
            on_status=lambda s: self.root.after(0, self.status_text.set, s),
            on_baud=lambda b: self.root.after(0, self.current_baud.set, b),
            on_protocol=lambda p: self.root.after(
                0, self.protocol_detected.set, p,
            ),
            on_error=lambda e: self.root.after(
                0, self._log_all, f"[{self._ts()}] ERROR: {e}",
            ),
            on_log=lambda msg: self.root.after(
                0, self._log_all, f"[{self._ts()}] \u2500\u2500 {msg} \u2500\u2500",
            ),
        )

        baud_sel = self.selected_baud.get()
        forced_baud = int(baud_sel) if baud_sel != "Auto-detect" else None

        try:
            self.engine.start(
                port, callbacks,
                serial_override=sim_serial,
                forced_baud=forced_baud,
            )
        except Exception:
            self.status_text.set("ERROR")
            self.window.controls.set_sniffing(False)
            return

        if sim_serial is None:
            label = port
        elif isinstance(sim_serial, NpcapSource):
            label = port  # already "UDP host:port"
        else:
            label = f"SIMULATION ({self.sim_protocol.get()})"
        self._log_all(
            f"[{self._ts()}] \u2500\u2500 Sniffer started on {label} "
            f"\u00b7 Target: device {self.target_address} \u2500\u2500",
        )
        self._log_target(
            f"[{self._ts()}] \u2500\u2500 Filtering for device "
            f"{self.target_address} \u2500\u2500",
        )

    def _stop(self) -> None:
        self.engine.stop()
        self.window.logs.set_paused(True)
        self.window.controls.set_sniffing(False)
        self._log_all(f"[{self._ts()}] \u2500\u2500 Sniffer stopped \u2500\u2500")
        self._log_target(f"[{self._ts()}] \u2500\u2500 Sniffer stopped \u2500\u2500")

    # ── packet handling (runs on main thread via root.after) ─────────

    def _handle_packet(
        self, decoded: dict[str, Any], raw: bytearray,
    ) -> None:
        ts = self._ts()
        proto = decoded["protocol"]
        src = decoded["src"]
        dst = decoded["dst"]
        cmd = decoded["cmd"]
        ptype = decoded["point_type"]
        pidx = decoded["point_index"]
        val = decoded["value"]
        raw_ascii = decoded.get("raw_ascii", "")

        row = [
            ts, proto, src, dst, cmd, ptype, pidx, val,
            decoded.get("raw_hex", ""), raw_ascii,
        ]

        with self._rows_lock:
            self.all_log_rows.append(row)
        self.packet_count_all.set(self.packet_count_all.get() + 1)

        # format display line
        raw_hex = decoded.get("raw_hex", "")
        if proto == "UNKNOWN":
            line = f"[{ts}] {proto:<12} RAW: {raw_ascii}"
        else:
            hex_suffix = f"  [{raw_hex}]" if raw_hex else ""
            line = (
                f"[{ts}] {proto:<12} "
                f"SRC:{str(src):>3} \u2192 DST:{str(dst):>3} "
                f"| {cmd:<18} | {ptype:<4} "
                f"IDX:{str(pidx):<4} VAL:{str(val):<12}"
                f"{hex_suffix}"
            )

        self._log_all(line)

        # device presence tracking
        if proto != "UNKNOWN" and str(src) not in ("JACE", "?"):
            self.window.logs.update_device(str(src), proto)

        if proto != "UNKNOWN" and str(src) == "JACE" and str(dst) not in ("JACE", "?", "—"):
            self.window.logs.update_device_rx(str(dst))

        if proto != "UNKNOWN":
            self.window.logs.update_comm(str(src), str(dst))

        # target device filtering
        if src == self.target_address or dst == self.target_address:
            with self._rows_lock:
                self.target_log_rows.append(row)
            self.packet_count_target.set(
                self.packet_count_target.get() + 1,
            )
            self._log_target(line)

    # ── BACnet/IP active query ────────────────────────────────────────

    def _query(self) -> None:
        if self._query_client is not None:
            self._log_all(f"[{self._ts()}] !! Query already in progress.")
            return

        jace_ip = self.jace_ip.get().strip()
        if not jace_ip:
            self._log_all(f"[{self._ts()}] !! Enter a JACE IP address before querying.")
            return

        udp_port_str = self.udp_port.get().strip()
        if not udp_port_str.isdigit() or not (1 <= int(udp_port_str) <= 65535):
            self._log_all(f"[{self._ts()}] !! UDP port must be 1–65535.")
            return

        port = int(udp_port_str)
        self.window.controls.set_querying(True)
        self._log_all(f"[{self._ts()}] ── BACnet Query → {jace_ip}:{port} ──")

        client = BACnetClient(jace_ip, port)
        self._query_client = client

        def on_log(msg: str) -> None:
            self.root.after(0, self._log_all, f"[{self._ts()}] {msg}")

        def on_result(label: str, name: str, value: str) -> None:
            line = f"[{self._ts()}]   {label:<10}  {name!r:<30}  = {value}"
            self.root.after(0, self._log_all, line)

        def on_done(ok: bool, msg: str) -> None:
            def _finish() -> None:
                self._log_all(f"[{self._ts()}] ── {msg} ──")
                self._query_client = None
                self.window.controls.set_querying(False)
            self.root.after(0, _finish)

        threading.Thread(
            target=client.full_query,
            args=(on_log, on_result, on_done),
            daemon=True,
        ).start()

    # ── rebuild ───────────────────────────────────────────────────────

    def _rebuild(self) -> None:
        self.window.controls.rebuild_btn.configure(state="disabled")
        self._log_all(f"[{self._ts()}] ── Rebuild started ──")

        import subprocess, tempfile

        if getattr(sys, "frozen", False):
            project_root = os.path.dirname(os.path.dirname(sys.executable))
        else:
            project_root = os.path.normpath(
                os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..")
            )
        bat = os.path.join(project_root, "build.bat")

        new_exe = os.path.join(project_root, "dist", "Sniffer.exe")

        # Deferred batch: waits for this process to fully exit (clean env, no
        # locked files), builds, then relaunches using an absolute path.
        deferred = (
            "@echo off\n"
            ":waitloop\n"
            'tasklist /fi "imagename eq Sniffer.exe" 2>nul | find /i "Sniffer.exe" >nul\n'
            "if not errorlevel 1 (\n"
            "    ping -n 2 127.0.0.1 >nul 2>&1\n"
            "    goto waitloop\n"
            ")\n"
            f'cd /d "{project_root}"\n'
            f'call "{bat}" REBUILD\n'
            f'if exist "{new_exe}" start "" "{new_exe}"\n'
            'del "%~f0"\n'
        )
        tf = tempfile.NamedTemporaryFile(
            mode="w", suffix=".bat", delete=False, dir=project_root,
        )
        tf.write(deferred)
        tf.close()
        subprocess.Popen(
            ["cmd", "/c", tf.name],
            creationflags=subprocess.CREATE_NO_WINDOW,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        self._log_all(f"[{self._ts()}] ── Rebuilding — app will restart when complete ──")
        self.root.after(1000, self.root.destroy)

    # ── export / clear ────────────────────────────────────────────────

    def _export(self) -> None:
        save_dir = self.save_dir.get().strip()
        if not save_dir or not os.path.isdir(save_dir):
            self._log_all(
                f"[{self._ts()}] !! Please select a valid save directory.",
            )
            return

        with self._rows_lock:
            all_rows = list(self.all_log_rows)
            target_rows = list(self.target_log_rows)

        all_path, target_path = export_csv(
            save_dir, all_rows, target_rows, self.device_address.get(),
        )

        self._log_all(
            f"[{self._ts()}] \u2500\u2500 Exported {len(all_rows)} rows "
            f"\u2192 {all_path}",
        )
        self._log_all(
            f"[{self._ts()}] \u2500\u2500 Exported {len(target_rows)} "
            f"target rows \u2192 {target_path}",
        )

    def _clear(self) -> None:
        self.window.logs.clear()
        self.window.logs.clear_presence()
        self.window.logs.clear_comm()
        with self._rows_lock:
            self.all_log_rows.clear()
            self.target_log_rows.clear()
        self.packet_count_all.set(0)
        self.packet_count_target.set(0)

    # ── helpers ───────────────────────────────────────────────────────

    def _log_all(self, text: str) -> None:
        self.window.logs.append(self.window.logs.all_log, text)

    def _log_target(self, text: str) -> None:
        self.window.logs.append(self.window.logs.target_log, text)

    @staticmethod
    def _ts() -> str:
        return datetime.now().strftime("%H:%M:%S.%f")[:-3]

    def run(self) -> None:
        """Enter the Tk main loop."""
        self.root.mainloop()


def _parse_obix(path: str) -> list[tuple[str, str]]:
    """Parse an oBIX/XML device roster and return (addr, name) pairs.

    Supports Niagara JciN2ODevice / JciN2BDevice exports where each <ref>
    carries a ``display`` attribute containing ``addr:<n>`` and an optional
    ``displayName`` attribute for the human-readable label.
    """
    tree = ET.parse(path)
    root = tree.getroot()

    # strip namespace prefix so tag matching works regardless of xmlns
    ns_strip = re.compile(r"^\{[^}]*\}")

    devices: list[tuple[str, str]] = []
    for elem in root.iter():
        if ns_strip.sub("", elem.tag) != "ref":
            continue
        display = elem.get("display", "")
        m = re.search(r"\baddr:(\d+)", display)
        if not m:
            continue
        addr = m.group(1)

        # prefer displayName; fall back to name with $XX → char decoding
        name = elem.get("displayName", "")
        if not name:
            raw_name = elem.get("name", "")
            name = re.sub(
                r"\$([0-9a-fA-F]{2})",
                lambda x: chr(int(x.group(1), 16)),
                raw_name,
            )

        devices.append((addr, name))

    return devices


def main() -> None:
    """Entry point used by ``pyproject.toml`` console script."""
    app = SnifferApp()
    app.run()
