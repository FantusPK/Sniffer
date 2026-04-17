"""Application layer -- wires the sniffing engine to the GUI."""

from __future__ import annotations

import os
import sys
import threading
import tkinter as tk
from datetime import datetime
from typing import Any

import serial.tools.list_ports

from sniffer.core.engine import EngineCallbacks, SnifferEngine
from sniffer.core.exporter import export_csv
from sniffer.gui.main_window import MainWindow
from sniffer.protocols import get_decoders


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

        self.target_address: int = 1
        self._rows_lock = threading.Lock()
        self.all_log_rows: list[list] = []
        self.target_log_rows: list[list] = []

        # ── engine ────────────────────────────────────────────────────
        self.engine = SnifferEngine(get_decoders())

        # ── GUI ───────────────────────────────────────────────────────
        self.window = MainWindow(
            self.root,
            app_title="Bus Sniffer",
            subtitle="Field Diagnostic  //  Auto-Detect Protocols",
            port_var=self.selected_port,
            addr_var=self.device_address,
            dir_var=self.save_dir,
            all_count_var=self.packet_count_all,
            target_count_var=self.packet_count_target,
            protocol_var=self.protocol_detected,
            baud_var=self.current_baud,
            status_var=self.status_text,
            on_refresh_ports=self._refresh_ports,
            on_start=self._start,
            on_stop=self._stop,
            on_export=self._export,
            on_clear=self._clear,
        )

        self._refresh_ports()
        self.window.config.force_display("1", _default_log_dir())

    # ── port helpers ──────────────────────────────────────────────────

    def _refresh_ports(self) -> None:
        ports = [p.device for p in serial.tools.list_ports.comports()]
        self.window.config.set_ports(ports)

    # ── start / stop ──────────────────────────────────────────────────

    def _start(self) -> None:
        port = self.selected_port.get()
        addr_str = self.device_address.get().strip()
        save_dir = self.save_dir.get().strip()

        if not port:
            self._log_all(f"[{self._ts()}] !! No COM port selected.")
            return
        if not addr_str.isdigit() or not (1 <= int(addr_str) <= 255):
            self._log_all(f"[{self._ts()}] !! Device address must be 1\u2013255.")
            return
        if not save_dir or not os.path.isdir(save_dir):
            self._log_all(
                f"[{self._ts()}] !! Please select a valid save directory.",
            )
            return

        self.target_address = int(addr_str)
        self.status_text.set("LIVE")
        self.protocol_detected.set("detecting\u2026")
        self.window.controls.set_sniffing(True)

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

        try:
            self.engine.start(port, callbacks)
        except Exception:
            self.status_text.set("ERROR")
            self.window.controls.set_sniffing(False)
            return

        self._log_all(
            f"[{self._ts()}] \u2500\u2500 Sniffer started on {port} "
            f"\u00b7 Target: device {self.target_address} \u2500\u2500",
        )
        self._log_target(
            f"[{self._ts()}] \u2500\u2500 Filtering for device "
            f"{self.target_address} \u2500\u2500",
        )

    def _stop(self) -> None:
        self.engine.stop()
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
        if proto == "UNKNOWN":
            line = f"[{ts}] {proto:<12} RAW: {raw_ascii}"
        else:
            line = (
                f"[{ts}] {proto:<12} "
                f"SRC:{str(src):>3} \u2192 DST:{str(dst):>3} "
                f"| {cmd:<18} | {ptype:<4} "
                f"IDX:{str(pidx):<4} VAL:{str(val):<12}"
            )

        self._log_all(line)

        # target device filtering
        if src == self.target_address or dst == self.target_address:
            with self._rows_lock:
                self.target_log_rows.append(row)
            self.packet_count_target.set(
                self.packet_count_target.get() + 1,
            )
            self._log_target(line)

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


def main() -> None:
    """Entry point used by ``pyproject.toml`` console script."""
    app = SnifferApp()
    app.run()
