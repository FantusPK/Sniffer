"""Tabbed log viewer -- All Devices, Target Device, Device Presence."""

from __future__ import annotations

import time
import tkinter as tk
from tkinter import scrolledtext, ttk
from typing import Callable

from sniffer.gui import theme

_ACTIVE_SECS = 10
_STALE_SECS  = 30


class LogView(ttk.Notebook):
    """Notebook with two scrolled-text panes and a live device presence tab."""

    def __init__(
        self,
        parent: tk.Widget,
        on_import: Callable[[], None] | None = None,
        on_export_presence: Callable[[], None] | None = None,
    ) -> None:
        super().__init__(parent)
        self._presence: dict[str, dict] = {}
        self._on_import = on_import
        self._on_export_presence = on_export_presence
        self._paused = False

        # -- all devices tab --
        all_frame = tk.Frame(self, bg=theme.BG)
        self.add(all_frame, text="  ALL DEVICES  ")
        self.all_log = scrolledtext.ScrolledText(
            all_frame,
            bg=theme.LOG_BG,
            fg="#a0c0a0",
            font=theme.FONT_MONO_SM,
            bd=0,
            state="disabled",
            wrap="none",
        )
        self.all_log.pack(fill="both", expand=True)

        # -- target device tab --
        target_frame = tk.Frame(self, bg=theme.BG)
        self.add(target_frame, text="  TARGET DEVICE  ")
        self.target_log = scrolledtext.ScrolledText(
            target_frame,
            bg=theme.LOG_BG,
            fg="#a0d0ff",
            font=theme.FONT_MONO_SM,
            bd=0,
            state="disabled",
            wrap="none",
        )
        self.target_log.pack(fill="both", expand=True)

        # -- device presence tab --
        presence_frame = tk.Frame(self, bg=theme.BG)
        self.add(presence_frame, text="  DEVICE PRESENCE  ")
        self._build_presence_tab(presence_frame)

        self.after(1000, self._tick)

    # ── presence tab construction ─────────────────────────────────────

    def _build_presence_tab(self, parent: tk.Frame) -> None:
        # legend row
        legend = tk.Frame(parent, bg=theme.BG, pady=5)
        legend.pack(fill="x", padx=10)
        for dot, label, colour in (
            ("●", "ACTIVE  (<10 s)",  "#50d080"),
            ("●", "STALE  (10–30 s)", "#d0a020"),
            ("○", "SILENT  (>30 s)",  "#555555"),
        ):
            tk.Label(
                legend, text=f"{dot} {label}", bg=theme.BG,
                fg=colour, font=theme.FONT_MONO_XS,
            ).pack(side="left", padx=12)

        if self._on_export_presence:
            tk.Button(
                legend,
                text="Export...",
                bg=theme.PANEL,
                fg=theme.MUTED,
                activebackground=theme.BORDER,
                activeforeground=theme.TEXT,
                font=theme.FONT_MONO_XS,
                relief="flat",
                bd=0,
                padx=8,
                pady=2,
                cursor="hand2",
                command=self._on_export_presence,
            ).pack(side="right", padx=4)

        if self._on_import:
            tk.Button(
                legend,
                text="Import Roster...",
                bg=theme.PANEL,
                fg=theme.MUTED,
                activebackground=theme.BORDER,
                activeforeground=theme.TEXT,
                font=theme.FONT_MONO_XS,
                relief="flat",
                bd=0,
                padx=8,
                pady=2,
                cursor="hand2",
                command=self._on_import,
            ).pack(side="right", padx=4)

        # treeview + scrollbar
        tree_frame = tk.Frame(parent, bg=theme.BG)
        tree_frame.pack(fill="both", expand=True)

        cols = ("status", "addr", "name", "protocol", "last_seen", "packets")
        self._tree = ttk.Treeview(
            tree_frame, columns=cols, show="headings",
            style="Presence.Treeview",
        )

        self._tree.heading("status",   text="")
        self._tree.heading("addr",     text="ADDR")
        self._tree.heading("name",     text="NAME")
        self._tree.heading("protocol", text="PROTOCOL")
        self._tree.heading("last_seen",text="LAST SEEN")
        self._tree.heading("packets",  text="PKTS")

        self._tree.column("status",    width=18,  minwidth=18,  stretch=False, anchor="center")
        self._tree.column("addr",      width=110, anchor="w")
        self._tree.column("name",      width=200, anchor="w")
        self._tree.column("protocol",  width=110, anchor="w")
        self._tree.column("last_seen", width=130, anchor="w")
        self._tree.column("packets",   width=60,  anchor="e")

        self._tree.tag_configure("active", foreground="#50d080")
        self._tree.tag_configure("stale",  foreground="#d0a020")
        self._tree.tag_configure("silent", foreground="#555555")

        sb = ttk.Scrollbar(tree_frame, orient="vertical", command=self._tree.yview)
        self._tree.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        self._tree.pack(fill="both", expand=True)

    # ── public API ────────────────────────────────────────────────────

    def update_device(self, addr: str, protocol: str, name: str = "") -> None:
        """Record a live packet from *addr*.  Must be called on the main thread."""
        now = time.monotonic()
        if addr not in self._presence:
            self._presence[addr] = {
                "name": name,
                "protocol": protocol,
                "last_seen": now,
                "count": 1,
                "iid": None,
            }
        else:
            e = self._presence[addr]
            e["last_seen"] = now
            e["count"] += 1
            e["protocol"] = protocol
            if name and not e["name"]:
                e["name"] = name

    def import_roster(self, devices: list[tuple[str, str]]) -> None:
        """Pre-populate the presence table from an imported device list.

        Each entry is (addr, name).  Devices already in the table get their
        name filled in if it was blank; live entries are never overwritten.
        """
        for addr, name in devices:
            if addr not in self._presence:
                self._presence[addr] = {
                    "name": name,
                    "protocol": "",
                    "last_seen": None,
                    "count": 0,
                    "iid": None,
                }
            elif name and not self._presence[addr]["name"]:
                self._presence[addr]["name"] = name

    def get_presence_rows(self) -> list[list]:
        """Return current presence table as plain rows for CSV export.

        Includes roster-only devices (last_seen=None / packets=0) so the
        export reflects every known device on the trunk.
        """
        now = time.monotonic()
        rows = []
        for addr, e in sorted(self._presence.items(), key=lambda x: _addr_sort(x[0])):
            if e["last_seen"] is None:
                status, last = "Not seen", "never"
            else:
                age = now - e["last_seen"]
                if age < _ACTIVE_SECS:
                    status = "Active"
                elif age < _STALE_SECS:
                    status = "Stale"
                else:
                    status = "Silent"
                last = _fmt_age(age)

            try:
                addr_int = int(addr)
                addr_hex = f"0x{addr_int:02X}"
            except ValueError:
                addr_int = addr
                addr_hex = ""

            rows.append([
                status,
                addr_int,
                addr_hex,
                e["name"],
                _short_proto(e["protocol"]) if e["protocol"] else "",
                last,
                e["count"],
            ])
        return rows

    def clear_presence(self) -> None:
        """Wipe the presence table (called when the user hits Clear)."""
        self._presence.clear()
        for iid in self._tree.get_children():
            self._tree.delete(iid)

    # ── helpers ───────────────────────────────────────────────────────

    def append(self, widget: scrolledtext.ScrolledText, text: str) -> None:
        widget.configure(state="normal")
        widget.insert("end", text + "\n")
        widget.see("end")
        widget.configure(state="disabled")

    def clear(self) -> None:
        for w in (self.all_log, self.target_log):
            w.configure(state="normal")
            w.delete("1.0", "end")
            w.configure(state="disabled")

    def set_paused(self, paused: bool) -> None:
        """Freeze or resume the presence table age/color updates."""
        self._paused = paused

    # ── 1-second tick ─────────────────────────────────────────────────

    def _tick(self) -> None:
        if self._paused:
            self.after(1000, self._tick)
            return
        now = time.monotonic()
        for addr, e in sorted(self._presence.items(), key=lambda x: _addr_sort(x[0])):
            if e["last_seen"] is None:
                tag, dot, last = "silent", "○", "never"
            else:
                age = now - e["last_seen"]
                if age < _ACTIVE_SECS:
                    tag, dot = "active", "●"
                elif age < _STALE_SECS:
                    tag, dot = "stale",  "●"
                else:
                    tag, dot = "silent", "○"
                last = _fmt_age(age)

            try:
                addr_disp = f"{int(addr):>3}  (0x{int(addr):02X})"
            except ValueError:
                addr_disp = addr

            values = (
                dot,
                addr_disp,
                e["name"],
                _short_proto(e["protocol"]),
                last,
                e["count"],
            )

            iid = e["iid"]
            if iid is None or not self._tree.exists(iid):
                e["iid"] = self._tree.insert("", "end", values=values, tags=(tag,))
            else:
                self._tree.item(iid, values=values, tags=(tag,))

        self.after(1000, self._tick)


# ── module-level helpers ──────────────────────────────────────────────

def _addr_sort(addr: str) -> int:
    try:
        return int(addr)
    except ValueError:
        return 9999


def _fmt_age(age: float) -> str:
    s = int(age)
    if s < 60:
        return f"{s}s ago"
    return f"{s // 60}m {s % 60}s ago"


def _short_proto(proto: str) -> str:
    return {
        "N2Open-CMD":  "N2-Open",
        "N2Open-RESP": "N2-Open",
        "N2-BIN":      "N2-BIN",
        "BACnet-MSTP": "BACnet",
    }.get(proto, proto)
