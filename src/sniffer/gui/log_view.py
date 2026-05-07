"""Tabbed log viewer -- All Devices, Target Device, Device Presence, Comm Graph."""

from __future__ import annotations

import math
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
        self._comm_pairs: dict[tuple[str, str], int] = {}
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

        # -- comm graph tab --
        graph_frame = tk.Frame(self, bg=theme.BG)
        self.add(graph_frame, text="  COMM GRAPH  ")
        self._build_graph_tab(graph_frame)

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

        cols = ("status", "addr", "name", "protocol", "last_seen", "tx", "rx", "health")
        self._tree = ttk.Treeview(
            tree_frame, columns=cols, show="headings",
            style="Presence.Treeview",
        )

        self._tree.heading("status",   text="")
        self._tree.heading("addr",     text="ADDR")
        self._tree.heading("name",     text="NAME")
        self._tree.heading("protocol", text="PROTOCOL")
        self._tree.heading("last_seen",text="LAST TX")
        self._tree.heading("tx",       text="TX")
        self._tree.heading("rx",       text="RX")
        self._tree.heading("health",   text="HEALTH")

        self._tree.column("status",    width=18,  minwidth=18,  stretch=False, anchor="center")
        self._tree.column("addr",      width=110, anchor="w")
        self._tree.column("name",      width=180, anchor="w")
        self._tree.column("protocol",  width=100, anchor="w")
        self._tree.column("last_seen", width=120, anchor="w")
        self._tree.column("tx",        width=55,  anchor="e")
        self._tree.column("rx",        width=55,  anchor="e")
        self._tree.column("health",    width=160, anchor="w")

        self._tree.tag_configure("active",        foreground="#50d080")
        self._tree.tag_configure("stale",         foreground="#d0a020")
        self._tree.tag_configure("silent",        foreground="#555555")
        self._tree.tag_configure("ghost",         foreground="#d0c040")
        self._tree.tag_configure("polled_silent", foreground="#e07030")

        sb = ttk.Scrollbar(tree_frame, orient="vertical", command=self._tree.yview)
        self._tree.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        self._tree.pack(fill="both", expand=True)

    # ── graph tab construction ────────────────────────────────────────

    def _build_graph_tab(self, parent: tk.Frame) -> None:
        toolbar = tk.Frame(parent, bg=theme.BG, pady=5)
        toolbar.pack(fill="x", padx=10)
        tk.Label(
            toolbar,
            text="Device communication topology  ·  edge brightness = traffic volume",
            bg=theme.BG, fg=theme.MUTED, font=theme.FONT_MONO_XS,
        ).pack(side="left", padx=12)
        tk.Button(
            toolbar,
            text="Clear",
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
            command=self.clear_comm,
        ).pack(side="right", padx=12)
        self._canvas = tk.Canvas(
            parent, bg=theme.LOG_BG, bd=0, highlightthickness=0,
        )
        self._canvas.pack(fill="both", expand=True)

    # ── public API ────────────────────────────────────────────────────

    def update_device(self, addr: str, protocol: str, name: str = "") -> None:
        """Record a live TX packet from *addr*.  Must be called on the main thread."""
        now = time.monotonic()
        if addr not in self._presence:
            self._presence[addr] = {
                "name": name,
                "protocol": protocol,
                "last_seen": now,
                "count": 1,
                "rx_count": 0,
                "in_roster": False,
                "iid": None,
            }
        else:
            e = self._presence[addr]
            e["last_seen"] = now
            e["count"] += 1
            e["protocol"] = protocol
            if name and not e["name"]:
                e["name"] = name

    def update_device_rx(self, addr: str) -> None:
        """Record a JACE poll directed at *addr*.  Must be called on the main thread."""
        if addr not in self._presence:
            self._presence[addr] = {
                "name": "",
                "protocol": "",
                "last_seen": None,
                "count": 0,
                "rx_count": 1,
                "in_roster": False,
                "iid": None,
            }
        else:
            self._presence[addr]["rx_count"] = self._presence[addr].get("rx_count", 0) + 1

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
                    "rx_count": 0,
                    "in_roster": True,
                    "iid": None,
                }
            else:
                self._presence[addr]["in_roster"] = True
                if name and not self._presence[addr]["name"]:
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

            tx = e["count"]
            rx = e.get("rx_count", 0)
            in_roster = e.get("in_roster", False)
            if tx == 0 and rx > 0:
                health = "POLLED · NO RESPONSE"
            elif tx > 0 and not in_roster:
                health = "Active · not in roster"
            elif tx == 0 and rx == 0 and in_roster:
                health = "Not polled"
            else:
                health = ""

            rows.append([
                status,
                addr_int,
                addr_hex,
                e["name"],
                _short_proto(e["protocol"]) if e["protocol"] else "",
                last,
                tx,
                rx,
                "yes" if in_roster else "no",
                health,
            ])
        return rows

    def update_comm(self, src: str, dst: str) -> None:
        """Record a src→dst packet.  Must be called on the main thread."""
        key = (src, dst)
        self._comm_pairs[key] = self._comm_pairs.get(key, 0) + 1

    def clear_comm(self) -> None:
        """Wipe the communication graph."""
        self._comm_pairs.clear()
        self._canvas.delete("all")

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
            tx = e["count"]
            rx = e.get("rx_count", 0)
            in_roster = e.get("in_roster", False)

            if e["last_seen"] is None:
                dot, last = "○", "never"
                base_tag = "silent"
            else:
                age = now - e["last_seen"]
                last = _fmt_age(age)
                if age < _ACTIVE_SECS:
                    dot, base_tag = "●", "active"
                elif age < _STALE_SECS:
                    dot, base_tag = "●", "stale"
                else:
                    dot, base_tag = "○", "silent"

            # derive health label and override tag
            if tx == 0 and rx > 0:
                health = "POLLED · NO RESPONSE"
                tag = "polled_silent"
            elif tx > 0 and not in_roster:
                health = "Active · not in roster"
                tag = "ghost"
            elif tx == 0 and rx == 0 and in_roster:
                health = "Not polled"
                tag = "silent"
            else:
                health = ""
                tag = base_tag

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
                tx,
                rx,
                health,
            )

            iid = e["iid"]
            if iid is None or not self._tree.exists(iid):
                e["iid"] = self._tree.insert("", "end", values=values, tags=(tag,))
            else:
                self._tree.item(iid, values=values, tags=(tag,))

        self._draw_graph()
        self.after(1000, self._tick)

    # ── graph drawing ─────────────────────────────────────────────────

    def _draw_graph(self) -> None:
        canvas = self._canvas
        w = canvas.winfo_width()
        h = canvas.winfo_height()
        if w <= 1 or h <= 1:
            return  # canvas not yet laid out

        canvas.delete("all")

        # Collect every known address from traffic + presence roster
        addrs: set[str] = set(self._presence)
        for src, dst in self._comm_pairs:
            addrs.add(src)
            addrs.add(dst)

        if not addrs:
            canvas.create_text(
                w // 2, h // 2,
                text="No traffic yet",
                fill=theme.MUTED,
                font=theme.FONT_MONO_SM,
            )
            return

        sorted_addrs = sorted(addrs, key=_addr_sort)
        n = len(sorted_addrs)
        cx, cy = w / 2, h / 2
        ring_r = min(w, h) * 0.38
        node_r = max(10, min(16, int(ring_r * 0.18)))

        if n == 1:
            pos: dict[str, tuple[float, float]] = {sorted_addrs[0]: (cx, cy)}
        else:
            pos = {}
            for i, addr in enumerate(sorted_addrs):
                angle = 2 * math.pi * i / n - math.pi / 2  # start at top
                pos[addr] = (
                    cx + ring_r * math.cos(angle),
                    cy + ring_r * math.sin(angle),
                )

        # Edge color/width tiers (dim → bright as traffic increases)
        _COLORS = ["#4a3008", "#906010", "#c07818", "#e8a020"]
        _WIDTHS  = [1, 2, 3, 4]
        max_count = max(self._comm_pairs.values()) if self._comm_pairs else 1
        log_max = math.log1p(max_count)

        for (src, dst), count in self._comm_pairs.items():
            if src == dst or src not in pos or dst not in pos:
                continue
            x1, y1 = pos[src]
            x2, y2 = pos[dst]
            dx, dy = x2 - x1, y2 - y1
            length = math.hypot(dx, dy)
            if length < 1:
                continue
            ux, uy = dx / length, dy / length
            tier = min(3, int(math.log1p(count) / log_max * 4)) if log_max else 0
            canvas.create_line(
                x1 + ux * node_r,
                y1 + uy * node_r,
                x2 - ux * (node_r + 5),
                y2 - uy * (node_r + 5),
                fill=_COLORS[tier],
                width=_WIDTHS[tier],
                arrow=tk.LAST,
                arrowshape=(8, 10, 4),
            )

        now = time.monotonic()
        for addr, (x, y) in pos.items():
            e = self._presence.get(addr)
            if e is None:
                fill, outline = "#3a3a3a", "#444444"
            elif e["last_seen"] is None:
                fill, outline = "#2a2a2a", "#555555"
            else:
                age = now - e["last_seen"]
                if age < _ACTIVE_SECS:
                    fill, outline = "#50d080", theme.ACCENT
                elif age < _STALE_SECS:
                    fill, outline = "#d0a020", theme.ACCENT
                else:
                    fill, outline = "#555555", "#777777"

            canvas.create_oval(
                x - node_r, y - node_r, x + node_r, y + node_r,
                fill=fill, outline=outline, width=2,
            )
            canvas.create_text(
                x, y, text=addr,
                fill=theme.TEXT, font=("Courier New", 8, "bold"),
            )
            name = (e or {}).get("name", "")
            if name:
                canvas.create_text(
                    x, y + node_r + 9,
                    text=name,
                    fill=theme.MUTED,
                    font=theme.FONT_MONO_XS,
                )


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
