"""Tabbed control bar -- Capture tab and Simulate tab."""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Callable

from sniffer.gui import theme

_SIM_PROTOCOLS = ["BACnet-MSTP", "N2", "Both"]


class ControlBar(ttk.Notebook):
    """Two-tab notebook: CAPTURE (primary actions) and SIMULATE (traffic gen)."""

    def __init__(
        self,
        parent: tk.Widget,
        *,
        on_start: Callable[[], None],
        on_stop: Callable[[], None],
        on_simulate: Callable[[], None],
        on_export: Callable[[], None],
        on_clear: Callable[[], None],
        on_rebuild: Callable[[], None],
        on_query: Callable[[], None],
        on_scan: Callable[[], None],
        on_query_all: Callable[[], None],
        sim_protocol_var: tk.StringVar,
    ) -> None:
        super().__init__(parent)

        # ── CAPTURE tab ───────────────────────────────────────────────
        capture_tab = tk.Frame(self, bg=theme.BG, pady=4, padx=4)
        self.add(capture_tab, text="  CAPTURE  ")

        # row 1: start / stop / export / clear / rebuild
        row1 = tk.Frame(capture_tab, bg=theme.BG)
        row1.pack(fill="x", pady=(2, 4))

        self.start_btn = tk.Button(
            row1,
            text="▶  START SNIFFING",
            bg=theme.ACCENT,
            fg="#1a1a1a",
            bd=0,
            font=theme.FONT_BTN,
            padx=20,
            pady=8,
            cursor="hand2",
            command=on_start,
        )
        self.start_btn.pack(side="left", padx=(0, 8))

        self.stop_btn = tk.Button(
            row1,
            text="■  STOP",
            bg=theme.DANGER,
            fg=theme.TEXT,
            bd=0,
            font=theme.FONT_BTN,
            padx=20,
            pady=8,
            cursor="hand2",
            state="disabled",
            command=on_stop,
        )
        self.stop_btn.pack(side="left", padx=(0, 8))

        tk.Frame(row1, bg=theme.BORDER, width=1, height=36).pack(
            side="left", padx=8, pady=4,
        )

        tk.Button(
            row1,
            text="⬇  EXPORT CSV",
            bg=theme.INPUT_BG,
            fg=theme.TEXT,
            bd=0,
            font=theme.FONT_BTN_SM,
            padx=16,
            pady=8,
            cursor="hand2",
            command=on_export,
        ).pack(side="left", padx=(0, 8))

        tk.Button(
            row1,
            text="\U0001f5d1  CLEAR LOG",
            bg=theme.INPUT_BG,
            fg=theme.TEXT,
            bd=0,
            font=theme.FONT_BTN_SM,
            padx=16,
            pady=8,
            cursor="hand2",
            command=on_clear,
        ).pack(side="left")

        tk.Frame(row1, bg=theme.BORDER, width=1, height=36).pack(
            side="left", padx=8, pady=4,
        )

        self.rebuild_btn = tk.Button(
            row1,
            text="⟳  REBUILD",
            bg=theme.PANEL,
            fg=theme.MUTED,
            activebackground=theme.BORDER,
            activeforeground=theme.TEXT,
            bd=0,
            font=theme.FONT_BTN_SM,
            padx=14,
            pady=8,
            cursor="hand2",
            command=on_rebuild,
        )
        self.rebuild_btn.pack(side="left")

        # row 2: query / scan / query-all
        row2 = tk.Frame(capture_tab, bg=theme.BG)
        row2.pack(fill="x", pady=(0, 2))

        self.query_btn = tk.Button(
            row2,
            text="☉  QUERY DEVICE",
            bg="#1e3a1e",
            fg="#80ff80",
            activebackground="#2a4a2a",
            activeforeground="#b0ffb0",
            bd=0,
            font=theme.FONT_BTN_SM,
            padx=16,
            pady=6,
            cursor="hand2",
            command=on_query,
        )
        self.query_btn.pack(side="left", padx=(0, 8))

        self.scan_btn = tk.Button(
            row2,
            text="⊙  SCAN NETWORK",
            bg="#1e2a3e",
            fg="#80c0ff",
            activebackground="#2a3a50",
            activeforeground="#b0d8ff",
            bd=0,
            font=theme.FONT_BTN_SM,
            padx=16,
            pady=6,
            cursor="hand2",
            command=on_scan,
        )
        self.scan_btn.pack(side="left", padx=(0, 8))

        self.query_all_btn = tk.Button(
            row2,
            text="⊛  QUERY ALL",
            bg="#2a1e3e",
            fg="#c080ff",
            activebackground="#3a2a50",
            activeforeground="#d8b0ff",
            bd=0,
            font=theme.FONT_BTN_SM,
            padx=16,
            pady=6,
            cursor="hand2",
            command=on_query_all,
        )
        self.query_all_btn.pack(side="left", padx=(0, 8))

        # ── SIMULATE tab ──────────────────────────────────────────────
        sim_tab = tk.Frame(self, bg=theme.BG, pady=6, padx=4)
        self.add(sim_tab, text="  SIMULATE  ")

        tk.Label(
            sim_tab,
            text="Protocol:",
            bg=theme.BG,
            fg=theme.MUTED,
            font=theme.FONT_MONO_SM,
        ).pack(side="left", padx=(0, 6))

        self.sim_proto_combo = ttk.Combobox(
            sim_tab,
            textvariable=sim_protocol_var,
            values=_SIM_PROTOCOLS,
            width=14,
            state="readonly",
            font=theme.FONT_MONO_SM,
        )
        self.sim_proto_combo.pack(side="left", padx=(0, 10))

        self.sim_btn = tk.Button(
            sim_tab,
            text="▶  START SIMULATION",
            bg="#2a4a6a",
            fg="#80c8ff",
            activebackground="#3a5a7a",
            activeforeground="#b0e0ff",
            bd=0,
            font=theme.FONT_BTN,
            padx=20,
            pady=8,
            cursor="hand2",
            command=on_simulate,
        )
        self.sim_btn.pack(side="left", padx=(0, 8))

        self.sim_stop_btn = tk.Button(
            sim_tab,
            text="■  STOP",
            bg=theme.DANGER,
            fg=theme.TEXT,
            bd=0,
            font=theme.FONT_BTN,
            padx=20,
            pady=8,
            cursor="hand2",
            state="disabled",
            command=on_stop,
        )
        self.sim_stop_btn.pack(side="left", padx=(0, 16))

        tk.Label(
            sim_tab,
            text="Generates synthetic bus traffic for UI testing — no hardware required.",
            bg=theme.BG,
            fg=theme.MUTED,
            font=theme.FONT_MONO_XS,
        ).pack(side="left")

    # ── state management ──────────────────────────────────────────────

    def set_sniffing(self, active: bool) -> None:
        """Toggle button enabled states for sniffing / idle."""
        self.start_btn.configure(state="disabled" if active else "normal")
        self.stop_btn.configure(state="normal" if active else "disabled")
        self.sim_btn.configure(state="disabled" if active else "normal")
        self.sim_stop_btn.configure(state="normal" if active else "disabled")
        self.sim_proto_combo.configure(state="disabled" if active else "readonly")
        if active:
            self.query_btn.configure(state="disabled")
            self.query_all_btn.configure(state="disabled")

    def set_querying(self, active: bool) -> None:
        """Toggle query button state while a query is in progress."""
        self.query_btn.configure(
            state="disabled" if active else "normal",
            text="⧖  QUERYING…" if active else "☉  QUERY DEVICE",
        )

    def set_scanning(self, active: bool) -> None:
        """Toggle scan/query-all button states while a scan or batch query runs."""
        self.scan_btn.configure(
            state="disabled" if active else "normal",
            text="⧖  SCANNING…" if active else "⊙  SCAN NETWORK",
        )
        self.query_all_btn.configure(state="disabled" if active else "normal")
