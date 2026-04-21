"""Button bar -- Start, Stop, Simulate, Export CSV, Clear Log."""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Callable

from sniffer.gui import theme

_SIM_PROTOCOLS = ["BACnet-MSTP", "N2", "Both"]


class ControlBar(tk.Frame):
    """Horizontal row of action buttons."""

    def __init__(
        self,
        parent: tk.Widget,
        *,
        on_start: Callable[[], None],
        on_stop: Callable[[], None],
        on_simulate: Callable[[], None],
        on_export: Callable[[], None],
        on_clear: Callable[[], None],
        sim_protocol_var: tk.StringVar,
    ) -> None:
        super().__init__(parent, bg=theme.BG)

        self.start_btn = tk.Button(
            self,
            text="\u25b6  START SNIFFING",
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
            self,
            text="\u25a0  STOP",
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

        # ── separator ─────────────────────────────────────────────────
        tk.Frame(self, bg=theme.BORDER, width=1, height=36).pack(
            side="left", padx=8, pady=4,
        )

        # ── simulate controls ─────────────────────────────────────────
        sim_frame = tk.Frame(self, bg=theme.BG)
        sim_frame.pack(side="left", padx=(0, 0))

        tk.Label(
            sim_frame, text="SIM", bg=theme.BG,
            fg=theme.MUTED, font=theme.FONT_MONO_XS,
        ).pack(side="left", padx=(0, 4))

        self.sim_proto_combo = ttk.Combobox(
            sim_frame,
            textvariable=sim_protocol_var,
            values=_SIM_PROTOCOLS,
            width=12,
            state="readonly",
            font=theme.FONT_MONO_SM,
        )
        self.sim_proto_combo.pack(side="left", padx=(0, 6))

        self.sim_btn = tk.Button(
            sim_frame,
            text="\u25b6  SIMULATE",
            bg="#2a4a6a",
            fg="#80c8ff",
            bd=0,
            font=theme.FONT_BTN_SM,
            padx=14,
            pady=8,
            cursor="hand2",
            command=on_simulate,
        )
        self.sim_btn.pack(side="left")

        # ── separator ─────────────────────────────────────────────────
        tk.Frame(self, bg=theme.BORDER, width=1, height=36).pack(
            side="left", padx=8, pady=4,
        )

        # ── utility buttons ───────────────────────────────────────────
        tk.Button(
            self,
            text="\u2b07  EXPORT CSV",
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
            self,
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

    def set_sniffing(self, active: bool) -> None:
        """Toggle button enabled states for sniffing / idle."""
        self.start_btn.configure(state="disabled" if active else "normal")
        self.stop_btn.configure(state="normal" if active else "disabled")
        self.sim_btn.configure(state="disabled" if active else "normal")
        self.sim_proto_combo.configure(state="disabled" if active else "readonly")
