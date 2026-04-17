"""Button bar -- Start, Stop, Export CSV, Clear Log."""

from __future__ import annotations

import tkinter as tk
from typing import Callable

from sniffer.gui import theme


class ControlBar(tk.Frame):
    """Horizontal row of action buttons."""

    def __init__(
        self,
        parent: tk.Widget,
        *,
        on_start: Callable[[], None],
        on_stop: Callable[[], None],
        on_export: Callable[[], None],
        on_clear: Callable[[], None],
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
