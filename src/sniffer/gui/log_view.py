"""Tabbed log viewer -- All Devices + Target Device."""

from __future__ import annotations

import tkinter as tk
from tkinter import scrolledtext, ttk

from sniffer.gui import theme


class LogView(ttk.Notebook):
    """Notebook with two scrolled-text panes for packet logs."""

    def __init__(self, parent: tk.Widget) -> None:
        super().__init__(parent)

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

    # ── helpers ───────────────────────────────────────────────────────

    def append(self, widget: scrolledtext.ScrolledText, text: str) -> None:
        """Append a line to the given log widget."""
        widget.configure(state="normal")
        widget.insert("end", text + "\n")
        widget.see("end")
        widget.configure(state="disabled")

    def clear(self) -> None:
        """Clear both log panes."""
        for w in (self.all_log, self.target_log):
            w.configure(state="normal")
            w.delete("1.0", "end")
            w.configure(state="disabled")
