"""Live statistics bar -- packet counts, protocol, baud, status."""

from __future__ import annotations

import tkinter as tk

from sniffer.gui import theme


class StatsBar(tk.Frame):
    """Horizontal stats panel with labelled counters."""

    def __init__(
        self,
        parent: tk.Widget,
        *,
        all_count_var: tk.IntVar,
        target_count_var: tk.IntVar,
        protocol_var: tk.StringVar,
        baud_var: tk.StringVar,
        status_var: tk.StringVar,
    ) -> None:
        super().__init__(
            parent,
            bg=theme.PANEL,
            highlightbackground=theme.BORDER,
            highlightthickness=1,
        )

        blocks = [
            ("ALL DEVICES  PACKETS", all_count_var, theme.ACCENT),
            ("TARGET DEVICE PACKETS", target_count_var, theme.ACCENT),
            ("PROTOCOL DETECTED", protocol_var, "#a0c0ff"),
            ("BAUD RATE", baud_var, "#c0a0ff"),
            ("STATUS", status_var, theme.SUCCESS),
        ]

        col = 0
        for label, var, colour in blocks:
            if col > 0:
                tk.Frame(self, bg=theme.BORDER, width=1).grid(
                    row=0, column=col, sticky="ns", pady=4,
                )
                col += 1

            cell = tk.Frame(self, bg=theme.PANEL, padx=16, pady=6)
            cell.grid(row=0, column=col, sticky="w")

            tk.Label(
                cell, text=label, bg=theme.PANEL,
                fg=theme.MUTED, font=theme.FONT_MONO_XS,
            ).pack(anchor="w")
            tk.Label(
                cell, textvariable=var, bg=theme.PANEL,
                fg=colour, font=theme.FONT_STAT,
            ).pack(anchor="w")

            col += 1
