"""Configuration panel -- COM port, device address, log directory."""

from __future__ import annotations

import tkinter as tk
from tkinter import filedialog, ttk

from sniffer.gui import theme


class ConfigPanel(tk.Frame):
    """Top configuration bar with port, address, and save-directory pickers."""

    def __init__(
        self,
        parent: tk.Widget,
        port_var: tk.StringVar,
        addr_var: tk.StringVar,
        dir_var: tk.StringVar,
        on_refresh: callable,
    ) -> None:
        super().__init__(
            parent,
            bg=theme.PANEL,
            pady=12,
            padx=16,
            highlightbackground=theme.BORDER,
            highlightthickness=1,
        )
        self._port_var = port_var
        self._addr_var = addr_var
        self._dir_var = dir_var

        # ── row 1: port + address ─────────────────────────────────────
        row1 = tk.Frame(self, bg=theme.PANEL)
        row1.pack(fill="x", pady=(0, 8))

        tk.Label(
            row1, text="COM PORT", bg=theme.PANEL,
            fg=theme.MUTED, font=theme.FONT_MONO_XS,
        ).grid(row=0, column=0, sticky="w")
        tk.Label(
            row1, text="DEVICE ADDRESS (1\u2013255)", bg=theme.PANEL,
            fg=theme.MUTED, font=theme.FONT_MONO_XS,
        ).grid(row=0, column=2, sticky="w", padx=(16, 0))

        self.port_combo = ttk.Combobox(
            row1, textvariable=self._port_var, width=18, state="readonly",
        )
        self.port_combo.grid(row=1, column=0, sticky="w")

        tk.Button(
            row1, text="\u27f3", bg=theme.PANEL, fg=theme.ACCENT, bd=0,
            font=theme.FONT_REFRESH, cursor="hand2", command=on_refresh,
        ).grid(row=1, column=1, padx=4)

        self.addr_entry = ttk.Entry(
            row1, textvariable=self._addr_var, width=8,
        )
        self.addr_entry.grid(row=1, column=2, sticky="w", padx=(16, 0))

        # ── row 2: save directory ─────────────────────────────────────
        row2 = tk.Frame(self, bg=theme.PANEL)
        row2.pack(fill="x")

        tk.Label(
            row2, text="LOG SAVE DIRECTORY", bg=theme.PANEL,
            fg=theme.MUTED, font=theme.FONT_MONO_XS,
        ).grid(row=0, column=0, sticky="w")

        self.dir_entry = ttk.Entry(
            row2, textvariable=self._dir_var, width=60,
        )
        self.dir_entry.grid(row=1, column=0, sticky="w")

        tk.Button(
            row2, text="Browse\u2026", bg=theme.INPUT_BG, fg=theme.TEXT,
            bd=0, font=theme.FONT_MONO_SM, cursor="hand2", padx=8, pady=4,
            command=self._browse,
        ).grid(row=1, column=1, padx=(8, 0))

    # ── helpers ───────────────────────────────────────────────────────

    def _browse(self) -> None:
        d = filedialog.askdirectory()
        if d:
            self._dir_var.set(d)

    def set_ports(self, ports: list[str]) -> None:
        self.port_combo["values"] = ports
        if ports:
            self.port_combo.current(0)

    def force_display(self, addr_default: str, dir_default: str) -> None:
        """Force entry widgets to show their values.

        Works around a Windows/ttk quirk where ``textvariable`` values
        may not render until the first mainloop tick.
        """
        self.addr_entry.delete(0, "end")
        self.addr_entry.insert(0, addr_default)
        self.dir_entry.delete(0, "end")
        self.dir_entry.insert(0, dir_default)
