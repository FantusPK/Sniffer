"""Main window assembly -- creates and lays out all GUI panels."""

from __future__ import annotations

import tkinter as tk
from typing import Callable

from sniffer.gui import theme
from sniffer.gui.config_panel import ConfigPanel
from sniffer.gui.controls import ControlBar
from sniffer.gui.log_view import LogView
from sniffer.gui.stats_bar import StatsBar


class MainWindow:
    """Assembles every GUI panel inside *root*.

    Owns no state -- variables and callbacks are injected by the
    application layer.
    """

    def __init__(
        self,
        root: tk.Tk,
        *,
        app_title: str,
        subtitle: str,
        # tk variables
        port_var: tk.StringVar,
        addr_var: tk.StringVar,
        dir_var: tk.StringVar,
        all_count_var: tk.IntVar,
        target_count_var: tk.IntVar,
        protocol_var: tk.StringVar,
        baud_var: tk.StringVar,
        status_var: tk.StringVar,
        sim_protocol_var: tk.StringVar,
        # callbacks
        on_refresh_ports: Callable[[], None],
        on_start: Callable[[], None],
        on_stop: Callable[[], None],
        on_simulate: Callable[[], None],
        on_export: Callable[[], None],
        on_clear: Callable[[], None],
    ) -> None:
        root.title(app_title)
        root.geometry("1000x700")
        root.resizable(True, True)
        root.configure(bg=theme.BG)
        theme.apply(root)

        # ── title bar ─────────────────────────────────────────────────
        title_bar = tk.Frame(root, bg=theme.BG, pady=10)
        title_bar.pack(fill="x", padx=16)
        tk.Label(
            title_bar, text=app_title.upper(), bg=theme.BG,
            fg=theme.ACCENT, font=theme.FONT_TITLE,
        ).pack(side="left")
        tk.Label(
            title_bar, text=f"  //  {subtitle}", bg=theme.BG,
            fg=theme.MUTED, font=theme.FONT_MONO_SM,
        ).pack(side="left", pady=6)

        # ── config panel ──────────────────────────────────────────────
        self.config = ConfigPanel(
            root,
            port_var=port_var,
            addr_var=addr_var,
            dir_var=dir_var,
            on_refresh=on_refresh_ports,
        )
        self.config.pack(fill="x", padx=16, pady=(0, 8))

        # ── controls ──────────────────────────────────────────────────
        self.controls = ControlBar(
            root,
            on_start=on_start,
            on_stop=on_stop,
            on_simulate=on_simulate,
            on_export=on_export,
            on_clear=on_clear,
            sim_protocol_var=sim_protocol_var,
        )
        self.controls.pack(fill="x", padx=16, pady=(0, 8))

        # ── stats bar ────────────────────────────────────────────────
        self.stats = StatsBar(
            root,
            all_count_var=all_count_var,
            target_count_var=target_count_var,
            protocol_var=protocol_var,
            baud_var=baud_var,
            status_var=status_var,
        )
        self.stats.pack(fill="x", padx=16, pady=(0, 8))

        # ── log view ─────────────────────────────────────────────────
        self.logs = LogView(root)
        self.logs.pack(fill="both", expand=True, padx=16, pady=(0, 16))

        # ── footer ────────────────────────────────────────────────────
        footer = tk.Frame(root, bg=theme.FOOTER_BG, pady=4)
        footer.pack(fill="x", side="bottom")
        tk.Label(
            footer,
            text=(
                "RS-485 \u00b7 Passive sniff \u00b7 Auto-baud "
                "\u00b7 Auto-detect protocols"
            ),
            bg=theme.FOOTER_BG,
            fg=theme.MUTED,
            font=theme.FONT_MONO_XS,
        ).pack(side="left", padx=12)
