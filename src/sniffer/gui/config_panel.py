"""Configuration panel -- COM port / UDP network, device address, log directory."""

from __future__ import annotations

import tkinter as tk
from tkinter import filedialog, ttk
from typing import Callable

from sniffer.gui import theme


class ConfigPanel(tk.Frame):
    """Top configuration bar with source type, port/network, address, protocol, and save-directory pickers."""

    SOURCE_OPTIONS  = ["Serial (COM)", "Network (BACnet/IP)"]
    PROTOCOL_OPTIONS_SERIAL  = ["Auto-detect", "BACnet-MSTP", "N2"]
    PROTOCOL_OPTIONS_NETWORK = ["BACnet-IP"]
    BAUD_OPTIONS = ["Auto-detect", "9600", "19200", "38400", "57600", "76800", "115200"]

    def __init__(
        self,
        parent: tk.Widget,
        *,
        port_var: tk.StringVar,
        addr_var: tk.StringVar,
        dir_var: tk.StringVar,
        selected_protocol_var: tk.StringVar,
        selected_baud_var: tk.StringVar,
        source_type_var: tk.StringVar,
        udp_host_var: tk.StringVar,
        udp_port_var: tk.StringVar,
        who_is_var: tk.BooleanVar,
        jace_ip_var: tk.StringVar,
        on_refresh: Callable[[], None],
        on_refresh_ifaces: Callable[[], None],
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
        self._selected_protocol_var = selected_protocol_var
        self._selected_baud_var = selected_baud_var
        self._source_type_var = source_type_var
        self._udp_host_var = udp_host_var
        self._udp_port_var = udp_port_var
        self._who_is_var = who_is_var
        self._jace_ip_var = jace_ip_var

        # ── row 0: source type selector ───────────────────────────────
        row0 = tk.Frame(self, bg=theme.PANEL)
        row0.pack(fill="x", pady=(0, 6))

        tk.Label(
            row0, text="SOURCE TYPE", bg=theme.PANEL,
            fg=theme.MUTED, font=theme.FONT_MONO_XS,
        ).grid(row=0, column=0, sticky="w")

        self.source_combo = ttk.Combobox(
            row0, textvariable=self._source_type_var,
            values=self.SOURCE_OPTIONS, width=20, state="readonly",
        )
        self.source_combo.grid(row=1, column=0, sticky="w")

        # ── row 1: port/network + address + protocol + baud ───────────
        row1 = tk.Frame(self, bg=theme.PANEL)
        row1.pack(fill="x", pady=(0, 8))

        # -- serial sub-frame --
        self._serial_frame = tk.Frame(row1, bg=theme.PANEL)
        self._serial_frame.grid(row=0, column=0, sticky="w")

        tk.Label(
            self._serial_frame, text="COM PORT", bg=theme.PANEL,
            fg=theme.MUTED, font=theme.FONT_MONO_XS,
        ).grid(row=0, column=0, sticky="w")

        self.port_combo = ttk.Combobox(
            self._serial_frame, textvariable=self._port_var, width=18, state="readonly",
        )
        self.port_combo.grid(row=1, column=0, sticky="w")

        tk.Button(
            self._serial_frame, text="⟳", bg=theme.PANEL, fg=theme.ACCENT, bd=0,
            font=theme.FONT_REFRESH, cursor="hand2", command=on_refresh,
        ).grid(row=1, column=1, padx=4)

        # -- network sub-frame --
        self._network_frame = tk.Frame(row1, bg=theme.PANEL)

        tk.Label(
            self._network_frame, text="NETWORK INTERFACE", bg=theme.PANEL,
            fg=theme.MUTED, font=theme.FONT_MONO_XS,
        ).grid(row=0, column=0, sticky="w")
        tk.Label(
            self._network_frame, text="UDP PORT", bg=theme.PANEL,
            fg=theme.MUTED, font=theme.FONT_MONO_XS,
        ).grid(row=0, column=2, sticky="w", padx=(12, 0))

        self.iface_combo = ttk.Combobox(
            self._network_frame, textvariable=self._udp_host_var,
            width=35, state="readonly",
        )
        self.iface_combo.grid(row=1, column=0, sticky="w")

        tk.Button(
            self._network_frame, text="⟳", bg=theme.PANEL, fg=theme.ACCENT, bd=0,
            font=theme.FONT_REFRESH, cursor="hand2", command=on_refresh_ifaces,
        ).grid(row=1, column=1, padx=4)

        self.udp_port_entry = ttk.Entry(
            self._network_frame, textvariable=self._udp_port_var, width=7,
        )
        self.udp_port_entry.grid(row=1, column=2, sticky="w", padx=(12, 0))

        tk.Checkbutton(
            self._network_frame, text="Send Who-Is on connect",
            variable=self._who_is_var,
            bg=theme.PANEL, fg=theme.TEXT, selectcolor=theme.INPUT_BG,
            activebackground=theme.PANEL, font=theme.FONT_MONO_XS,
        ).grid(row=1, column=3, sticky="w", padx=(16, 0))

        tk.Label(
            self._network_frame, text="JACE IP (for Query)", bg=theme.PANEL,
            fg=theme.MUTED, font=theme.FONT_MONO_XS,
        ).grid(row=0, column=4, sticky="w", padx=(16, 0))
        self.jace_ip_entry = ttk.Entry(
            self._network_frame, textvariable=self._jace_ip_var, width=18,
        )
        self.jace_ip_entry.grid(row=1, column=4, sticky="w", padx=(16, 0))

        # shared: device address
        tk.Label(
            row1, text="DEVICE ADDRESS (1–255)", bg=theme.PANEL,
            fg=theme.MUTED, font=theme.FONT_MONO_XS,
        ).grid(row=0, column=2, sticky="w", padx=(16, 0))
        self.addr_entry = ttk.Entry(
            row1, textvariable=self._addr_var, width=8,
        )
        self.addr_entry.grid(row=1, column=2, sticky="w", padx=(16, 0))

        # shared: protocol
        tk.Label(
            row1, text="PROTOCOL", bg=theme.PANEL,
            fg=theme.MUTED, font=theme.FONT_MONO_XS,
        ).grid(row=0, column=4, sticky="w", padx=(16, 0))
        self.proto_combo = ttk.Combobox(
            row1, textvariable=self._selected_protocol_var,
            values=self.PROTOCOL_OPTIONS_SERIAL, width=14, state="readonly",
        )
        self.proto_combo.grid(row=1, column=4, sticky="w", padx=(16, 0))

        # shared: baud rate
        tk.Label(
            row1, text="BAUD RATE", bg=theme.PANEL,
            fg=theme.MUTED, font=theme.FONT_MONO_XS,
        ).grid(row=0, column=6, sticky="w", padx=(16, 0))
        self.baud_combo = ttk.Combobox(
            row1, textvariable=self._selected_baud_var,
            values=self.BAUD_OPTIONS, width=13, state="readonly",
        )
        self.baud_combo.grid(row=1, column=6, sticky="w", padx=(16, 0))

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
            row2, text="Browse…", bg=theme.INPUT_BG, fg=theme.TEXT,
            bd=0, font=theme.FONT_MONO_SM, cursor="hand2", padx=8, pady=4,
            command=self._browse,
        ).grid(row=1, column=1, padx=(8, 0))

        # wire up source-type toggle
        self._source_type_var.trace_add("write", self._on_source_change)
        self._on_source_change()  # apply initial state

    # ── source type toggle ────────────────────────────────────────────

    def _on_source_change(self, *_: object) -> None:
        is_network = self._source_type_var.get() == "Network (BACnet/IP)"
        if is_network:
            self._serial_frame.grid_remove()
            self._network_frame.grid(row=1, column=0, sticky="w")
            self.proto_combo.configure(values=self.PROTOCOL_OPTIONS_NETWORK, state="readonly")
            self._selected_protocol_var.set("BACnet-IP")
            self.baud_combo.grid_remove()
            # re-push port value — ttk won't render textvariable on a widget
            # that was hidden when the window first drew
            self.udp_port_entry.delete(0, "end")
            self.udp_port_entry.insert(0, self._udp_port_var.get())
        else:
            self._network_frame.grid_remove()
            self._serial_frame.grid(row=1, column=0, sticky="w")
            self.proto_combo.configure(values=self.PROTOCOL_OPTIONS_SERIAL, state="readonly")
            if self._selected_protocol_var.get() == "BACnet-IP":
                self._selected_protocol_var.set("Auto-detect")
            self.baud_combo.grid()

    # ── helpers ───────────────────────────────────────────────────────

    def _browse(self) -> None:
        d = filedialog.askdirectory()
        if d:
            self._dir_var.set(d)

    def set_ports(self, ports: list[str]) -> None:
        self.port_combo["values"] = ports
        if ports:
            self.port_combo.current(0)

    def set_interfaces(self, labels: list[str]) -> None:
        self.iface_combo["values"] = labels
        if labels and not self._udp_host_var.get():
            self.iface_combo.current(0)

    def force_display(self, addr_default: str, dir_default: str) -> None:
        """Force entry widgets to show their values.

        Works around a Windows/ttk quirk where ``textvariable`` values
        may not render until the first mainloop tick.
        """
        self.addr_entry.delete(0, "end")
        self.addr_entry.insert(0, addr_default)
        self.dir_entry.delete(0, "end")
        self.dir_entry.insert(0, dir_default)
        self.udp_port_entry.delete(0, "end")
        self.udp_port_entry.insert(0, self._udp_port_var.get())
