"""Promiscuous BACnet/IP capture using Npcap via Scapy.

Replaces UDPSource so the sniffer sees ALL BACnet/IP traffic on the wire,
not just packets addressed to this machine.  Requires Npcap (installed with
Wireshark) and the scapy Python package.
"""

from __future__ import annotations

import socket
from collections import deque
from typing import Any


def list_interfaces() -> list[tuple[str, Any, str]]:
    """Return [(label, scapy_iface, ip), ...] for all usable network interfaces.

    Returns an empty list if Scapy is not installed or Npcap is unavailable.
    """
    try:
        from scapy.all import conf as scapy_conf
        result: list[tuple[str, Any, str]] = []
        for iface in scapy_conf.ifaces.values():
            ip: str = getattr(iface, "ip", "") or ""
            if not ip or ip == "0.0.0.0" or ip.startswith("127."):
                continue
            desc: str = (
                getattr(iface, "description", "")
                or getattr(iface, "name", "")
                or "Unknown"
            )
            label = f"{desc} — {ip}"
            result.append((label, iface, ip))
        return sorted(result, key=lambda x: x[0])
    except Exception:
        return []


class NpcapSource:
    """Capture all BACnet/IP datagrams on an interface via Npcap promiscuous mode."""

    skip_baud_rotation = True

    def __init__(self, iface: Any, port: int, host_ip: str = "") -> None:
        """
        Parameters
        ----------
        iface:
            Scapy NetworkInterface object to sniff on.
        port:
            UDP port to filter for (typically 47808).
        host_ip:
            Source IP used when sending Who-Is broadcasts.
        """
        self._iface = iface
        self._port = port
        self._host_ip = host_ip
        self._queue: deque[bytes] = deque()
        self._closed = False

        from scapy.all import AsyncSniffer
        self._sniffer = AsyncSniffer(
            iface=iface,
            filter=f"udp port {port}",
            prn=self._on_packet,
            store=False,
        )
        self._sniffer.start()

    def _on_packet(self, pkt: Any) -> None:
        try:
            from scapy.layers.inet import IP, UDP
            from scapy.packet import Raw
            import socket as _socket
            if pkt.haslayer(UDP) and pkt.haslayer(Raw):
                payload = bytes(pkt[Raw].load)
                if payload and payload[0] == 0x81:  # BACnet/IP BVLC marker
                    # Prepend 8-byte IP envelope so the decoder can show src/dst.
                    # Format: [4 src IP][4 dst IP][BVLC 0x81 ...]
                    if pkt.haslayer(IP):
                        src = _socket.inet_aton(pkt[IP].src)
                        dst = _socket.inet_aton(pkt[IP].dst)
                    else:
                        src = dst = b"\x00\x00\x00\x00"
                    self._queue.append(src + dst + payload)
        except Exception:
            pass

    # ── serial-compatible interface ───────────────────────────────────

    @property
    def in_waiting(self) -> int:
        return len(self._queue[0]) if self._queue else 0

    def read(self, n: int) -> bytes:  # n ignored — return one complete datagram
        if self._queue:
            return self._queue.popleft()
        return b""

    @property
    def is_open(self) -> bool:
        return not self._closed

    def close(self) -> None:
        self._closed = True
        try:
            if self._sniffer.running:
                self._sniffer.stop()
        except Exception:
            pass

    @property
    def baudrate(self) -> int:
        return 0

    @baudrate.setter
    def baudrate(self, value: int) -> None:
        pass

    def reset_input_buffer(self) -> None:
        pass

    def send_who_is(self) -> None:
        """Broadcast a BACnet Who-Is to prompt I-Am responses from all devices."""
        who_is = bytes([
            0x81, 0x0B, 0x00, 0x0C,              # BVLC: type, Orig-Broadcast, len=12
            0x01, 0x20, 0xFF, 0xFF, 0x00, 0xFF,  # NPDU: ver, ctrl+dst, DNET, DLEN, hop
            0x10, 0x08,                           # APDU: Unconfirmed-REQ, Who-Is
        ])
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                if self._host_ip:
                    s.bind((self._host_ip, 0))
                s.sendto(who_is, ("255.255.255.255", self._port))
        except OSError:
            pass
