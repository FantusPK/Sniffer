"""UDP socket adapter that duck-types serial.Serial for the sniffing engine.

Each UDP datagram is a complete BACnet/IP packet, so read() always returns
one whole datagram regardless of the requested byte count.
"""

from __future__ import annotations

import socket
from collections import deque


class UDPSource:
    """Receive BACnet/IP datagrams over UDP, presented as a serial-like source."""

    skip_baud_rotation = True  # engine checks this to disable baud cycling

    def __init__(self, host: str, port: int) -> None:
        self._host = host
        self._port = port
        self._queue: deque[bytes] = deque()
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self._sock.settimeout(0.05)
        self._sock.bind(("", port))  # bind all interfaces on the given port

    # ── serial-compatible interface ───────────────────────────────────

    @property
    def in_waiting(self) -> int:
        self._poll()
        return len(self._queue[0]) if self._queue else 0

    def read(self, n: int) -> bytes:  # n ignored — return one complete datagram
        self._poll()
        if self._queue:
            return self._queue.popleft()
        return b""

    @property
    def is_open(self) -> bool:
        return self._sock is not None

    def close(self) -> None:
        if self._sock:
            self._sock.close()
            self._sock = None  # type: ignore[assignment]

    # no-ops so engine._rotate_baud() doesn't crash before the guard fires
    @property
    def baudrate(self) -> int:
        return 0

    @baudrate.setter
    def baudrate(self, value: int) -> None:
        pass

    def reset_input_buffer(self) -> None:
        pass

    def send_who_is(self) -> None:
        """Broadcast a BACnet Who-Is to trigger I-Am responses from all devices.

        BVLC Original-Broadcast-NPDU + NPDU global-broadcast (DNET=0xFFFF) +
        Unconfirmed-REQ Who-Is with no range (discovers every device).
        """
        who_is = bytes([
            0x81, 0x0B, 0x00, 0x0C,        # BVLC: type, Orig-Broadcast, len=12
            0x01, 0x20, 0xFF, 0xFF, 0x00, 0xFF,  # NPDU: ver, ctrl+dst, DNET, DLEN, hop
            0x10, 0x08,                     # APDU: Unconfirmed-REQ, Who-Is
        ])
        try:
            self._sock.sendto(who_is, ("255.255.255.255", self._port))
        except OSError:
            pass

    # ── internals ─────────────────────────────────────────────────────

    def _poll(self) -> None:
        """Drain any pending datagrams from the socket into the queue."""
        if not self._sock:
            return
        try:
            while True:
                data, _ = self._sock.recvfrom(4096)
                if data:
                    self._queue.append(data)
        except (socket.timeout, OSError):
            pass
