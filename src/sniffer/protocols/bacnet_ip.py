"""BACnet/IP decoder (BVLC + NPDU/APDU).

BACnet/IP packet structure (ASHRAE 135 Annex J):

    [BVLC-Type=0x81][BVLC-Function][Length-Hi][Length-Lo][...][NPDU...]

BVLC functions handled:
    0x0A  Original-Unicast-NPDU   -- NPDU starts at byte 4
    0x0B  Original-Broadcast-NPDU -- NPDU starts at byte 4
    0x04  Forwarded-NPDU          -- 6-byte originating IP+port follows header,
                                     NPDU starts at byte 10
"""

from __future__ import annotations

import socket
from typing import Any

from . import register
from .base import ProtocolDecoder
from .bacnet_mstp import _decode_npdu_apdu

_BVLC_TYPE = 0x81
_BVLC_FORWARDED = 0x04


@register
class BACnetIPDecoder(ProtocolDecoder):
    """BACnet/IP decoder for traffic received via UDP port 47808."""

    @property
    def name(self) -> str:
        return "BACnet-IP"

    @property
    def priority(self) -> int:
        return 5

    @property
    def default_baud_rates(self) -> list[int]:
        return []  # N/A for UDP

    def reset(self) -> None:
        pass

    # ── extraction ────────────────────────────────────────────────────

    def extract_packets(
        self, buffer: bytearray,
    ) -> tuple[list[bytearray], bytearray]:
        """Each buffer is one complete UDP datagram — return it as one packet.

        Accepts both plain BVLC (0x81 at byte 0) and the NpcapSource format
        where 8 bytes of src/dst IP precede the BVLC header (0x81 at byte 8).
        """
        if len(buffer) >= 4 and buffer[0] == _BVLC_TYPE:
            return [bytearray(buffer)], bytearray()
        if len(buffer) >= 12 and buffer[8] == _BVLC_TYPE:
            return [bytearray(buffer)], bytearray()
        return [], bytearray()

    # ── decode ────────────────────────────────────────────────────────

    def decode(self, pkt: bytearray) -> dict[str, Any]:
        try:
            # NpcapSource prepends [4-byte src IP][4-byte dst IP] before 0x81.
            # Detect by checking that byte 0 is not 0x81 but byte 8 is.
            src_ip = dst_ip = "?"
            bvlc = pkt
            if len(pkt) >= 9 and pkt[0] != _BVLC_TYPE and pkt[8] == _BVLC_TYPE:
                src_ip = socket.inet_ntoa(bytes(pkt[:4]))
                dst_ip = socket.inet_ntoa(bytes(pkt[4:8]))
                bvlc = pkt[8:]

            bvlc_fn = bvlc[1]
            npdu_offset = 10 if bvlc_fn == _BVLC_FORWARDED else 4

            base: dict[str, Any] = {
                "protocol": "BACnet-IP",
                "src": src_ip,
                "dst": dst_ip,
                "cmd": "—",
                "point_type": "—",
                "point_index": "—",
                "value": "—",
                "raw_hex": self._to_hex(bvlc),
                "raw_ascii": "",
            }

            if npdu_offset >= len(bvlc):
                return base

            npdu_data = bytes(bvlc[npdu_offset:])
            apdu_info = _decode_npdu_apdu(npdu_data)
            base.update(apdu_info)
            return base

        except Exception as exc:
            return {
                "protocol": "BACnet-IP",
                "src": "?",
                "dst": "?",
                "cmd": f"PARSE_ERROR ({exc})",
                "point_type": "—",
                "point_index": "—",
                "value": "—",
                "raw_hex": self._to_hex(pkt),
                "raw_ascii": "",
            }
