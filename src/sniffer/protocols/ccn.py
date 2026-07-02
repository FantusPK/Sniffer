"""Carrier Comfort Network (CCN) decoder — framing / lock pass.

CCN is Carrier's proprietary RS-485 building-automation bus.  Unlike the
other decoders here, this first pass is deliberately scoped to **framing
and CRC lock only**: it finds real CCN frame boundaries, validates them,
and reports the src/dst addresses so the engine can lock onto the bus and
the Device Presence tab can populate.  Function-code and point/value
payload decoding is intentionally deferred to a later pass.

Frame model (public CCN structure — best-effort, tune against captures)::

    +------+------+------+------+------+= ... =+------+------+
    | DBus | DElm | SBus | SElm | Func |  data | CRChi| CRClo|
    +------+------+------+------+------+= ... =+------+------+
      dst address    src address   ^ msg type   ^ CRC-16 trailer

  * Addresses are (bus, element) pairs; bus/element realistically 0-239.
  * There is **no fixed preamble byte**, so frames are located by sliding
    through the buffer and accepting the first candidate whose trailing
    two bytes match a CRC-16/CCITT computed over the preceding bytes.
  * Two CRC init variants (CCITT-FALSE 0xFFFF, XMODEM 0x0000) and both
    byte orders are tried during detection.  Once a frame validates, the
    matching variant is latched for the rest of the lock so subsequent
    frames don't drift onto a different (false-positive) variant.

Because the framing relies purely on CRC + address plausibility, a
low-entropy noise filter (shared idea with the N2 decoder) rejects
baud-rate garbage that happens to satisfy the length gate.
"""

from __future__ import annotations

from collections import Counter
from typing import Any

from . import register
from .base import ProtocolDecoder

# Frame geometry: 4 address bytes + 1 function byte + 2 CRC bytes = 7 min.
_MIN_FRAME_LEN = 7
_MAX_FRAME_LEN = 64

# Plausible CCN address component range (bus / element numbers).
_ADDR_MAX = 239

# CRC-16/CCITT init variants tried during detection (poly 0x1021, no reflect).
_CRC_INITS = (0xFFFF, 0x0000)
_CRC_BYTEORDERS = ("big", "little")


# ══════════════════════════════════════════════════════════════════════
#  Registered decoder
# ══════════════════════════════════════════════════════════════════════

@register
class CCNDecoder(ProtocolDecoder):
    """Locates and CRC-validates Carrier Comfort Network frames."""

    def __init__(self) -> None:
        # Latched CRC variant (init, byteorder) once a frame validates.
        self._crc_variant: tuple[int, str] | None = None

    @property
    def name(self) -> str:
        return "CCN"

    @property
    def priority(self) -> int:
        # Highest number = runs last.  CCN has no sync byte and is the most
        # ambiguous framer, so it should never steal BACnet/N2 traffic.
        return 30

    @property
    def default_baud_rates(self) -> list[int]:
        return [9600, 19200, 38400]

    def reset(self) -> None:
        self._crc_variant = None

    # ── extraction ────────────────────────────────────────────────────

    def extract_packets(
        self, buffer: bytearray,
    ) -> tuple[list[bytearray], bytearray]:
        packets: list[bytearray] = []
        i = 0

        while i < len(buffer):
            remaining = len(buffer) - i

            # Not enough bytes to even attempt a frame — wait for more.
            if remaining < _MIN_FRAME_LEN:
                break

            if not _plausible_header(buffer, i):
                i += 1
                continue

            frame_len = self._match_frame(buffer, i)
            if frame_len is not None:
                packets.append(bytearray(buffer[i : i + frame_len]))
                i += frame_len
                continue

            # Header looked plausible but no CRC matched.  If we simply
            # haven't received enough bytes for a full max-length frame,
            # hold here and wait for more data rather than misframing.
            if remaining < _MAX_FRAME_LEN:
                break

            i += 1

        return packets, buffer[i:]

    def _match_frame(self, buffer: bytearray, start: int) -> int | None:
        """Return frame length if a CRC-valid CCN frame begins at *start*."""
        limit = min(_MAX_FRAME_LEN, len(buffer) - start)

        # end = index (relative to start) just past the payload, where the
        # two CRC bytes begin.  Smallest payload is func byte only.
        for end in range(_MIN_FRAME_LEN - 2, limit - 1):
            body = buffer[start : start + end]
            crc_hi = buffer[start + end]
            crc_lo = buffer[start + end + 1]

            match = self._crc_ok(body, crc_hi, crc_lo)
            if match is None:
                continue

            frame = buffer[start : start + end + 2]
            if _is_low_entropy(frame):
                continue

            self._crc_variant = match
            return end + 2

        return None

    def _crc_ok(
        self, body: bytearray, crc_hi: int, crc_lo: int,
    ) -> tuple[int, str] | None:
        """Return the matching (init, byteorder) variant, or None."""
        variants = (
            (self._crc_variant,)
            if self._crc_variant is not None
            else tuple(
                (init, order)
                for init in _CRC_INITS
                for order in _CRC_BYTEORDERS
            )
        )
        for init, order in variants:
            calc = _crc16_ccitt(body, init)
            if order == "big":
                expected = (crc_hi << 8) | crc_lo
            else:
                expected = (crc_lo << 8) | crc_hi
            if calc == expected:
                return (init, order)
        return None

    # ── decode ────────────────────────────────────────────────────────

    def decode(self, pkt: bytearray) -> dict[str, Any]:
        if len(pkt) < _MIN_FRAME_LEN:
            return self._unknown(self._to_ascii(pkt), "CCN frame too short")

        dst_bus, dst_elem, src_bus, src_elem, func = pkt[0:5]
        data_len = len(pkt) - 5 - 2  # minus header (5) and CRC trailer (2)

        return {
            "protocol": "CCN",
            "src": f"{src_bus}.{src_elem}",
            "dst": f"{dst_bus}.{dst_elem}",
            "cmd": f"FN 0x{func:02X}",
            "point_type": "—",
            "point_index": "—",
            "value": f"{data_len}B" if data_len > 0 else "—",
            "raw_hex": self._to_hex(pkt),
            "raw_ascii": "",
        }


# ══════════════════════════════════════════════════════════════════════
#  Helpers
# ══════════════════════════════════════════════════════════════════════

def _plausible_header(buffer: bytearray, i: int) -> bool:
    """Cheap gate before the (more expensive) CRC search."""
    dst_bus, dst_elem, src_bus, src_elem = buffer[i : i + 4]

    # Reject the BACnet MS/TP preamble so the two can coexist on a trunk.
    if dst_bus == 0x55 and dst_elem == 0xFF:
        return False

    # All four address bytes zero is not a real conversation.
    if dst_bus == 0 and dst_elem == 0 and src_bus == 0 and src_elem == 0:
        return False

    return (
        dst_bus <= _ADDR_MAX
        and dst_elem <= _ADDR_MAX
        and src_bus <= _ADDR_MAX
        and src_elem <= _ADDR_MAX
    )


def _crc16_ccitt(data: bytearray, init: int) -> int:
    """CRC-16/CCITT (poly 0x1021, MSB-first, no reflection)."""
    crc = init
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            if crc & 0x8000:
                crc = (crc << 1) ^ 0x1021
            else:
                crc <<= 1
            crc &= 0xFFFF
    return crc


def _is_low_entropy(pkt: bytearray) -> bool:
    """Reject baud-rate noise that happens to satisfy the CRC gate.

    Real frames have varied byte values; noise is highly repetitive.
    """
    if len(pkt) < 4:
        return False
    counts = Counter(pkt)
    total = len(pkt)
    top2 = counts.most_common(2)
    top1_pct = top2[0][1] / total
    top2_pct = (top2[0][1] + (top2[1][1] if len(top2) > 1 else 0)) / total
    return top1_pct > 0.40 or top2_pct > 0.70
