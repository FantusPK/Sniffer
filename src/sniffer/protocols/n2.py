"""N2 / N2 Open dual-mode decoder.

Handles mixed-protocol trunks where binary N2 and N2 Open ASCII frames
coexist on the same bus.  Both sub-protocols share the same RS-485 wire
at 9600 baud, so they are disambiguated in a single extraction pass:

1. Starts with ``>`` (0x3E), ends with ``\\r``, printable interior
   --> N2 Open command
2. Starts with ``A`` (0x41), hex interior, ends with ``\\r``, len >= 6
   --> N2 Open response
3. Passes XOR CRC, sane address / length / command byte
   --> Binary N2
4. Everything else --> UNKNOWN
"""

from __future__ import annotations

from collections import Counter
from typing import Any

from . import register
from .base import ProtocolDecoder

# ── Binary N2 tables ──────────────────────────────────────────────────

BINARY_COMMANDS: dict[int, str] = {
    0x00: "POLL",        0x01: "POLL_RESP",
    0x02: "WRITE_AO",   0x03: "WRITE_DO",
    0x04: "READ_AI",     0x05: "READ_AI_RESP",
    0x06: "READ_DI",     0x07: "READ_DI_RESP",
    0x08: "READ_AO",     0x09: "READ_AO_RESP",
    0x0A: "READ_DO",     0x0B: "READ_DO_RESP",
    0x10: "OVERRIDE",    0x11: "RELEASE",
    0x20: "ALARM",       0x21: "ACK_ALARM",
    0xFF: "BROADCAST",
}

BINARY_POINT_TYPE: dict[int, str] = {
    0x02: "AO", 0x03: "DO", 0x04: "AI", 0x05: "AI",
    0x06: "DI", 0x07: "DI", 0x08: "AO", 0x09: "AO",
    0x0A: "DO", 0x0B: "DO",
}

# ── N2 Open tables ────────────────────────────────────────────────────

N2OPEN_COMMANDS: dict[int, str] = {
    0x01: "READ_AI",        0x02: "READ_AI_RESP",
    0x03: "READ_AO",        0x04: "READ_AO_RESP",
    0x05: "READ_DI",        0x06: "READ_DI_RESP",
    0x07: "READ_DO",        0x08: "READ_DO_RESP",
    0x09: "WRITE_AO",       0x0A: "WRITE_DO",
    0x0B: "OVERRIDE_AO",    0x0C: "OVERRIDE_DO",
    0x0D: "RELEASE_AO",     0x0E: "RELEASE_DO",
    0x0F: "READ_SETPOINT",  0x10: "WRITE_SETPOINT",
    0x11: "POLL",            0x12: "POLL_RESP",
    0x13: "ALARM",           0x14: "ACK_ALARM",
    0x15: "READ_ALL_AI",     0x16: "READ_ALL_AO",
    0x17: "READ_ALL_DI",     0x18: "READ_ALL_DO",
}

N2OPEN_POINT_TYPE: dict[int, str] = {
    0x01: "AI", 0x02: "AI", 0x03: "AO", 0x04: "AO",
    0x05: "DI", 0x06: "DI", 0x07: "DO", 0x08: "DO",
    0x09: "AO", 0x0A: "DO", 0x0B: "AO", 0x0C: "DO",
    0x0D: "AO", 0x0E: "DO", 0x15: "AI", 0x16: "AO",
    0x17: "DI", 0x18: "DO",
}

_MIN_BINARY_LEN = 5


# ══════════════════════════════════════════════════════════════════════
#  Registered decoder
# ══════════════════════════════════════════════════════════════════════

@register
class N2Decoder(ProtocolDecoder):
    """Decodes both N2 Binary and N2 Open ASCII in a single pass."""

    @property
    def name(self) -> str:
        return "N2"

    @property
    def priority(self) -> int:
        return 20

    @property
    def default_baud_rates(self) -> list[int]:
        return [9600]

    # ── extraction ────────────────────────────────────────────────────

    def extract_packets(
        self, buffer: bytearray,
    ) -> tuple[list[bytearray], bytearray]:
        packets: list[bytearray] = []
        i = 0

        while i < len(buffer):
            b = buffer[i]

            # -- N2 Open command: '>' ... \r --
            if b == 0x3E:
                end = buffer.find(0x0D, i + 1)
                if end == -1:
                    break  # incomplete -- wait for more data
                pkt = bytearray(buffer[i : end + 1])
                if len(pkt) >= 6 and _is_printable_ascii(pkt[1:-1]):
                    packets.append(pkt)
                    i = end + 1
                    continue
                i += 1
                continue

            # -- N2 Open response: 'A' + hex chars + \r --
            if b == 0x41:
                end = buffer.find(0x0D, i + 1)
                if end != -1:
                    pkt = bytearray(buffer[i : end + 1])
                    interior = pkt[1:-1]
                    if (
                        len(pkt) >= 6
                        and len(interior) >= 4
                        and all(_is_hex_char(x) for x in interior)
                    ):
                        packets.append(pkt)
                        i = end + 1
                        continue
                # fall through to binary attempt

            # -- Binary N2 --
            if i + _MIN_BINARY_LEN <= len(buffer):
                sac = buffer[i]
                dac = buffer[i + 1]

                # Reject BACnet preamble
                if sac == 0x55 and dac == 0xFF:
                    i += 1
                    continue

                # N2 addresses are realistically 1-127
                if sac > 127 or dac > 127:
                    i += 1
                    continue

                length = buffer[i + 2]
                total = 4 + length + 1
                if sac != 0 and dac != 0 and 0 < length <= 64:
                    if i + total <= len(buffer):
                        candidate = buffer[i : i + total]
                        if _check_binary_crc(candidate):
                            cmd = candidate[3]
                            if cmd in BINARY_COMMANDS:
                                if not _is_low_entropy(candidate):
                                    packets.append(bytearray(candidate))
                                    i += total
                                    continue
                    else:
                        break  # incomplete frame

            i += 1

        return packets, buffer[i:]

    # ── decode dispatch ───────────────────────────────────────────────

    def decode(self, pkt: bytearray) -> dict[str, Any]:
        if not pkt:
            return self._unknown("", "empty packet")

        first = pkt[0]
        last = pkt[-1]

        # N2 Open command
        if first == 0x3E and last == 0x0D and _is_printable_ascii(pkt[1:-1]):
            return _decode_n2open_command(pkt)

        # N2 Open response
        if (
            first == 0x41
            and last == 0x0D
            and len(pkt) >= 6
            and all(_is_hex_char(x) for x in pkt[1:-1])
        ):
            return _decode_n2open_response(pkt)

        # Binary N2
        if len(pkt) >= _MIN_BINARY_LEN and _check_binary_crc(pkt):
            sac, dac, cmd = pkt[0], pkt[1], pkt[3]
            if sac == 0x55 and dac == 0xFF:
                return self._unknown(self._to_ascii(pkt), "BACnet preamble")
            if (
                sac != 0
                and dac != 0
                and sac <= 127
                and dac <= 127
                and cmd in BINARY_COMMANDS
                and not _is_low_entropy(pkt)
            ):
                return _decode_binary(pkt)

        return self._unknown(self._to_ascii(pkt), "no protocol matched")


# ══════════════════════════════════════════════════════════════════════
#  Binary N2 internals
# ══════════════════════════════════════════════════════════════════════

def _decode_binary(pkt: bytearray) -> dict[str, Any]:
    sac, dac, length, cmd = pkt[0], pkt[1], pkt[2], pkt[3]
    data = pkt[4 : 4 + length] if length > 0 else bytearray()
    cmd_name = BINARY_COMMANDS.get(cmd, f"CMD_0x{cmd:02X}")
    point_type = BINARY_POINT_TYPE.get(cmd, "??")
    point_index, value = _parse_binary_data(cmd, data)
    return {
        "protocol": "N2-BIN",
        "src": sac,
        "dst": dac,
        "cmd": cmd_name,
        "point_type": point_type,
        "point_index": point_index,
        "value": value,
        "raw_hex": ProtocolDecoder._to_hex(pkt),
        "raw_ascii": ProtocolDecoder._to_ascii(pkt),
    }


def _parse_binary_data(
    cmd: int, data: bytearray,
) -> tuple[int | str, str]:
    if not data:
        return "\u2014", "\u2014"
    idx = data[0]
    if cmd in (0x02, 0x04, 0x05, 0x08, 0x09):
        if len(data) >= 3:
            return idx, f"{((data[1] << 8) | data[2]) / 10.0:.1f}"
        if len(data) >= 2:
            return idx, str(data[1])
    elif cmd in (0x03, 0x06, 0x07, 0x0A, 0x0B):
        if len(data) >= 2:
            return idx, "ON" if data[1] else "OFF"
    return idx, ProtocolDecoder._to_hex(data[1:]) or "\u2014"


def _check_binary_crc(pkt: bytearray) -> bool:
    if len(pkt) < 2:
        return False
    crc = 0
    for b in pkt[:-1]:
        crc ^= b
    return crc == pkt[-1]


# ══════════════════════════════════════════════════════════════════════
#  N2 Open internals
# ══════════════════════════════════════════════════════════════════════

def _decode_n2open_command(pkt: bytearray) -> dict[str, Any]:
    try:
        content = pkt[1:-1].decode("ascii", errors="replace").strip()
        if len(content) < 4:
            return ProtocolDecoder._unknown(content, "N2Open cmd too short")
        addr = int(content[0:2], 16)
        cmd = int(content[2:4], 16)
        cmd_name, pt, pidx, val = _n2open_fields(cmd, content[4:])
        return {
            "protocol": "N2Open-CMD",
            "src": "JACE",
            "dst": addr,
            "cmd": cmd_name,
            "point_type": pt,
            "point_index": pidx,
            "value": val,
            "raw_hex": ProtocolDecoder._to_hex(pkt),
            "raw_ascii": content,
        }
    except Exception as exc:
        return ProtocolDecoder._unknown(
            ProtocolDecoder._to_ascii(pkt), f"N2Open cmd error: {exc}",
        )


def _decode_n2open_response(pkt: bytearray) -> dict[str, Any]:
    try:
        content = pkt[1:-1].decode("ascii", errors="replace").strip()
        if len(content) < 4:
            return ProtocolDecoder._unknown(content, "N2Open resp too short")
        addr = int(content[0:2], 16)
        cmd = int(content[2:4], 16)
        cmd_name, pt, pidx, val = _n2open_fields(cmd, content[4:])
        return {
            "protocol": "N2Open-RESP",
            "src": addr,
            "dst": "JACE",
            "cmd": cmd_name,
            "point_type": pt,
            "point_index": pidx,
            "value": val,
            "raw_hex": ProtocolDecoder._to_hex(pkt),
            "raw_ascii": content,
        }
    except Exception as exc:
        return ProtocolDecoder._unknown(
            ProtocolDecoder._to_ascii(pkt), f"N2Open resp error: {exc}",
        )


def _n2open_fields(
    cmd: int, data_str: str,
) -> tuple[str, str, int | str, str]:
    cmd_name = N2OPEN_COMMANDS.get(cmd, f"CMD_0x{cmd:02X}")
    point_type = N2OPEN_POINT_TYPE.get(cmd, "??")
    pidx, val = _parse_n2open_data(cmd, data_str)
    return cmd_name, point_type, pidx, val


def _parse_n2open_data(
    cmd: int, data_str: str,
) -> tuple[int | str, str]:
    if not data_str or len(data_str) < 2:
        return "\u2014", "\u2014"
    try:
        db = bytes.fromhex(data_str)
    except ValueError:
        return "\u2014", data_str
    pidx: int | str = db[0] if db else "\u2014"
    if cmd in (0x02, 0x04, 0x10):
        if len(db) >= 3:
            return pidx, f"{((db[1] << 8) | db[2]) / 10.0:.1f}"
        if len(db) >= 2:
            return pidx, str(db[1])
    elif cmd in (0x06, 0x08):
        if len(db) >= 2:
            return pidx, "ON" if db[1] else "OFF"
    elif cmd in (0x15, 0x16, 0x17, 0x18):
        vals: list[str] = []
        step = 3 if cmd in (0x15, 0x16) else 2
        for j in range(0, len(db), step):
            if cmd in (0x15, 0x16) and j + 2 < len(db):
                vals.append(
                    f"{db[j]}={((db[j + 1] << 8) | db[j + 2]) / 10.0:.1f}",
                )
            elif cmd in (0x17, 0x18) and j + 1 < len(db):
                vals.append(f"{db[j]}={'ON' if db[j + 1] else 'OFF'}")
        return "ALL", " | ".join(vals) if vals else "\u2014"
    return pidx, ProtocolDecoder._to_hex(db[1:]) or "\u2014"


# ══════════════════════════════════════════════════════════════════════
#  Shared helpers
# ══════════════════════════════════════════════════════════════════════

def _is_hex_char(b: int) -> bool:
    return (0x30 <= b <= 0x39) or (0x41 <= b <= 0x46) or (0x61 <= b <= 0x66)


def _is_printable_ascii(data: bytearray) -> bool:
    return all(0x20 <= b <= 0x7E for b in data)


def _is_low_entropy(pkt: bytearray) -> bool:
    """Return True if the packet looks like baud-rate noise.

    Real N2 packets have varied byte values.  Noise at the wrong baud
    rate produces highly repetitive patterns.

    Checks:
      - Any single byte value > 40 % of packet = noise
      - Top two byte values combined > 70 % of packet = noise
    """
    if len(pkt) < 4:
        return False
    counts = Counter(pkt)
    total = len(pkt)
    top2 = counts.most_common(2)
    top1_pct = top2[0][1] / total
    top2_pct = (top2[0][1] + (top2[1][1] if len(top2) > 1 else 0)) / total
    return top1_pct > 0.40 or top2_pct > 0.70
