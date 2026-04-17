"""BACnet MS/TP decoder.

MS/TP frame structure::

    [0x55][0xFF][FT][DA][SA][LEN_HI][LEN_LO][CRC_HDR][DATA...][CRC16_HI][CRC16_LO]

    Preamble  : 0x55 0xFF  (2 bytes)
    FT        : Frame Type  (1 byte)
    DA        : Destination  (1 byte)
    SA        : Source       (1 byte)
    LEN       : Data length big-endian (2 bytes)
    CRC_HDR   : CRC-8 of FT+DA+SA+LEN (1 byte)
    DATA      : NPDU + APDU payload (LEN bytes)
    CRC_DATA  : CRC-16 of DATA (2 bytes, only when LEN > 0)

Decoded APDU types:
    Confirmed Request, Unconfirmed Request, SimpleACK, ComplexACK,
    Error, Reject, Abort

Decoded services:
    Who-Is, I-Am, Read-Property, Write-Property,
    Read-Property-Multiple, COV-Notification, Alarm/Event
"""

from __future__ import annotations

import struct
from typing import Any

from . import register
from .base import ProtocolDecoder

# ── MS/TP Frame Types ─────────────────────────────────────────────────

MSTP_FRAME_TYPES: dict[int, str] = {
    0x00: "TOKEN",
    0x01: "POLL_FOR_MASTER",
    0x02: "REPLY_TO_POLL",
    0x03: "TEST_REQUEST",
    0x04: "TEST_RESPONSE",
    0x05: "BACNET_DATA_EXPECTING_REPLY",
    0x06: "BACNET_DATA_NOT_EXPECTING_REPLY",
    0x07: "REPLY_POSTPONED",
}

# ── APDU Types ────────────────────────────────────────────────────────

APDU_TYPES: dict[int, str] = {
    0x00: "Confirmed-REQ",
    0x10: "Unconfirmed-REQ",
    0x20: "SimpleACK",
    0x30: "ComplexACK",
    0x40: "Segment-ACK",
    0x50: "Error",
    0x60: "Reject",
    0x70: "Abort",
}

# ── Confirmed Services ────────────────────────────────────────────────

CONFIRMED_SERVICES: dict[int, str] = {
    0x01: "Subscribe-COV",
    0x02: "Atomic-Read-File",
    0x03: "Atomic-Write-File",
    0x04: "Add-List-Element",
    0x05: "Remove-List-Element",
    0x06: "Create-Object",
    0x07: "Delete-Object",
    0x08: "Read-Property",
    0x0A: "Read-Property-Multiple",
    0x0B: "Write-Property",
    0x0C: "Read-Range",
    0x0E: "Subscribe-COV-Property",
    0x0F: "Write-Property-Multiple",
    0x1A: "Confirmed-Event-Notification",
    0x1B: "Get-Alarm-Summary",
    0x1C: "Get-Enrollment-Summary",
    0x1D: "Subscribe-COV",
    0x1E: "Confirmed-Private-Transfer",
}

# ── Unconfirmed Services ──────────────────────────────────────────────

UNCONFIRMED_SERVICES: dict[int, str] = {
    0x00: "I-Am",
    0x01: "I-Have",
    0x02: "Unconfirmed-COV-Notification",
    0x03: "Unconfirmed-Event-Notification",
    0x04: "Unconfirmed-Private-Transfer",
    0x05: "Unconfirmed-Text-Message",
    0x06: "Time-Synchronization",
    0x07: "Who-Has",
    0x08: "Who-Is",
    0x09: "UTC-Time-Synchronization",
}

# ── BACnet Object Types ──────────────────────────────────────────────

OBJECT_TYPES: dict[int, str] = {
    0:  "Analog-Input",      1:  "Analog-Output",     2:  "Analog-Value",
    3:  "Binary-Input",      4:  "Binary-Output",     5:  "Binary-Value",
    8:  "Device",            10: "File",              11: "Group",
    13: "Multi-State-Input", 14: "Multi-State-Output", 19: "Multi-State-Value",
    20: "Notification-Class", 23: "Program",           25: "Schedule",
    26: "Averaging",         27: "Multi-State-Value",  56: "Structured-View",
}

# ── BACnet Property IDs ──────────────────────────────────────────────

PROPERTY_IDS: dict[int, str] = {
    0:   "Acked-Transitions",    28:  "Event-State",
    35:  "Description",          55:  "Object-Identifier",
    56:  "Object-List",          57:  "Object-Name",
    60:  "Object-Type",          75:  "Present-Value",
    76:  "Priority-Array",       77:  "Reliability",
    79:  "Relinquish-Default",   85:  "Present-Value",
    87:  "Profile-Name",         103: "Status-Flags",
    104: "System-Status",        107: "Units",
    111: "Vendor-Identifier",    112: "Vendor-Name",
    120: "Protocol-Version",     121: "Protocol-Revision",
}

_MSTP_HEADER_LEN = 8  # preamble(2) + FT(1) + DA(1) + SA(1) + LEN(2) + CRC(1)


# ══════════════════════════════════════════════════════════════════════
#  Registered decoder
# ══════════════════════════════════════════════════════════════════════

@register
class BACnetMSTPDecoder(ProtocolDecoder):
    """BACnet MS/TP RS-485 decoder."""

    @property
    def name(self) -> str:
        return "BACnet-MSTP"

    @property
    def priority(self) -> int:
        return 10  # unambiguous preamble -- run first during detection

    @property
    def default_baud_rates(self) -> list[int]:
        return [19200, 38400, 76800, 57600, 115200]

    # ── extraction ────────────────────────────────────────────────────

    def extract_packets(
        self, buffer: bytearray,
    ) -> tuple[list[bytearray], bytearray]:
        packets: list[bytearray] = []
        i = 0

        while i < len(buffer) - 1:
            has_full = (
                buffer[i] == 0x55
                and i + 1 < len(buffer)
                and buffer[i + 1] == 0xFF
            )
            has_partial = buffer[i] == 0xFF and not has_full

            if not (has_full or has_partial):
                i += 1
                continue

            hdr_start = i + 2 if has_full else i + 1

            if hdr_start + 6 > len(buffer):
                break  # incomplete header

            ft = buffer[hdr_start]
            da = buffer[hdr_start + 1]
            sa = buffer[hdr_start + 2]
            length = (buffer[hdr_start + 3] << 8) | buffer[hdr_start + 4]
            crc_hdr = buffer[hdr_start + 5]

            # sanity
            if length > 512 or ft > 0x07:
                i += 1
                continue

            # validate header CRC-8
            hdr_bytes = bytes(buffer[hdr_start : hdr_start + 5])
            if not _check_crc8(hdr_bytes, crc_hdr):
                i += 1
                continue

            preamble_len = 2 if has_full else 1
            total = preamble_len + 6 + (length + 2 if length > 0 else 0)

            if i + total > len(buffer):
                break  # incomplete data

            pkt = bytearray(buffer[i : i + total])

            # reconstruct full preamble when adapter dropped 0x55
            if has_partial:
                pkt = bytearray([0x55]) + pkt

            packets.append(pkt)
            i += total

        return packets, buffer[i:]

    # ── decode ────────────────────────────────────────────────────────

    def decode(self, pkt: bytearray) -> dict[str, Any]:
        try:
            ft = pkt[2]
            da = pkt[3]
            sa = pkt[4]
            length = (pkt[5] << 8) | pkt[6]
            ft_name = MSTP_FRAME_TYPES.get(ft, f"FT_0x{ft:02X}")

            base: dict[str, Any] = {
                "protocol": "BACnet-MSTP",
                "src": sa,
                "dst": da,
                "cmd": ft_name,
                "point_type": "??",
                "point_index": "\u2014",
                "value": "\u2014",
                "raw_hex": self._to_hex(pkt),
                "raw_ascii": "",
            }

            if length == 0 or ft not in (0x05, 0x06):
                return base

            data = pkt[_MSTP_HEADER_LEN : _MSTP_HEADER_LEN + length]
            apdu_info = _decode_npdu_apdu(data)
            base.update(apdu_info)
            return base

        except Exception as exc:
            return {
                "protocol": "BACnet-MSTP",
                "src": "?",
                "dst": "?",
                "cmd": f"PARSE_ERROR ({exc})",
                "point_type": "??",
                "point_index": "\u2014",
                "value": "\u2014",
                "raw_hex": self._to_hex(pkt),
                "raw_ascii": "",
            }


# ══════════════════════════════════════════════════════════════════════
#  NPDU / APDU parsing
# ══════════════════════════════════════════════════════════════════════

def _decode_npdu_apdu(data: bytes) -> dict[str, Any]:
    if len(data) < 2:
        return {}

    npdu_control = data[1]
    offset = 2

    # skip DNET routing
    if npdu_control & 0x20:
        if offset + 3 > len(data):
            return {}
        offset += 3
        dlen = data[offset - 1]
        offset += dlen

    # skip SNET routing
    if npdu_control & 0x08:
        if offset + 3 > len(data):
            return {}
        offset += 3
        slen = data[offset - 1]
        offset += slen

    if npdu_control & 0x01:
        return {"cmd": "NPDU-Network-Msg"}

    if offset >= len(data):
        return {}

    return _decode_apdu(data[offset:])


def _decode_apdu(apdu: bytes) -> dict[str, Any]:
    if not apdu:
        return {}

    pdu_type = apdu[0] & 0xF0
    type_name = APDU_TYPES.get(pdu_type, f"APDU_0x{pdu_type:02X}")

    # -- Unconfirmed Request --
    if pdu_type == 0x10:
        if len(apdu) < 2:
            return {"cmd": type_name}
        svc = apdu[1]
        svc_name = UNCONFIRMED_SERVICES.get(svc, f"UNC_SVC_0x{svc:02X}")
        result: dict[str, Any] = {"cmd": svc_name}
        if svc == 0x08:
            result.update(_decode_who_is(apdu[2:]))
        elif svc == 0x00:
            result.update(_decode_i_am(apdu[2:]))
        elif svc in (0x02, 0x03):
            result.update(_decode_cov_notification(apdu[2:]))
        return result

    # -- Confirmed Request --
    if pdu_type == 0x00:
        if len(apdu) < 4:
            return {"cmd": type_name}
        svc = apdu[3]
        svc_name = CONFIRMED_SERVICES.get(svc, f"CONF_SVC_0x{svc:02X}")
        result = {"cmd": svc_name}
        if svc == 0x08:
            result.update(_decode_read_property_req(apdu[4:]))
        elif svc == 0x0B:
            result.update(_decode_write_property_req(apdu[4:]))
        elif svc == 0x0A:
            result.update(_decode_rpm_req(apdu[4:]))
        return result

    # -- ComplexACK --
    if pdu_type == 0x30:
        if len(apdu) < 4:
            return {"cmd": type_name}
        svc = apdu[3]
        svc_name = CONFIRMED_SERVICES.get(svc, f"ACK_SVC_0x{svc:02X}")
        result = {"cmd": f"ACK:{svc_name}"}
        if svc == 0x08:
            result.update(_decode_read_property_ack(apdu[4:]))
        elif svc == 0x0A:
            result.update(_decode_rpm_ack(apdu[4:]))
        return result

    # -- SimpleACK --
    if pdu_type == 0x20:
        if len(apdu) >= 4:
            svc = apdu[3]
            svc_name = CONFIRMED_SERVICES.get(svc, f"SVC_0x{svc:02X}")
            return {"cmd": f"SimpleACK:{svc_name}"}
        return {"cmd": "SimpleACK"}

    # -- Error --
    if pdu_type == 0x50:
        return {
            "cmd": "Error",
            "value": _to_hex_local(apdu[4:]) if len(apdu) > 4 else "\u2014",
        }

    return {"cmd": type_name}


# ══════════════════════════════════════════════════════════════════════
#  Service decoders
# ══════════════════════════════════════════════════════════════════════

def _decode_who_is(data: bytes) -> dict[str, Any]:
    if len(data) < 4:
        return {"point_type": "DISC", "value": "Who-Is (broadcast)"}
    try:
        lo = _decode_unsigned(data[1 : data[0] + 1 + 1])
        hi_start = data[0] + 1 + 1
        hi = _decode_unsigned(data[hi_start + 1 :])
        return {"point_type": "DISC", "value": f"Who-Is range {lo}\u2013{hi}"}
    except Exception:
        return {"point_type": "DISC", "value": "Who-Is"}


def _decode_i_am(data: bytes) -> dict[str, Any]:
    try:
        if len(data) < 5:
            return {"point_type": "DISC", "value": "I-Am"}
        obj_raw = data[1] << 24 | data[2] << 16 | data[3] << 8 | data[4]
        obj_type = (obj_raw >> 22) & 0x3FF
        instance = obj_raw & 0x3FFFFF
        obj_name = OBJECT_TYPES.get(obj_type, f"OBJ_{obj_type}")
        return {
            "point_type": "DISC",
            "point_index": instance,
            "value": f"I-Am {obj_name}:{instance}",
        }
    except Exception:
        return {"point_type": "DISC", "value": "I-Am"}


def _decode_read_property_req(data: bytes) -> dict[str, Any]:
    try:
        i = 0
        obj_type = obj_inst = prop_id = None

        while i < len(data):
            tag = data[i]
            tag_num = (tag >> 4) & 0x0F
            tag_class = (tag >> 3) & 0x01
            length = tag & 0x07
            i += 1

            if tag_class == 1:
                if tag_num == 0 and length == 4:
                    obj_raw = (
                        data[i] << 24
                        | data[i + 1] << 16
                        | data[i + 2] << 8
                        | data[i + 3]
                    )
                    obj_type = (obj_raw >> 22) & 0x3FF
                    obj_inst = obj_raw & 0x3FFFFF
                    i += 4
                elif tag_num == 1:
                    prop_id = (
                        data[i] if length == 1 else (data[i] << 8 | data[i + 1])
                    )
                    i += length
                else:
                    i += length
            else:
                i += length

        obj_name = (
            OBJECT_TYPES.get(obj_type, f"OBJ_{obj_type}")
            if obj_type is not None
            else "?"
        )
        prop_name = (
            PROPERTY_IDS.get(prop_id, f"PROP_{prop_id}")
            if prop_id is not None
            else "?"
        )
        return {
            "point_type": obj_name,
            "point_index": obj_inst if obj_inst is not None else "\u2014",
            "value": f"READ {prop_name}",
        }
    except Exception:
        return {"value": "Read-Property-Req"}


def _decode_read_property_ack(data: bytes) -> dict[str, Any]:
    try:
        i = 0
        obj_type = obj_inst = prop_id = pv = None

        while i < len(data) - 1:
            tag = data[i]
            tag_num = (tag >> 4) & 0x0F
            tag_class = (tag >> 3) & 0x01
            length = tag & 0x07
            i += 1

            if length == 5:
                length = data[i] & 0x07
                i += 1

            if tag_class == 1:
                if tag_num == 0 and length == 4:
                    obj_raw = (
                        data[i] << 24
                        | data[i + 1] << 16
                        | data[i + 2] << 8
                        | data[i + 3]
                    )
                    obj_type = (obj_raw >> 22) & 0x3FF
                    obj_inst = obj_raw & 0x3FFFFF
                    i += 4
                elif tag_num == 1:
                    prop_id = (
                        data[i] if length == 1 else (data[i] << 8 | data[i + 1])
                    )
                    i += length
                elif tag_num == 3:
                    pv = _decode_application_value(data, i, length)
                    break
                else:
                    i += length
            else:
                i += length

        obj_name = (
            OBJECT_TYPES.get(obj_type, f"OBJ_{obj_type}")
            if obj_type is not None
            else "?"
        )
        prop_name = (
            PROPERTY_IDS.get(prop_id, f"PROP_{prop_id}")
            if prop_id is not None
            else "?"
        )
        return {
            "point_type": obj_name,
            "point_index": obj_inst if obj_inst is not None else "\u2014",
            "value": f"{prop_name}={pv}" if pv is not None else prop_name,
        }
    except Exception:
        return {"value": "Read-Property-ACK"}


def _decode_write_property_req(data: bytes) -> dict[str, Any]:
    try:
        result = _decode_read_property_req(data)
        result["cmd"] = "Write-Property"
        if "value" in result:
            result["value"] = result["value"].replace("READ", "WRITE")
        return result
    except Exception:
        return {"value": "Write-Property-Req"}


def _decode_rpm_req(data: bytes) -> dict[str, Any]:
    return {"value": "Read-Property-Multiple"}


def _decode_rpm_ack(data: bytes) -> dict[str, Any]:
    return {"value": "Read-Property-Multiple-ACK"}


def _decode_cov_notification(data: bytes) -> dict[str, Any]:
    try:
        i = 0
        obj_type = obj_inst = None
        while i < len(data) - 1:
            tag = data[i]
            tag_num = (tag >> 4) & 0x0F
            tag_class = (tag >> 3) & 0x01
            length = tag & 0x07
            i += 1
            if tag_class == 1 and tag_num == 1 and length == 4:
                obj_raw = (
                    data[i] << 24
                    | data[i + 1] << 16
                    | data[i + 2] << 8
                    | data[i + 3]
                )
                obj_type = (obj_raw >> 22) & 0x3FF
                obj_inst = obj_raw & 0x3FFFFF
                i += 4
            else:
                i += max(length, 1)

        obj_name = (
            OBJECT_TYPES.get(obj_type, f"OBJ_{obj_type}")
            if obj_type is not None
            else "?"
        )
        return {
            "point_type": obj_name,
            "point_index": obj_inst if obj_inst is not None else "\u2014",
            "value": "COV-Notification",
        }
    except Exception:
        return {"value": "COV-Notification"}


# ══════════════════════════════════════════════════════════════════════
#  Application value decoder
# ══════════════════════════════════════════════════════════════════════

def _decode_application_value(
    data: bytes, i: int, hint_len: int,
) -> str:
    try:
        if i >= len(data):
            return "?"
        tag = data[i]
        app_type = (tag >> 4) & 0x0F
        length = tag & 0x07
        i += 1

        if app_type == 1:  # Boolean
            return "TRUE" if (length & 0x01) else "FALSE"
        if app_type == 2:  # Unsigned int
            val = 0
            for _ in range(length):
                val = (val << 8) | data[i]
                i += 1
            return str(val)
        if app_type == 4 and length == 4:  # Real (float)
            f = struct.unpack(">f", bytes(data[i : i + 4]))[0]
            return f"{f:.2f}"
        if app_type == 9:  # Enumerated
            if length == 1:
                return str(data[i])
            return str(data[i] << 8 | data[i + 1])
        if app_type == 7:  # Character string
            return data[i + 1 : i + length].decode("ascii", errors="replace")

        return _to_hex_local(data[i : i + length])
    except Exception:
        return "?"


# ══════════════════════════════════════════════════════════════════════
#  CRC helpers
# ══════════════════════════════════════════════════════════════════════

def _check_crc8(data: bytes, expected: int) -> bool:
    """MS/TP header CRC-8."""
    crc = 0xFF
    for b in data:
        byte_val = b
        for _ in range(8):
            if (crc ^ byte_val) & 0x01:
                crc = (crc >> 1) ^ 0xB8
            else:
                crc >>= 1
            byte_val >>= 1
    return (~crc & 0xFF) == expected


def _check_crc16(
    data: bytes, expected_hi: int, expected_lo: int,
) -> bool:
    """MS/TP data CRC-16."""
    crc = 0xFFFF
    for b in data:
        byte_val = b
        for _ in range(8):
            if (crc ^ byte_val) & 0x0001:
                crc = (crc >> 1) ^ 0xA001
            else:
                crc >>= 1
            byte_val >>= 1
    crc = ~crc & 0xFFFF
    return ((crc >> 8) & 0xFF) == expected_hi and (crc & 0xFF) == expected_lo


# ── tiny utilities ────────────────────────────────────────────────────

def _decode_unsigned(data: bytes) -> int:
    val = 0
    for b in data:
        val = (val << 8) | b
    return val


def _to_hex_local(data: bytes | bytearray) -> str:
    return " ".join(f"{b:02X}" for b in data)
