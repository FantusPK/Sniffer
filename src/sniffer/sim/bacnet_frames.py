"""BACnet MS/TP frame builders for the simulator.

Produces correctly framed, CRC-checked MS/TP packets so the real
:class:`~sniffer.protocols.bacnet_mstp.BACnetMSTPDecoder` can decode
them without any special-casing.

Network topology simulated
--------------------------
    Node 1  -- JACE / BACnet router  (master)
    Node 2  -- AHU controller
    Node 3  -- VAV controller
    Node 4  -- Chiller plant controller

Traffic mix
-----------
    * Token passing between masters
    * Who-Is / I-Am device discovery
    * Read-Property requests  (Present-Value, Object-Name)
    * ComplexACK responses with float present values
    * Unconfirmed COV notifications
"""

from __future__ import annotations

import itertools
import random
import struct
from collections.abc import Iterator


# ── CRC helpers ───────────────────────────────────────────────────────

def _crc8(data: bytes) -> int:
    crc = 0xFF
    for b in data:
        for _ in range(8):
            if (crc ^ b) & 0x01:
                crc = (crc >> 1) ^ 0xB8
            else:
                crc >>= 1
            b >>= 1
    return (~crc) & 0xFF


def _crc16(data: bytes) -> tuple[int, int]:
    crc = 0xFFFF
    for b in data:
        for _ in range(8):
            if (crc ^ b) & 0x0001:
                crc = (crc >> 1) ^ 0xA001
            else:
                crc >>= 1
            b >>= 1
    crc = (~crc) & 0xFFFF
    return (crc >> 8) & 0xFF, crc & 0xFF


# ── low-level frame assembly ──────────────────────────────────────────

def _mstp_frame(
    frame_type: int,
    dst: int,
    src: int,
    data: bytes = b"",
) -> bytes:
    """Build a complete MS/TP frame with preamble and CRCs."""
    length_hi = (len(data) >> 8) & 0xFF
    length_lo = len(data) & 0xFF
    header_bytes = bytes([frame_type, dst, src, length_hi, length_lo])
    crc_hdr = _crc8(header_bytes)
    frame = bytearray([0x55, 0xFF]) + bytearray(header_bytes) + bytearray([crc_hdr])
    if data:
        crc_hi, crc_lo = _crc16(data)
        frame += bytearray(data) + bytearray([crc_hi, crc_lo])
    return bytes(frame)


# ── NPDU / APDU builders ──────────────────────────────────────────────

def _npdu(apdu: bytes) -> bytes:
    """Wrap APDU in a minimal NPDU (no routing)."""
    return bytes([0x01, 0x04]) + apdu  # version=1, normal priority


def _unconfirmed_req(service: int, payload: bytes) -> bytes:
    return bytes([0x10, service]) + payload


def _confirmed_req(invoke_id: int, service: int, payload: bytes) -> bytes:
    # PDU type=0x00, segmentation=0, max-segments=0x05, max-apdu=0x0C
    return bytes([0x00, 0x05, invoke_id, service]) + payload


def _complex_ack(invoke_id: int, service: int, payload: bytes) -> bytes:
    return bytes([0x30, invoke_id, 0x00, service]) + payload


def _encode_object_id(obj_type: int, instance: int) -> bytes:
    """BACnet 4-byte object identifier."""
    val = ((obj_type & 0x3FF) << 22) | (instance & 0x3FFFFF)
    return struct.pack(">I", val)


def _context_tag(tag_num: int, data: bytes) -> bytes:
    """Context-tagged value (class=1)."""
    return bytes([(tag_num << 4) | 0x08 | len(data)]) + data


def _app_real(value: float) -> bytes:
    """Application-tagged REAL (type 4)."""
    return bytes([0x44]) + struct.pack(">f", value)


def _app_unsigned(value: int) -> bytes:
    """Application-tagged unsigned int (type 2, 2 bytes)."""
    return bytes([0x22, (value >> 8) & 0xFF, value & 0xFF])


# ── Who-Is / I-Am ─────────────────────────────────────────────────────

def _who_is(src: int) -> bytes:
    apdu = _unconfirmed_req(0x08, b"")  # service 8 = Who-Is, broadcast range
    npdu = _npdu(apdu)
    return _mstp_frame(0x06, 0xFF, src, npdu)  # broadcast


def _i_am(src: int, instance: int) -> bytes:
    # Object-ID: Device type=8, plus max-apdu, segmentation, vendor-id
    obj_id = _encode_object_id(8, instance)
    payload = (
        bytes([0xC4]) + obj_id        # app tag: object-id
        + bytes([0x22, 0x01, 0xE0])   # max-apdu = 480
        + bytes([0x91, 0x00])         # segmentation = none
        + bytes([0x21, 0x4D])         # vendor-id = 77
    )
    apdu = _unconfirmed_req(0x00, payload)
    npdu = _npdu(apdu)
    return _mstp_frame(0x06, 0xFF, src, npdu)


# ── Read-Property ─────────────────────────────────────────────────────

def _read_property_req(
    src: int, dst: int, invoke_id: int,
    obj_type: int, instance: int, prop_id: int,
) -> bytes:
    obj_bytes = _encode_object_id(obj_type, instance)
    payload = (
        _context_tag(0, obj_bytes)           # object-identifier [0]
        + _context_tag(1, bytes([prop_id]))  # property-identifier [1]
    )
    apdu = _confirmed_req(invoke_id, 0x08, payload)
    npdu = _npdu(apdu)
    return _mstp_frame(0x05, dst, src, npdu)  # FT=5: data expecting reply


def _read_property_ack(
    src: int, dst: int, invoke_id: int,
    obj_type: int, instance: int, prop_id: int, value: float,
) -> bytes:
    obj_bytes = _encode_object_id(obj_type, instance)
    payload = (
        _context_tag(0, obj_bytes)
        + _context_tag(1, bytes([prop_id]))
        + bytes([0x3E])           # opening tag [3]
        + _app_real(value)
        + bytes([0x3F])           # closing tag [3]
    )
    apdu = _complex_ack(invoke_id, 0x08, payload)
    npdu = _npdu(apdu)
    return _mstp_frame(0x06, dst, src, npdu)


# ── COV Notification ──────────────────────────────────────────────────

def _cov_notification(
    src: int, obj_type: int, instance: int, value: float,
) -> bytes:
    obj_bytes = _encode_object_id(obj_type, instance)
    payload = (
        _context_tag(0, bytes([0x01]))       # subscriber-process-id
        + _context_tag(1, bytes([0x01]))     # initiating-device-id (simplified)
        + bytes([0x1C]) + obj_bytes          # monitored-object-id context[1] 4-byte
        + _context_tag(3, bytes([0x00]))     # time-remaining
    )
    apdu = _unconfirmed_req(0x02, payload)
    npdu = _npdu(apdu)
    return _mstp_frame(0x06, 0xFF, src, npdu)


# ── Token ─────────────────────────────────────────────────────────────

def _token(src: int, dst: int) -> bytes:
    return _mstp_frame(0x00, dst, src)  # FT=0: Token, no data


# ══════════════════════════════════════════════════════════════════════
#  Traffic generator
# ══════════════════════════════════════════════════════════════════════

# Simulated nodes: (address, device-instance, description)
_NODES = [
    (1, 1001, "JACE"),
    (2, 1002, "AHU-1"),
    (3, 1003, "VAV-1"),
    (4, 1004, "Chiller"),
]

# Analog-Input points per controller: (obj_type, instance, description, base_value)
_AI_POINTS = {
    2: [(0, 1, "supply_air_temp",    62.5), (0, 2, "return_air_temp", 74.2)],
    3: [(0, 1, "zone_temp",          71.0), (0, 3, "damper_pos",      45.0)],
    4: [(0, 1, "chw_supply_temp",    44.0), (0, 2, "chw_return_temp", 56.0)],
}

_MASTERS = [addr for addr, _, _ in _NODES]


def bacnet_traffic() -> Iterator[bytes]:
    """Infinite iterator of realistic BACnet MS/TP frames."""
    invoke_id = itertools.count(0)
    rng = random.Random(42)

    # Kick off with discovery
    yield _who_is(1)
    for addr, inst, _ in _NODES:
        yield _i_am(addr, inst)

    token_cycle = itertools.cycle(_MASTERS)
    next(token_cycle)  # skip first -- JACE holds token initially

    while True:
        # ── Token pass ────────────────────────────────────────────────
        holder = 1
        for next_master in itertools.islice(token_cycle, len(_MASTERS)):
            yield _token(holder, next_master)
            holder = next_master

            # ── Read a random AI point from a controller ──────────────
            if holder != 1:
                points = _AI_POINTS.get(holder, [])
                if points:
                    obj_type, inst, _, base = rng.choice(points)
                    iid = next(invoke_id) % 256
                    value = round(base + rng.uniform(-2.0, 2.0), 1)

                    # JACE (1) reads from controller
                    yield _read_property_req(1, holder, iid, obj_type, inst, 85)
                    yield _read_property_ack(holder, 1, iid, obj_type, inst, 85, value)

        # ── Occasional COV from a controller ─────────────────────────
        ctrl_addr = rng.choice([2, 3, 4])
        points = _AI_POINTS.get(ctrl_addr, [])
        if points:
            obj_type, inst, _, base = rng.choice(points)
            value = round(base + rng.uniform(-3.0, 3.0), 1)
            yield _cov_notification(ctrl_addr, obj_type, inst, value)

        # ── Periodic Who-Is from JACE ────────────────────────────────
        if rng.random() < 0.15:
            yield _who_is(1)
            for addr, dinst, _ in _NODES:
                if addr != 1:
                    yield _i_am(addr, dinst)
