"""N2 / N2 Open frame builders for the simulator.

Produces correctly framed binary N2 and N2 Open ASCII packets so the
real :class:`~sniffer.protocols.n2.N2Decoder` can decode them.

Network topology simulated
--------------------------
    JACE (address 1) polls controllers at addresses 5, 6, 7

    Node 5  -- DX Rooftop Unit  (binary N2)
    Node 6  -- Hot-Water Loop   (binary N2)
    Node 7  -- VAV box cluster  (N2 Open ASCII)

Traffic mix
-----------
    * Binary N2: JACE polls AI / DI points; controllers respond
    * Binary N2: JACE writes AO / DO setpoints
    * N2 Open: JACE sends ASCII commands; controller responds
    * Occasional broadcast alarm
"""

from __future__ import annotations

import itertools
import random
from collections.abc import Iterator


# ── Binary N2 helpers ─────────────────────────────────────────────────

def _n2_crc(frame_without_crc: bytearray) -> int:
    crc = 0
    for b in frame_without_crc:
        crc ^= b
    return crc


def _n2_frame(src: int, dst: int, cmd: int, data: bytes = b"") -> bytes:
    body = bytearray([src, dst, len(data), cmd]) + bytearray(data)
    body.append(_n2_crc(body))
    return bytes(body)


# ── Binary N2: specific packet types ─────────────────────────────────

def _n2_read_ai_req(jace: int, ctrl: int, point_idx: int) -> bytes:
    """JACE requests analog input from controller."""
    return _n2_frame(jace, ctrl, 0x04, bytes([point_idx]))


def _n2_read_ai_resp(ctrl: int, jace: int, point_idx: int, value: float) -> bytes:
    """Controller responds with scaled analog value (×10 fixed-point)."""
    raw = int(value * 10) & 0xFFFF
    return _n2_frame(ctrl, jace, 0x05, bytes([point_idx, (raw >> 8) & 0xFF, raw & 0xFF]))


def _n2_read_di_req(jace: int, ctrl: int, point_idx: int) -> bytes:
    return _n2_frame(jace, ctrl, 0x06, bytes([point_idx]))


def _n2_read_di_resp(ctrl: int, jace: int, point_idx: int, state: bool) -> bytes:
    return _n2_frame(ctrl, jace, 0x07, bytes([point_idx, 1 if state else 0]))


def _n2_write_ao(jace: int, ctrl: int, point_idx: int, value: float) -> bytes:
    raw = int(value * 10) & 0xFFFF
    return _n2_frame(jace, ctrl, 0x02, bytes([point_idx, (raw >> 8) & 0xFF, raw & 0xFF]))


def _n2_write_do(jace: int, ctrl: int, point_idx: int, state: bool) -> bytes:
    return _n2_frame(jace, ctrl, 0x03, bytes([point_idx, 1 if state else 0]))


def _n2_poll(jace: int, ctrl: int) -> bytes:
    return _n2_frame(jace, ctrl, 0x00)


def _n2_poll_resp(ctrl: int, jace: int) -> bytes:
    return _n2_frame(ctrl, jace, 0x01)


# ── N2 Open helpers ───────────────────────────────────────────────────

def _n2open_cmd(addr: int, cmd: int, data_bytes: bytes = b"") -> bytes:
    """Build an N2 Open ASCII command frame: >{AADDCC[DATA]}\r"""
    hex_data = data_bytes.hex().upper()
    content = f"{addr:02X}{cmd:02X}{hex_data}"
    return (b">" + content.encode("ascii") + b"\r")


def _n2open_resp(addr: int, cmd: int, data_bytes: bytes = b"") -> bytes:
    """Build an N2 Open ASCII response frame: A{AADDCC[DATA]}\r"""
    hex_data = data_bytes.hex().upper()
    content = f"{addr:02X}{cmd:02X}{hex_data}"
    return (b"A" + content.encode("ascii") + b"\r")


def _n2open_read_ai(jace_ignored: int, ctrl_addr: int, point_idx: int) -> bytes:
    return _n2open_cmd(ctrl_addr, 0x01, bytes([point_idx]))


def _n2open_read_ai_resp(ctrl_addr: int, point_idx: int, value: float) -> bytes:
    raw = int(value * 10) & 0xFFFF
    return _n2open_resp(ctrl_addr, 0x02, bytes([point_idx, (raw >> 8) & 0xFF, raw & 0xFF]))


def _n2open_read_ao(ctrl_addr: int, point_idx: int) -> bytes:
    return _n2open_cmd(ctrl_addr, 0x03, bytes([point_idx]))


def _n2open_read_ao_resp(ctrl_addr: int, point_idx: int, value: float) -> bytes:
    raw = int(value * 10) & 0xFFFF
    return _n2open_resp(ctrl_addr, 0x04, bytes([point_idx, (raw >> 8) & 0xFF, raw & 0xFF]))


def _n2open_write_ao(ctrl_addr: int, point_idx: int, value: float) -> bytes:
    raw = int(value * 10) & 0xFFFF
    return _n2open_cmd(ctrl_addr, 0x09, bytes([point_idx, (raw >> 8) & 0xFF, raw & 0xFF]))


# ══════════════════════════════════════════════════════════════════════
#  Traffic generator
# ══════════════════════════════════════════════════════════════════════

_JACE = 1

# Binary N2 controllers
_BINARY_NODES = {
    5: {
        "name": "DX-RTU",
        "ai": [(1, 55.0), (2, 48.5), (3, 72.3)],   # (point_idx, base_value)
        "di": [(1, True), (2, False)],
        "ao": [(1, 60.0)],
    },
    6: {
        "name": "HW-Loop",
        "ai": [(1, 140.0), (2, 120.5), (3, 65.2)],
        "di": [(1, True)],
        "ao": [(1, 130.0), (2, 10.0)],
    },
}

# N2 Open ASCII controller
_N2OPEN_NODES = {
    7: {
        "name": "VAV-Cluster",
        "ai": [(1, 71.5), (2, 70.0), (3, 69.8)],
        "ao": [(1, 55.0), (2, 22.5)],
    },
}


def n2_traffic() -> Iterator[bytes]:
    """Infinite iterator of realistic N2 / N2 Open frames."""
    rng = random.Random(99)

    while True:
        # ── Binary N2 poll-response cycles ───────────────────────────
        for ctrl_addr, node in _BINARY_NODES.items():
            yield _n2_poll(_JACE, ctrl_addr)
            yield _n2_poll_resp(ctrl_addr, _JACE)

            # Read a random AI
            if node["ai"]:
                pidx, base = rng.choice(node["ai"])
                val = round(base + rng.uniform(-1.5, 1.5), 1)
                yield _n2_read_ai_req(_JACE, ctrl_addr, pidx)
                yield _n2_read_ai_resp(ctrl_addr, _JACE, pidx, val)

            # Read a DI occasionally
            if node["di"] and rng.random() < 0.5:
                pidx, state = rng.choice(node["di"])
                # Randomly flip state sometimes
                actual = state if rng.random() < 0.9 else not state
                yield _n2_read_di_req(_JACE, ctrl_addr, pidx)
                yield _n2_read_di_resp(ctrl_addr, _JACE, pidx, actual)

            # Write an AO occasionally
            if node["ao"] and rng.random() < 0.3:
                pidx, base = rng.choice(node["ao"])
                val = round(base + rng.uniform(-5.0, 5.0), 1)
                yield _n2_write_ao(_JACE, ctrl_addr, pidx, val)

        # ── N2 Open poll-response cycles ─────────────────────────────
        for ctrl_addr, node in _N2OPEN_NODES.items():
            # Read AI
            if node["ai"]:
                pidx, base = rng.choice(node["ai"])
                val = round(base + rng.uniform(-1.0, 1.0), 1)
                yield _n2open_read_ai(_JACE, ctrl_addr, pidx)
                yield _n2open_read_ai_resp(ctrl_addr, pidx, val)

            # Read AO
            if node["ao"]:
                pidx, base = rng.choice(node["ao"])
                val = round(base + rng.uniform(-2.0, 2.0), 1)
                yield _n2open_read_ao(ctrl_addr, pidx)
                yield _n2open_read_ao_resp(ctrl_addr, pidx, val)

            # Write AO occasionally
            if node["ao"] and rng.random() < 0.25:
                pidx, base = rng.choice(node["ao"])
                val = round(base + rng.uniform(-5.0, 5.0), 1)
                yield _n2open_write_ao(ctrl_addr, pidx, val)
