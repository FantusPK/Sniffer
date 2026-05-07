"""Active BACnet/IP unicast query client.

Sends Who-Is → reads I-Am → reads Object-List → reads Present-Value + Object-Name
for every point object on the target device.  Runs on a plain UDP socket; does
not require Npcap or the capture engine to be running.
"""

from __future__ import annotations

import socket
import struct
import threading
import time
from typing import Callable

# ── BACnet property / object constants ────────────────────────────────

PROP_OBJECT_LIST   = 76
PROP_PRESENT_VALUE = 85
PROP_OBJECT_NAME   = 77

OBJ_DEVICE = 8

# Object types that carry Present-Value
OBJECTS_WITH_PV: set[int] = {0, 1, 2, 3, 4, 5, 13, 14, 19}

OBJECT_TYPE_NAMES: dict[int, str] = {
    0: "AI", 1: "AO", 2: "AV",
    3: "BI", 4: "BO", 5: "BV",
    8: "DEV", 10: "File", 11: "Group",
    13: "MSI", 14: "MSO", 19: "MSV",
    20: "NC", 23: "Prog", 25: "Sched",
}


# ══════════════════════════════════════════════════════════════════════
#  Client
# ══════════════════════════════════════════════════════════════════════

class BACnetClient:
    """Unicast BACnet/IP request-response client for a single target device."""

    def __init__(
        self,
        target_ip: str,
        port: int = 47808,
        timeout: float = 2.0,
    ) -> None:
        self._target_ip = target_ip
        self._port = port
        self._timeout = timeout
        self._invoke_id = 0
        self._stop = threading.Event()
        self._sock: socket.socket | None = None

    # ── public ────────────────────────────────────────────────────────

    def full_query(
        self,
        on_log: Callable[[str], None],
        on_result: Callable[[str, str, str], None],  # (obj_label, name, value)
        on_done: Callable[[bool, str], None],         # (success, message)
    ) -> None:
        """Run the full discovery + read sequence.  Call from a background thread."""
        try:
            sock = self._open_socket()
            self._sock = sock

            # Step 1 — discover device instance via Who-Is
            on_log(f"→ Who-Is to {self._target_ip}:{self._port}…")
            device_instance = self._discover(sock)
            if device_instance is None:
                on_done(False, f"No I-Am response from {self._target_ip} (timeout).")
                return
            on_log(f"✓ Device instance {device_instance} found.")

            # Step 2 — read Object-List from the Device object
            on_log("→ Reading Object-List…")
            ack = self._read_property(sock, OBJ_DEVICE, device_instance, PROP_OBJECT_LIST)
            if ack is None:
                on_done(False, "No response to Object-List request.")
                return
            objects = _parse_object_list(ack)
            pv_objects = [(t, i) for t, i in objects if t in OBJECTS_WITH_PV]
            on_log(
                f"✓ {len(objects)} objects total, "
                f"{len(pv_objects)} with Present-Value — reading…"
            )

            # Step 3 — read Object-Name + Present-Value for each point object
            count = 0
            for obj_type, obj_inst in pv_objects:
                if self._stop.is_set():
                    on_done(False, "Query cancelled.")
                    return

                type_name = OBJECT_TYPE_NAMES.get(obj_type, f"OBJ{obj_type}")
                label = f"{type_name}:{obj_inst}"

                # Object-Name
                name = "—"
                ack_name = self._read_property(sock, obj_type, obj_inst, PROP_OBJECT_NAME)
                if ack_name is not None:
                    name = _parse_string_value(ack_name) or "—"

                # Present-Value
                value = "—"
                ack_pv = self._read_property(sock, obj_type, obj_inst, PROP_PRESENT_VALUE)
                if ack_pv is not None:
                    value = _parse_present_value(ack_pv)

                on_result(label, name, value)
                count += 1

            on_done(True, f"Query complete — {count} of {len(pv_objects)} objects read.")

        except Exception as exc:
            on_done(False, f"Query error: {exc}")
        finally:
            if self._sock:
                try:
                    self._sock.close()
                except Exception:
                    pass
                self._sock = None

    def stop(self) -> None:
        """Signal the query to stop after the current request."""
        self._stop.set()
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass

    # ── socket helpers ────────────────────────────────────────────────

    def _open_socket(self) -> socket.socket:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.settimeout(self._timeout)
        try:
            sock.bind(("", self._port))
        except OSError:
            sock.bind(("", 0))  # fall back to ephemeral port
        return sock

    def _next_invoke_id(self) -> int:
        self._invoke_id = (self._invoke_id % 255) + 1
        return self._invoke_id

    # ── BACnet request builders ───────────────────────────────────────

    def _build_who_is(self) -> bytes:
        npdu = bytes([0x01, 0x00])
        apdu = bytes([0x10, 0x08])
        payload = npdu + apdu
        return bytes([0x81, 0x0A]) + struct.pack(">H", 4 + len(payload)) + payload

    def _build_read_property(
        self, obj_type: int, obj_inst: int, prop_id: int, invoke_id: int
    ) -> bytes:
        obj_id_raw = (obj_type << 22) | obj_inst
        apdu = bytes([0x00, 0x05, invoke_id, 0x0C])  # Confirmed-REQ, ReadProperty
        apdu += bytes([0x0C]) + struct.pack(">I", obj_id_raw)  # ctx tag 0: obj-id
        if prop_id <= 0xFF:
            apdu += bytes([0x19, prop_id])             # ctx tag 1: prop-id (1 byte)
        else:
            apdu += bytes([0x1A]) + struct.pack(">H", prop_id)  # prop-id (2 bytes)
        npdu = bytes([0x01, 0x04])
        payload = npdu + apdu
        return bytes([0x81, 0x0A]) + struct.pack(">H", 4 + len(payload)) + payload

    # ── send / receive ────────────────────────────────────────────────

    def _discover(self, sock: socket.socket) -> int | None:
        sock.sendto(self._build_who_is(), (self._target_ip, self._port))
        deadline = time.monotonic() + self._timeout
        while time.monotonic() < deadline:
            try:
                data, addr = sock.recvfrom(65535)
                if addr[0] != self._target_ip:
                    continue
                inst = _parse_i_am(data)
                if inst is not None:
                    return inst
            except socket.timeout:
                break
            except OSError:
                break
        return None

    def _read_property(
        self,
        sock: socket.socket,
        obj_type: int,
        obj_inst: int,
        prop_id: int,
    ) -> bytes | None:
        iid = self._next_invoke_id()
        pkt = self._build_read_property(obj_type, obj_inst, prop_id, iid)
        sock.sendto(pkt, (self._target_ip, self._port))
        deadline = time.monotonic() + self._timeout
        while time.monotonic() < deadline:
            try:
                data, addr = sock.recvfrom(65535)
                if addr[0] != self._target_ip:
                    continue
                payload = _parse_read_property_ack(data, iid)
                if payload is not None:
                    return payload
            except socket.timeout:
                break
            except OSError:
                break
        return None


# ══════════════════════════════════════════════════════════════════════
#  Response parsers (module-level, operate on raw bytes)
# ══════════════════════════════════════════════════════════════════════

def _npdu_offset(data: bytes) -> int:
    """Return byte offset of NPDU within a BACnet/IP datagram."""
    return 10 if data[1] == 0x04 else 4  # Forwarded-NPDU vs direct


def _apdu_from_datagram(data: bytes) -> bytes | None:
    """Strip BVLC + NPDU, return bare APDU bytes."""
    if len(data) < 6 or data[0] != 0x81:
        return None
    off = _npdu_offset(data)
    if off + 2 > len(data):
        return None
    npdu_ctrl = data[off + 1]
    skip = 2
    # skip DNET routing
    if npdu_ctrl & 0x20:
        if off + skip + 3 > len(data):
            return None
        dlen = data[off + skip + 2]
        skip += 3 + dlen
    # skip SNET routing
    if npdu_ctrl & 0x08:
        if off + skip + 3 > len(data):
            return None
        slen = data[off + skip + 2]
        skip += 3 + slen
    # hop count present when DNET is set
    if npdu_ctrl & 0x20:
        skip += 1
    apdu_start = off + skip
    if apdu_start >= len(data):
        return None
    return data[apdu_start:]


def _parse_i_am(data: bytes) -> int | None:
    """Return device instance from an I-Am datagram, or None if not an I-Am."""
    apdu = _apdu_from_datagram(data)
    if apdu is None or len(apdu) < 7:
        return None
    if apdu[0] != 0x10 or apdu[1] != 0x00:  # Unconfirmed-REQ, I-Am
        return None
    if apdu[2] != 0xC4:  # application tag 12 (object-identifier), length 4
        return None
    obj_raw = struct.unpack(">I", bytes(apdu[3:7]))[0]
    obj_type = (obj_raw >> 22) & 0x3FF
    if obj_type != OBJ_DEVICE:
        return None
    return obj_raw & 0x3FFFFF


def _parse_read_property_ack(data: bytes, invoke_id: int) -> bytes | None:
    """Return ACK payload (after service choice byte) for a matching ReadProperty-ACK."""
    apdu = _apdu_from_datagram(data)
    if apdu is None or len(apdu) < 4:
        return None
    # Complex-ACK: 0x30, invoke-id, service=ReadProperty(0x0C)
    if apdu[0] != 0x30 or apdu[1] != invoke_id or apdu[2] != 0x0C:
        return None
    return bytes(apdu[3:])


def _skip_context_tags(payload: bytes) -> int:
    """Return index just past the object-id (ctx0) and prop-id (ctx1) tags."""
    i = 0
    skipped = 0
    while i < len(payload) and skipped < 2:
        tag = payload[i]
        tag_num = (tag >> 4) & 0x0F
        is_ctx = (tag >> 3) & 0x01
        lvt = tag & 0x07
        i += 1
        if lvt == 5:          # extended-length indicator
            lvt = payload[i] & 0x07
            i += 1
        if lvt == 6 or lvt == 7:  # opening / closing tag
            continue
        i += lvt
        if is_ctx and tag_num in (0, 1):
            skipped += 1
    return i


def _parse_object_list(payload: bytes) -> list[tuple[int, int]]:
    """Parse ReadProperty-ACK payload for Object-List → list of (type, instance)."""
    objects: list[tuple[int, int]] = []
    i = _skip_context_tags(payload)
    # find opening tag 3 (ctx, tag_num=3, lvt=6)
    while i < len(payload):
        b = payload[i]
        if (b >> 3) & 1 and (b >> 4) & 0xF == 3 and (b & 7) == 6:
            i += 1
            break
        i += 1
    # parse application-tagged object-identifiers (tag 12, length 4 → 0xC4)
    while i < len(payload):
        b = payload[i]
        if b == 0x3F:  # closing tag 3
            break
        if b == 0xC4:  # app tag 12, len 4
            i += 1
            if i + 4 <= len(payload):
                raw = struct.unpack(">I", bytes(payload[i:i + 4]))[0]
                objects.append(((raw >> 22) & 0x3FF, raw & 0x3FFFFF))
                i += 4
        else:
            i += 1
    return objects


def _parse_present_value(payload: bytes) -> str:
    """Parse ReadProperty-ACK payload for any single application-tagged value."""
    i = _skip_context_tags(payload)
    # find opening tag 3
    while i < len(payload):
        b = payload[i]
        if (b >> 3) & 1 and (b >> 4) & 0xF == 3 and (b & 7) == 6:
            i += 1
            break
        i += 1
    return _decode_app_tag(payload, i)


def _parse_string_value(payload: bytes) -> str:
    """Parse ReadProperty-ACK payload expecting a character-string value."""
    return _parse_present_value(payload)


def _decode_app_tag(data: bytes, i: int) -> str:
    """Decode one application-tagged value at offset i and return a display string."""
    try:
        if i >= len(data):
            return "?"
        tag = data[i]
        app_type = (tag >> 4) & 0x0F
        length = tag & 0x07
        i += 1

        if length == 5:  # extended length
            length = data[i]
            i += 1

        if app_type == 0:   # Null
            return "Null"
        if app_type == 1:   # Boolean (value encoded in LVT)
            return "TRUE" if (tag & 0x01) else "FALSE"
        if app_type == 2:   # Unsigned integer
            v = int.from_bytes(data[i:i + length], "big")
            return str(v)
        if app_type == 3:   # Signed integer
            v = int.from_bytes(data[i:i + length], "big", signed=True)
            return str(v)
        if app_type == 4 and length == 4:   # Real
            f = struct.unpack(">f", bytes(data[i:i + 4]))[0]
            return f"{f:.6g}"
        if app_type == 5 and length == 8:   # Double
            f = struct.unpack(">d", bytes(data[i:i + 8]))[0]
            return f"{f:.6g}"
        if app_type == 7:   # Character string
            # first byte is encoding (0=UTF-8/ASCII)
            return data[i + 1:i + length].decode("utf-8", errors="replace")
        if app_type == 9:   # Enumerated
            v = int.from_bytes(data[i:i + length], "big")
            return str(v)
        if app_type == 10:  # Date
            return f"{data[i+1]:02d}/{data[i+2]:02d}/{data[i]:04d}"
        if app_type == 11:  # Time
            return f"{data[i]:02d}:{data[i+1]:02d}:{data[i+2]:02d}"
        if app_type == 12:  # Object Identifier
            raw = struct.unpack(">I", bytes(data[i:i + 4]))[0]
            t = (raw >> 22) & 0x3FF
            inst = raw & 0x3FFFFF
            return f"{OBJECT_TYPE_NAMES.get(t, f'OBJ{t}')}:{inst}"
        return " ".join(f"{b:02X}" for b in data[i:i + length])
    except Exception:
        return "?"
