"""Broadcast BACnet Who-Is scanner.

Sends a broadcast (or ranged) Who-Is to 255.255.255.255:47808 and collects
all I-Am responses within a configurable timeout.  Runs on a plain UDP socket;
does not require the passive capture engine to be active.
"""

from __future__ import annotations

import socket
import struct
import time
from typing import Callable

from sniffer.core.bacnet_client import _apdu_from_datagram
from sniffer.protocols.vendors import vendor_name as _vname


def _encode_ctx_uint(tag_num: int, value: int) -> bytes:
    """Encode *value* as a context-tagged unsigned integer."""
    if value <= 0xFF:
        length = 1
    elif value <= 0xFFFF:
        length = 2
    else:
        length = 3
    tag_byte = (tag_num << 4) | 0x08 | length  # class=context, length
    return bytes([tag_byte]) + value.to_bytes(length, "big")


def _build_who_is(lo: int | None, hi: int | None) -> bytes:
    npdu = bytes([0x01, 0x20, 0xFF, 0xFF, 0x00, 0xFF])  # global broadcast
    apdu = bytes([0x10, 0x08])
    if lo is not None and hi is not None:
        apdu += _encode_ctx_uint(0, lo) + _encode_ctx_uint(1, hi)
    payload = npdu + apdu
    length = 4 + len(payload)
    return bytes([0x81, 0x0B]) + struct.pack(">H", length) + payload


def _parse_i_am_full(data: bytes) -> tuple[int, int | None] | None:
    """Return (device_instance, vendor_id) from an I-Am UDP datagram.

    The source IP is not carried in the APDU; the caller supplies it from the
    ``recvfrom`` address.  Returns None if the datagram is not a valid I-Am.
    """
    apdu = _apdu_from_datagram(data)
    if apdu is None or len(apdu) < 7:
        return None
    if apdu[0] != 0x10 or apdu[1] != 0x00:  # Unconfirmed-REQ, I-Am
        return None
    if apdu[2] != 0xC4:  # application tag 12 (object-identifier), length 4
        return None

    obj_raw = struct.unpack(">I", bytes(apdu[3:7]))[0]
    if (obj_raw >> 22) & 0x3FF != 8:  # must be Device object
        return None
    instance = obj_raw & 0x3FFFFF

    # parse vendor ID (field 4: skip object-id, max-apdu, segmentation)
    vid: int | None = None
    try:
        i = 7  # byte after object-identifier (0xC4 tag + 4 data bytes)
        for _ in range(2):  # skip max-apdu-length, segmentation
            if i >= len(apdu):
                break
            length = apdu[i] & 0x07
            i += 1 + length
        if i < len(apdu):
            length = apdu[i] & 0x07
            i += 1
            if i + length <= len(apdu):
                vid = int.from_bytes(apdu[i: i + length], "big")
    except Exception:
        vid = None

    # src_ip is not in the APDU; caller must supply it from recvfrom addr
    return instance, vid


class BroadcastScanner:
    """Sends a broadcast Who-Is and collects I-Am responses.

    Call ``scan()`` from a background thread.  All callbacks are invoked
    from that thread; callers must marshal to the main thread via
    ``root.after(0, ...)`` if needed.
    """

    def __init__(self, port: int = 47808, timeout: float = 3.0) -> None:
        self._port = port
        self._timeout = timeout

    def scan(
        self,
        on_result: Callable[[str, int, int | None], None],
        on_done: Callable[[], None],
        lo: int | None = None,
        hi: int | None = None,
    ) -> None:
        """Broadcast Who-Is and call *on_result* for each responding device.

        Args:
            on_result: called as ``on_result(src_ip, device_instance, vendor_id)``
            on_done:   called when the timeout window expires
            lo/hi:     optional instance range (both None = global Who-Is)
        """
        pkt = _build_who_is(lo, hi)
        seen: set[str] = set()
        sock: socket.socket | None = None

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.settimeout(0.5)
            try:
                sock.bind(("", self._port))
            except OSError:
                sock.bind(("", 0))

            sock.sendto(pkt, ("255.255.255.255", self._port))
            deadline = time.monotonic() + self._timeout

            while time.monotonic() < deadline:
                try:
                    data, addr = sock.recvfrom(65535)
                    src_ip = addr[0]
                    result = _parse_i_am_full(data)
                    if result is None:
                        continue
                    instance, vid = result
                    key = f"{src_ip}:{instance}"
                    if key in seen:
                        continue
                    seen.add(key)
                    on_result(src_ip, instance, vid)
                except socket.timeout:
                    continue
                except OSError:
                    break
        except OSError:
            # Socket setup / send failed (e.g. no network) — report nothing
            # found, but never leave the caller hanging on on_done().
            pass
        finally:
            if sock is not None:
                try:
                    sock.close()
                except Exception:
                    pass
            on_done()
