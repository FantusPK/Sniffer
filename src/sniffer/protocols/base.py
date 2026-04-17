"""Abstract base class for protocol decoders."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class ProtocolDecoder(ABC):
    """Base class every protocol decoder must implement.

    Lifecycle managed by :class:`~sniffer.core.engine.SnifferEngine`:

    1. **Detection phase** -- the engine feeds raw serial bytes to *all*
       registered decoders simultaneously.  Each decoder independently
       extracts and decodes packets.  The first decoder to produce
       ``LOCK_THRESHOLD`` consecutive valid packets wins.
    2. **Locked phase** -- only the winning decoder receives bytes;
       all others go dormant.
    3. **Baud rotation** -- when the engine switches baud rate it calls
       :meth:`reset` on every decoder and re-enters the detection phase.
    """

    # ── identity ──────────────────────────────────────────────────────

    @property
    @abstractmethod
    def name(self) -> str:
        """Short identifier shown in logs (e.g. ``'N2'``, ``'BACnet-MSTP'``)."""

    @property
    @abstractmethod
    def priority(self) -> int:
        """Processing order during detection -- lower values run first.

        Protocols with an unambiguous preamble should use a low number so
        they can claim valid traffic quickly.
        """

    @property
    @abstractmethod
    def default_baud_rates(self) -> list[int]:
        """Baud rates this protocol commonly uses, in priority order."""

    # ── packet extraction / decode ────────────────────────────────────

    @abstractmethod
    def extract_packets(
        self, buffer: bytearray,
    ) -> tuple[list[bytearray], bytearray]:
        """Scan *buffer* for complete frames.

        Returns ``(packets, remaining)`` where *remaining* holds bytes
        that could not yet form a complete frame (kept for the next
        call).
        """

    @abstractmethod
    def decode(self, packet: bytearray) -> dict[str, Any]:
        """Decode a raw frame into a standardised dict.

        Required keys::

            protocol    -- str   e.g. "N2-BIN", "BACnet-MSTP"
            src         -- int | str
            dst         -- int | str
            cmd         -- str
            point_type  -- str
            point_index -- int | str
            value       -- str
            raw_hex     -- str
            raw_ascii   -- str
        """

    # ── optional hooks ────────────────────────────────────────────────

    def reset(self) -> None:
        """Clear internal state (called on baud-rate switch)."""

    # ── convenience helpers available to all subclasses ───────────────

    @staticmethod
    def _to_hex(data: bytes | bytearray) -> str:
        return " ".join(f"{b:02X}" for b in data)

    @staticmethod
    def _to_ascii(data: bytes | bytearray) -> str:
        return (
            data.decode("ascii", errors="replace")
            .replace("\r", "\\r")
            .strip()
        )

    @staticmethod
    def _unknown(raw_ascii: str = "", reason: str = "") -> dict[str, Any]:
        return {
            "protocol": "UNKNOWN",
            "src": "?",
            "dst": "?",
            "cmd": f"UNDECODABLE ({reason})" if reason else "UNDECODABLE",
            "point_type": "??",
            "point_index": "\u2014",
            "value": "\u2014",
            "raw_hex": "",
            "raw_ascii": raw_ascii,
        }
