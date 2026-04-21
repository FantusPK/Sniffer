"""Serial sniffing engine with auto-baud and protocol locking.

Detection strategy
------------------
During the **detection phase** every registered decoder receives a copy
of the raw serial bytes simultaneously (each into its own buffer).
The first decoder to produce ``LOCK_THRESHOLD`` consecutive valid
packets wins -- the engine enters the **locked phase** where *only*
the winning decoder receives data and all other buffers are discarded.

This works because N2 and BACnet MS/TP are mutually exclusive on the
same RS-485 trunk.  Once we know the protocol, there is no reason to
keep the other decoder running.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable

import serial

from sniffer.protocols.base import ProtocolDecoder


@dataclass
class EngineCallbacks:
    """Callbacks the engine invokes (always from the sniff thread)."""

    on_packet: Callable[[dict[str, Any], bytearray], None] | None = None
    on_status: Callable[[str], None] | None = None
    on_baud: Callable[[str], None] | None = None
    on_protocol: Callable[[str], None] | None = None
    on_error: Callable[[str], None] | None = None
    on_log: Callable[[str], None] | None = None


class SnifferEngine:
    """Protocol-agnostic serial sniffer with auto-baud detection."""

    BAUD_LOCK_THRESHOLD = 3
    BAUD_TIMEOUT = 2.0  # seconds before trying next baud rate

    def __init__(self, decoders: list[ProtocolDecoder]) -> None:
        self._decoders = sorted(decoders, key=lambda d: d.priority)
        self._buffers: dict[str, bytearray] = {
            d.name: bytearray() for d in self._decoders
        }

        self._serial: serial.Serial | None = None
        self._running = False
        self._thread: threading.Thread | None = None
        self._cb = EngineCallbacks()

        # auto-baud state
        self._baud_rates = self._merge_baud_rates()
        self._baud_index = 0
        self._baud_confidence = 0
        self._baud_locked = False

        # protocol lock state
        self._proto_locked = False
        self._locked_decoder: ProtocolDecoder | None = None
        self._decoder_hits: dict[str, int] = {d.name: 0 for d in self._decoders}

        # display label tracking
        self._proto_counts: dict[str, int] = {}

    # ── public API ────────────────────────────────────────────────────

    @property
    def running(self) -> bool:
        return self._running

    @property
    def current_baud(self) -> int:
        return self._baud_rates[self._baud_index] if self._baud_rates else 9600

    def start(
        self,
        port: str,
        callbacks: EngineCallbacks,
        *,
        serial_override: object | None = None,
    ) -> None:
        """Open *port* and begin sniffing in a background thread.

        Parameters
        ----------
        port:
            Serial port name (e.g. ``"COM3"``).  Ignored when
            *serial_override* is supplied.
        callbacks:
            Engine event callbacks.
        serial_override:
            Optional pre-built object that implements the
            ``serial.Serial`` interface (``in_waiting``, ``read``,
            ``baudrate``, ``is_open``, ``rts``, ``dtr``,
            ``reset_input_buffer``, ``close``).  When provided the
            engine skips opening a real COM port -- used by the
            simulator.
        """
        if self._running:
            return

        self._cb = callbacks
        self._running = True
        self._reset_detection()

        if serial_override is not None:
            self._serial = serial_override  # type: ignore[assignment]
        else:
            try:
                self._serial = serial.Serial(
                    port=port,
                    baudrate=self._baud_rates[0],
                    bytesize=serial.EIGHTBITS,
                    parity=serial.PARITY_NONE,
                    stopbits=serial.STOPBITS_ONE,
                    timeout=1,
                    rtscts=False,
                    dsrdtr=False,
                )
                self._serial.rts = False
                self._serial.dtr = False
            except Exception as exc:
                self._running = False
                self._emit_error(f"Failed to open port: {exc}")
                raise

        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

        self._emit_baud(str(self._baud_rates[0]))
        rates_str = ", ".join(str(b) for b in self._baud_rates)

        if serial_override is not None:
            self._emit_log("Sniffer started · SIMULATION MODE · RTS/DTR suppressed")
        else:
            self._emit_log(
                f"Sniffer started on {port} · Auto-baud ON · RTS/DTR suppressed",
            )
        self._emit_log(f"Trying baud rates: {rates_str} · 2 s timeout per rate")

    def stop(self) -> None:
        self._running = False
        if self._serial and self._serial.is_open:
            self._serial.close()
        self._emit_status("STOPPED")

    # ── main loop ─────────────────────────────────────────────────────

    def _loop(self) -> None:
        last_traffic = time.time()

        while self._running:
            try:
                now = time.time()

                # auto-baud rotation
                if (
                    not self._baud_locked
                    and now - last_traffic > self.BAUD_TIMEOUT
                ):
                    self._rotate_baud()
                    last_traffic = now

                if not self._serial or not self._serial.in_waiting:
                    time.sleep(0.01)
                    continue

                data = self._serial.read(self._serial.in_waiting)
                got_valid = self._process_data(data)

                if got_valid:
                    last_traffic = now
                    self._advance_baud_confidence()
                elif not self._baud_locked and self._baud_confidence > 0:
                    self._baud_confidence = max(0, self._baud_confidence - 1)

            except Exception as exc:
                if self._running:
                    self._emit_error(str(exc))
                break

    # ── data processing ───────────────────────────────────────────────

    def _process_data(self, data: bytes) -> bool:
        """Feed *data* to active decoder(s).  Returns True if any valid
        (non-UNKNOWN) packet was decoded."""
        got_valid = False

        if self._proto_locked and self._locked_decoder is not None:
            # --- locked phase: single decoder only ---
            got_valid = self._feed_decoder(self._locked_decoder, data)
        else:
            # --- detection phase: all decoders in parallel ---
            for decoder in self._decoders:
                if self._feed_decoder(decoder, data):
                    got_valid = True

        return got_valid

    def _feed_decoder(
        self, decoder: ProtocolDecoder, data: bytes,
    ) -> bool:
        """Feed *data* into *decoder*'s buffer, extract & decode."""
        buf = self._buffers[decoder.name]
        buf.extend(data)
        packets, self._buffers[decoder.name] = decoder.extract_packets(buf)

        got_valid = False
        for pkt in packets:
            decoded = decoder.decode(pkt)
            proto = decoded.get("protocol", "UNKNOWN")

            if proto != "UNKNOWN":
                got_valid = True
                self._proto_counts[proto] = (
                    self._proto_counts.get(proto, 0) + 1
                )
                self._register_hit(decoder)

            if self._cb.on_packet:
                self._cb.on_packet(decoded, pkt)

        if got_valid:
            self._update_protocol_label()

        return got_valid

    # ── protocol locking ──────────────────────────────────────────────

    def _register_hit(self, decoder: ProtocolDecoder) -> None:
        """Track consecutive valid packets per decoder during detection."""
        if self._proto_locked:
            return

        # A valid packet from *this* decoder increments its count and
        # resets every other decoder's streak.
        for name in self._decoder_hits:
            if name == decoder.name:
                self._decoder_hits[name] += 1
            else:
                self._decoder_hits[name] = 0

        if self._decoder_hits[decoder.name] >= self.BAUD_LOCK_THRESHOLD:
            self._proto_locked = True
            self._locked_decoder = decoder

            # discard other decoders' buffers
            for name in list(self._buffers):
                if name != decoder.name:
                    self._buffers[name].clear()

            self._emit_log(
                f"✓ Protocol locked: {decoder.name} "
                f"({self._decoder_hits[decoder.name]} consecutive valid packets)",
            )
            self._emit_protocol(decoder.name)

    # ── auto-baud ─────────────────────────────────────────────────────

    def _merge_baud_rates(self) -> list[int]:
        """Merge baud rates from all decoders, preserving priority order."""
        seen: set[int] = set()
        rates: list[int] = []
        for d in self._decoders:
            for rate in d.default_baud_rates:
                if rate not in seen:
                    seen.add(rate)
                    rates.append(rate)
        return rates or [9600]

    def _rotate_baud(self) -> None:
        self._baud_confidence = 0
        self._baud_index = (self._baud_index + 1) % len(self._baud_rates)
        new_baud = self._baud_rates[self._baud_index]

        try:
            if self._serial:
                self._serial.baudrate = new_baud
                self._serial.reset_input_buffer()
        except Exception:
            pass

        # full reset: buffers, decoder state, detection counters
        self._reset_buffers()
        self._proto_counts.clear()
        self._proto_locked = False
        self._locked_decoder = None
        for name in self._decoder_hits:
            self._decoder_hits[name] = 0

        self._emit_baud(str(new_baud))
        self._emit_log(f"No confident lock · trying {new_baud} baud")

    def _advance_baud_confidence(self) -> None:
        if self._baud_locked:
            return
        self._baud_confidence += 1
        baud = self._baud_rates[self._baud_index]

        self._emit_baud(
            f"{baud} ({self._baud_confidence}/{self.BAUD_LOCK_THRESHOLD})",
        )

        if self._baud_confidence >= self.BAUD_LOCK_THRESHOLD:
            self._baud_locked = True
            self._emit_baud(f"{baud} ✓")
            self._emit_log(
                f"✓ Baud rate locked at {baud} "
                f"({self._baud_confidence} consecutive valid packets)",
            )

    # ── reset helpers ─────────────────────────────────────────────────

    def _reset_detection(self) -> None:
        self._baud_index = 0
        self._baud_confidence = 0
        self._baud_locked = False
        self._proto_locked = False
        self._locked_decoder = None
        self._proto_counts.clear()
        for name in self._decoder_hits:
            self._decoder_hits[name] = 0
        self._reset_buffers()

    def _reset_buffers(self) -> None:
        for name in self._buffers:
            self._buffers[name].clear()
        for d in self._decoders:
            d.reset()

    # ── protocol label ────────────────────────────────────────────────

    def _update_protocol_label(self) -> None:
        if not self._proto_counts:
            return
        dominant = max(self._proto_counts, key=self._proto_counts.get)
        others = [
            f"{k}({v})"
            for k, v in self._proto_counts.items()
            if k != dominant and v > 0
        ]
        label = dominant
        if others:
            label += " +" + "+".join(others)
        self._emit_protocol(label)

    # ── callback helpers ──────────────────────────────────────────────

    def _emit_status(self, msg: str) -> None:
        if self._cb.on_status:
            self._cb.on_status(msg)

    def _emit_baud(self, msg: str) -> None:
        if self._cb.on_baud:
            self._cb.on_baud(msg)

    def _emit_protocol(self, msg: str) -> None:
        if self._cb.on_protocol:
            self._cb.on_protocol(msg)

    def _emit_error(self, msg: str) -> None:
        if self._cb.on_error:
            self._cb.on_error(msg)

    def _emit_log(self, msg: str) -> None:
        if self._cb.on_log:
            self._cb.on_log(msg)
