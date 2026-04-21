"""Simulated serial port.

Implements the subset of the ``serial.Serial`` interface that
:class:`~sniffer.core.engine.SnifferEngine` actually uses:

    - ``in_waiting``  (property)
    - ``read(n)``     (method)
    - ``baudrate``    (settable property)
    - ``is_open``     (property)
    - ``rts``         (settable, ignored)
    - ``dtr``         (settable, ignored)
    - ``reset_input_buffer()``
    - ``close()``

A background thread calls the supplied ``frame_generator`` coroutine at
the requested packet-per-second rate and stuffs the produced bytes into
an internal ``bytearray`` buffer.  The engine's read loop drains that
buffer through ``in_waiting`` / ``read()``.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Iterator
from typing import Callable

# Type alias: a zero-arg callable that returns an iterator of raw frames
FrameGen = Callable[[], Iterator[bytes]]


class SimulatedSerial:
    """Drop-in replacement for ``serial.Serial`` used during simulation."""

    def __init__(
        self,
        frame_gen: FrameGen,
        *,
        packets_per_second: float = 5.0,
        initial_baudrate: int = 19200,
    ) -> None:
        self._frame_gen = frame_gen
        self._pps = packets_per_second
        self._baudrate = initial_baudrate
        self._is_open = True

        self._buf: bytearray = bytearray()
        self._lock = threading.Lock()

        self._thread = threading.Thread(
            target=self._produce, daemon=True,
        )
        self._thread.start()

    # ── serial.Serial interface ───────────────────────────────────────

    @property
    def in_waiting(self) -> int:
        with self._lock:
            return len(self._buf)

    def read(self, size: int = 1) -> bytes:
        with self._lock:
            chunk = bytes(self._buf[:size])
            del self._buf[:size]
            return chunk

    @property
    def baudrate(self) -> int:
        return self._baudrate

    @baudrate.setter
    def baudrate(self, value: int) -> None:
        self._baudrate = value  # accepted, no-op

    @property
    def is_open(self) -> bool:
        return self._is_open

    # rts / dtr are written by the engine; just accept silently
    @property
    def rts(self) -> bool:
        return False

    @rts.setter
    def rts(self, value: bool) -> None:
        pass

    @property
    def dtr(self) -> bool:
        return False

    @dtr.setter
    def dtr(self, value: bool) -> None:
        pass

    def reset_input_buffer(self) -> None:
        with self._lock:
            self._buf.clear()

    def close(self) -> None:
        self._is_open = False

    # ── producer thread ───────────────────────────────────────────────

    def _produce(self) -> None:
        interval = 1.0 / self._pps
        gen = self._frame_gen()
        while self._is_open:
            try:
                frame = next(gen)
            except StopIteration:
                # generator exhausted -- restart it
                gen = self._frame_gen()
                continue

            with self._lock:
                self._buf.extend(frame)

            time.sleep(interval)
