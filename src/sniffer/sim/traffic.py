"""Top-level traffic generator for the simulator.

Exposes :func:`make_generator` which returns a zero-arg callable
suitable for :class:`~sniffer.sim.serial_sim.SimulatedSerial`.

Supported modes
---------------
``"BACnet-MSTP"``
    Pure BACnet MS/TP traffic between a JACE and three controllers.

``"N2"``
    Pure N2 / N2 Open traffic between a JACE and three controllers.

``"Both"``
    Interleaved BACnet and N2 traffic (round-robin, one frame at a
    time from each stream).
"""

from __future__ import annotations

import itertools
from collections.abc import Iterator
from typing import Callable

from .bacnet_frames import bacnet_traffic
from .n2_frames import n2_traffic

FrameGen = Callable[[], Iterator[bytes]]


def make_generator(protocol: str) -> FrameGen:
    """Return a fresh frame-generator factory for *protocol*.

    Parameters
    ----------
    protocol:
        One of ``"BACnet-MSTP"``, ``"N2"``, or ``"Both"``.

    Returns
    -------
    A zero-arg callable that, when called, returns an iterator of
    raw ``bytes`` objects (one complete frame per item).
    """
    protocol = protocol.strip()

    if protocol == "BACnet-MSTP":
        return bacnet_traffic

    if protocol == "N2":
        return n2_traffic

    if protocol == "Both":
        def _both() -> Iterator[bytes]:
            bac = bacnet_traffic()
            n2 = n2_traffic()
            for frame in _interleave(bac, n2):
                yield frame
        return _both

    raise ValueError(
        f"Unknown simulation protocol {protocol!r}. "
        "Expected 'BACnet-MSTP', 'N2', or 'Both'."
    )


def _interleave(*iters: Iterator[bytes]) -> Iterator[bytes]:
    """Round-robin across iterators; stops only if all are exhausted."""
    nexts = [iter(it) for it in iters]
    while nexts:
        still_alive = []
        for it in nexts:
            try:
                yield next(it)
                still_alive.append(it)
            except StopIteration:
                pass
        nexts = still_alive
