"""raw_diag.py — RS-485 physical-layer diagnostic for the Sniffer project.

Bypasses every protocol decoder and answers one question: do ANY bytes ever
reach the UART?  Used to diagnose a silent bus (the "0 bytes so far — nothing
arriving" case).

It sweeps the two things most likely to be misconfigured:
  * baud rate   — the framing clock
  * RTS / DTR   — the transceiver direction/enable lines on USB-RS485 dongles

For each (RTS, DTR) combination it opens the port and listens across a set of
baud rates, reporting the byte count and a short hex sample for each.  Because
this is a *raw* byte count, a wrong baud rate still shows bytes arriving (as
garbage) — so ANY non-zero count means the wiring/direction is fine and only the
baud rate needs finding.  Zero across every combination points at the physical
layer: A/B swap, missing ground, wrong port, or a genuinely idle bus.

Usage:
    python raw_diag.py                 # port COM3, ~3 s per test
    python raw_diag.py COM4            # pick a port
    python raw_diag.py COM3 5          # ~5 s per test

Ctrl+C stops the current test and moves on.
"""

from __future__ import annotations

import sys
import time

import serial
import serial.tools.list_ports as list_ports

# Baud rates worth trying, ordered by how common they are on the buses this
# sniffer targets (BACnet MS/TP, N2, CCN).
BAUD_RATES = [9600, 19200, 38400, 76800, 57600, 115200]

# (RTS, DTR) line states to try.  Different USB-RS485 adapters use these lines
# for driver-enable in different (and sometimes inverted) ways.
LINE_STATES = [
    (False, False),  # what the app currently uses (engine.py)
    (True, False),
    (False, True),
    (True, True),
]


def list_available_ports() -> list[str]:
    ports = list(list_ports.comports())
    if not ports:
        print("No COM ports detected. Is the USB-RS485 adapter plugged in?")
        return []
    print("Available ports:")
    for p in ports:
        print(f"  {p.device:8s} | {p.description} | {p.hwid}")
    print()
    return [p.device for p in ports]


def sample_hex(data: bytes, limit: int = 24) -> str:
    head = data[:limit]
    hx = " ".join(f"{b:02X}" for b in head)
    return hx + (" ..." if len(data) > limit else "")


def listen(port: str, baud: int, rts: bool, dtr: bool, seconds: float) -> int:
    """Open the port with the given settings and return the raw byte count."""
    try:
        ser = serial.Serial(
            port=port,
            baudrate=baud,
            bytesize=serial.EIGHTBITS,
            parity=serial.PARITY_NONE,
            stopbits=serial.STOPBITS_ONE,
            timeout=0.2,
            rtscts=False,
            dsrdtr=False,
        )
    except serial.SerialException as exc:
        print(f"    {baud:>6} baud: CANNOT OPEN ({exc})")
        return -1

    total = bytearray()
    try:
        ser.rts = rts
        ser.dtr = dtr
        ser.reset_input_buffer()
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            n = ser.in_waiting
            if n:
                total += ser.read(n)
            else:
                time.sleep(0.02)
    except KeyboardInterrupt:
        print("    (interrupted)")
    finally:
        ser.close()

    if total:
        print(f"    {baud:>6} baud: {len(total):>5} bytes   {sample_hex(bytes(total))}")
    else:
        print(f"    {baud:>6} baud:     0 bytes")
    return len(total)


def main() -> None:
    port = sys.argv[1] if len(sys.argv) > 1 else "COM3"
    per_test = float(sys.argv[2]) if len(sys.argv) > 2 else 3.0

    print("=" * 68)
    print("RS-485 RAW DIAGNOSTIC")
    print("=" * 68)
    available = list_available_ports()
    if available and port not in available:
        print(f"WARNING: {port} is not in the list above — is it the right port?\n")

    print(f"Port: {port}   |   {per_test:.0f}s per test   |   8N1")
    print("Any non-zero byte count = wiring/direction OK, just find the baud.")
    print("All zeros everywhere    = physical layer (A/B swap, ground, port, idle bus).")
    print("=" * 68)

    grand_total = 0
    best: tuple[int, bool, bool, int] | None = None  # (bytes, rts, dtr, baud)

    for rts, dtr in LINE_STATES:
        print(f"\n--- RTS={rts}  DTR={dtr} ---")
        try:
            for baud in BAUD_RATES:
                count = listen(port, baud, rts, dtr, per_test)
                if count > 0:
                    grand_total += count
                    if best is None or count > best[0]:
                        best = (count, rts, dtr, baud)
        except KeyboardInterrupt:
            print("  (skipped remaining baud rates for this line state)")
            continue

    print("\n" + "=" * 68)
    if grand_total == 0:
        print("RESULT: 0 bytes across every combination.")
        print("The problem is BELOW the software — nothing is reaching the UART.")
        print("Check, in order:")
        print("  1. A/B (D+/D-) swapped — swap the two data wires and retry.")
        print("  2. Signal ground not connected between adapter and bus.")
        print("  3. Wrong COM port, or adapter not actually tapped onto the bus.")
        print("  4. Bus genuinely idle right now (no controller polling).")
        print("  5. Termination/biasing missing on a long run (line floats).")
    else:
        cnt, rts, dtr, baud = best  # type: ignore[misc]
        print(f"RESULT: bytes ARE arriving. Best: {cnt} bytes at "
              f"{baud} baud, RTS={rts} DTR={dtr}.")
        print("Wiring/direction is fine. If the app still shows nothing, the")
        print("decoders aren't locking — focus there, not on the physical layer.")
    print("=" * 68)


if __name__ == "__main__":
    main()
