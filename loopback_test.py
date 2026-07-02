"""loopback_test.py — RS-485 adapter self-test (ACTIVE — transmits bytes).

Proves the adapter's TX and RX paths work end-to-end, isolating an
adapter/driver fault from a bus/wiring fault.  On a 2-wire half-duplex
RS-485 adapter the driver and receiver share the same A/B terminals, so when
we transmit a known pattern the receiver usually hears its own echo.

    Echo received & matches  -> adapter TX+RX both work. The fault is EXTERNAL
                                (bus wiring, A/B, ground, idle/dead bus).
    No echo                  -> inconclusive: some adapters mute RX while
                                driving (RE tied to DE). Combined with the
                                all-zero passive scan, this points at the
                                adapter/driver OR just a non-echoing design.

*** THIS TRANSMITS ON THE BUS. Disconnect the adapter's A/B from any live
    bus first, so test bytes cannot collide with real controllers. ***

Usage:
    python loopback_test.py            # COM3, 9600 baud
    python loopback_test.py COM4 19200
"""

from __future__ import annotations

import sys
import time

import serial

PATTERN = bytes([0x55, 0xAA, 0x01, 0x02, 0x03, 0x04, 0xF0, 0x0F, 0x55, 0xAA])

# The driver-enable line differs by adapter; try each so a non-default wiring
# still gets a chance to transmit.
LINE_STATES = [(False, False), (True, False), (False, True), (True, True)]


def hexs(data: bytes) -> str:
    return " ".join(f"{b:02X}" for b in data) if data else "(none)"


def self_test(port: str, baud: int, rts: bool, dtr: bool) -> bytes:
    try:
        ser = serial.Serial(
            port=port,
            baudrate=baud,
            bytesize=serial.EIGHTBITS,
            parity=serial.PARITY_NONE,
            stopbits=serial.STOPBITS_ONE,
            timeout=0.3,
            rtscts=False,
            dsrdtr=False,
        )
    except serial.SerialException as exc:
        print(f"  RTS={rts} DTR={dtr}: CANNOT OPEN ({exc})")
        return b""

    received = bytearray()
    try:
        ser.rts = rts
        ser.dtr = dtr
        ser.reset_input_buffer()
        ser.reset_output_buffer()
        ser.write(PATTERN)
        ser.flush()  # block until the OS hands the bytes to the UART
        deadline = time.monotonic() + 0.5
        while time.monotonic() < deadline:
            n = ser.in_waiting
            if n:
                received += ser.read(n)
            else:
                time.sleep(0.01)
    finally:
        ser.close()

    rx = bytes(received)
    match = "  <-- MATCHES sent pattern" if rx == PATTERN else ""
    print(f"  RTS={rts} DTR={dtr}: rx {len(rx)} bytes  {hexs(rx)}{match}")
    return rx


def main() -> None:
    port = sys.argv[1] if len(sys.argv) > 1 else "COM3"
    baud = int(sys.argv[2]) if len(sys.argv) > 2 else 9600

    print("=" * 68)
    print("RS-485 ADAPTER SELF-TEST  (ACTIVE — transmits bytes)")
    print("=" * 68)
    print(f"Port: {port}   baud: {baud}   8N1")
    print(f"Sending pattern: {hexs(PATTERN)}")
    print("Disconnect A/B from any LIVE bus before running this.")
    print("-" * 68)

    any_echo = False
    exact = False
    for rts, dtr in LINE_STATES:
        rx = self_test(port, baud, rts, dtr)
        if rx:
            any_echo = True
        if rx == PATTERN:
            exact = True

    print("=" * 68)
    if exact:
        print("RESULT: exact echo — adapter TX+RX paths BOTH work.")
        print("The fault is EXTERNAL to the adapter: bus wiring, A/B, ground,")
        print("or the bus is dead/idle. Adapter and driver are proven good.")
    elif any_echo:
        print("RESULT: partial echo — adapter is transmitting and receiving,")
        print("but bytes came back garbled. Likely a bias/termination/timing")
        print("quirk, not a total failure. Adapter RX path is alive.")
    else:
        print("RESULT: no echo on any line state.")
        print("Either this adapter mutes its receiver while driving (normal for")
        print("some designs — not a fault by itself), OR the TX/RX path has a")
        print("problem. Inconclusive alone; consider a physical loopback: jumper")
        print("the adapter's A and B together and re-run the PASSIVE raw_diag,")
        print("or try a known-good adapter.")
    print("=" * 68)


if __name__ == "__main__":
    main()
