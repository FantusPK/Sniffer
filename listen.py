"""listen.py — live continuous raw listener for RS-485 bus debugging.

Opens the port at ONE baud rate and prints any bytes the instant they arrive,
with a timestamp and hex/ascii dump. Runs until Ctrl+C. Unlike raw_diag.py's
fixed windows, this gives real-time feedback so you can swap +/- , reseat a
wire, or power-cycle a controller and immediately see the line come alive.

Passive — never transmits. RTS/DTR are held low (same as the app).

Usage:
    python listen.py                 # COM3 @ 9600
    python listen.py COM3 38400      # pick baud
"""

from __future__ import annotations

import sys
import time

import serial


def dump(data: bytes) -> str:
    hx = " ".join(f"{b:02X}" for b in data)
    asc = "".join(chr(b) if 32 <= b < 127 else "." for b in data)
    return f"{hx:<48}  {asc}"


def main() -> None:
    port = sys.argv[1] if len(sys.argv) > 1 else "COM3"
    baud = int(sys.argv[2]) if len(sys.argv) > 2 else 9600

    try:
        ser = serial.Serial(
            port=port,
            baudrate=baud,
            bytesize=serial.EIGHTBITS,
            parity=serial.PARITY_NONE,
            stopbits=serial.STOPBITS_ONE,
            timeout=0.1,
            rtscts=False,
            dsrdtr=False,
        )
    except serial.SerialException as exc:
        print(f"Cannot open {port}: {exc}")
        return

    ser.rts = False
    ser.dtr = False
    ser.reset_input_buffer()

    print(f"Listening on {port} @ {baud} 8N1 (RTS=False DTR=False) - Ctrl+C to stop")
    print("Swap +/-, reseat wires, or power-cycle the bus and watch for bytes.")
    print("-" * 72)

    total = 0
    last_tick = time.monotonic()
    try:
        while True:
            n = ser.in_waiting
            if n:
                chunk = ser.read(n)
                total += len(chunk)
                ts = time.strftime("%H:%M:%S")
                # split into 16-byte rows for readability
                for i in range(0, len(chunk), 16):
                    row = chunk[i:i + 16]
                    prefix = ts if i == 0 else "        "
                    print(f"{prefix}  {dump(row)}")
                last_tick = time.monotonic()
            else:
                time.sleep(0.02)
                # heartbeat every 5 s of silence so you know it's still running
                if time.monotonic() - last_tick > 5.0:
                    print(f"        ... {total} bytes so far (line quiet)")
                    last_tick = time.monotonic()
    except KeyboardInterrupt:
        print("-" * 72)
        print(f"Stopped. {total} bytes total.")
    finally:
        ser.close()


if __name__ == "__main__":
    main()
