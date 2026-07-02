# CLAUDE.md — RS-485 Bus Sniffer Project Context

This file gives you persistent context for the Sniffer project. Read it at the
start of every session. It covers architecture, current state, past decisions,
and working preferences.

---

## Project Overview

A passive bus sniffer with a Tkinter GUI. Captures raw serial data or live
network traffic, decodes BACnet MS/TP, BACnet/IP, N2/N2 Open, and Carrier CCN protocols,
and logs packets to screen and CSV. Also includes an active BACnet client that
can query a JACE for its full point list. Targets Windows, distributed as a
single `Sniffer.exe` via PyInstaller. Current version: **1.1.0**.

---

## Repository Layout

```
C:\Sniffer\
├── build.bat                        # Build script (see notes below)
├── Sniffer.spec                     # PyInstaller spec
├── pyproject.toml
└── src/sniffer/
    ├── __init__.py
    ├── __main__.py                  # Entry point: calls app.main()
    ├── app.py                       # Top-level app, wires engine → GUI
    ├── core/
    │   ├── engine.py                # Serial sniffing engine, auto-baud, protocol lock
    │   ├── exporter.py              # CSV export
    │   ├── bacnet_client.py         # Active BACnet/IP client: Who-Is → I-Am → point walk
    │   ├── npcap_source.py          # Promiscuous BACnet/IP capture via Npcap/Scapy
    │   ├── udp_source.py            # Simpler UDP adapter (non-promiscuous)
    │   └── obix_server.py           # Embedded oBIX HTTP bridge for Niagara integration
    ├── gui/
    │   ├── main_window.py           # Assembles all panels inside root Tk window
    │   ├── config_panel.py          # Source type, COM/network config, oBIX bridge toggle
    │   ├── controls.py              # Start/Stop/Export/Clear + Query Device/Rebuild
    │   ├── stats_bar.py             # Live packet counts, protocol, baud, status
    │   ├── log_view.py              # Tabbed log: All Devices, Target Device, Device Presence
    │   └── theme.py                 # Dark theme colours, fonts, ttk styles
    ├── protocols/
    │   ├── __init__.py              # Decoder registry (@register decorator)
    │   ├── base.py                  # Abstract ProtocolDecoder base class
    │   ├── bacnet_mstp.py           # BACnet MS/TP decoder
    │   ├── bacnet_ip.py             # BACnet/IP (UDP) decoder
    │   ├── n2.py                    # N2 Binary + N2 Open dual-mode decoder
    │   └── ccn.py                   # Carrier Comfort Network (framing/CRC lock)
    └── sim/                         # Traffic simulators (dev/test use)
        ├── serial_sim.py
        ├── bacnet_frames.py
        ├── n2_frames.py
        └── traffic.py
```

---

## Architecture

### Engine (`core/engine.py`)

- **Detection phase**: all registered decoders run in parallel on the same raw
  bytes, each with its own buffer.
- **Lock phase**: first decoder to produce `BAUD_LOCK_THRESHOLD` (3) consecutive
  valid packets wins. All other buffers are discarded.
- **Auto-baud**: rotates through merged baud rate list from all decoders.
  Default timeout is `BAUD_TIMEOUT = 2.0` seconds (extended to ~7 s when valid
  traffic is seen) before trying the next rate.
- **Network sources**: when a `NpcapSource` or `UDPSource` is active,
  `skip_baud_rotation = True` — baud cycling is bypassed entirely.
- Callbacks (`EngineCallbacks`) fire from the sniff thread; the app layer
  marshals them to the main thread via `root.after(0, ...)`.

### App layer (`app.py` — `SnifferApp`)

- Owns all `tk.StringVar` / `tk.IntVar` state.
- Creates `SnifferEngine` and `MainWindow`, wires them together.
- Handles packet display formatting and target-device filtering.
- Target filtering: packets where `src` or `dst` matches `target_address` also
  appear in the Target Device log tab.
- Maintains a **device registry** (address → metadata) updated live from the
  sniff thread; cleared on log clear. Feeds the Device Presence tab and the
  oBIX bridge.

### Network capture (`core/npcap_source.py`, `core/udp_source.py`)

- `NpcapSource`: promiscuous capture via Npcap + Scapy. Prepends an 8-byte IP
  envelope (src IP, dst IP, UDP port) so decoded packets carry real addresses.
- `UDPSource`: simpler non-promiscuous UDP socket adapter; useful when Npcap is
  not installed.
- Both satisfy the same source interface as the serial port.

### Active BACnet client (`core/bacnet_client.py` — `BACnetClient`)

- Sends Who-Is → receives I-Am → walks Object-List → fetches Object-Name +
  Present-Value per point. Runs independently of passive capture.
- Triggered by the **QUERY DEVICE** button (single JACE query) or **REBUILD**
  (headless re-query used from build.bat).
- Results appear in the Device Presence tab and are exported to CSV.

### oBIX bridge (`core/obix_server.py` — `ObixBridgeServer`)

- Embedded HTTP server that publishes discovered bus devices at
  `/obix/BusSniffer/` in oBIX XML format.
- Enable via checkbox + port entry in the config panel; status label shows
  running/stopped. A Niagara AX/N4 oBIX Client connector can point at it to
  auto-import devices.
- Device registry is updated live and cleared on log clear.

### GUI (`gui/`)

- `MainWindow` is a pure layout class — no state, no logic. Everything is
  injected via constructor args.
- `ConfigPanel` — source type selector (Serial / Network); COM port or network
  interface picker; device address entry; log directory; oBIX bridge
  checkbox + port; JACE IP field; Who-Is-on-connect checkbox.
- `Controls` — Start / Stop / Export CSV / Clear Log + **Query Device** /
  **Rebuild** buttons.
- `StatsBar` — reads directly from the app's `tk.*Var` objects.
- `LogView` — three `ScrolledText` / treeview panes in a `ttk.Notebook`:
  **All Devices**, **Target Device**, **Device Presence**.

### Device Presence tab

- Tracks each device address seen on the bus. Columns: Address, TX (packets
  sent by device), RX (polls sent *to* device by JACE), Health.
- Health states: **Active** (normal), **POLLED · NO RESPONSE** (orange — RX
  seen but no TX back), **Active · not in roster** (yellow — ghost device),
  **Not polled** (grey).
- **Import Roster** button loads an oBIX manifest and sets the `in_roster` flag
  so unknown addresses are highlighted on arrival.

### Protocol decoders (`protocols/`)

- Subclass `ProtocolDecoder`, decorate with `@register`.
- Must implement: `name`, `priority`, `default_baud_rates`,
  `extract_packets(buffer)`, `decode(packet)`.
- `BACnetMSTPDecoder` — priority 10, baud rates [19200, 38400, 76800, 57600,
  115200]. Validates CRC-8 header. Decodes NPDU/APDU down to service level.
  Includes corrected Who-Is range parse and Who-Has object-name/identifier
  decode (JCI UTF-16-BE CharacterString supported).
- `BACnetIPDecoder` — priority 5, UDP port 47808. Decodes BACnet/IP BVLC +
  NPDU/APDU; real IP addresses carried in the 8-byte envelope from NpcapSource.
- `N2Decoder` — priority 20, baud rate [9600]. Handles binary N2 and N2 Open
  ASCII in a single extraction pass.
- `CCNDecoder` — priority 30 (runs last), baud rates [9600, 19200, 38400].
  Carrier Comfort Network. **Framing / CRC-lock pass only** — payload decode
  is deferred. CCN has no sync/preamble byte, so frames are located by a
  sliding CRC-16/CCITT search over an address-plausibility gate: dst/src as
  (bus, element) pairs (0–239), func byte, then a 2-byte CRC trailer. Two CRC
  inits (CCITT-FALSE 0xFFFF, XMODEM 0x0000) × both byte orders are tried
  during detection, then the matching variant is **latched** for the rest of
  the lock; `reset()` clears it. A low-entropy filter rejects baud-rate noise.
  Built from the *public* CCN structure — CRC variant / byte order want
  confirmation against a real capture.

---

## Change History (condensed)

### CCN protocol support (framing pass) — 2026-07-02
- **CCNDecoder** (`protocols/ccn.py`): new decoder for Carrier Comfort
  Network. First pass is **framing + CRC lock only**; payload/function-code
  decode deferred. Sliding CRC-16/CCITT framer (no sync byte) over a
  (bus, element) address-plausibility gate; auto-detects then latches the CRC
  init/byte-order variant. Priority 30 so it never steals BACnet/N2 traffic.
- **GUI**: `"CCN"` added to `PROTOCOL_OPTIONS_SERIAL` in `config_panel.py`.
- Built from the *public* CCN structure — needs tuning (CRC variant, byte
  order, then payload decode) against a real bus capture.

### v1.1.0 — BACnet/IP network capture + active JACE query
- **NpcapSource / UDPSource**: promiscuous and non-promiscuous BACnet/IP
  capture. Engine skips baud rotation for network sources.
- **BACnetIPDecoder**: new decoder for UDP BACnet/IP; reads IP envelope
  prepended by NpcapSource for real src/dst addresses.
- **BACnetClient**: active unicast client — Who-Is → I-Am → Object-List →
  Object-Name + Present-Value per point. Triggered by QUERY DEVICE button.
- **Device Presence tab**: tracks TX/RX per device, three health states,
  Import Roster wires oBIX manifest into `in_roster` flag.
- **GUI**: Network source type with interface picker, UDP port, Who-Is on
  connect, JACE IP field; QUERY DEVICE + REBUILD buttons in controls.
- **build.bat**: REBUILD flow (headless, no pause); offline-safe dep install;
  kills running Sniffer.exe before clean; auto-launches on success.
- **bacnet_mstp**: fix hop-count byte skipped in NPDU routing parse.

### Who-Is / Who-Has fixes
- Who-Is: LVT was read as a byte offset instead of a length mask → garbage
  instance numbers. Fixed.
- Who-Has: added `_decode_who_has()` — extracts object-name (ctx tag 3) or
  object-identifier (ctx tag 2); handles JCI UTF-16-BE CharacterString.

### oBIX HTTP bridge
- `ObixBridgeServer` embedded in the app; publishes `/obix/BusSniffer/` so a
  Niagara AX/N4 oBIX Client connector can import devices automatically.
- Toggled via checkbox + port entry in config panel. Registry updated live,
  cleared on log clear.

### Earlier changes (now stable)
- Manual protocol selector dropdown (BACnet MS/TP, N2, or blank → default
  MS/TP). `selected_protocol_var` is distinct from the stats bar
  `protocol_var` — do not conflate them.
- Baud rate rotation timeout extended to ~7 s when valid traffic is seen.
- `selected_protocol_var` duplicate-kwarg bug in `MainWindow.__init__` fixed.

---

## Working Preferences

- **Minimal, targeted changes.** Only touch files that actually need changing.
  Don't refactor or reorganise things that aren't broken.
- **Clarify before implementing.** If the desired behaviour is ambiguous, ask
  one focused question before writing any code.
- **Read the full relevant file(s) before making changes.** Understand the
  surrounding context first.
- **Coordinate across files when needed**, but keep each change purposeful and
  explain which files are being touched and why.
- Dan is comfortable reading code but prefers not to write it. Explanations of
  *what* changed and *why* are welcome; don't assume he'll infer it from a diff.

---

## Build & Run

**Debug run (no build needed):**
```powershell
cd C:\Sniffer
python -m sniffer   # requires: pip install -e ".[build]"
```

**Build exe:**
```bat
build.bat
```
Output: `dist\Sniffer.exe`

**Dependencies:**
- Python 3.10+
- `pyserial >= 3.5`
- `scapy >= 2.5` (BACnet/IP network capture; requires Npcap on Windows)
- `pyinstaller >= 6.0` (build only)

---

## Decoded Packet Dict Shape

Every decoder's `decode()` must return a dict with these keys:

| Key           | Type       | Example                  |
|---------------|------------|--------------------------|
| `protocol`    | str        | `"BACnet-MSTP"`, `"N2-BIN"`, `"UNKNOWN"` |
| `src`         | int \| str | `12`, `"JACE"`           |
| `dst`         | int \| str | `255`                    |
| `cmd`         | str        | `"Read-Property"`        |
| `point_type`  | str        | `"AI"`, `"Analog-Input"` |
| `point_index` | int \| str | `3`, `"—"`               |
| `value`       | str        | `"72.50"`, `"—"`         |
| `raw_hex`     | str        | `"55 FF 06 FF 0C ..."`   |
| `raw_ascii`   | str        | `""`                     |

Packets with `protocol == "UNKNOWN"` are displayed differently in the log
(raw ASCII only, no src/dst/cmd columns).

---

## Adding a New Protocol

1. Create `src/sniffer/protocols/my_proto.py`
2. Subclass `ProtocolDecoder`, implement all abstract methods
3. Decorate the class with `@register`
4. Add `from . import my_proto as _mp` at the bottom of `protocols/__init__.py`
