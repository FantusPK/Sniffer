# CLAUDE.md — RS-485 Bus Sniffer Project Context

This file gives you persistent context for the Sniffer project. Read it at the
start of every session. It covers architecture, current state, past decisions,
and working preferences.

---

## Project Overview

A passive RS-485 bus sniffer with a Tkinter GUI. Captures raw serial data,
decodes BACnet MS/TP and N2/N2 Open protocols, and logs packets to screen and
CSV. Targets Windows, distributed as a single `Sniffer.exe` via PyInstaller.

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
    │   └── exporter.py              # CSV export
    ├── gui/
    │   ├── main_window.py           # Assembles all panels inside root Tk window
    │   ├── config_panel.py          # COM port, device address, log directory
    │   ├── controls.py              # Start / Stop / Export CSV / Clear Log buttons
    │   ├── stats_bar.py             # Live packet counts, protocol, baud, status
    │   ├── log_view.py              # Tabbed log: All Devices + Target Device
    │   └── theme.py                 # Dark theme colours, fonts, ttk styles
    └── protocols/
        ├── __init__.py              # Decoder registry (@register decorator)
        ├── base.py                  # Abstract ProtocolDecoder base class
        ├── bacnet_mstp.py           # BACnet MS/TP decoder
        └── n2.py                    # N2 Binary + N2 Open dual-mode decoder
```

---

## Architecture

### Engine (`core/engine.py`)

- **Detection phase**: all registered decoders run in parallel on the same raw
  bytes, each with its own buffer.
- **Lock phase**: first decoder to produce `BAUD_LOCK_THRESHOLD` (3) consecutive
  valid packets wins. All other buffers are discarded.
- **Auto-baud**: rotates through merged baud rate list from all decoders.
  Default timeout is `BAUD_TIMEOUT = 2.0` seconds of no valid traffic before
  trying the next rate.
- Callbacks (`EngineCallbacks`) fire from the sniff thread; the app layer
  marshals them to the main thread via `root.after(0, ...)`.

### App layer (`app.py` — `SnifferApp`)

- Owns all `tk.StringVar` / `tk.IntVar` state.
- Creates `SnifferEngine` and `MainWindow`, wires them together.
- Handles packet display formatting and target-device filtering.
- Target filtering: packets where `src` or `dst` matches `target_address` also
  appear in the Target Device log tab.

### GUI (`gui/`)

- `MainWindow` is a pure layout class — no state, no logic. Everything is
  injected via constructor args.
- `ConfigPanel` — COM port combobox + refresh button, device address entry,
  log directory picker.
- `StatsBar` — reads directly from the app's `tk.*Var` objects.
- `LogView` — two `ScrolledText` panes in a `ttk.Notebook`.

### Protocol decoders (`protocols/`)

- Subclass `ProtocolDecoder`, decorate with `@register`.
- Must implement: `name`, `priority`, `default_baud_rates`,
  `extract_packets(buffer)`, `decode(packet)`.
- `BACnetMSTPDecoder` — priority 10, baud rates [19200, 38400, 76800, 57600,
  115200]. Validates CRC-8 header. Decodes NPDU/APDU down to service level.
- `N2Decoder` — priority 20, baud rate [9600]. Handles binary N2 and N2 Open
  ASCII in a single extraction pass.

---

## Recent Changes (as of last session)

### 1. Manual protocol selector dropdown
- Replaced auto-detection-only flow with a manual protocol selector in
  `ConfigPanel`. User can pick BACnet MS/TP, N2, or leave it blank.
- BACnet MS/TP is the **silent default** when no protocol is selected.
- Baud rates shown in the UI are filtered to match the selected protocol.
- `selected_protocol_var` (a `tk.StringVar`) is threaded through as a **distinct
  parameter** from the stats bar `protocol_var`. These are different variables —
  don't conflate them.

### 2. Extended baud rate rotation timeout
- When valid traffic is detected, the baud rotation timeout is extended by
  5 seconds (effectively ~7 s window after the last good packet).

### 3. `build.bat` updates
- Kills any running `Sniffer.exe` before the clean/build phase
  (`taskkill /f /im Sniffer.exe`).
- Auto-launches the new `dist\Sniffer.exe` on successful build.

### Known bug fixed
- Duplicate keyword argument in `MainWindow.__init__` — `selected_protocol_var`
  was being passed twice (once as `protocol_var`, once correctly). Fixed by
  keeping them as distinct parameters.

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
