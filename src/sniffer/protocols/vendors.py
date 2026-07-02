"""BACnet vendor ID lookup table (HVAC-relevant subset)."""

from __future__ import annotations

VENDORS: dict[int, str] = {
    0:   "ASHRAE",
    5:   "Johnson Controls",
    7:   "Honeywell",
    8:   "Siemens",
    10:  "Trane",
    11:  "Carrier",
    12:  "Andover Controls",
    14:  "Echelon",
    24:  "Automated Logic",
    25:  "TAC (Schneider)",
    30:  "Sauter",
    33:  "Invensys",
    36:  "Reliable Controls",
    42:  "LONG Building Technologies",
    52:  "Alerton",
    63:  "Alerton",
    73:  "Distech Controls",
    74:  "KMC Controls",
    86:  "Daikin",
    98:  "Delta Controls",
    116: "WattStopper",
    135: "Acuity Brands",
    148: "Computrols",
    171: "KMC Controls",
    195: "Crestron",
    260: "Schneider Electric",
    315: "Daikin Applied",
    387: "Mitsubishi",
    419: "Lennox",
    433: "York (Johnson Controls)",
}


def vendor_name(vendor_id: int) -> str:
    """Return the vendor name for *vendor_id*, or ``'Vendor#NNN'`` if unknown."""
    return VENDORS.get(vendor_id, f"Vendor#{vendor_id}")
