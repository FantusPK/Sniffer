"""CSV export for captured packet logs."""

from __future__ import annotations

import csv
import os
from datetime import datetime

HEADERS = [
    "Timestamp",
    "Protocol",
    "Source",
    "Destination",
    "Command",
    "Point Type",
    "Point Index",
    "Value",
    "Raw Hex",
    "Raw ASCII",
]


def export_csv(
    save_dir: str,
    all_rows: list[list],
    target_rows: list[list],
    target_address: int | str,
) -> tuple[str, str]:
    """Write two CSV files (all devices + target-filtered).

    Returns ``(all_path, target_path)``.
    """
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    all_path = os.path.join(save_dir, f"sniffer_all_{ts}.csv")
    _write(all_path, all_rows)

    target_path = os.path.join(
        save_dir, f"sniffer_target_{target_address}_{ts}.csv",
    )
    _write(target_path, target_rows)

    return all_path, target_path


PRESENCE_HEADERS = [
    "Status",
    "Addr",
    "Addr Hex",
    "Name",
    "Protocol",
    "Last Seen",
    "Packets",
]


def export_presence_csv(save_dir: str, rows: list[list]) -> str:
    """Write a device-presence snapshot CSV.  Returns the file path."""
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(save_dir, f"sniffer_presence_{ts}.csv")
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(PRESENCE_HEADERS)
        writer.writerows(rows)
    return path


def _write(path: str, rows: list[list]) -> None:
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(HEADERS)
        writer.writerows(rows)
