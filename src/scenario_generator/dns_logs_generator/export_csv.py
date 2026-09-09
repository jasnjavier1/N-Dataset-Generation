from __future__ import annotations

import csv
from pathlib import Path
from typing import Iterable

try:
    from .event_factory import CSV_COLUMNS
except ImportError:  # pragma: no cover - script-mode fallback
    from event_factory import CSV_COLUMNS


def write_csv(output_path: Path, events: Iterable[dict[str, str]]) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter[str](handle, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        for event in events:
            writer.writerow(event)
