from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


@dataclass(slots=True)
class GeneratorConfig:
    output_path: Path
    start_time: datetime
    duration_hours: int = 24
    benign_events_per_hour: int = 60
    include_breach_examples: bool = False
    include_subtle_signals: bool = False
    seed: int | None = 42
    tenant_id: str = "contoso.onmicrosoft.com"


def parse_start_time(value: str) -> datetime:
    raw = value.strip()
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    parsed = datetime.fromisoformat(raw)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed
