from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass(slots=True)
class ScenarioConfig:
    """Run-level settings for generating one scenario."""

    scenario_name: str
    scenario_id: str
    time_start: str
    time_end: str
    timezone: str = "UTC"
    seed: Optional[int] = None
    row_count: Optional[int] = None
    output_path: Optional[Path] = None
    source_type: tuple[str, ...] = ("identity",) # for now, only identity is supported
    enabled_plugins: tuple[str,...] = ("benign_baseline",)
    benign_ratio: float = 0.99 # we will inject malicious events later

