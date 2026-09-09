from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Sequence

from scenario_generator.models.canonical_event import CanonicalEvent


@dataclass(slots=True)
class GeneratorResult:
    """Container for a generation run's output and metadata."""

    run_id: str
    scenario_id: str
    scenario_time: str
    start_time: datetime
    end_time: datetime
    benign_count: int = 0
    malicious_count: int = 0
    events: Sequence[CanonicalEvent] = field(default_factory=tuple)
    warnings: Sequence[str] = field(default_factory=tuple)
    errors: Sequence[str] = field(default_factory=tuple)
