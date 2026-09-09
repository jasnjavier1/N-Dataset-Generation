from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Optional


@dataclass(slots=True)
class CanonicalEvent:
    """Normalized event shape used before CSV export."""

    scenario_id: str
    session_id: str
    trace_id: str
    phase: str
    actor: str
    timestamp: datetime
    action: str
    outcome: str
    label: str # benign or malicious
    platform: Optional[str] = None
    target: Optional[str] = None
    risk: Optional[str] = None
    device: Optional[str] = None
    network: Optional[str] = None
    geo: Optional[str] = None
    source_type: Optional[str] = None
