from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass(slots=True)
class ScenarioPhase:
    """One stage in a scenario timeline."""

    name: str
    order: int
    phase_id: str
    description: str = ""
    duration_minutes: Optional[int] = None
    min_events: Optional[int] = None # volume bounds to prevent distortion
    max_events: Optional[int] = None
    event_intensity: float = 1.0 # multiplier for how many events to generate in this phase, relative to the default intensity
    allowed_actions: tuple[str, ...] = () # empty by default, but used for filtering OK actions ie sign_in, mfa_challenge
    allowed_plugins: tuple[str, ...] = ("benign_baseline",) # empty by default, but used for filtering which plugins are allowed to generate events in this phase
    is_malicious: bool = False # default to benign, but can be used to mark a phase as malicious for filtering
    
