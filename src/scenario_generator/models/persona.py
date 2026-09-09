from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass(slots=True)
class Persona:
    """Describes a benign or compromised actor baseline."""

    persona_id: str
    persona_type: str
    role: str
    timezone: str = "UTC"
    start_time: int = 8 # 0-23
    end_time: int = 17 # 0-23
    baseline_volume: float = 2.0 # average number of events per hour, used to scale the number of events generated for this persona
    allowed_actions: tuple[str, ...] = field(default_factory=tuple) # empty by default, but used for filtering OK actions ie sign_in, mfa_challenge 
    typical_loco: tuple[str, ...] = field(default_factory=tuple) # empty by default, but used for filtering typical locations ie home, work, travel
    typical_device: tuple[str, ...] = field(default_factory=tuple) # empty by default, but used for filtering typical devices ie laptop, mobile, tablet
    typical_network: tuple[str, ...] = field(default_factory=tuple) # empty by default, but used for filtering typical networks ie home, work, public
    is_compromised: bool = False # default to benign, but can be used to mark a persona as compromised for filtering