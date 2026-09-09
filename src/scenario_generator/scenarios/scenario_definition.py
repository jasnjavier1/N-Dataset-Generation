from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from scenario_generator.scenarios.scenario_phase import ScenarioPhase


@dataclass(slots=True)
class ScenarioDefinition:
    """Declarative description of a scenario to generate."""

    scenario_name: str # readable version to differentiate scenarios
    scenario_id: str
    phases: Sequence[ScenarioPhase]
    description: str = ""
    tags: tuple[str, ...] = () # empty by default, but can be used to categorize scenarios for filtering
    required_source_types: tuple[str, ...] = ("identity",)
    default_enabled_plugins: tuple[str, ...] = ("benign_baseline",) # needs a default setting