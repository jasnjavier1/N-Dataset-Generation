from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from random import Random
from typing import Sequence

from scenario_generator.config.scenario_config import ScenarioConfig
from scenario_generator.models.persona import Persona
from scenario_generator.scenarios.scenario_definition import ScenarioDefinition
from scenario_generator.scenarios.scenario_phase import ScenarioPhase


@dataclass(slots=True)
class GenerationContext:
    """Shared state available while generating a run."""

    config: ScenarioConfig
    scenario_definition: ScenarioDefinition
    random: Random
    start_time: datetime
    end_time: datetime
    personas: Sequence[Persona] = ()
    current_phase: ScenarioPhase | None = None
    current_time: datetime = field(init=False)
    events_emitted: int = 0
    benign_events_emitted: int = 0
    malicious_events_emitted: int = 0

    def __post_init__(self) -> None:
        if self.start_time > self.end_time:
            raise ValueError("start_time must be before or equal to end_time")

        self.current_time = self.start_time

    def set_phase(self, phase: ScenarioPhase) -> None:
        self.current_phase = phase

    def advance_time(self, new_time: datetime) -> None:
        if new_time < self.current_time:
            raise ValueError("new_time cannot move backward")

        self.current_time = new_time

    def record_event(self, is_malicious: bool) -> None:
        self.events_emitted += 1
        if is_malicious:
            self.malicious_events_emitted += 1
        else:
            self.benign_events_emitted += 1

