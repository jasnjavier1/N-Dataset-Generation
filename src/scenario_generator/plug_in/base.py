from __future__ import annotations
from dataclasses import dataclass
from typing import Protocol, Sequence
from scenario_generator.models.canonical_event import CanonicalEvent
from scenario_generator.models.generation_context import GenerationContext
from scenario_generator.scenarios.scenario_phase import ScenarioPhase

@dataclass(frozen=True, slots=True)
class PluginMetadata:
    """Static metadata describing a plugin's identity."""

    plugin_name: str
    description: str = ""

class Plugin(Protocol):
    """Contract every scenario-generation plugin must satisfy.
    Plugins receive the current generation context and the active phase,
    then return canonical events for that phase only. They do not own
    orchestration, export, or result packaging.
    """
    metadata: PluginMetadata

    def generate(
        self,
        context: GenerationContext,
        phase: ScenarioPhase,
    ) -> Sequence[CanonicalEvent]:
        """Generate canonical events for the supplied phase."""
        ...