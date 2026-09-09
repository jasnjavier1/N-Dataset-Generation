from __future__ import annotations
from dataclasses import replace
from datetime import timedelta
from typing import Sequence
from uuid import uuid4
from typing import Protocol, Sequence
from scenario_generator.models.canonical_event import CanonicalEvent
from scenario_generator.models.generation_context import GenerationContext
from scenario_generator.scenarios.scenario_phase import ScenarioPhase

class BenignBaselinePlugin:
    """Generates benign baseline activity from persona profiles."""

    name = "benign_baseline"

    def generate(
        self,
        context: GenerationContext,
        phase: ScenarioPhase,
    ) -> Sequence[CanonicalEvent]:
        if not context.personas:
            return ()

        phase_minutes = max(1, phase.duration_minutes or 5)
        events: list[CanonicalEvent] = []

        for persona in context.personas:
            # Start from persona actions, then constrain by phase actions.
            persona_actions = tuple(persona.allowed_actions) if persona.allowed_actions else ()
            if phase.allowed_actions:
                allowed = tuple(a for a in persona_actions if a in phase.allowed_actions) if persona_actions else tuple(phase.allowed_actions)
            else:
                allowed = persona_actions or ("read_profile", "list_resources", "query_directory")

            if not allowed:
                continue

            # Approximate per-persona baseline volume for this phase window.
            rate_per_hour = max(0.0, float(persona.baseline_volume))
            expected = int(round((rate_per_hour * phase_minutes) / 60.0))
            target_count = max(1, expected)

            for _ in range(target_count):
                offset_seconds = context.random.randint(0, max(1, phase_minutes * 60) - 1)
                timestamp = context.current_time + timedelta(seconds=offset_seconds)
                if timestamp > context.end_time:
                    timestamp = context.end_time

                action = context.random.choice(allowed)

                events.append(
                    CanonicalEvent(
                        scenario_id=context.config.scenario_id,
                        session_id=uuid4().hex,
                        trace_id=uuid4().hex,
                        phase=phase.name,
                        actor=persona.persona_id,
                        timestamp=timestamp,
                        action=action,
                        outcome="success",
                        platform=None,
                        target="tenant_resource",
                        risk="low",
                        device=context.random.choice(persona.typical_device) if persona.typical_device else None,
                        network=context.random.choice(persona.typical_network) if persona.typical_network else None,
                        geo=context.random.choice(persona.typical_loco) if persona.typical_loco else None,
                        source_type=(context.config.source_type[0] if context.config.source_type else None),
                        label="benign",
                    )
                )

        return tuple(events)