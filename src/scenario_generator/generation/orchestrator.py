from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from random import Random
from typing import Protocol, Sequence
from uuid import uuid4

from scenario_generator.config.scenario_config import ScenarioConfig
from scenario_generator.models.canonical_event import CanonicalEvent
from scenario_generator.models.generation_context import GenerationContext
from scenario_generator.models.generator_result import GeneratorResult
from scenario_generator.models.persona import Persona
from scenario_generator.scenarios.scenario_definition import ScenarioDefinition
from scenario_generator.scenarios.scenario_phase import ScenarioPhase


class Plugin(Protocol):
    """Contract for plugins used by the scenario orchestrator."""

    def generate(
        self,
        context: GenerationContext,
        phase: ScenarioPhase,
    ) -> Sequence[CanonicalEvent]:
        """Generate canonical events for the given context and phase."""
        ...


class ScenarioOrchestrator:
    """Coordinates scenario execution across phases and plugins."""

    def __init__(self, plugins: dict[str, Plugin] | None = None) -> None:
        self.plugins = plugins or {}

    def run(
        self,
        config: ScenarioConfig,
        scenario_definition: ScenarioDefinition,
        personas: Sequence[Persona],
    ) -> GeneratorResult:
        warnings: list[str] = []
        errors: list[str] = []
        all_events: list[CanonicalEvent] = []

        context = self._build_context(
            config=config,
            scenario_definition=scenario_definition,
            personas=personas,
        )

        phases = sorted(scenario_definition.phases, key=lambda phase: phase.order)
        self._validate_phase_order(phases=phases, errors=errors)

        for phase in phases:
            context.set_phase(phase)

            phase_events = self._run_phase_plugins(
                context=context,
                phase=phase,
                warnings=warnings,
                errors=errors,
            )
            phase_events = self._apply_phase_constraints(
                context=context,
                phase=phase,
                events=phase_events,
                warnings=warnings,
            )
            phase_events = self._correlate_phase_events(
                context=context,
                phase=phase,
                events=phase_events,
            )

            for event in phase_events:
                context.record_event(is_malicious=(event.label == "malicious"))

            all_events.extend(phase_events)
            self._advance_context_time(
                context=context,
                phase=phase,
                phase_events=phase_events,
            )

        return self._build_result(
            context=context,
            events=all_events,
            warnings=warnings,
            errors=errors,
        )

    def _build_context(
        self,
        config: ScenarioConfig,
        scenario_definition: ScenarioDefinition,
        personas: Sequence[Persona],
    ) -> GenerationContext:
        start_time = self._parse_iso_datetime(config.time_start)
        end_time = self._parse_iso_datetime(config.time_end)
        random_state = Random(config.seed)

        return GenerationContext(
            config=config,
            scenario_definition=scenario_definition,
            random=random_state,
            start_time=start_time,
            end_time=end_time,
            personas=personas,
        )

    def _run_phase_plugins(
        self,
        context: GenerationContext,
        phase: ScenarioPhase,
        warnings: list[str],
        errors: list[str],
    ) -> list[CanonicalEvent]:
        events: list[CanonicalEvent] = []
        enabled_plugins = self._resolve_enabled_plugins(context=context, phase=phase)

        for plugin_name in enabled_plugins:
            plugin = self.plugins.get(plugin_name)

            if plugin is None:
                warnings.append(
                    f"Plugin '{plugin_name}' is enabled but not registered; skipping"
                )
                continue

            try:
                plugin_events = plugin.generate(context=context, phase=phase)
            except Exception as exc:
                errors.append(
                    f"Plugin '{plugin_name}' failed in phase '{phase.name}': {exc}"
                )
                continue

            events.extend(plugin_events)

        return events

    def _apply_phase_constraints(
        self,
        context: GenerationContext,
        phase: ScenarioPhase,
        events: Sequence[CanonicalEvent],
        warnings: list[str],
    ) -> list[CanonicalEvent]:
        constrained = list(events)

        if phase.allowed_actions:
            allowed_set = set(phase.allowed_actions)
            kept = [event for event in constrained if event.action in allowed_set]
            dropped = len(constrained) - len(kept)
            constrained = kept
            if dropped > 0:
                warnings.append(
                    f"Phase '{phase.name}' removed {dropped} events due to allowed_actions"
                )

        constrained = self._apply_event_intensity(
            random_state=context.random,
            events=constrained,
            intensity=phase.event_intensity,
        )

        constrained = self._enforce_event_count_bounds(
            random_state=context.random,
            phase=phase,
            events=constrained,
            warnings=warnings,
        )

        constrained = self._apply_phase_malicious_ratio(
            random_state=context.random,
            events=constrained,
            phase=phase,
            benign_ratio=context.config.benign_ratio,
        )

        return constrained

    def _correlate_phase_events(
        self,
        context: GenerationContext,
        phase: ScenarioPhase,
        events: Sequence[CanonicalEvent],
    ) -> list[CanonicalEvent]:
        if not events:
            return []

        correlated: list[CanonicalEvent] = []
        shared_session_id = uuid4().hex
        shared_trace_id = uuid4().hex
        source_type = context.config.source_type[0] if context.config.source_type else None
        phase_start = max(context.current_time, context.start_time)
        phase_window_minutes = max(1, phase.duration_minutes or 5)
        phase_window_seconds = phase_window_minutes * 60

        for index, event in enumerate(events):
            max_offset = min(phase_window_seconds - 1, index * 5)
            offset_seconds = context.random.randint(0, max_offset) if max_offset > 0 else 0
            timestamp = phase_start + timedelta(seconds=offset_seconds)
            timestamp = min(timestamp, context.end_time)

            correlated.append(
                replace(
                    event,
                    scenario_id=context.config.scenario_id,
                    phase=phase.name,
                    session_id=shared_session_id,
                    trace_id=shared_trace_id,
                    timestamp=timestamp,
                    source_type=event.source_type or source_type,
                    label=event.label or ("malicious" if phase.is_malicious else "benign"),
                )
            )

        return correlated

    def _advance_context_time(
        self,
        context: GenerationContext,
        phase: ScenarioPhase,
        phase_events: Sequence[CanonicalEvent],
    ) -> None:
        if phase.duration_minutes is not None:
            target_time = context.current_time + timedelta(minutes=phase.duration_minutes)
        elif phase_events:
            target_time = max(event.timestamp for event in phase_events) + timedelta(seconds=1)
        else:
            target_time = context.current_time

        context.advance_time(min(target_time, context.end_time))

    def _build_result(
        self,
        context: GenerationContext,
        events: Sequence[CanonicalEvent],
        warnings: Sequence[str],
        errors: Sequence[str],
    ) -> GeneratorResult:
        malicious_count = sum(1 for event in events if event.label == "malicious")
        benign_count = len(events) - malicious_count
        scenario_time = f"{context.start_time.isoformat()} -> {context.current_time.isoformat()}"

        return GeneratorResult(
            run_id=uuid4().hex,
            scenario_id=context.config.scenario_id,
            scenario_time=scenario_time,
            start_time=context.start_time,
            end_time=context.current_time,
            benign_count=benign_count,
            malicious_count=malicious_count,
            events=tuple(events),
            warnings=tuple(warnings),
            errors=tuple(errors),
        )

    def _resolve_enabled_plugins(
        self,
        context: GenerationContext,
        phase: ScenarioPhase,
    ) -> list[str]:
        configured = set(context.config.enabled_plugins)
        scenario_default = set(context.scenario_definition.default_enabled_plugins)
        phase_allowed = set(phase.allowed_plugins)
        enabled = configured & scenario_default & phase_allowed

        return sorted(enabled)

    def _validate_phase_order(
        self,
        phases: Sequence[ScenarioPhase],
        errors: list[str],
    ) -> None:
        seen_orders: set[int] = set()
        for phase in phases:
            if phase.order in seen_orders:
                errors.append(f"Duplicate phase order detected: {phase.order}")
            seen_orders.add(phase.order)

    def _apply_event_intensity(
        self,
        random_state: Random,
        events: Sequence[CanonicalEvent],
        intensity: float,
    ) -> list[CanonicalEvent]:
        if not events:
            return []

        if intensity <= 0:
            return []

        target_count = int(round(len(events) * intensity))
        target_count = max(0, target_count)

        if target_count <= len(events):
            return self._sample_without_replacement(
                random_state=random_state,
                events=events,
                target_count=target_count,
            )

        expanded = list(events)
        while len(expanded) < target_count:
            expanded.append(random_state.choice(events))

        return expanded

    def _enforce_event_count_bounds(
        self,
        random_state: Random,
        phase: ScenarioPhase,
        events: Sequence[CanonicalEvent],
        warnings: list[str],
    ) -> list[CanonicalEvent]:
        bounded = list(events)

        if phase.max_events is not None and len(bounded) > phase.max_events:
            bounded = self._sample_without_replacement(
                random_state=random_state,
                events=bounded,
                target_count=phase.max_events,
            )

        if phase.min_events is not None and len(bounded) < phase.min_events:
            if not bounded:
                warnings.append(
                    f"Phase '{phase.name}' requested min_events={phase.min_events} but generated no events"
                )
            else:
                while len(bounded) < phase.min_events:
                    bounded.append(random_state.choice(bounded))

        return bounded

    def _apply_phase_malicious_ratio(
        self,
        random_state: Random,
        events: Sequence[CanonicalEvent],
        phase: ScenarioPhase,
        benign_ratio: float,
    ) -> list[CanonicalEvent]:
        if not events:
            return []

        normalized_ratio = max(0.0, min(1.0, benign_ratio))

        if phase.is_malicious:
            target_malicious = max(1, int(round(len(events) * (1 - normalized_ratio))))
        else:
            target_malicious = 0

        target_malicious = min(target_malicious, len(events))
        malicious_indexes = set(random_state.sample(range(len(events)), target_malicious))

        labeled: list[CanonicalEvent] = []
        for index, event in enumerate(events):
            label = "malicious" if index in malicious_indexes else "benign"
            labeled.append(replace(event, label=label))

        return labeled

    def _sample_without_replacement(
        self,
        random_state: Random,
        events: Sequence[CanonicalEvent],
        target_count: int,
    ) -> list[CanonicalEvent]:
        if target_count <= 0:
            return []

        if target_count >= len(events):
            return list(events)

        indexes = sorted(random_state.sample(range(len(events)), target_count))
        return [events[index] for index in indexes]

    def _parse_iso_datetime(self, value: str) -> datetime:
        normalized = value.strip()
        if normalized.endswith("Z"):
            normalized = normalized[:-1] + "+00:00"

        parsed = datetime.fromisoformat(normalized)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)

        return parsed