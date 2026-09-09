from __future__ import annotations

from datetime import timedelta
from typing import Sequence
from uuid import uuid4

from scenario_generator.models.canonical_event import CanonicalEvent
from scenario_generator.models.generation_context import GenerationContext
from scenario_generator.scenarios.scenario_phase import ScenarioPhase


class CredentialAbusePlugin:
    """Generates stolen-credentials attack behavior for malicious phases."""

    name = "credential_abuse"

    def generate(
        self,
        context: GenerationContext,
        phase: ScenarioPhase,
    ) -> Sequence[CanonicalEvent]:
        # Keep this plugin scoped to malicious phases.
        if not phase.is_malicious:
            return ()

        if not context.personas:
            return ()

        # Use one compromised actor for V1 simplicity.
        actor = self._pick_compromised_actor(context=context)
        if actor is None:
            return ()

        source_type = context.config.source_type[0] if context.config.source_type else None
        session_id = uuid4().hex
        trace_id = uuid4().hex

        phase_minutes = max(1, phase.duration_minutes or 10)
        phase_start = context.current_time
        phase_end = min(context.end_time, phase_start + timedelta(minutes=phase_minutes))

        events: list[CanonicalEvent] = []

        # V1 progression:
        # 1) failed sign-ins
        # 2) successful sign-in
        # 3) suspicious follow-on access actions
        failed_attempts = max(2, min(5, phase_minutes // 5))
        for index in range(failed_attempts):
            ts = self._timestamp_in_window(
                context=context,
                start=phase_start,
                end=phase_end,
                prefer_early=True,
                offset_hint_seconds=index * 30,
            )
            events.append(
                CanonicalEvent(
                    scenario_id=context.config.scenario_id,
                    session_id=session_id,
                    trace_id=trace_id,
                    phase=phase.name,
                    actor=actor.persona_id,
                    timestamp=ts,
                    action="sign_in",
                    outcome="failure",
                    platform=None,
                    target="identity_provider",
                    risk="medium",
                    device=self._pick_or_fallback(context, actor.typical_device, "unknown_device"),
                    network=self._pick_or_fallback(context, actor.typical_network, "unknown_network"),
                    geo=self._pick_suspicious_geo(context=context, actor_geos=actor.typical_loco),
                    source_type=source_type,
                    label="malicious",
                )
            )

        # Successful login after failures.
        success_ts = self._timestamp_in_window(
            context=context,
            start=phase_start,
            end=phase_end,
            prefer_early=True,
            offset_hint_seconds=(failed_attempts * 30) + 30,
        )
        events.append(
            CanonicalEvent(
                scenario_id=context.config.scenario_id,
                session_id=session_id,
                trace_id=trace_id,
                phase=phase.name,
                actor=actor.persona_id,
                timestamp=success_ts,
                action="sign_in",
                outcome="success",
                platform=None,
                target="identity_provider",
                risk="high",
                device=self._pick_or_fallback(context, actor.typical_device, "unknown_device"),
                network=self._pick_or_fallback(context, actor.typical_network, "unknown_network"),
                geo=self._pick_suspicious_geo(context=context, actor_geos=actor.typical_loco),
                source_type=source_type,
                label="malicious",
            )
        )

        # Suspicious follow-on actions after compromise.
        follow_on_actions = self._allowed_follow_on_actions(phase=phase)
        follow_on_count = max(2, min(8, phase_minutes // 4))

        for index in range(follow_on_count):
            ts = self._timestamp_in_window(
                context=context,
                start=success_ts,
                end=phase_end,
                prefer_early=False,
                offset_hint_seconds=(index + 1) * 45,
            )
            action = context.random.choice(follow_on_actions)
            outcome = "success"

            events.append(
                CanonicalEvent(
                    scenario_id=context.config.scenario_id,
                    session_id=session_id,
                    trace_id=trace_id,
                    phase=phase.name,
                    actor=actor.persona_id,
                    timestamp=ts,
                    action=action,
                    outcome=outcome,
                    platform=None,
                    target=self._target_for_action(action),
                    risk="high",
                    device=self._pick_or_fallback(context, actor.typical_device, "unknown_device"),
                    network=self._pick_or_fallback(context, actor.typical_network, "unknown_network"),
                    geo=self._pick_suspicious_geo(context=context, actor_geos=actor.typical_loco),
                    source_type=source_type,
                    label="malicious",
                )
            )

        # Respect phase allowed_actions if present.
        if phase.allowed_actions:
            allowed = set(phase.allowed_actions)
            events = [event for event in events if event.action in allowed]

        return tuple(events)

    def _pick_compromised_actor(self, context: GenerationContext):
        candidates = [p for p in context.personas if p.persona_type in ("user", "admin")]
        if not candidates:
            return None
        return context.random.choice(candidates)

    def _allowed_follow_on_actions(self, phase: ScenarioPhase) -> tuple[str, ...]:
        defaults = ("list_resources", "read_mailbox", "download_file", "query_data")
        if not phase.allowed_actions:
            return defaults
        filtered = tuple(action for action in defaults if action in phase.allowed_actions)
        return filtered or tuple(phase.allowed_actions)

    def _target_for_action(self, action: str) -> str:
        if action in ("read_mailbox", "forward_email"):
            return "mailbox"
        if action in ("download_file", "query_data"):
            return "data_store"
        return "tenant_resource"

    def _pick_suspicious_geo(
        self,
        context: GenerationContext,
        actor_geos: tuple[str, ...],
    ) -> str:
        unusual_pool = ("RU", "CN", "KP", "IR", "UNKNOWN")
        if not actor_geos:
            return context.random.choice(unusual_pool)

        # Mostly choose a geo not in the actor's usual set.
        if context.random.random() < 0.8:
            non_typical = [geo for geo in unusual_pool if geo not in actor_geos]
            if non_typical:
                return context.random.choice(non_typical)

        return context.random.choice(actor_geos)

    def _pick_or_fallback(
        self,
        context: GenerationContext,
        values: tuple[str, ...],
        fallback: str,
    ) -> str:
        if values:
            return context.random.choice(values)
        return fallback

    def _timestamp_in_window(
        self,
        context: GenerationContext,
        start,
        end,
        prefer_early: bool,
        offset_hint_seconds: int = 0,
    ):
        if end <= start:
            return start

        window_seconds = int((end - start).total_seconds())
        if window_seconds <= 0:
            return start

        if prefer_early:
            upper = max(1, min(window_seconds, max(60, window_seconds // 3)))
            offset = context.random.randint(0, upper - 1)
        else:
            offset = context.random.randint(0, window_seconds - 1)

        offset = min(window_seconds - 1, offset + max(0, offset_hint_seconds))
        return start + timedelta(seconds=offset)