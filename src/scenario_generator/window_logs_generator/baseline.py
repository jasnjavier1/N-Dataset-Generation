from __future__ import annotations

from datetime import datetime
from random import Random

try:
    from .event_factory import EventFactory
except ImportError:  # pragma: no cover - script-mode fallback
    from event_factory import EventFactory


class BaselineScenario:
    def __init__(
        self,
        random: Random,
        factory: EventFactory,
        hosts: tuple[str, ...],
        users: tuple[str, ...],
        workstations: tuple[str, ...],
        internal_ips: tuple[str, ...],
    ) -> None:
        self.random = random
        self.factory = factory
        self.hosts = hosts
        self.users = users
        self.workstations = workstations
        self.internal_ips = internal_ips

    def generate(
        self,
        *,
        start: datetime,
        end: datetime,
        duration_hours: int,
        benign_events_per_hour: int,
    ) -> list[dict[str, str]]:
        total = max(1, duration_hours * benign_events_per_hour)
        events: list[dict[str, str]] = []
        event_mix = (4624, 4634, 4648, 4672, 4688)
        event_weights = (55, 25, 10, 5, 5)

        for _ in range(total):
            user = self.random.choice(self.users)
            ts = self.factory.random_time(start, end)
            event_id = self.random.choices(event_mix, weights=event_weights, k=1)[0]
            logon_id = self.factory.logon_id()
            ip = self.random.choice(self.internal_ips)
            workstation = self.random.choice(self.workstations)
            computer = self.random.choice(self.hosts)
            events.append(
                self.factory.build_benign_event(
                    event_id=event_id,
                    timestamp=ts,
                    user=user,
                    computer=computer,
                    ip=ip,
                    workstation=workstation,
                    logon_id=logon_id,
                )
            )

        return events
