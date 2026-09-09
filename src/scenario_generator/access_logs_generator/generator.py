from __future__ import annotations

from datetime import timedelta
from random import Random

try:
    from .baseline import BaselineScenario
    from .config import GeneratorConfig
    from .event_factory import EventFactory
    from .overt_breaches import OvertBreachScenarios
    from .subtle_signals import SubtleBreachScenarios
except ImportError:  # pragma: no cover - script-mode fallback
    from baseline import BaselineScenario
    from config import GeneratorConfig
    from event_factory import EventFactory
    from overt_breaches import OvertBreachScenarios
    from subtle_signals import SubtleBreachScenarios


class AccessLogGenerator:
    def __init__(self, config: GeneratorConfig) -> None:
        self.config = config
        self.random = Random(config.seed)

        self.users = (
            ("uid-1001", "alice@contoso.com"),
            ("uid-1002", "bob@contoso.com"),
            ("uid-1003", "charlie@contoso.com"),
            ("uid-1004", "dana@contoso.com"),
            ("uid-1005", "svc-backup@contoso.com"),
        )
        self.apps = ("M365", "Salesforce", "VPN", "SharePoint", "GitHub")
        self.geos = ("US", "CA", "DE", "GB", "IN")
        self.source_ips = ("10.0.1.15", "10.0.1.16", "10.0.1.17", "10.0.2.42")

        self.factory = EventFactory(config=config, random=self.random)
        self.baseline = BaselineScenario(
            random=self.random,
            factory=self.factory,
            users=self.users,
            apps=self.apps,
            geos=self.geos,
            source_ips=self.source_ips,
        )
        self.overt_breaches = OvertBreachScenarios(
            random=self.random,
            factory=self.factory,
            users=self.users,
            apps=self.apps,
            geos=self.geos,
            source_ips=self.source_ips,
        )
        self.subtle_signals = SubtleBreachScenarios(
            random=self.random,
            factory=self.factory,
            users=self.users,
            apps=self.apps,
            geos=self.geos,
            source_ips=self.source_ips,
        )

    def generate(self) -> list[dict[str, str]]:
        start = self.factory.ensure_tz(self.config.start_time)
        end = start + timedelta(hours=max(1, self.config.duration_hours))

        events: list[dict[str, str]] = []
        events.extend(
            self.baseline.generate(
                start=start,
                end=end,
                duration_hours=self.config.duration_hours,
                benign_events_per_hour=self.config.benign_events_per_hour,
            )
        )

        if self.config.include_breach_examples:
            events.extend(self.overt_breaches.generate(start=start, end=end))

        if self.config.include_subtle_signals:
            events.extend(self.subtle_signals.generate(start=start, end=end))

        events.sort(key=lambda row: row["TimeCreated"])
        return events
