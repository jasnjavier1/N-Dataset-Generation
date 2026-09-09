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


class DnsLogGenerator:
    def __init__(self, config: GeneratorConfig) -> None:
        self.config = config
        self.random = Random(config.seed)

        self.domains = (
            "login.contoso.com",
            "portal.contoso.com",
            "www.office.com",
            "api.salesforce.com",
            "github.com",
            "cdn.example.net",
            "drive.microsoft.com",
            "update.windows.com",
        )
        self.resolvers = (
            "10.0.0.10",
            "10.0.0.11",
            "10.0.0.12",
            "172.16.0.10",
        )
        self.source_ips = (
            "10.0.1.15",
            "10.0.1.16",
            "10.0.1.17",
            "10.0.2.42",
            "192.168.10.20",
        )
        self.source_types = ("endpoint_dns", "resolver_dns", "proxy_dns")
        self.host_profiles = (
            {
                "device_id": "HOST-1001",
                "user_id": "alice",
                "role": "user",
                "client_ip": "10.0.1.15",
                "source_type": "endpoint_dns",
                "source_name": "endpoint-win10-01",
                "resolver_ip": "10.0.0.10",
                "preferred_domains": ("login.contoso.com", "portal.contoso.com", "www.office.com", "api.salesforce.com"),
            },
            {
                "device_id": "HOST-1002",
                "user_id": "bob",
                "role": "user",
                "client_ip": "10.0.1.16",
                "source_type": "endpoint_dns",
                "source_name": "endpoint-win10-02",
                "resolver_ip": "10.0.0.11",
                "preferred_domains": ("www.office.com", "github.com", "drive.microsoft.com", "portal.contoso.com"),
            },
            {
                "device_id": "HOST-1003",
                "user_id": "charlie",
                "role": "user",
                "client_ip": "10.0.1.17",
                "source_type": "endpoint_dns",
                "source_name": "endpoint-win10-03",
                "resolver_ip": "10.0.0.10",
                "preferred_domains": ("login.contoso.com", "api.salesforce.com", "portal.contoso.com", "github.com"),
            },
            {
                "device_id": "HOST-2001",
                "user_id": "svc-update",
                "role": "service",
                "client_ip": "10.0.2.45",
                "source_type": "endpoint_dns",
                "source_name": "endpoint-update-service",
                "resolver_ip": "10.0.0.12",
                "preferred_domains": ("update.windows.com", "cdn.example.net", "login.contoso.com", "www.office.com"),
            },
            {
                "device_id": "DNS-RESOLVER-01",
                "user_id": "",
                "role": "resolver",
                "client_ip": "10.0.0.10",
                "source_type": "resolver_dns",
                "source_name": "resolver-core-01",
                "resolver_ip": "10.0.0.10",
                "preferred_domains": ("login.contoso.com", "portal.contoso.com", "api.salesforce.com", "drive.microsoft.com"),
            },
        )

        self.factory = EventFactory(config=config, random=self.random)
        self.baseline = BaselineScenario(
            random=self.random,
            factory=self.factory,
            domains=self.domains,
            resolvers=self.resolvers,
            source_ips=self.source_ips,
            hosts=self.host_profiles,
        )
        self.overt_breaches = OvertBreachScenarios(
            random=self.random,
            factory=self.factory,
            domains=self.domains,
            resolvers=self.resolvers,
            source_ips=self.source_ips,
        )
        self.subtle_signals = SubtleBreachScenarios(
            random=self.random,
            factory=self.factory,
            domains=self.domains,
            resolvers=self.resolvers,
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
