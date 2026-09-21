from __future__ import annotations

from random import Random
from typing import Any

DEFAULT_HOSTS: tuple[dict[str, object], ...] = (
    {
        "device_id": "HOST-1001",
        "user_id": "alice",
        "role": "user",
        "client_ip": "10.0.1.15",
        "source_type": "endpoint_dns",
        "source_name": "endpoint-win10-01",
        "resolver_ip": "10.0.0.10",
        "preferred_domains": (
            "login.contoso.com",
            "portal.contoso.com",
            "www.office.com",
            "api.salesforce.com",
        ),
    },
    {
        "device_id": "HOST-1002",
        "user_id": "bob",
        "role": "user",
        "client_ip": "10.0.1.16",
        "source_type": "endpoint_dns",
        "source_name": "endpoint-win10-02",
        "resolver_ip": "10.0.0.11",
        "preferred_domains": (
            "www.office.com",
            "github.com",
            "drive.microsoft.com",
            "portal.contoso.com",
        ),
    },
    {
        "device_id": "HOST-1003",
        "user_id": "charlie",
        "role": "user",
        "client_ip": "10.0.1.17",
        "source_type": "endpoint_dns",
        "source_name": "endpoint-win10-03",
        "resolver_ip": "10.0.0.10",
        "preferred_domains": (
            "login.contoso.com",
            "api.salesforce.com",
            "portal.contoso.com",
            "github.com",
        ),
    },
    {
        "device_id": "HOST-2001",
        "user_id": "svc-update",
        "role": "service",
        "client_ip": "10.0.2.45",
        "source_type": "endpoint_dns",
        "source_name": "endpoint-update-service",
        "resolver_ip": "10.0.0.12",
        "preferred_domains": (
            "update.windows.com",
            "cdn.example.net",
            "login.contoso.com",
            "www.office.com",
        ),
    },
    {
        "device_id": "DNS-RESOLVER-01",
        "user_id": "",
        "role": "resolver",
        "client_ip": "10.0.0.10",
        "source_type": "resolver_dns",
        "source_name": "resolver-core-01",
        "resolver_ip": "10.0.0.10",
        "preferred_domains": (
            "login.contoso.com",
            "portal.contoso.com",
            "api.salesforce.com",
            "drive.microsoft.com",
        ),
    },
)

PERSONA_PROFILES: dict[str, dict[str, Any]] = {
    "user": {
        "applications": ("m365", "browser", "salesforce", "github"),
        "session_count_per_day": (1, 4),
        "burst_size": (2, 7),
        "day_bias": {0: 1.0, 1: 1.0, 2: 1.1, 3: 1.1, 4: 1.2, 5: 0.7, 6: 0.5},
    },
    "service": {
        "applications": ("update", "internal", "cdn"),
        "session_count_per_day": (1, 3),
        "burst_size": (2, 5),
        "day_bias": {0: 1.0, 1: 1.0, 2: 1.0, 3: 1.0, 4: 1.0, 5: 0.8, 6: 0.7},
    },
    "resolver": {
        "applications": ("recursive", "cache", "internal"),
        "session_count_per_day": (2, 6),
        "burst_size": (3, 9),
        "day_bias": {0: 1.0, 1: 1.0, 2: 1.1, 3: 1.1, 4: 1.1, 5: 0.9, 6: 0.8},
    },
}


class PersonaManager:
    def __init__(self, random: Random, hosts: tuple[dict[str, object], ...] | None = None) -> None:
        self.random = random
        self.hosts = hosts or DEFAULT_HOSTS
        self.persona_profiles = PERSONA_PROFILES

    def default_hosts(self) -> tuple[dict[str, object], ...]:
        return DEFAULT_HOSTS

    def persona_for_host(self, host: dict[str, object]) -> str:
        role = str(host.get("role", "user")).lower()
        if role == "service":
            return "service"
        if role == "resolver":
            return "resolver"
        return "user"

    def choose_application_for_host(self, host: dict[str, object], weekday: int) -> str:
        persona = self.persona_for_host(host)
        apps = self.persona_profiles[persona]["applications"]
        weights = [
            6 if app == "m365" else 5 if app == "browser" else 4 if app == "salesforce" else 3 if app == "github" else 5 if app == "update" else 4 if app == "cdn" else 4
            for app in apps
        ]
        if weekday in (5, 6) and "browser" in apps:
            return self.random.choices(apps, weights=weights, k=1)[0]
        return self.random.choices(apps, weights=weights, k=1)[0]

    def choose_host(self) -> dict[str, object]:
        role_weights = {
            "user": 10,
            "service": 4,
            "resolver": 6,
        }
        weights = [
            role_weights.get(str(host.get("role", "user")), 1)
            for host in self.hosts
        ]
        return self.random.choices(self.hosts, weights=weights, k=1)[0]
