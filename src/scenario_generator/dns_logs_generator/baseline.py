from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from math import ceil
from random import Random
from typing import Any

try:
    from .event_factory import EventFactory
except ImportError:  # pragma: no cover - script-mode fallback
    from event_factory import EventFactory


@dataclass(frozen=True, slots=True)
class DNSCacheEntry:
    answers: tuple[str, ...]
    expires_at: datetime


@dataclass(slots=True)
class QueryPayload:
    raw: dict[str, Any]
    enrichment: dict[str, Any]
    labels: dict[str, str]


class BaselineScenario:
    def __init__(
        self,
        random: Random,
        factory: EventFactory,
        domains: tuple[str, ...],
        resolvers: tuple[str, ...],
        source_ips: tuple[str, ...],
        hosts: tuple[dict[str, object], ...] | None = None,
    ) -> None:
        self.random = random
        self.factory = factory
        self.domains = domains
        self.resolvers = resolvers
        self.source_ips = source_ips
        self.hosts = hosts or self._default_hosts()
        self._cache: dict[tuple[str, str, str], list[DNSCacheEntry]] = defaultdict(list)

        self.domain_categories = {
            "login.contoso.com": "business",
            "portal.contoso.com": "business",
            "www.office.com": "business",
            "api.salesforce.com": "saas",
            "github.com": "developer",
            "cdn.example.net": "cloud",
            "drive.microsoft.com": "cloud",
            "update.windows.com": "system",
            "teams.microsoft.com": "business",
            "outlook.office.com": "business",
            "sharepoint.com": "business",
            "app.powerbi.com": "business",
            "docs.microsoft.com": "developer",
            "www.google.com": "web",
            "www.bing.com": "search",
            "www.linkedin.com": "social",
            "www.netflix.com": "streaming",
            "api.github.com": "developer",
            "raw.githubusercontent.com": "developer",
            "pypi.org": "developer",
            "www.npmjs.com": "developer",
            "www.amazon.com": "shopping",
            "www.wikipedia.org": "reference",
            "status.office.com": "business",
            "onedrive.live.com": "cloud",
            "dl.delivery.mp.microsoft.com": "system",
            "windowsupdate.com": "system",
            "crl.microsoft.com": "system",
            "login.microsoftonline.com": "business",
            "graph.microsoft.com": "business",
            "login.salesforce.com": "saas",
            "naXX.salesforce.com": "saas",
            "assets.adobe.com": "creative",
            "www.dropbox.com": "cloud",
            "api.dropboxapi.com": "cloud",
        }
        self.domain_weights = {
            "login.contoso.com": 26,
            "portal.contoso.com": 18,
            "www.office.com": 16,
            "api.salesforce.com": 12,
            "github.com": 9,
            "cdn.example.net": 7,
            "drive.microsoft.com": 6,
            "update.windows.com": 4,
            "teams.microsoft.com": 13,
            "outlook.office.com": 10,
            "sharepoint.com": 11,
            "app.powerbi.com": 6,
            "docs.microsoft.com": 6,
            "www.google.com": 5,
            "www.bing.com": 4,
            "www.linkedin.com": 3,
            "www.netflix.com": 2,
            "api.github.com": 5,
            "raw.githubusercontent.com": 4,
            "pypi.org": 3,
            "www.npmjs.com": 3,
            "www.amazon.com": 2,
            "www.wikipedia.org": 2,
            "status.office.com": 3,
            "onedrive.live.com": 4,
            "dl.delivery.mp.microsoft.com": 3,
            "windowsupdate.com": 3,
            "crl.microsoft.com": 2,
            "login.microsoftonline.com": 8,
            "graph.microsoft.com": 6,
            "login.salesforce.com": 5,
            "naXX.salesforce.com": 4,
            "assets.adobe.com": 2,
            "www.dropbox.com": 2,
            "api.dropboxapi.com": 2,
        }
        self.domain_families = {
            "m365": ("login.contoso.com", "portal.contoso.com", "www.office.com", "teams.microsoft.com", "outlook.office.com", "sharepoint.com", "status.office.com", "login.microsoftonline.com", "graph.microsoft.com"),
            "browser": ("www.google.com", "www.bing.com", "www.linkedin.com", "www.wikipedia.org", "www.amazon.com", "www.netflix.com", "www.dropbox.com", "www.office.com", "github.com", "drive.microsoft.com", "cdn.example.net"),
            "salesforce": ("api.salesforce.com", "login.salesforce.com", "naXX.salesforce.com", "login.contoso.com", "portal.contoso.com"),
            "github": ("github.com", "api.github.com", "raw.githubusercontent.com", "docs.microsoft.com", "pypi.org", "www.npmjs.com"),
            "update": ("update.windows.com", "windowsupdate.com", "dl.delivery.mp.microsoft.com", "crl.microsoft.com", "cdn.example.net", "status.office.com"),
            "internal": ("login.contoso.com", "portal.contoso.com", "graph.microsoft.com", "sharepoint.com", "onedrive.live.com", "drive.microsoft.com"),
            "cdn": ("cdn.example.net", "onedrive.live.com", "assets.adobe.com", "drive.microsoft.com", "www.dropbox.com"),
            "recursive": ("login.contoso.com", "portal.contoso.com", "api.salesforce.com", "github.com", "login.microsoftonline.com"),
        }
        self.persona_profiles = {
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

    def _default_hosts(self) -> tuple[dict[str, object], ...]:
        return (
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

    def _weighted_choice(self, options: dict[str, int]) -> str:
        return self.random.choices(
            population=list(options.keys()),
            weights=list(options.values()),
            k=1,
        )[0]

    def _persona_for_host(self, host: dict[str, object]) -> str:
        role = str(host.get("role", "user")).lower()
        if role == "service":
            return "service"
        if role == "resolver":
            return "resolver"
        return "user"

    def _choose_application_for_host(self, host: dict[str, object], weekday: int) -> str:
        persona = self._persona_for_host(host)
        apps = self.persona_profiles[persona]["applications"]
        weights = [
            6 if app == "m365" else 5 if app == "browser" else 4 if app == "salesforce" else 3 if app == "github" else 5 if app == "update" else 4 if app == "cdn" else 4
            for app in apps
        ]
        if weekday in (5, 6):
            if "browser" in apps:
                return self.random.choices(apps, weights=weights, k=1)[0]
        return self.random.choices(apps, weights=weights, k=1)[0]

    def _choose_host(self) -> dict[str, object]:
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

    def _choose_domain_for_host(self, host: dict[str, object], app: str | None = None) -> str:
        preferred_raw = host.get("preferred_domains", self.domains)
        preferred = tuple(str(domain) for domain in preferred_raw) if isinstance(preferred_raw, (list, tuple)) else self.domains
        app_domain_map = self.domain_families
        app_key = app if app is not None else ""
        source_domains = tuple(str(domain) for domain in app_domain_map.get(app_key, ())) or preferred
        if source_domains and self.random.random() < 0.85:
            preferred_weights = {
                domain: self.domain_weights.get(domain, 1)
                for domain in source_domains
            }
            return self._weighted_choice(preferred_weights)
        if preferred:
            preferred_weights = {
                domain: self.domain_weights.get(domain, 1)
                for domain in preferred
            }
            return self._weighted_choice(preferred_weights)
        return self._weighted_choice(self.domain_weights)

    def _choose_query_type(self, domain: str) -> str:
        if domain.endswith(".contoso.com"):
            return self.random.choices(["A", "AAAA", "CNAME"], weights=[78, 20, 2], k=1)[0]
        if domain == "update.windows.com":
            return self.random.choices(["A", "AAAA"], weights=[85, 15], k=1)[0]
        if domain == "github.com":
            return self.random.choices(["A", "AAAA"], weights=[88, 12], k=1)[0]
        if domain in {"drive.microsoft.com", "www.office.com", "api.salesforce.com"}:
            return self.random.choices(["A", "AAAA", "CNAME"], weights=[80, 18, 2], k=1)[0]
        return self.random.choices(["A", "AAAA", "TXT", "MX"], weights=[75, 20, 3, 2], k=1)[0]

    def _build_answer(self, domain: str, query_type: str) -> list[str]:
        if query_type == "AAAA":
            if domain.endswith(".contoso.com"):
                return ["fd00:10:0:1::10"]
            if domain == "update.windows.com":
                return ["2620:1ec:c11::200"]
            return ["2606:4700:4700::1111"]

        if query_type == "MX":
            if domain.endswith(".contoso.com"):
                return ["mail.contoso.com"]
            return ["mail.protection.outlook.com"]

        if query_type == "TXT":
            if domain.endswith(".contoso.com"):
                return ["v=spf1 include:contoso.com -all"]
            return ["v=spf1 include:spf.protection.outlook.com -all"]

        if query_type == "CNAME":
            if domain == "login.contoso.com":
                return ["auth.contoso.com"]
            if domain == "portal.contoso.com":
                return ["portal-frontdoor.contoso.com"]
            return ["cdn.redirect.example.net"]

        if domain.endswith(".contoso.com"):
            return [self.random.choice(("10.20.30.40", "10.20.30.41", "10.20.30.42"))]

        if domain == "update.windows.com":
            return [self.random.choice(("13.107.42.14", "13.107.246.40", "20.190.160.10"))]

        return [self.random.choice(("93.184.216.34", "151.101.1.69", "104.16.123.96"))]

    def _hour_weights_for_role(self, role: str) -> dict[int, int]:
        if role == "service":
            return {
                0: 4, 1: 5, 2: 8, 3: 10, 4: 8, 5: 6,
                6: 4, 7: 3, 8: 3, 9: 4, 10: 4, 11: 4,
                12: 4, 13: 4, 14: 4, 15: 4, 16: 4, 17: 4,
                18: 4, 19: 4, 20: 4, 21: 4, 22: 4, 23: 4,
            }
        if role == "resolver":
            return {
                0: 2, 1: 2, 2: 2, 3: 2, 4: 2, 5: 3,
                6: 5, 7: 9, 8: 18, 9: 22, 10: 20, 11: 18,
                12: 17, 13: 17, 14: 18, 15: 19, 16: 16, 17: 10,
                18: 6, 19: 4, 20: 3, 21: 3, 22: 2, 23: 2,
            }
        return {
            0: 1, 1: 1, 2: 1, 3: 1, 4: 1, 5: 2,
            6: 4, 7: 10, 8: 20, 9: 24, 10: 18, 11: 16,
            12: 15, 13: 15, 14: 16, 15: 18, 16: 14, 17: 8,
            18: 4, 19: 2, 20: 2, 21: 2, 22: 1, 23: 1,
        }

    def _sample_timestamp(self, start: datetime, end: datetime, host: dict[str, object]) -> datetime:
        role = str(host.get("role", "user"))
        hour_weights = self._hour_weights_for_role(role)
        total_days = max(0, (end.date() - start.date()).days)

        for _ in range(25):
            day_offset = self.random.randint(0, total_days)
            base_day = start.date() + timedelta(days=day_offset)
            hour = self.random.choices(
                population=list(hour_weights.keys()),
                weights=list(hour_weights.values()),
                k=1,
            )[0]
            minute = self.random.randint(0, 59)
            second = self.random.randint(0, 59)

            ts = datetime(
                year=base_day.year,
                month=base_day.month,
                day=base_day.day,
                hour=hour,
                minute=minute,
                second=second,
                tzinfo=start.tzinfo,
            )
            if start <= ts <= end:
                return ts

        return self.factory.random_time(start, end)

    def _maybe_make_nxdomain(self, domain: str) -> str:
        if "." not in domain:
            return f"{domain}-typo.invalid"

        labels = domain.split(".")
        first = labels[0]
        if len(first) > 4:
            first = first[:-1]
        else:
            first = first + "x"
        labels[0] = first
        return ".".join(labels)

    def _sample_response(
        self,
        timestamp: datetime,
        host: dict[str, object],
        domain: str,
        query_type: str,
    ) -> dict[str, Any]:
        role = str(host.get("role", "user"))
        resolver_ip = str(host.get("resolver_ip", self.random.choice(self.resolvers)))

        nxdomain_rate = 0.03 if role == "user" else 0.01
        servfail_rate = 0.005 if role != "service" else 0.01

        failure_roll = self.random.random()
        if failure_roll < nxdomain_rate:
            typo_domain = self._maybe_make_nxdomain(domain)
            return {
                "query_name": typo_domain,
                "response_code": "NXDOMAIN",
                "answers": [],
                "ttl": 0,
                "result": "failure",
                "result_code": "DNS-9003",
                "response_latency_ms": self.random.randint(18, 55),
                "cache_hit": False,
                "answer_count": 0,
                "resolver_ip": resolver_ip,
            }

        if failure_roll < nxdomain_rate + servfail_rate:
            return {
                "query_name": domain,
                "response_code": "SERVFAIL",
                "answers": [],
                "ttl": 0,
                "result": "failure",
                "result_code": "DNS-2",
                "response_latency_ms": self.random.randint(25, 80),
                "cache_hit": False,
                "answer_count": 0,
                "resolver_ip": resolver_ip,
            }

        cache_key = (resolver_ip, domain, query_type)
        cached_entries = self._cache.get(cache_key, [])
        fresh_candidates = [entry for entry in cached_entries if entry.expires_at > timestamp]
        self._cache[cache_key] = fresh_candidates

        if fresh_candidates:
            ordered = sorted(fresh_candidates, key=lambda item: item.expires_at)
            active_entry = ordered[0]
            remaining_ttl = max(1, int((active_entry.expires_at - timestamp).total_seconds()))
            return {
                "query_name": domain,
                "response_code": "NOERROR",
                "answers": list(active_entry.answers),
                "ttl": remaining_ttl,
                "result": "success",
                "result_code": "DNS-0",
                "response_latency_ms": self.random.randint(2, 10),
                "cache_hit": True,
                "answer_count": len(active_entry.answers),
                "resolver_ip": resolver_ip,
            }

        ttl = self.random.choices([30, 60, 120, 300, 600], weights=[5, 15, 25, 35, 20], k=1)[0]
        answers = self._build_answer(domain, query_type)
        self._cache[cache_key].append(
            DNSCacheEntry(
                answers=tuple(answers),
                expires_at=timestamp + timedelta(seconds=ttl),
            )
        )

        return {
            "query_name": domain,
            "response_code": "NOERROR",
            "answers": answers,
            "ttl": ttl,
            "result": "success",
            "result_code": "DNS-0",
            "response_latency_ms": self.random.randint(12, 45),
            "cache_hit": False,
            "answer_count": len(answers),
            "resolver_ip": resolver_ip,
        }

    def _sample_query(
        self,
        timestamp: datetime,
        host: dict[str, object],
        *,
        app: str | None = None,
        persona: str | None = None,
        domain: str | None = None,
    ) -> QueryPayload:
        app_name = app or self._choose_application_for_host(host, 0)
        persona_name = persona or self._persona_for_host(host)
        chosen_domain = domain or self._choose_domain_for_host(host, app_name)
        query_type = self._choose_query_type(chosen_domain)
        response = self._sample_response(timestamp, host, chosen_domain, query_type)
        query_name = str(response["query_name"])
        category = self.domain_categories.get(chosen_domain, "business")
        is_external = not query_name.endswith(".contoso.com")

        raw: dict[str, Any] = {
            "timestamp": timestamp,
            "query_name": query_name,
            "query_type": query_type,
            "query_class": "IN",
            "response_code": str(response["response_code"]),
            "answers": list(response["answers"]) if isinstance(response.get("answers"), list) else [],
            "resolver_ip": str(response["resolver_ip"]),
            "ttl": int(response["ttl"]),
            "result": str(response["result"]),
            "result_code": str(response["result_code"]),
            "answer_count": int(response["answer_count"]),
            "response_latency_ms": int(response["response_latency_ms"]),
            "cache_hit": bool(response["cache_hit"]),
        }

        enrichment: dict[str, Any] = {
            "source_type": str(host.get("source_type", "endpoint_dns")),
            "source_name": str(host.get("source_name", "endpoint-win10")),
            "client_ip": str(host.get("client_ip", self.random.choice(self.source_ips))),
            "user_id": str(host.get("user_id", "")),
            "device_id": str(host.get("device_id", "")),
            "tenant_id": "contoso.onmicrosoft.com",
            "domain_category": category,
            "is_external_domain": is_external,
            "query_length": len(query_name),
            "subdomain_depth": max(0, query_name.count(".") - 1),
            "application": app_name,
            "persona": persona_name,
        }

        labels: dict[str, str] = {
            "risk_level": "low",
            "policy_decision": "allow",
            "label": "benign",
        }

        return QueryPayload(raw=raw, enrichment=enrichment, labels=labels)

    def _build_domain_chain(self, host: dict[str, object], app: str, persona: str) -> list[str]:
        family = tuple(self.domain_families.get(app, self.domain_families["browser"]))
        preferred_raw = host.get("preferred_domains", self.domains)
        preferred = tuple(str(domain) for domain in preferred_raw) if isinstance(preferred_raw, (list, tuple)) else tuple(str(domain) for domain in self.domains)
        if preferred:
            family = tuple(dict.fromkeys((*preferred, *family)))
        if not family:
            return []
        size = self.random.randint(2, min(5, len(family))) if len(family) > 1 else 1
        chain = self.random.sample(list(family), k=size)
        if persona == "resolver":
            chain = self.random.sample(list(family), k=min(len(family), self.random.randint(4, 8)))
        return list(chain)

    def _build_event_record(
        self,
        *,
        timestamp: datetime,
        host: dict[str, object],
        raw: dict[str, Any],
        enrichment: dict[str, Any],
        labels: dict[str, str],
    ) -> dict[str, str]:
        return self.factory.build_event(
            timestamp=self.factory.clamp_to_end(timestamp, timestamp),
            source_type=str(enrichment["source_type"]),
            source_name=str(enrichment["source_name"]),
            client_ip=str(enrichment["client_ip"]),
            query_name=str(raw["query_name"]),
            query_type=str(raw["query_type"]),
            query_class=str(raw["query_class"]),
            response_code=str(raw["response_code"]),
            answers=list(raw["answers"]),
            resolver_ip=str(raw["resolver_ip"]),
            ttl=int(raw["ttl"]),
            result=str(raw["result"]),
            result_code=str(raw["result_code"]),
            user_id=str(enrichment["user_id"]),
            device_id=str(enrichment["device_id"]),
            tenant_id=str(enrichment["tenant_id"]),
            domain_category=str(enrichment["domain_category"]),
            is_external_domain=bool(enrichment["is_external_domain"]),
            query_length=int(enrichment["query_length"]),
            subdomain_depth=int(enrichment["subdomain_depth"]),
            response_latency_ms=int(raw["response_latency_ms"]),
            cache_hit=bool(raw["cache_hit"]),
            answer_count=int(raw["answer_count"]),
            risk_level=str(labels["risk_level"]),
            policy_decision=str(labels["policy_decision"]),
            label=str(labels["label"]),
        )

    def generate(
        self,
        *,
        start: datetime,
        end: datetime,
        duration_hours: int,
        benign_events_per_hour: int,
    ) -> list[dict[str, str]]:
        _ = duration_hours

        window_hours = max(1, ceil((end - start).total_seconds() / 3600))
        target_total = max(1, window_hours * benign_events_per_hour)
        self._cache.clear()

        events: list[dict[str, str]] = []
        day_count = max(1, (end.date() - start.date()).days + 1)

        for day_index in range(day_count):
            day_start = start + timedelta(days=day_index)
            day_end = min(day_start + timedelta(days=1), end)
            if day_end <= day_start:
                continue

            weekday = day_start.weekday()
            for host in self.hosts:
                if len(events) >= target_total:
                    break

                persona = self._persona_for_host(host)
                profile = self.persona_profiles[persona]
                day_bias = float(profile["day_bias"].get(weekday, 1.0))
                if self.random.random() > min(0.98, day_bias * 0.9):
                    continue

                desired_sessions = self.random.randint(*profile["session_count_per_day"])
                if persona == "resolver":
                    desired_sessions = self.random.randint(6, 20)

                for _ in range(desired_sessions):
                    if len(events) >= target_total:
                        break

                    app = self._choose_application_for_host(host, weekday)
                    session_start = self._sample_timestamp(day_start, day_end, host)
                    chain = self._build_domain_chain(host, app, persona)
                    if persona == "resolver":
                        burst_size = self.random.randint(8, 18)
                        gap_seconds = self.random.randint(1, 8)
                    else:
                        burst_size = self.random.randint(*profile["burst_size"])
                        gap_seconds = self.random.randint(10, 45)

                    for offset in range(min(len(chain), max(2, burst_size))):
                        if len(events) >= target_total:
                            break

                        ts = session_start + timedelta(seconds=offset * gap_seconds)
                        if ts < start or ts > end:
                            continue

                        domain = chain[offset % len(chain)]
                        payload = self._sample_query(ts, host, app=app, persona=persona, domain=domain)
                        events.append(
                            self._build_event_record(
                                timestamp=ts,
                                host=host,
                                raw=payload.raw,
                                enrichment=payload.enrichment,
                                labels=payload.labels,
                            )
                        )

        if len(events) < target_total:
            while len(events) < target_total:
                host = self._choose_host()
                ts = self._sample_timestamp(start, end, host)
                persona = self._persona_for_host(host)
                app = self._choose_application_for_host(host, ts.weekday())
                domain = self._choose_domain_for_host(host, app)
                payload = self._sample_query(ts, host, app=app, persona=persona, domain=domain)
                events.append(
                    self._build_event_record(
                        timestamp=ts,
                        host=host,
                        raw=payload.raw,
                        enrichment=payload.enrichment,
                        labels=payload.labels,
                    )
                )

        events.sort(key=lambda row: row["TimeCreated"])
        return events[:target_total]

    def validate_schema_contract(self, rows: list[dict[str, Any]]) -> dict[str, Any]:
        required = {
            "TimeCreated",
            "EventId",
            "SourceType",
            "SourceName",
            "TenantId",
            "DeviceId",
            "UserId",
            "ClientIp",
            "QueryName",
            "QueryType",
            "QueryClass",
            "ResponseCode",
            "Answers",
            "ResolverIp",
            "Ttl",
            "AnswerCount",
            "Result",
            "ResultCode",
            "RiskLevel",
            "PolicyDecision",
            "DomainCategory",
            "IsExternalDomain",
            "QueryLength",
            "SubdomainDepth",
            "ResponseLatencyMs",
            "CacheHit",
            "Label",
        }

        if not rows:
            return {"passed": False, "details": {"reason": "no rows available"}}

        missing = sorted(required - set(rows[0].keys()))
        if missing:
            return {"passed": False, "details": {"missing_fields": missing}}

        issues = []
        for row in rows:
            if not row.get("QueryName"):
                issues.append({"row": row.get("EventId"), "issue": "empty query name"})
            if row.get("SourceType") not in {"endpoint_dns", "resolver_dns", "proxy_dns"}:
                issues.append({"row": row.get("EventId"), "issue": f"invalid source type: {row.get('SourceType')}"})
            if row.get("ResponseCode") not in {"NOERROR", "NXDOMAIN", "SERVFAIL"}:
                issues.append({"row": row.get("EventId"), "issue": f"unexpected response code: {row.get('ResponseCode')}"})

        return {
            "passed": not issues,
            "details": {
                "required_fields_present": len(required),
                "issues": issues[:10],
                "total_rows": len(rows),
            },
        }

    def validate_time_of_day_and_weekday_distribution(self, rows: list[dict[str, Any]]) -> dict[str, Any]:
        if not rows:
            return {"passed": False, "details": {"reason": "no rows available"}}

        hours = Counter()
        weekdays = Counter()

        for row in rows:
            try:
                ts = datetime.fromisoformat(str(row["TimeCreated"]))
            except ValueError:
                continue
            hours[ts.hour] += 1
            weekdays[ts.weekday()] += 1

        daytime = sum(count for hour, count in hours.items() if 8 <= hour <= 18)
        overnight = sum(count for hour, count in hours.items() if hour < 8 or hour > 18)
        weekday_total = sum(count for day, count in weekdays.items() if day < 5)
        weekend_total = sum(count for day, count in weekdays.items() if day >= 5)

        passed = daytime > overnight and weekday_total >= weekend_total
        return {
            "passed": passed,
            "details": {
                "daytime_count": daytime,
                "overnight_count": overnight,
                "weekday_count": weekday_total,
                "weekend_count": weekend_total,
                "hour_distribution": dict(sorted(hours.items())),
            },
        }

    def validate_device_continuity(self, rows: list[dict[str, Any]]) -> dict[str, Any]:
        by_device: dict[str, dict[str, Any]] = defaultdict(lambda: {"ips": set(), "times": [], "domains": set()})
        for row in rows:
            device = str(row.get("DeviceId", ""))
            by_device[device]["ips"].add(str(row.get("ClientIp", "")))
            by_device[device]["domains"].add(str(row.get("QueryName", "")))
            try:
                by_device[device]["times"].append(datetime.fromisoformat(str(row["TimeCreated"])))
            except ValueError:
                pass

        issues = []
        summaries = []
        for device, payload in by_device.items():
            if len(payload["times"]) < 2:
                issues.append({"device": device, "issue": "insufficient continuity"})
            if len(payload["ips"]) > 3:
                issues.append({"device": device, "issue": "too many IPs"})
            if len(payload["domains"]) < 2:
                issues.append({"device": device, "issue": "too few domains"})
            summaries.append({
                "device": device,
                "query_count": len(payload["times"]),
                "unique_ips": len(payload["ips"]),
                "unique_domains": len(payload["domains"]),
            })

        return {
            "passed": not issues,
            "details": {"issues": issues[:10], "summaries": summaries[:10]},
        }

    def validate_query_type_distribution(self, rows: list[dict[str, Any]]) -> dict[str, Any]:
        if not rows:
            return {"passed": False, "details": {"reason": "no rows available"}}

        counts = Counter(str(row.get("QueryType", "")).upper() for row in rows)
        total = sum(counts.values())
        if total == 0:
            return {"passed": False, "details": {"reason": "no query types"}}

        distribution = {key: round(value / total, 4) for key, value in counts.items()}
        a_share = distribution.get("A", 0.0)
        passed = a_share >= 0.5 and max(distribution.values()) < 0.98
        return {"passed": passed, "details": {"distribution": distribution, "counts": dict(counts)}}

    def validate_domain_frequency_distribution(self, rows: list[dict[str, Any]]) -> dict[str, Any]:
        if not rows:
            return {"passed": False, "details": {"reason": "no rows available"}}

        freq = Counter(str(row.get("QueryName", "")).lower() for row in rows)
        total = sum(freq.values())
        top_10 = sum(value for _, value in freq.most_common(10))
        top_1 = next(iter(freq.values()), 0)

        passed = len(freq) >= 10 and (top_10 / total) > 0.25 and top_1 > 0
        return {
            "passed": passed,
            "details": {
                "unique_domains": len(freq),
                "top_10_share": round(top_10 / total, 4) if total else 0.0,
                "most_common": freq.most_common(10),
            },
        }

    def validate_cache_hit_consistency(self, rows: list[dict[str, Any]]) -> dict[str, Any]:
        if not rows:
            return {"passed": False, "details": {"reason": "no rows available"}}

        cache_true = sum(1 for row in rows if str(row.get("CacheHit", "")).lower() == "true")
        cache_true_ratio = cache_true / len(rows)

        by_query = defaultdict(list)
        for row in rows:
            by_query[(str(row.get("ResolverIp", "")), str(row.get("QueryName", "")), str(row.get("QueryType", "")))].append(row)

        repeated_keys = [entries for entries in by_query.values() if len(entries) > 1]
        singleton_cache_hits = sum(
            1
            for entries in by_query.values()
            if len(entries) == 1 and any(str(e.get("CacheHit", "")).lower() == "true" for e in entries)
        )

        repeated_cache_hits = sum(
            1
            for entries in repeated_keys
            if any(str(e.get("CacheHit", "")).lower() == "true" for e in entries)
        )

        # Real enterprise DNS resolvers often see enough repeated lookups that a meaningful share of
        # queries are served from cache. The key consistency check is not whether cache hits are absent,
        # but whether they are concentrated on repeated resolver-domain-type lookups and not wildly
        # impossible for the underlying dataset.
        passed = (
            0.05 <= cache_true_ratio <= 0.9
            and singleton_cache_hits <= max(1, len(by_query) * 0.08)
            and repeated_cache_hits >= max(1, len(repeated_keys) * 0.05)
        )

        return {
            "passed": passed,
            "details": {
                "cache_true_ratio": round(cache_true_ratio, 4),
                "singleton_cache_hits": singleton_cache_hits,
                "repeated_cache_hits": repeated_cache_hits,
                "repeated_queries": len(repeated_keys),
            },
        }

    def validate_nxdomain_servfail_validity(self, rows: list[dict[str, Any]]) -> dict[str, Any]:
        if not rows:
            return {"passed": False, "details": {"reason": "no rows available"}}

        nxdomain = [row for row in rows if str(row.get("ResponseCode", "")).upper() == "NXDOMAIN"]
        servfail = [row for row in rows if str(row.get("ResponseCode", "")).upper() == "SERVFAIL"]

        nxdomain_issues = []
        for row in nxdomain:
            if int(row.get("AnswerCount", 0)) > 0 or row.get("Answers"):
                nxdomain_issues.append({"row": row.get("EventId"), "issue": "NXDOMAIN with answers"})

        servfail_issues = []
        for row in servfail:
            if int(row.get("AnswerCount", 0)) > 0 or row.get("Answers"):
                servfail_issues.append({"row": row.get("EventId"), "issue": "SERVFAIL with answers"})

        nxdomain_ratio = len(nxdomain) / len(rows)
        servfail_ratio = len(servfail) / len(rows)
        passed = len(nxdomain_issues) == 0 and len(servfail_issues) == 0 and nxdomain_ratio < 0.1 and servfail_ratio < 0.05
        return {
            "passed": passed,
            "details": {
                "nxdomain_rows": len(nxdomain),
                "nxdomain_ratio": round(nxdomain_ratio, 4),
                "servfail_rows": len(servfail),
                "servfail_ratio": round(servfail_ratio, 4),
                "nxdomain_issues": nxdomain_issues[:10],
                "servfail_issues": servfail_issues[:10],
            },
        }

    def validate_per_host_behavior_summary(self, rows: list[dict[str, Any]]) -> dict[str, Any]:
        if not rows:
            return {"passed": False, "details": {"reason": "no rows available"}}

        by_host: dict[str, dict[str, Any]] = defaultdict(lambda: {"domains": Counter(), "types": Counter(), "timestamps": []})
        for row in rows:
            host = str(row.get("DeviceId", ""))
            by_host[host]["domains"][str(row.get("QueryName", "")).lower()] += 1
            by_host[host]["types"][str(row.get("QueryType", "")).upper()] += 1
            try:
                by_host[host]["timestamps"].append(datetime.fromisoformat(str(row["TimeCreated"])))
            except ValueError:
                pass

        issues = []
        summary = {}
        for host, payload in by_host.items():
            domains = payload["domains"]
            types = payload["types"]
            if len(domains) < 3:
                issues.append({"host": host, "issue": "too few domains"})
            if not types:
                issues.append({"host": host, "issue": "no query types"})
            summary[host] = {
                "query_count": sum(domains.values()),
                "unique_domains": len(domains),
                "top_domains": domains.most_common(5),
                "query_types": dict(types),
            }

        return {
            "passed": not issues,
            "details": {"issues": issues[:10], "summary": summary},
        }

    def validate_baseline_dns_suite(self, rows: list[dict[str, Any]]) -> dict[str, Any]:
        checks = {
            "schema_completeness": self.validate_schema_contract(rows),
            "time_of_day_weekday_distribution": self.validate_time_of_day_and_weekday_distribution(rows),
            "device_continuity": self.validate_device_continuity(rows),
            "query_type_distribution": self.validate_query_type_distribution(rows),
            "domain_frequency_distribution": self.validate_domain_frequency_distribution(rows),
            "cache_hit_consistency": self.validate_cache_hit_consistency(rows),
            "nxdomain_servfail_validity": self.validate_nxdomain_servfail_validity(rows),
            "per_host_behavior_summary": self.validate_per_host_behavior_summary(rows),
        }

        overall_passed = all(result["passed"] for result in checks.values())
        return {"passed": overall_passed, "checks": checks}