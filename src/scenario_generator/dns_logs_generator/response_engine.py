from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from random import Random
from typing import Any


@dataclass(frozen=True, slots=True)
class DNSCacheEntry:
    answers: tuple[str, ...]
    expires_at: datetime


class DNSResponseEngine:
    def __init__(self, random: Random, resolvers: tuple[str, ...]) -> None:
        self.random = random
        self.resolvers = resolvers
        self._cache: dict[tuple[str, str, str], list[DNSCacheEntry]] = defaultdict(list)

    def clear(self) -> None:
        self._cache.clear()

    def maybe_make_nxdomain(self, domain: str) -> str:
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

    def build_answer(self, domain: str, query_type: str, *, random: Random | None = None) -> list[str]:
        randomizer = random or self.random
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
            return [randomizer.choice(("10.20.30.40", "10.20.30.41", "10.20.30.42"))]

        if domain == "update.windows.com":
            return [randomizer.choice(("13.107.42.14", "13.107.246.40", "20.190.160.10"))]

        return [randomizer.choice(("93.184.216.34", "151.101.1.69", "104.16.123.96"))]

    def sample_response(self, timestamp: datetime, host: dict[str, object], domain: str, query_type: str) -> dict[str, Any]:
        role = str(host.get("role", "user"))
        resolver_ip = str(host.get("resolver_ip", self.random.choice(self.resolvers)))

        nxdomain_rate = 0.03 if role == "user" else 0.01
        servfail_rate = 0.005 if role != "service" else 0.01

        failure_roll = self.random.random()
        if failure_roll < nxdomain_rate:
            typo_domain = self.maybe_make_nxdomain(domain)
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
        answers = self.build_answer(domain, query_type)
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
