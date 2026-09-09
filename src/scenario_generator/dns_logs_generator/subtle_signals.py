from __future__ import annotations

from datetime import datetime, timedelta
from random import Random

try:
    from .event_factory import EventFactory
except ImportError:  # pragma: no cover - script-mode fallback
    from event_factory import EventFactory


class SubtleBreachScenarios:
    def __init__(
        self,
        random: Random,
        factory: EventFactory,
        domains: tuple[str, ...],
        resolvers: tuple[str, ...],
        source_ips: tuple[str, ...],
    ) -> None:
        self.random = random
        self.factory = factory
        self.domains = domains
        self.resolvers = resolvers
        self.source_ips = source_ips

    def _make_answer(self) -> str:
        return self.random.choice(("91.198.174.192", "104.16.123.96", "203.0.113.10", "198.51.100.22"))

    def _build_event(
        self,
        *,
        timestamp: datetime,
        client_ip: str,
        query_name: str,
        query_type: str,
        response_code: str,
        answers: list[str] | tuple[str, ...],
        resolver_ip: str,
        user_id: str,
        device_id: str,
        risk_level: str,
        label: str = "malicious",
    ) -> dict[str, str]:
        return self.factory.build_event(
            timestamp=timestamp,
            source_type="endpoint_dns",
            source_name="endpoint-win10-subtle",
            client_ip=client_ip,
            query_name=query_name,
            query_type=query_type,
            query_class="IN",
            response_code=response_code,
            answers=answers,
            resolver_ip=resolver_ip,
            ttl=self.random.choice((30, 60, 120, 300)),
            result="success" if response_code == "NOERROR" else "failure",
            result_code="DNS-0" if response_code == "NOERROR" else "DNS-9003",
            user_id=user_id,
            device_id=device_id,
            tenant_id="contoso.onmicrosoft.com",
            domain_category="low-confidence",
            is_external_domain=True,
            query_length=len(query_name),
            subdomain_depth=max(0, query_name.count(".") - 1),
            response_latency_ms=self.random.randint(25, 180),
            cache_hit=False,
            answer_count=len(answers),
            risk_level=risk_level,
            policy_decision="allow",
            label=label,
        )

    def _generate_low_and_slow_beaconing(self, start: datetime, end: datetime) -> list[dict[str, str]]:
        events: list[dict[str, str]] = []
        base = "beacon-update.example.net"
        source_ip = self.random.choice(self.source_ips)
        resolver = self.random.choice(self.resolvers)
        user_id = self.random.choice(("alice", "bob", "charlie"))
        device_id = self.random.choice(("HOST-1001", "HOST-1002", "HOST-1003"))
        interval_seconds = self.random.choice((300, 600, 900, 1800))

        for idx in range(self.random.randint(8, 16)):
            ts = start + timedelta(seconds=idx * interval_seconds)
            if ts > end:
                break
            query_name = f"{idx:02d}.beacon-update.example.net"
            events.append(
                self._build_event(
                    timestamp=ts,
                    client_ip=source_ip,
                    query_name=query_name,
                    query_type="A",
                    response_code="NOERROR",
                    answers=[self._make_answer()],
                    resolver_ip=resolver,
                    user_id=user_id,
                    device_id=device_id,
                    risk_level="medium",
                )
            )

        return events

    def _generate_txt_query_abuse(self, start: datetime, end: datetime) -> list[dict[str, str]]:
        events: list[dict[str, str]] = []
        source_ip = self.random.choice(self.source_ips)
        resolver = self.random.choice(self.resolvers)
        user_id = self.random.choice(("alice", "bob", "charlie", "svc-update"))
        device_id = self.random.choice(("HOST-1001", "HOST-1002", "HOST-2001"))

        for idx in range(self.random.randint(3, 7)):
            ts = start + timedelta(minutes=10 + idx * 40)
            if ts > end:
                break
            payload = "".join(self.random.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(self.random.randint(18, 32)))
            query_name = f"{payload}.txt-check.example.net"
            events.append(
                self._build_event(
                    timestamp=ts,
                    client_ip=source_ip,
                    query_name=query_name,
                    query_type="TXT",
                    response_code="NOERROR",
                    answers=[self._make_answer()],
                    resolver_ip=resolver,
                    user_id=user_id,
                    device_id=device_id,
                    risk_level="medium",
                )
            )

        return events

    def _generate_rare_domain_access_by_normal_host(self, start: datetime, end: datetime) -> list[dict[str, str]]:
        events: list[dict[str, str]] = []
        source_ip = self.random.choice(self.source_ips)
        resolver = self.random.choice(self.resolvers)
        user_id = self.random.choice(("alice", "bob", "charlie"))
        device_id = self.random.choice(("HOST-1001", "HOST-1002", "HOST-1003"))

        for idx in range(self.random.randint(2, 5)):
            ts = start + timedelta(hours=3 + idx * 8)
            if ts > end:
                break
            query_name = f"rare-{idx:02d}.offhours-check.example.net"
            events.append(
                self._build_event(
                    timestamp=ts,
                    client_ip=source_ip,
                    query_name=query_name,
                    query_type="A",
                    response_code="NOERROR",
                    answers=[self._make_answer()],
                    resolver_ip=resolver,
                    user_id=user_id,
                    device_id=device_id,
                    risk_level="high" if idx == 0 else "medium",
                )
            )

        return events

    def _generate_off_hours_low_volume_lookups(self, start: datetime, end: datetime) -> list[dict[str, str]]:
        events: list[dict[str, str]] = []
        source_ip = self.random.choice(self.source_ips)
        resolver = self.random.choice(self.resolvers)
        user_id = self.random.choice(("alice", "bob", "charlie"))
        device_id = self.random.choice(("HOST-1001", "HOST-1002", "HOST-1003"))

        for idx in range(self.random.randint(3, 8)):
            ts = start + timedelta(hours=1 + idx * 3)
            ts = ts.replace(hour=self.random.choice((1, 2, 3, 4, 22, 23)))
            if ts > end:
                break
            query_name = f"offhours-{idx:02d}.check.example.net"
            events.append(
                self._build_event(
                    timestamp=ts,
                    client_ip=source_ip,
                    query_name=query_name,
                    query_type="A",
                    response_code="NOERROR",
                    answers=[self._make_answer()],
                    resolver_ip=resolver,
                    user_id=user_id,
                    device_id=device_id,
                    risk_level="medium",
                )
            )

        return events

    def _generate_subdomain_entropy_drift(self, start: datetime, end: datetime) -> list[dict[str, str]]:
        events: list[dict[str, str]] = []
        source_ip = self.random.choice(self.source_ips)
        resolver = self.random.choice(self.resolvers)
        user_id = self.random.choice(("alice", "bob", "charlie"))
        device_id = self.random.choice(("HOST-1001", "HOST-1002", "HOST-1003"))

        for idx in range(self.random.randint(4, 8)):
            ts = start + timedelta(hours=5 + idx * 6)
            if ts > end:
                break
            token = "".join(self.random.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(self.random.randint(12, 28)))
            query_name = f"{token}.entropy-drift.example.net"
            events.append(
                self._build_event(
                    timestamp=ts,
                    client_ip=source_ip,
                    query_name=query_name,
                    query_type="A",
                    response_code="NOERROR",
                    answers=[self._make_answer()],
                    resolver_ip=resolver,
                    user_id=user_id,
                    device_id=device_id,
                    risk_level="high" if idx % 2 == 0 else "medium",
                )
            )

        return events

    def generate(self, start: datetime, end: datetime) -> list[dict[str, str]]:
        events: list[dict[str, str]] = []
        events.extend(self._generate_low_and_slow_beaconing(start, end))
        events.extend(self._generate_txt_query_abuse(start, end))
        events.extend(self._generate_rare_domain_access_by_normal_host(start, end))
        events.extend(self._generate_off_hours_low_volume_lookups(start, end))
        events.extend(self._generate_subdomain_entropy_drift(start, end))
        return events
