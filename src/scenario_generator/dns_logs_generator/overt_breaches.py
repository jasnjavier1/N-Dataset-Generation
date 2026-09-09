from __future__ import annotations

from datetime import datetime, timedelta
from random import Random

try:
    from .event_factory import EventFactory
except ImportError:  # pragma: no cover - script-mode fallback
    from event_factory import EventFactory


class OvertBreachScenarios:
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

    def _make_malicious_ip(self) -> str:
        return f"198.51.100.{self.random.randint(2, 254)}"

    def _make_domain(self, prefix: str) -> str:
        suffix = self.random.choice(("cdn", "svc", "api", "mail", "update"))
        return f"{prefix}-{suffix}.example.net"

    def _dns_tunneling_burst(self, start: datetime, end: datetime) -> list[dict[str, str]]:
        events: list[dict[str, str]] = []
        burst_start = start + timedelta(minutes=self.random.randint(5, 90))
        domain = self._make_domain("exfil")
        resolver = self.random.choice(self.resolvers)
        source_ip = self.random.choice(self.source_ips)

        for idx in range(self.random.randint(8, 16)):
            payload = "".join(self.random.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(self.random.randint(28, 72)))
            query_name = f"{payload}.{domain}"
            query_type = self.random.choice(("TXT", "HTTPS", "CNAME", "NULL"))
            ts = burst_start + timedelta(seconds=idx * self.random.randint(2, 7))
            if ts > end:
                break

            answers = [self._make_malicious_ip(), self._make_malicious_ip()]
            events.append(
                self.factory.build_event(
                    timestamp=ts,
                    source_type="endpoint_dns",
                    source_name="endpoint-win10-malware",
                    client_ip=source_ip,
                    query_name=query_name,
                    query_type=query_type,
                    query_class="IN",
                    response_code="NOERROR",
                    answers=answers,
                    resolver_ip=resolver,
                    ttl=self.random.choice((5, 15, 30)),
                    result="success",
                    result_code="DNS-0",
                    user_id="svc-malware",
                    device_id="HOST-4001",
                    tenant_id="contoso.onmicrosoft.com",
                    domain_category="malicious",
                    is_external_domain=True,
                    query_length=len(query_name),
                    subdomain_depth=query_name.count(".") - 1,
                    response_latency_ms=self.random.randint(90, 220),
                    cache_hit=False,
                    answer_count=len(answers),
                    risk_level="high",
                    policy_decision="deny",
                    label="malicious",
                )
            )

        return events

    def _dga_nxdomain_burst(self, start: datetime, end: datetime) -> list[dict[str, str]]:
        events: list[dict[str, str]] = []
        burst_start = start + timedelta(minutes=self.random.randint(30, 140))
        resolver = self.random.choice(self.resolvers)
        source_ip = self.random.choice(self.source_ips)

        for idx in range(self.random.randint(18, 35)):
            token = "".join(self.random.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(self.random.randint(10, 22)))
            base = self.random.choice(("c2", "update", "agent", "svc", "mail"))
            query_name = f"{token}.{base}{self.random.randint(10, 99)}.net"
            ts = burst_start + timedelta(seconds=idx * self.random.randint(1, 3))
            if ts > end:
                break

            events.append(
                self.factory.build_event(
                    timestamp=ts,
                    source_type="endpoint_dns",
                    source_name="endpoint-win10-malware",
                    client_ip=source_ip,
                    query_name=query_name,
                    query_type=self.random.choice(("A", "AAAA", "TXT")),
                    query_class="IN",
                    response_code="NXDOMAIN",
                    answers=[],
                    resolver_ip=resolver,
                    ttl=0,
                    result="failure",
                    result_code="DNS-9003",
                    user_id="svc-malware",
                    device_id="HOST-4002",
                    tenant_id="contoso.onmicrosoft.com",
                    domain_category="malicious",
                    is_external_domain=True,
                    query_length=len(query_name),
                    subdomain_depth=query_name.count(".") - 1,
                    response_latency_ms=self.random.randint(60, 180),
                    cache_hit=False,
                    answer_count=0,
                    risk_level="high",
                    policy_decision="deny",
                    label="malicious",
                )
            )

        return events

    def _fast_flux_burst(self, start: datetime, end: datetime) -> list[dict[str, str]]:
        events: list[dict[str, str]] = []
        burst_start = start + timedelta(minutes=self.random.randint(70, 190))
        domain = self._make_domain("flux")
        resolver = self.random.choice(self.resolvers)
        source_ip = self.random.choice(self.source_ips)

        for idx in range(self.random.randint(6, 12)):
            answers = [
                self._make_malicious_ip(),
                self._make_malicious_ip(),
                self._make_malicious_ip(),
            ]
            ts = burst_start + timedelta(seconds=idx * self.random.randint(5, 15))
            if ts > end:
                break

            events.append(
                self.factory.build_event(
                    timestamp=ts,
                    source_type="endpoint_dns",
                    source_name="endpoint-win10-malware",
                    client_ip=source_ip,
                    query_name=domain,
                    query_type="A",
                    query_class="IN",
                    response_code="NOERROR",
                    answers=answers,
                    resolver_ip=resolver,
                    ttl=self.random.choice((15, 30, 60)),
                    result="success",
                    result_code="DNS-0",
                    user_id="svc-malware",
                    device_id="HOST-4003",
                    tenant_id="contoso.onmicrosoft.com",
                    domain_category="malicious",
                    is_external_domain=True,
                    query_length=len(domain),
                    subdomain_depth=domain.count(".") - 1,
                    response_latency_ms=self.random.randint(80, 200),
                    cache_hit=False,
                    answer_count=len(answers),
                    risk_level="high",
                    policy_decision="deny",
                    label="malicious",
                )
            )

        return events

    def _beaconing_to_suspicious_domain(self, start: datetime, end: datetime) -> list[dict[str, str]]:
        events: list[dict[str, str]] = []
        burst_start = start + timedelta(minutes=self.random.randint(20, 180))
        domain = self._make_domain("beacon")
        resolver = self.random.choice(self.resolvers)
        source_ip = self.random.choice(self.source_ips)
        interval_seconds = self.random.choice((60, 90, 120, 180, 300))

        for idx in range(self.random.randint(18, 42)):
            ts = burst_start + timedelta(seconds=idx * interval_seconds)
            if ts > end:
                break

            answers = [self._make_malicious_ip()]
            events.append(
                self.factory.build_event(
                    timestamp=ts,
                    source_type="endpoint_dns",
                    source_name="endpoint-win10-malware",
                    client_ip=source_ip,
                    query_name=domain,
                    query_type=self.random.choice(("A", "AAAA", "TXT")),
                    query_class="IN",
                    response_code="NOERROR",
                    answers=answers,
                    resolver_ip=resolver,
                    ttl=self.random.choice((30, 60, 120)),
                    result="success",
                    result_code="DNS-0",
                    user_id="svc-malware",
                    device_id="HOST-4004",
                    tenant_id="contoso.onmicrosoft.com",
                    domain_category="malicious",
                    is_external_domain=True,
                    query_length=len(domain),
                    subdomain_depth=domain.count(".") - 1,
                    response_latency_ms=self.random.randint(40, 140),
                    cache_hit=False,
                    answer_count=len(answers),
                    risk_level="high",
                    policy_decision="deny",
                    label="malicious",
                )
            )

        return events

    def generate(self, start: datetime, end: datetime) -> list[dict[str, str]]:
        events: list[dict[str, str]] = []
        events.extend(self._dns_tunneling_burst(start, end))
        events.extend(self._dga_nxdomain_burst(start, end))
        events.extend(self._fast_flux_burst(start, end))
        events.extend(self._beaconing_to_suspicious_domain(start, end))
        return events
