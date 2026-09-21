from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from math import ceil
from random import Random
from typing import Any

try:
    from .domain_catalog import DomainCatalog
    from .event_factory import EventFactory
    from .personas import PersonaManager
    from .response_engine import DNSResponseEngine
    from .time_scheduler import TimeScheduler
except ImportError:  # pragma: no cover - script-mode fallback
    from domain_catalog import DomainCatalog
    from event_factory import EventFactory
    from personas import PersonaManager
    from response_engine import DNSResponseEngine
    from time_scheduler import TimeScheduler


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

        default_hosts = PersonaManager(random=random).default_hosts()
        self.persona_manager = PersonaManager(random=random, hosts=hosts or default_hosts)
        self.hosts = self.persona_manager.hosts
        self.persona_profiles = self.persona_manager.persona_profiles
        self.domain_catalog = DomainCatalog(random=random, domains=domains, host_profiles=self.hosts)
        self.time_scheduler = TimeScheduler(random=random, factory=factory)
        self.response_engine = DNSResponseEngine(random=random, resolvers=resolvers)
        self.domain_categories = self.domain_catalog.domain_categories
        self.domain_weights = self.domain_catalog.domain_weights
        self.domain_families = self.domain_catalog.domain_families

    def _sample_query(
        self,
        timestamp: datetime,
        host: dict[str, object],
        *,
        app: str | None = None,
        persona: str | None = None,
        domain: str | None = None,
    ) -> QueryPayload:
        app_name = app or self.persona_manager.choose_application_for_host(host, 0)
        persona_name = persona or self.persona_manager.persona_for_host(host)
        chosen_domain = domain or self.domain_catalog.choose_domain_for_host(host, app_name)
        query_type = self.domain_catalog.choose_query_type(chosen_domain)
        response = self.response_engine.sample_response(timestamp, host, chosen_domain, query_type)
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
        self.response_engine.clear()

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

                    app = self.persona_manager.choose_application_for_host(host, weekday)
                    session_start = self.time_scheduler.sample_timestamp(day_start, day_end, host)
                    chain = self._build_domain_chain(host, app, persona)
                    if persona == "resolver":
                        burst_size, gap_seconds = self.time_scheduler.choose_burst(host, profile)
                    else:
                        burst_size, gap_seconds = self.time_scheduler.choose_burst(host, profile)

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
                host = self.persona_manager.choose_host()
                ts = self.time_scheduler.sample_timestamp(start, end, host)
                persona = self.persona_manager.persona_for_host(host)
                app = self.persona_manager.choose_application_for_host(host, ts.weekday())
                domain = self.domain_catalog.choose_domain_for_host(host, app)
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