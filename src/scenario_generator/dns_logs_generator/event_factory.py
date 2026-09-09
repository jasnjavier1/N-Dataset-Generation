from __future__ import annotations

from datetime import datetime
from random import Random
from uuid import uuid4

try:
    from .config import GeneratorConfig
except ImportError:  # pragma: no cover - script-mode fallback
    from config import GeneratorConfig


CSV_COLUMNS: tuple[str, ...] = (
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
)


class EventFactory:
    def __init__(self, config: GeneratorConfig, random: Random) -> None:
        self.config = config
        self.random = random

    def event_id(self) -> str:
        return f"evt-{uuid4().hex[:12]}"

    def ensure_tz(self, value: datetime) -> datetime:
        return value if value.tzinfo is not None else value.replace(tzinfo=None)

    def random_time(self, start: datetime, end: datetime) -> datetime:
        delta_seconds = max(1, int((end - start).total_seconds()))
        offset = self.random.randint(0, delta_seconds)
        return start + __import__("datetime").timedelta(seconds=offset)

    def clamp_to_end(self, value: datetime, end: datetime) -> datetime:
        if value > end:
            return end
        return value

    def build_event(
        self,
        *,
        timestamp: datetime,
        source_type: str,
        source_name: str,
        client_ip: str,
        query_name: str,
        query_type: str,
        query_class: str,
        response_code: str,
        answers: list[str] | tuple[str, ...] | str,
        resolver_ip: str,
        ttl: int,
        result: str,
        result_code: str,
        user_id: str = "",
        device_id: str = "",
        tenant_id: str = "contoso.onmicrosoft.com",
        domain_category: str = "business",
        is_external_domain: bool = False,
        query_length: int = 0,
        subdomain_depth: int = 0,
        response_latency_ms: int = 0,
        cache_hit: bool = False,
        answer_count: int = 1,
        risk_level: str = "low",
        policy_decision: str = "allow",
        label: str = "benign",
    ) -> dict[str, str]:
        answers_value = ",".join(answers) if isinstance(answers, (list, tuple)) else str(answers)
        return {
            "TimeCreated": timestamp.isoformat(),
            "EventId": self.event_id(),
            "SourceType": source_type,
            "SourceName": source_name,
            "TenantId": tenant_id,
            "DeviceId": device_id,
            "UserId": user_id,
            "ClientIp": client_ip,
            "QueryName": query_name,
            "QueryType": query_type,
            "QueryClass": query_class,
            "ResponseCode": response_code,
            "Answers": answers_value,
            "ResolverIp": resolver_ip,
            "Ttl": str(ttl),
            "AnswerCount": str(answer_count),
            "Result": result,
            "ResultCode": result_code,
            "RiskLevel": risk_level,
            "PolicyDecision": policy_decision,
            "DomainCategory": domain_category,
            "IsExternalDomain": str(bool(is_external_domain)).lower(),
            "QueryLength": str(query_length),
            "SubdomainDepth": str(subdomain_depth),
            "ResponseLatencyMs": str(response_latency_ms),
            "CacheHit": str(bool(cache_hit)).lower(),
            "Label": label,
        }
