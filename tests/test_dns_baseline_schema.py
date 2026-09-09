from __future__ import annotations

from datetime import datetime, timezone

from src.scenario_generator.dns_logs_generator.config import GeneratorConfig
from src.scenario_generator.dns_logs_generator.generator import DnsLogGenerator


def test_dns_baseline_schema_has_core_fields() -> None:
    config = GeneratorConfig(
        output_path="output/dns_baseline_schema_test.csv",
        start_time=datetime.now(timezone.utc).replace(microsecond=0),
        duration_hours=1,
        benign_events_per_hour=5,
        include_breach_examples=False,
        include_subtle_signals=False,
        seed=42,
    )

    events = DnsLogGenerator(config).generate()
    assert events

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
        "ResolvedIps",
        "ResolverIp",
        "Ttl",
        "AnswerCount",
        "Result",
        "ResultCode",
        "RiskLevel",
        "PolicyDecision",
        "Label",
    }

    row = events[0]
    assert required.issubset(row.keys())
    assert row["SourceType"] in {"endpoint_dns", "resolver_dns", "proxy_dns"}
    assert row["Label"] == "benign"


def test_dns_subtle_signals_include_stealthy_patterns() -> None:
    config = GeneratorConfig(
        output_path="output/dns_subtle_signals_test.csv",
        start_time=datetime.now(timezone.utc).replace(microsecond=0),
        duration_hours=24,
        benign_events_per_hour=25,
        include_breach_examples=False,
        include_subtle_signals=True,
        seed=42,
    )

    events = DnsLogGenerator(config).generate()
    assert events

    query_names = [row["QueryName"].lower() for row in events]
    suspicious_markers = (
        "beacon",
        "txt",
        "offhours",
        "entropy",
        "drift",
    )

    assert any(marker in name for name in query_names for marker in suspicious_markers)
    assert any(row["RiskLevel"] == "medium" for row in events)
    assert any(row["RiskLevel"] == "high" for row in events)
