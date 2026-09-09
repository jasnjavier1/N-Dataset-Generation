from __future__ import annotations

from datetime import datetime, timezone

try:
    from .config import GeneratorConfig
    from .generator import DnsLogGenerator
except ImportError:  # pragma: no cover - script-mode fallback
    from config import GeneratorConfig
    from generator import DnsLogGenerator


def sample_events() -> list[dict[str, str]]:
    config = GeneratorConfig(
        output_path="output/dns_sample.csv",
        start_time=datetime.now(timezone.utc).replace(microsecond=0),
        duration_hours=1,
        benign_events_per_hour=5,
        include_breach_examples=True,
        include_subtle_signals=True,
        seed=42,
    )
    return DnsLogGenerator(config).generate()
