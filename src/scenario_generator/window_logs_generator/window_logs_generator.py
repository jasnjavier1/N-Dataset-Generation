from __future__ import annotations

import argparse
from datetime import datetime, timezone
from pathlib import Path

try:
    from .config import GeneratorConfig, parse_start_time
    from .export_csv import write_csv
    from .generator import WindowsSecurityLogGenerator
except ImportError:  # pragma: no cover - script-mode fallback
    from config import GeneratorConfig, parse_start_time
    from export_csv import write_csv
    from generator import WindowsSecurityLogGenerator


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate synthetic Windows Security logs (baseline with optional overt breaches)."
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("output\\windows_security_baseline_v5.csv"),
        help="CSV output path.",
    )
    parser.add_argument(
        "--start-time",
        type=parse_start_time,
        default=datetime.now(timezone.utc).replace(microsecond=0),
        help="ISO start time, e.g. 2026-07-07T00:00:00Z",
    )
    parser.add_argument("--duration-hours", type=int, default=24)
    parser.add_argument("--benign-events-per-hour", type=int, default=60)
    parser.add_argument(
        "--include-breach-examples",
        action="store_true",
        help="Include overt malicious breach examples (credential stuffing, MFA fatigue, impossible travel, ransomware).",
    )
    parser.add_argument(
        "--include-subtle-signals",
        action="store_true",
        help="Include subtle breach signals (password spraying, unusual workstation logon, admin-tool lateral movement).",
    )
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    config = GeneratorConfig(
        output_path=args.output,
        start_time=args.start_time,
        duration_hours=args.duration_hours,
        benign_events_per_hour=args.benign_events_per_hour,
        include_breach_examples=args.include_breach_examples,
        include_subtle_signals=args.include_subtle_signals,
        seed=args.seed,
    )
    generator = WindowsSecurityLogGenerator(config)
    events = generator.generate()
    write_csv(config.output_path, events)
    print(f"Wrote {len(events)} events to {config.output_path}")


if __name__ == "__main__":
    main()
