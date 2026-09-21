from __future__ import annotations

from datetime import datetime, timedelta
from random import Random


class TimeScheduler:
    def __init__(self, random: Random, factory: object | None = None) -> None:
        self.random = random
        self.factory = factory

    def hour_weights_for_role(self, role: str) -> dict[int, int]:
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

    def sample_timestamp(self, start: datetime, end: datetime, host: dict[str, object]) -> datetime:
        role = str(host.get("role", "user"))
        hour_weights = self.hour_weights_for_role(role)
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

        if self.factory is not None:
            return self.factory.random_time(start, end)
        return start

    def choose_burst(self, host: dict[str, object], persona_profile: dict[str, object]) -> tuple[int, int]:
        role = str(host.get("role", "user"))
        if role == "resolver":
            return self.random.randint(8, 18), self.random.randint(1, 8)
        return self.random.randint(*persona_profile["burst_size"]), self.random.randint(10, 45)
