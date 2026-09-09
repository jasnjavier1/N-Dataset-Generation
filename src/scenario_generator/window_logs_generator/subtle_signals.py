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
        hosts: tuple[str, ...],
        users: tuple[str, ...],
        workstations: tuple[str, ...],
        internal_ips: tuple[str, ...],
        external_ips: tuple[str, ...],
    ) -> None:
        self.random = random
        self.factory = factory
        self.hosts = hosts
        self.users = users
        self.workstations = workstations
        self.internal_ips = internal_ips
        self.external_ips = external_ips

    def generate(self, start: datetime, end: datetime) -> list[dict[str, str]]:
        span_seconds = max(1, int((end - start).total_seconds()))
        anchors = (
            start + timedelta(seconds=int(span_seconds * 0.15)),
            start + timedelta(seconds=int(span_seconds * 0.50)),
            start + timedelta(seconds=int(span_seconds * 0.75)),
        )

        events: list[dict[str, str]] = []
        events.extend(self._generate_low_and_slow_password_spraying(anchors[0], end))
        events.extend(self._generate_unusual_workstation_logon(anchors[1], end))
        events.extend(self._generate_lateral_movement_admin_tools(anchors[2], end))
        return events

    def _generate_low_and_slow_password_spraying(self, start: datetime, end: datetime) -> list[dict[str, str]]:
        events: list[dict[str, str]] = []
        attacker_ip = self.random.choice(self.external_ips)
        computer = self.random.choice(self.hosts)
        workstation = "UNKNOWN-REMOTE"
        candidate_users = [user for user in self.users if not user.startswith("svc_")]
        targets = self.random.sample(candidate_users, k=min(4, len(candidate_users)))

        for index, target_user in enumerate(targets):
            failure_ts = self.factory.clamp_to_end(start + timedelta(minutes=index * 35), end)
            events.append(
                self.factory.event(
                    timestamp=failure_ts,
                    event_id=4625,
                    computer=computer,
                    subject_user="SYSTEM",
                    target_user=target_user,
                    logon_type="3",
                    ip_address=attacker_ip,
                    workstation=workstation,
                    auth_package="Negotiate",
                    status="0xC000006D",
                    sub_status="0xC000006A",
                    logon_id=self.factory.logon_id(),
                    process_name="C:\\Windows\\System32\\winlogon.exe",
                    message=f"Low-and-slow password spray: single failed sign-in for User={target_user}",
                    label="malicious",
                )
            )

        if targets:
            success_user = targets[0]
            success_ts = self.factory.clamp_to_end(start + timedelta(hours=3), end)
            events.append(
                self.factory.event(
                    timestamp=success_ts,
                    event_id=4624,
                    computer=computer,
                    subject_user="SYSTEM",
                    target_user=success_user,
                    logon_type="3",
                    ip_address=attacker_ip,
                    workstation=workstation,
                    auth_package="Negotiate",
                    status="0x0",
                    sub_status="0x0",
                    logon_id=self.factory.logon_id(),
                    process_name="C:\\Windows\\System32\\lsass.exe",
                    message=f"Low-and-slow spray success observed for User={success_user}",
                    label="malicious",
                )
            )

        return events

    def _generate_unusual_workstation_logon(self, start: datetime, end: datetime) -> list[dict[str, str]]:
        user = self.random.choice([user for user in self.users if not user.startswith("svc_")])
        computer = self.random.choice(self.hosts)
        workstation = self.random.choice(("ENG-LAPTOP-14", "REMOTE-JUMP-22", "WKSTN-99", "LAPTOP-UNLISTED-07"))
        ip = self.random.choice(self.internal_ips)
        logon_id = self.factory.logon_id()
        logon_ts = self.factory.clamp_to_end(start + timedelta(minutes=20), end)

        events = [
            self.factory.event(
                timestamp=logon_ts,
                event_id=4624,
                computer=computer,
                subject_user="SYSTEM",
                target_user=user,
                logon_type="3",
                ip_address=ip,
                workstation=workstation,
                auth_package="Negotiate",
                status="0x0",
                sub_status="0x0",
                logon_id=logon_id,
                process_name="C:\\Windows\\System32\\lsass.exe",
                message=f"Login from unusual workstation observed for User={user} on {workstation}",
                label="malicious",
            ),
            self.factory.event(
                timestamp=self.factory.clamp_to_end(logon_ts + timedelta(minutes=3), end),
                event_id=4688,
                computer=computer,
                subject_user=user,
                target_user=user,
                logon_type="3",
                ip_address=ip,
                workstation=workstation,
                auth_package="Negotiate",
                status="0x0",
                sub_status="0x0",
                logon_id=logon_id,
                process_name="C:\\Windows\\explorer.exe",
                message=f"Suspicious follow-on activity after unusual workstation logon for User={user}",
                label="malicious",
            ),
        ]
        return events

    def _generate_lateral_movement_admin_tools(self, start: datetime, end: datetime) -> list[dict[str, str]]:
        events: list[dict[str, str]] = []
        admin_user = self.random.choice([user for user in self.users if not user.startswith("svc_")])
        source_host = self.random.choice(("WIN10-CLIENT1", "WIN10-CLIENT2"))
        target_host = self.random.choice(("SRV-APP-01", "SRV-FILE-01"))
        ip = self.random.choice(self.internal_ips)
        workstation = self.random.choice(self.workstations)
        logon_id = self.factory.logon_id()
        base_ts = self.factory.clamp_to_end(start + timedelta(minutes=45), end)

        events.append(
            self.factory.event(
                timestamp=base_ts,
                event_id=4624,
                computer=target_host,
                subject_user="SYSTEM",
                target_user=admin_user,
                logon_type="3",
                ip_address=ip,
                workstation=workstation,
                auth_package="Negotiate",
                status="0x0",
                sub_status="0x0",
                logon_id=logon_id,
                process_name="C:\\Windows\\System32\\lsass.exe",
                message=f"Administrative logon to {target_host} for User={admin_user}",
                label="malicious",
            )
        )
        events.append(
            self.factory.event(
                timestamp=self.factory.clamp_to_end(base_ts + timedelta(minutes=2), end),
                event_id=4672,
                computer=target_host,
                subject_user=admin_user,
                target_user=admin_user,
                logon_type="3",
                ip_address=ip,
                workstation=workstation,
                auth_package="Negotiate",
                status="0x0",
                sub_status="0x0",
                logon_id=logon_id,
                process_name="C:\\Windows\\System32\\services.exe",
                message=f"Special privileges assigned during admin session for User={admin_user}",
                label="malicious",
            )
        )
        events.append(
            self.factory.event(
                timestamp=self.factory.clamp_to_end(base_ts + timedelta(minutes=4), end),
                event_id=4688,
                computer=target_host,
                subject_user=admin_user,
                target_user=admin_user,
                logon_type="3",
                ip_address=ip,
                workstation=workstation,
                auth_package="Negotiate",
                status="0x0",
                sub_status="0x0",
                logon_id=logon_id,
                process_name="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                message=f"Remote admin tool usage detected on {target_host} for User={admin_user}",
                label="malicious",
            )
        )
        events.append(
            self.factory.event(
                timestamp=self.factory.clamp_to_end(base_ts + timedelta(minutes=7), end),
                event_id=4688,
                computer=target_host,
                subject_user=admin_user,
                target_user=admin_user,
                logon_type="3",
                ip_address=ip,
                workstation=workstation,
                auth_package="Negotiate",
                status="0x0",
                sub_status="0x0",
                logon_id=logon_id,
                process_name="C:\\Windows\\System32\\wbem\\wmic.exe",
                message=f"Lateral movement via legitimate admin tooling on {target_host} for User={admin_user}",
                label="malicious",
            )
        )
        events.append(
            self.factory.event(
                timestamp=self.factory.clamp_to_end(base_ts + timedelta(minutes=10), end),
                event_id=4688,
                computer=target_host,
                subject_user=admin_user,
                target_user=admin_user,
                logon_type="3",
                ip_address=ip,
                workstation=workstation,
                auth_package="Negotiate",
                status="0x0",
                sub_status="0x0",
                logon_id=logon_id,
                process_name="C:\\Windows\\System32\\schtasks.exe",
                message=f"Scheduled task created during remote admin activity on {target_host} for User={admin_user}",
                label="malicious",
            )
        )

        return events
