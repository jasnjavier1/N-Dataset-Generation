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
            start + timedelta(seconds=int(span_seconds * 0.20)),
            start + timedelta(seconds=int(span_seconds * 0.40)),
            start + timedelta(seconds=int(span_seconds * 0.60)),
            start + timedelta(seconds=int(span_seconds * 0.80)),
        )

        events: list[dict[str, str]] = []
        events.extend(self._generate_credential_stuffing_sequence(anchors[0], end))
        events.extend(self._generate_mfa_fatigue_sequence(anchors[1], end))
        events.extend(self._generate_impossible_travel_sequence(anchors[2], end))
        events.extend(self._generate_ransomware_sequence(anchors[3], end))
        return events

    def _generate_credential_stuffing_sequence(self, start: datetime, end: datetime) -> list[dict[str, str]]:
        events: list[dict[str, str]] = []
        attacker_ip = self.random.choice(self.external_ips)
        computer = self.random.choice(self.hosts)
        workstation = "UNKNOWN-REMOTE"
        candidate_users = [u for u in self.users if not u.startswith("svc_")]
        targets = self.random.sample(candidate_users, k=min(3, len(candidate_users)))

        for index, target_user in enumerate(targets):
            for attempt in range(4):
                ts = self.factory.clamp_to_end(
                    start + timedelta(seconds=(index * 120) + (attempt * 20)),
                    end,
                )
                events.append(
                    self.factory.event(
                        timestamp=ts,
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
                        message=f"Credential stuffing: failed sign-in burst for User={target_user}",
                        label="malicious",
                    )
                )

        compromised_user = targets[0] if targets else self.random.choice(self.users)
        success_ts = self.factory.clamp_to_end(start + timedelta(minutes=8), end)
        compromise_logon_id = self.factory.logon_id()
        events.append(
            self.factory.event(
                timestamp=success_ts,
                event_id=4624,
                computer=computer,
                subject_user="SYSTEM",
                target_user=compromised_user,
                logon_type="3",
                ip_address=attacker_ip,
                workstation=workstation,
                auth_package="Negotiate",
                status="0x0",
                sub_status="0x0",
                logon_id=compromise_logon_id,
                process_name="C:\\Windows\\System32\\lsass.exe",
                message=f"Credential stuffing success: account takeover suspected for User={compromised_user}",
                label="malicious",
            )
        )
        events.append(
            self.factory.event(
                timestamp=self.factory.clamp_to_end(success_ts + timedelta(seconds=45), end),
                event_id=4648,
                computer=computer,
                subject_user=compromised_user,
                target_user=compromised_user,
                logon_type="3",
                ip_address=attacker_ip,
                workstation=workstation,
                auth_package="Negotiate",
                status="0x0",
                sub_status="0x0",
                logon_id=compromise_logon_id,
                process_name="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                message=f"Post-compromise credential use for User={compromised_user}",
                label="malicious",
            )
        )

        return events

    def _generate_mfa_fatigue_sequence(self, start: datetime, end: datetime) -> list[dict[str, str]]:
        events: list[dict[str, str]] = []
        victim = self.random.choice([u for u in self.users if not u.startswith("svc_")])
        attacker_ip = self.random.choice(self.external_ips)
        computer = self.random.choice(self.hosts)
        workstation = "UNKNOWN-REMOTE"
        logon_id = self.factory.logon_id()

        for prompt in range(8):
            ts = self.factory.clamp_to_end(start + timedelta(seconds=prompt * 25), end)
            events.append(
                self.factory.event(
                    timestamp=ts,
                    event_id=4625,
                    computer=computer,
                    subject_user="SYSTEM",
                    target_user=victim,
                    logon_type="3",
                    ip_address=attacker_ip,
                    workstation=workstation,
                    auth_package="Negotiate",
                    status="0xC000006D",
                    sub_status="0xC000006A",
                    logon_id=logon_id,
                    process_name="C:\\Windows\\System32\\winlogon.exe",
                    message=f"MFA fatigue pattern: repeated prompt denied/ignored for User={victim}",
                    label="malicious",
                )
            )

        approval_ts = self.factory.clamp_to_end(start + timedelta(minutes=5), end)
        events.append(
            self.factory.event(
                timestamp=approval_ts,
                event_id=4624,
                computer=computer,
                subject_user="SYSTEM",
                target_user=victim,
                logon_type="3",
                ip_address=attacker_ip,
                workstation=workstation,
                auth_package="Negotiate",
                status="0x0",
                sub_status="0x0",
                logon_id=logon_id,
                process_name="C:\\Windows\\System32\\lsass.exe",
                message=f"MFA fatigue success: unexpected approval observed for User={victim}",
                label="malicious",
            )
        )
        events.append(
            self.factory.event(
                timestamp=self.factory.clamp_to_end(approval_ts + timedelta(seconds=30), end),
                event_id=4672,
                computer=computer,
                subject_user=victim,
                target_user=victim,
                logon_type="3",
                ip_address=attacker_ip,
                workstation=workstation,
                auth_package="Negotiate",
                status="0x0",
                sub_status="0x0",
                logon_id=logon_id,
                process_name="C:\\Windows\\System32\\services.exe",
                message=f"MFA fatigue follow-on: elevated session behavior for User={victim}",
                label="malicious",
            )
        )

        return events

    def _generate_impossible_travel_sequence(self, start: datetime, end: datetime) -> list[dict[str, str]]:
        user = self.random.choice([u for u in self.users if not u.startswith("svc_")])
        computer = self.random.choice(self.hosts)
        baseline_ip = self.random.choice(self.internal_ips)
        remote_ip = self.random.choice(self.external_ips)
        logon_id = self.factory.logon_id()

        first_ts = self.factory.clamp_to_end(start, end)
        second_ts = self.factory.clamp_to_end(start + timedelta(minutes=20), end)

        return [
            self.factory.event(
                timestamp=first_ts,
                event_id=4624,
                computer=computer,
                subject_user="SYSTEM",
                target_user=user,
                logon_type="3",
                ip_address=baseline_ip,
                workstation="WKSTN-01",
                auth_package="Negotiate",
                status="0x0",
                sub_status="0x0",
                logon_id=logon_id,
                process_name="C:\\Windows\\System32\\lsass.exe",
                message=f"Impossible travel baseline login for User={user} from US network",
                label="malicious",
            ),
            self.factory.event(
                timestamp=second_ts,
                event_id=4624,
                computer=computer,
                subject_user="SYSTEM",
                target_user=user,
                logon_type="3",
                ip_address=remote_ip,
                workstation="UNKNOWN-REMOTE",
                auth_package="Negotiate",
                status="0x0",
                sub_status="0x0",
                logon_id=logon_id,
                process_name="C:\\Windows\\System32\\lsass.exe",
                message=f"Impossible travel alert: same user login from distant region within 20 minutes for User={user}",
                label="malicious",
            ),
        ]

    def _generate_ransomware_sequence(self, start: datetime, end: datetime) -> list[dict[str, str]]:
        events: list[dict[str, str]] = []
        user = self.random.choice([u for u in self.users if not u.startswith("svc_")])
        computer = "SRV-FILE-01"
        ip = self.random.choice(self.internal_ips)
        workstation = self.random.choice(self.workstations)
        logon_id = self.factory.logon_id()

        process_chain = (
            (
                4688,
                "C:\\Windows\\System32\\cmd.exe",
                "Ransomware behavior: launched shadow copy deletion command",
            ),
            (
                4688,
                "C:\\Windows\\System32\\vssadmin.exe",
                "Ransomware behavior: vssadmin delete shadows /all /quiet",
            ),
            (
                4688,
                "C:\\Windows\\System32\\wbadmin.exe",
                "Ransomware behavior: backup catalog deletion activity",
            ),
            (
                4663,
                "C:\\Windows\\System32\\svchost.exe",
                "Ransomware behavior: rapid file rewrite/encryption activity detected",
            ),
            (
                1102,
                "C:\\Windows\\System32\\wevtutil.exe",
                "Ransomware behavior: audit log clear attempt observed",
            ),
        )

        for index, (event_id, process_name, message) in enumerate(process_chain):
            ts = self.factory.clamp_to_end(start + timedelta(seconds=index * 50), end)
            events.append(
                self.factory.event(
                    timestamp=ts,
                    event_id=event_id,
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
                    process_name=process_name,
                    message=f"{message}. User={user}",
                    label="malicious",
                )
            )

        return events
