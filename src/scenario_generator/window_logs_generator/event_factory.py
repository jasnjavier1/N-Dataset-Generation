from __future__ import annotations

from datetime import datetime, timedelta, timezone
from random import Random
from uuid import uuid4

try:
    from .config import GeneratorConfig
except ImportError:  # pragma: no cover - script-mode fallback
    from config import GeneratorConfig


CSV_COLUMNS: tuple[str, ...] = (
    "TimeCreated",
    "EventID",
    "Level",
    "Channel",
    "ProviderName",
    "Computer",
    "SubjectUserName",
    "TargetUserName",
    "TargetDomainName",
    "LogonType",
    "IpAddress",
    "WorkstationName",
    "AuthenticationPackageName",
    "Status",
    "SubStatus",
    "LogonId",
    "ProcessName",
    "Message",
    "Label",
)


class EventFactory:
    def __init__(self, config: GeneratorConfig, random: Random) -> None:
        self.config = config
        self.random = random
        self.provider = "Microsoft-Windows-Security-Auditing"
        self.channel = "Security"

    def build_benign_event(
        self,
        *,
        event_id: int,
        timestamp: datetime,
        user: str,
        computer: str,
        ip: str,
        workstation: str,
        logon_id: str,
    ) -> dict[str, str]:
        if event_id == 4634:
            return self.event(
                timestamp=timestamp,
                event_id=4634,
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
                process_name="C:\\Windows\\System32\\lsass.exe",
                message=f"An account was logged off. User={user}",
                label="benign",
            )

        if event_id == 4648:
            return self.event(
                timestamp=timestamp,
                event_id=4648,
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
                process_name="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                message=f"A logon was attempted using explicit credentials. User={user}",
                label="benign",
            )

        if event_id == 4672:
            return self.event(
                timestamp=timestamp,
                event_id=4672,
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
                process_name="C:\\Windows\\System32\\services.exe",
                message=f"Special privileges assigned to new logon. User={user}",
                label="benign",
            )

        if event_id == 4688:
            process_pool = (
                "C:\\Windows\\System32\\svchost.exe",
                "C:\\Windows\\System32\\taskhostw.exe",
                "C:\\Windows\\System32\\RuntimeBroker.exe",
                "C:\\Windows\\explorer.exe",
                "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE",
                "C:\\Users\\AppData\\Local\\Microsoft\\Teams\\current\\Teams.exe",
                "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
            )
            process_weights = (30, 15, 15, 15, 10, 10, 5)
            process_name = self.random.choices(process_pool, weights=process_weights, k=1)[0]
            return self.event(
                timestamp=timestamp,
                event_id=4688,
                computer=computer,
                subject_user=user,
                target_user=user,
                logon_type="2",
                ip_address=ip,
                workstation=workstation,
                auth_package="Negotiate",
                status="0x0",
                sub_status="0x0",
                logon_id=logon_id,
                process_name=process_name,
                message=f"A new process has been created. User={user}",
                label="benign",
            )

        return self.event(
            timestamp=timestamp,
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
            message=f"An account was successfully logged on. User={user}",
            label="benign",
        )

    def event(
        self,
        *,
        timestamp: datetime,
        event_id: int,
        computer: str,
        subject_user: str,
        target_user: str,
        logon_type: str,
        ip_address: str,
        workstation: str,
        auth_package: str,
        status: str,
        sub_status: str,
        logon_id: str,
        process_name: str,
        message: str,
        label: str,
    ) -> dict[str, str]:
        return {
            "TimeCreated": timestamp.isoformat(),
            "EventID": str(event_id),
            "Level": "Information",
            "Channel": self.channel,
            "ProviderName": self.provider,
            "Computer": computer,
            "SubjectUserName": subject_user,
            "TargetUserName": target_user,
            "TargetDomainName": self.config.domain,
            "LogonType": logon_type,
            "IpAddress": ip_address,
            "WorkstationName": workstation,
            "AuthenticationPackageName": auth_package,
            "Status": status,
            "SubStatus": sub_status,
            "LogonId": logon_id,
            "ProcessName": process_name,
            "Message": message,
            "Label": label,
        }

    def random_time(self, start: datetime, end: datetime) -> datetime:
        total_seconds = int((end - start).total_seconds())
        offset = self.random.randint(0, max(0, total_seconds - 1))
        return start + timedelta(seconds=offset)

    @staticmethod
    def ensure_tz(value: datetime) -> datetime:
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value

    @staticmethod
    def clamp_to_end(value: datetime, end: datetime) -> datetime:
        return value if value <= end else end

    @staticmethod
    def logon_id() -> str:
        return f"0x{uuid4().hex[:8]}"
