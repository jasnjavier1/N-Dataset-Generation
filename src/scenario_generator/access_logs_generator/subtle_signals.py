from __future__ import annotations

from datetime import datetime, timedelta
from random import Random
from uuid import uuid4

try:
    from .event_factory import EventFactory
except ImportError:  # pragma: no cover - script-mode fallback
    from event_factory import EventFactory


class SubtleBreachScenarios:
    def __init__(
        self,
        random: Random,
        factory: EventFactory,
        users: tuple[tuple[str, str], ...],
        apps: tuple[str, ...],
        geos: tuple[str, ...],
        source_ips: tuple[str, ...],
    ) -> None:
        self.random = random
        self.factory = factory
        self.users = users
        self.apps = apps
        self.geos = geos
        self.source_ips = source_ips
        self.external_ips = ("203.0.113.44", "198.51.100.87", "45.95.147.22", "91.219.236.31")
        self.external_geos = ("RU", "CN", "IR", "BR")
        self.regions = ("east", "west", "central")
        self.cities = ("Seattle", "Toronto", "Berlin", "London", "Bangalore", "Dublin")
        self.device_platforms = ("windows", "macos", "ios", "android")

    def generate(self, start: datetime, end: datetime) -> list[dict[str, str]]:
        span_seconds = max(1, int((end - start).total_seconds()))
        anchors = (
            start + timedelta(seconds=int(span_seconds * 0.15)),
            start + timedelta(seconds=int(span_seconds * 0.42)),
            start + timedelta(seconds=int(span_seconds * 0.64)),
            start + timedelta(seconds=int(span_seconds * 0.83)),
        )

        events: list[dict[str, str]] = []
        events.extend(self._generate_low_and_slow_exfiltration(anchors[0], end))
        events.extend(self._generate_token_session_reuse_new_context(anchors[1], end))
        events.extend(self._generate_reconnaissance_browsing(anchors[2], end))
        events.extend(self._generate_rare_resource_access(anchors[3], end))
        return events

    def _pick_member_user(self) -> tuple[str, str]:
        candidates = [user for user in self.users if not user[1].startswith("svc-") and not user[1].startswith("svc_")]
        return self.random.choice(candidates or list(self.users))

    def _build_context(self, app: str, *, geo_country: str, source_ip: str, managed: bool = True) -> dict[str, str]:
        return {
            "application": app,
            "application_id": f"app-{app.lower()}",
            "resource_id": f"res-{app.lower()}-{self.random.randint(100, 999)}",
            "resource_type": "application",
            "source_ip": source_ip,
            "asn": f"AS{self.random.randint(1200, 64500)}",
            "network_type": "corporate" if source_ip in self.source_ips else "home",
            "proxy_type": "none" if source_ip in self.source_ips else "vpn",
            "geo_country": geo_country,
            "geo_region": self.random.choice(self.regions),
            "geo_city": self.random.choice(self.cities),
            "device_id": f"subtle-dev-{self.random.randint(1000, 9999)}",
            "device_platform": self.random.choice(self.device_platforms),
            "device_trust_type": "registered" if managed else "unregistered",
            "device_compliance_state": "compliant" if managed else "unknown",
            "device_managed": "true" if managed else "false",
            "device_risk_score": str(self.random.randint(10, 45) if managed else self.random.randint(35, 65)),
            "user_agent": self.factory.pick_user_agent(),
            "identity_provider": "entra_id",
            "account_status": "enabled",
            "tenant_region": "global",
            "policy_set": "default_access_policy",
            "policy_version": "2026.08",
        }

    def _build_event(
        self,
        *,
        timestamp: datetime,
        user_id: str,
        user_principal_name: str,
        session_id: str,
        trace_id: str,
        correlation_id: str,
        attack_family: str,
        scenario_phase: str,
        action: str,
        result: str,
        message: str,
        context: dict[str, str],
        result_code: str = "",
        result_reason: str = "",
        failure_stage: str = "",
        policy_decision: str = "allow",
        risk_level: str = "medium",
        auth_method: str = "password",
        auth_strength: str = "single_factor",
        mfa_method: str = "",
        token_type: str = "bearer",
        grant_type: str = "authorization_code",
        policy_rule_id: str = "rule-monitor-subtle-signals",
        parent_session_id: str = "",
    ) -> dict[str, str]:
        return self.factory.event(
            timestamp=self.factory.clamp_to_end(timestamp, self._end_time),
            user_id=user_id,
            user_principal_name=user_principal_name,
            user_type="member",
            account_status=context["account_status"],
            identity_provider=context["identity_provider"],
            tenant_region=context["tenant_region"],
            action=action,
            result=result,
            result_code=result_code,
            result_reason=result_reason,
            failure_stage=failure_stage,
            application=context["application"],
            application_id=context["application_id"],
            resource_id=context["resource_id"],
            resource_type=context["resource_type"],
            source_ip=context["source_ip"],
            asn=context["asn"],
            network_type=context["network_type"],
            proxy_type=context["proxy_type"],
            geo_country=context["geo_country"],
            geo_region=context["geo_region"],
            geo_city=context["geo_city"],
            device_id=context["device_id"],
            device_platform=context["device_platform"],
            device_trust_type=context["device_trust_type"],
            device_compliance_state=context["device_compliance_state"],
            device_managed=context["device_managed"],
            device_risk_score=context["device_risk_score"],
            user_agent=context["user_agent"],
            auth_method=auth_method,
            auth_strength=auth_strength,
            mfa_method=mfa_method,
            token_type=token_type,
            grant_type=grant_type,
            policy_set=context["policy_set"],
            policy_rule_id=policy_rule_id,
            policy_version=context["policy_version"],
            session_id=session_id,
            parent_session_id=parent_session_id,
            trace_id=trace_id,
            correlation_id=correlation_id,
            request_id=self.factory.request_id(),
            risk_level=risk_level,
            policy_decision=policy_decision,
            scenario_id="access_subtle_v1",
            scenario_phase=scenario_phase,
            attack_family=attack_family,
            message=message,
            label="malicious",
        )

    def _generate_low_and_slow_exfiltration(self, start: datetime, end: datetime) -> list[dict[str, str]]:
        self._end_time = end
        user_id, upn = self._pick_member_user()
        app = self.random.choice(self.apps)
        context = self._build_context(
            app,
            geo_country=self.random.choice(self.geos),
            source_ip=self.random.choice(self.source_ips),
            managed=True,
        )

        session_id = uuid4().hex
        trace_id = uuid4().hex
        correlation_id = self.factory.correlation_id()
        events: list[dict[str, str]] = [
            self._build_event(
                timestamp=start,
                user_id=user_id,
                user_principal_name=upn,
                session_id=session_id,
                trace_id=trace_id,
                correlation_id=correlation_id,
                attack_family="subtle_low_slow_exfiltration",
                scenario_phase="low_slow_exfiltration",
                action="sign_in_interactive",
                result="success",
                result_code="A1000",
                result_reason="routine_access_session_started",
                risk_level="low",
                message=f"Low-and-slow exfiltration staging: normal login observed for {upn}",
                context=context,
            ),
            self._build_event(
                timestamp=start + timedelta(minutes=3),
                user_id=user_id,
                user_principal_name=upn,
                session_id=session_id,
                trace_id=trace_id,
                correlation_id=correlation_id,
                attack_family="subtle_low_slow_exfiltration",
                scenario_phase="low_slow_exfiltration",
                action="token_issue",
                result="success",
                result_code="A2100",
                result_reason="token_issued_for_session",
                risk_level="low",
                message=f"Low-and-slow exfiltration staging: token issuance for {upn}",
                context=context,
            ),
        ]

        for idx in range(4):
            events.append(
                self._build_event(
                    timestamp=start + timedelta(minutes=35 + (idx * 42)),
                    user_id=user_id,
                    user_principal_name=upn,
                    session_id=session_id,
                    trace_id=trace_id,
                    correlation_id=correlation_id,
                    attack_family="subtle_low_slow_exfiltration",
                    scenario_phase="low_slow_exfiltration",
                    action="app_resource_access",
                    result="success",
                    result_code="A2200",
                    result_reason="periodic_access_to_sensitive_resource",
                    risk_level="medium",
                    message=f"Low-and-slow exfiltration pattern: periodic resource access by {upn}",
                    context=context,
                )
            )

        events.append(
            self._build_event(
                timestamp=start + timedelta(minutes=220),
                user_id=user_id,
                user_principal_name=upn,
                session_id=session_id,
                trace_id=trace_id,
                correlation_id=correlation_id,
                attack_family="subtle_low_slow_exfiltration",
                scenario_phase="low_slow_exfiltration",
                action="token_refresh",
                result="success",
                result_code="A2101",
                result_reason="long_running_session_token_refreshed",
                risk_level="medium",
                message=f"Low-and-slow exfiltration pattern: long session token refresh for {upn}",
                context=context,
            )
        )

        return [event for event in events if event["TimeCreated"] <= end.isoformat()]

    def _generate_token_session_reuse_new_context(self, start: datetime, end: datetime) -> list[dict[str, str]]:
        self._end_time = end
        user_id, upn = self._pick_member_user()
        app = self.random.choice(self.apps)

        baseline_context = self._build_context(
            app,
            geo_country=self.random.choice(self.geos),
            source_ip=self.random.choice(self.source_ips),
            managed=True,
        )
        drift_geo_pool = [geo for geo in self.geos if geo != baseline_context["geo_country"]]
        reuse_context = self._build_context(
            app,
            geo_country=self.random.choice(drift_geo_pool or self.geos),
            source_ip=self.random.choice(self.external_ips if self.random.random() < 0.45 else self.source_ips),
            managed=False,
        )

        parent_session_id = uuid4().hex
        replay_session_id = uuid4().hex
        trace_id = uuid4().hex
        correlation_id = self.factory.correlation_id()

        events = [
            self._build_event(
                timestamp=start,
                user_id=user_id,
                user_principal_name=upn,
                session_id=parent_session_id,
                trace_id=trace_id,
                correlation_id=correlation_id,
                attack_family="subtle_token_session_reuse",
                scenario_phase="token_session_reuse",
                action="sign_in_interactive",
                result="success",
                result_code="A1000",
                result_reason="normal_session_started",
                risk_level="low",
                message=f"Token/session reuse setup: baseline login for {upn}",
                context=baseline_context,
            ),
            self._build_event(
                timestamp=start + timedelta(minutes=2),
                user_id=user_id,
                user_principal_name=upn,
                session_id=parent_session_id,
                trace_id=trace_id,
                correlation_id=correlation_id,
                attack_family="subtle_token_session_reuse",
                scenario_phase="token_session_reuse",
                action="token_issue",
                result="success",
                result_code="A2100",
                result_reason="token_issued_for_normal_session",
                risk_level="low",
                message=f"Token/session reuse setup: token issued for {upn}",
                context=baseline_context,
            ),
            self._build_event(
                timestamp=start + timedelta(minutes=55),
                user_id=user_id,
                user_principal_name=upn,
                session_id=replay_session_id,
                parent_session_id=parent_session_id,
                trace_id=trace_id,
                correlation_id=correlation_id,
                attack_family="subtle_token_session_reuse",
                scenario_phase="token_session_reuse",
                action="token_redeem",
                result="success",
                result_code="A2102",
                result_reason="token_redeemed_from_new_context",
                risk_level="medium",
                token_type="bearer",
                grant_type="refresh_token",
                message=f"Subtle token/session reuse: token redeemed from new context for {upn}",
                context=reuse_context,
            ),
            self._build_event(
                timestamp=start + timedelta(minutes=58),
                user_id=user_id,
                user_principal_name=upn,
                session_id=replay_session_id,
                parent_session_id=parent_session_id,
                trace_id=trace_id,
                correlation_id=correlation_id,
                attack_family="subtle_token_session_reuse",
                scenario_phase="token_session_reuse",
                action="app_resource_access",
                result="success",
                result_code="A2200",
                result_reason="resource_access_after_context_shift",
                risk_level="medium",
                token_type="bearer",
                grant_type="refresh_token",
                message=f"Subtle token/session reuse: resource access after session context drift for {upn}",
                context=reuse_context,
            ),
        ]

        return [event for event in events if event["TimeCreated"] <= end.isoformat()]

    def _generate_reconnaissance_browsing(self, start: datetime, end: datetime) -> list[dict[str, str]]:
        self._end_time = end
        user_id, upn = self._pick_member_user()
        base_geo = self.random.choice(self.geos)
        source_ip = self.random.choice(self.source_ips)

        session_id = uuid4().hex
        trace_id = uuid4().hex
        correlation_id = self.factory.correlation_id()
        scout_apps = self.random.sample(self.apps, k=min(3, len(self.apps)))
        events: list[dict[str, str]] = []

        for idx, app in enumerate(scout_apps):
            context = self._build_context(app, geo_country=base_geo, source_ip=source_ip, managed=True)
            launch_ts = start + timedelta(minutes=idx * 18)
            events.append(
                self._build_event(
                    timestamp=launch_ts,
                    user_id=user_id,
                    user_principal_name=upn,
                    session_id=session_id,
                    trace_id=trace_id,
                    correlation_id=correlation_id,
                    attack_family="subtle_recon_browsing",
                    scenario_phase="recon_browsing",
                    action="app_launch",
                    result="success",
                    result_code="A2201",
                    result_reason="cross_application_browsing",
                    risk_level="low",
                    message=f"Recon browsing: launched {app} during broad discovery activity by {upn}",
                    context=context,
                )
            )
            events.append(
                self._build_event(
                    timestamp=launch_ts + timedelta(minutes=2),
                    user_id=user_id,
                    user_principal_name=upn,
                    session_id=session_id,
                    trace_id=trace_id,
                    correlation_id=correlation_id,
                    attack_family="subtle_recon_browsing",
                    scenario_phase="recon_browsing",
                    action="app_resource_access",
                    result="success",
                    result_code="A2200",
                    result_reason="shallow_listing_access_pattern",
                    risk_level="medium",
                    message=f"Recon browsing: shallow listing-style resource access in {app} by {upn}",
                    context=context,
                )
            )

        return [event for event in events if event["TimeCreated"] <= end.isoformat()]

    def _generate_rare_resource_access(self, start: datetime, end: datetime) -> list[dict[str, str]]:
        self._end_time = end
        user_id, upn = self._pick_member_user()
        app = self.random.choice(self.apps)
        context = self._build_context(
            app,
            geo_country=self.random.choice(self.geos),
            source_ip=self.random.choice(self.source_ips),
            managed=True,
        )
        # Rare access is subtle: normal context, unusual target and timing.
        context["resource_id"] = f"res-sensitive-{app.lower()}-{self.random.randint(5000, 9999)}"

        session_id = uuid4().hex
        trace_id = uuid4().hex
        correlation_id = self.factory.correlation_id()

        events = [
            self._build_event(
                timestamp=start,
                user_id=user_id,
                user_principal_name=upn,
                session_id=session_id,
                trace_id=trace_id,
                correlation_id=correlation_id,
                attack_family="subtle_rare_resource_access",
                scenario_phase="rare_resource_access",
                action="sign_in_interactive",
                result="success",
                result_code="A1000",
                result_reason="off_pattern_but_valid_login",
                risk_level="low",
                message=f"Rare resource access setup: valid sign-in for {upn}",
                context=context,
            ),
            self._build_event(
                timestamp=start + timedelta(minutes=4),
                user_id=user_id,
                user_principal_name=upn,
                session_id=session_id,
                trace_id=trace_id,
                correlation_id=correlation_id,
                attack_family="subtle_rare_resource_access",
                scenario_phase="rare_resource_access",
                action="app_resource_access",
                result="success",
                result_code="A2200",
                result_reason="rare_sensitive_resource_access",
                risk_level="medium",
                message=f"Rare resource access: unusual sensitive resource touched by {upn}",
                context=context,
            ),
            self._build_event(
                timestamp=start + timedelta(minutes=9),
                user_id=user_id,
                user_principal_name=upn,
                session_id=session_id,
                trace_id=trace_id,
                correlation_id=correlation_id,
                attack_family="subtle_rare_resource_access",
                scenario_phase="rare_resource_access",
                action="token_refresh",
                result="success",
                result_code="A2101",
                result_reason="session_maintained_after_rare_access",
                risk_level="medium",
                message=f"Rare resource access: token refresh after uncommon access pattern for {upn}",
                context=context,
            ),
        ]

        return [event for event in events if event["TimeCreated"] <= end.isoformat()]
