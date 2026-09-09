from __future__ import annotations

from datetime import datetime, timedelta
from random import Random
from uuid import uuid4

try:
    from .event_factory import EventFactory
except ImportError:  # pragma: no cover - script-mode fallback
    from event_factory import EventFactory


class OvertBreachScenarios:
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
        self.cities = ("Seattle", "Toronto", "Berlin", "London", "Bangalore", "Moscow", "Sao Paulo")
        self.device_platforms = ("windows", "macos", "ios", "android")

    def generate(self, start: datetime, end: datetime) -> list[dict[str, str]]:
        span_seconds = max(1, int((end - start).total_seconds()))
        stuffing_anchor = start + timedelta(seconds=int(span_seconds * 0.25))
        travel_anchor = start + timedelta(seconds=int(span_seconds * 0.48))
        mfa_anchor = start + timedelta(seconds=int(span_seconds * 0.65))
        replay_anchor = start + timedelta(seconds=int(span_seconds * 0.82))

        events: list[dict[str, str]] = []
        events.extend(self._generate_credential_stuffing_sequence(stuffing_anchor, end))
        events.extend(self._generate_impossible_travel_sequence(travel_anchor, end))
        events.extend(self._generate_mfa_fatigue_sequence(mfa_anchor, end))
        events.extend(self._generate_token_replay_sequence(replay_anchor, end))
        return events

    def _pick_member_user(self) -> tuple[str, str]:
        candidates = [user for user in self.users if not user[1].startswith("svc-") and not user[1].startswith("svc_")]
        return self.random.choice(candidates or list(self.users))

    def _build_attack_context(self, app: str, *, geo_country: str, source_ip: str) -> dict[str, str]:
        return {
            "application": app,
            "application_id": f"app-{app.lower()}",
            "resource_id": f"res-{app.lower()}-{self.random.randint(100, 999)}",
            "resource_type": "application",
            "source_ip": source_ip,
            "asn": f"AS{self.random.randint(1200, 64500)}",
            "network_type": "anonymous_proxy" if source_ip in self.external_ips else "corporate",
            "proxy_type": "vpn" if source_ip in self.external_ips else "none",
            "geo_country": geo_country,
            "geo_region": self.random.choice(self.regions),
            "geo_city": self.random.choice(self.cities),
            "device_id": f"atk-dev-{self.random.randint(1000, 9999)}",
            "device_platform": self.random.choice(self.device_platforms),
            "device_trust_type": "unregistered",
            "device_compliance_state": "unknown",
            "device_managed": "false",
            "device_risk_score": str(self.random.randint(65, 95)),
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
        risk_level: str = "high",
        auth_method: str = "password",
        auth_strength: str = "single_factor",
        mfa_method: str = "",
        token_type: str = "bearer",
        grant_type: str = "authorization_code",
        policy_rule_id: str = "rule-detect-overt-risk",
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
            scenario_id="access_overt_v1",
            scenario_phase=scenario_phase,
            attack_family=attack_family,
            message=message,
            label="malicious",
        )

    def _generate_credential_stuffing_sequence(self, start: datetime, end: datetime) -> list[dict[str, str]]:
        self._end_time = end
        app = self.random.choice(self.apps)
        attacker_ip = self.random.choice(self.external_ips)
        attacker_geo = self.random.choice(self.external_geos)
        context = self._build_attack_context(app, geo_country=attacker_geo, source_ip=attacker_ip)

        session_id = uuid4().hex
        trace_id = uuid4().hex
        correlation_id = self.factory.correlation_id()
        targets = self.random.sample(
            [user for user in self.users if not user[1].startswith("svc-") and not user[1].startswith("svc_")],
            k=min(3, max(1, len([user for user in self.users if not user[1].startswith("svc-") and not user[1].startswith("svc_")])))
        )

        events: list[dict[str, str]] = []
        for user_index, (user_id, upn) in enumerate(targets):
            for attempt in range(4):
                ts = start + timedelta(seconds=(user_index * 150) + (attempt * 20))
                events.append(
                    self._build_event(
                        timestamp=ts,
                        user_id=user_id,
                        user_principal_name=upn,
                        session_id=session_id,
                        trace_id=trace_id,
                        correlation_id=correlation_id,
                        attack_family="credential_stuffing",
                        scenario_phase="credential_stuffing",
                        action="sign_in_interactive",
                        result="failure",
                        result_code="A1004",
                        result_reason="invalid_password_spray_pattern",
                        failure_stage="credential_validation",
                        policy_decision="allow",
                        risk_level="high",
                        message=f"Credential stuffing burst: failed interactive sign-in for {upn}",
                        context=context,
                    )
                )

        compromised_user_id, compromised_upn = targets[0] if targets else self._pick_member_user()
        success_time = start + timedelta(minutes=9)
        events.append(
            self._build_event(
                timestamp=success_time,
                user_id=compromised_user_id,
                user_principal_name=compromised_upn,
                session_id=session_id,
                trace_id=trace_id,
                correlation_id=correlation_id,
                attack_family="credential_stuffing",
                scenario_phase="credential_stuffing",
                action="sign_in_interactive",
                result="success",
                result_code="A1000",
                result_reason="credential_reuse_success_after_spray",
                policy_decision="allow",
                risk_level="critical",
                message=f"Credential stuffing success: account takeover likely for {compromised_upn}",
                context=context,
            )
        )
        events.append(
            self._build_event(
                timestamp=success_time + timedelta(seconds=25),
                user_id=compromised_user_id,
                user_principal_name=compromised_upn,
                session_id=session_id,
                trace_id=trace_id,
                correlation_id=correlation_id,
                attack_family="credential_stuffing",
                scenario_phase="credential_stuffing",
                action="conditional_access_eval",
                result="success",
                result_code="A3002",
                result_reason="high_risk_sign_in_allowed_for_observation",
                policy_decision="allow",
                risk_level="critical",
                message=f"Conditional access evaluated risky successful sign-in for {compromised_upn}",
                context=context,
            )
        )
        events.append(
            self._build_event(
                timestamp=success_time + timedelta(seconds=50),
                user_id=compromised_user_id,
                user_principal_name=compromised_upn,
                session_id=session_id,
                trace_id=trace_id,
                correlation_id=correlation_id,
                attack_family="credential_stuffing",
                scenario_phase="credential_stuffing",
                action="token_issue",
                result="success",
                result_code="A2100",
                result_reason="token_issued_after_compromise",
                policy_decision="allow",
                risk_level="critical",
                message=f"Token issued following stuffing success for {compromised_upn}",
                context=context,
            )
        )
        events.append(
            self._build_event(
                timestamp=success_time + timedelta(seconds=75),
                user_id=compromised_user_id,
                user_principal_name=compromised_upn,
                session_id=session_id,
                trace_id=trace_id,
                correlation_id=correlation_id,
                attack_family="credential_stuffing",
                scenario_phase="credential_stuffing",
                action="session_start",
                result="success",
                result_code="A2301",
                result_reason="malicious_session_started",
                policy_decision="allow",
                risk_level="critical",
                message=f"Malicious post-compromise session established for {compromised_upn}",
                context=context,
            )
        )
        events.append(
            self._build_event(
                timestamp=success_time + timedelta(seconds=110),
                user_id=compromised_user_id,
                user_principal_name=compromised_upn,
                session_id=session_id,
                trace_id=trace_id,
                correlation_id=correlation_id,
                attack_family="credential_stuffing",
                scenario_phase="credential_stuffing",
                action="app_launch",
                result="success",
                result_code="A2201",
                result_reason="compromised_app_opened",
                policy_decision="allow",
                risk_level="critical",
                message=f"Compromised actor launched {app} immediately after takeover for {compromised_upn}",
                context=context,
            )
        )
        for index in range(2):
            events.append(
                self._build_event(
                    timestamp=success_time + timedelta(seconds=150 + (index * 40)),
                    user_id=compromised_user_id,
                    user_principal_name=compromised_upn,
                    session_id=session_id,
                    trace_id=trace_id,
                    correlation_id=correlation_id,
                    attack_family="credential_stuffing",
                    scenario_phase="credential_stuffing",
                    action="app_resource_access",
                    result="success",
                    result_code="A2200",
                    result_reason="suspicious_resource_access_after_stuffing",
                    policy_decision="allow",
                    risk_level="critical",
                    message=f"Suspicious resource access after stuffing success for {compromised_upn}",
                    context=context,
                )
            )

        return [event for event in events if event["TimeCreated"] <= end.isoformat()]

    def _generate_impossible_travel_sequence(self, start: datetime, end: datetime) -> list[dict[str, str]]:
        self._end_time = end
        victim_user_id, victim_upn = self._pick_member_user()
        app = self.random.choice(self.apps)

        home_geo = self.random.choice(self.geos)
        attacker_geo = self.random.choice([geo for geo in self.external_geos if geo != home_geo] or list(self.external_geos))

        home_context = self._build_attack_context(
            app,
            geo_country=home_geo,
            source_ip=self.random.choice(self.source_ips),
        )
        home_context["network_type"] = "corporate"
        home_context["proxy_type"] = "none"
        home_context["device_trust_type"] = "registered"
        home_context["device_compliance_state"] = "compliant"
        home_context["device_managed"] = "true"
        home_context["device_risk_score"] = str(self.random.randint(0, 15))

        attacker_context = self._build_attack_context(
            app,
            geo_country=attacker_geo,
            source_ip=self.random.choice(self.external_ips),
        )

        first_session_id = uuid4().hex
        second_session_id = uuid4().hex
        trace_id = uuid4().hex
        correlation_id = self.factory.correlation_id()

        first_ts = start
        second_ts = start + timedelta(minutes=20)
        events = [
            self._build_event(
                timestamp=first_ts,
                user_id=victim_user_id,
                user_principal_name=victim_upn,
                session_id=first_session_id,
                trace_id=trace_id,
                correlation_id=correlation_id,
                attack_family="impossible_travel",
                scenario_phase="impossible_travel",
                action="sign_in_interactive",
                result="success",
                result_code="A1000",
                result_reason="baseline_login_before_travel_impossible_event",
                risk_level="low",
                message=f"Impossible travel baseline login observed for {victim_upn} from {home_geo}",
                context=home_context,
            ),
            self._build_event(
                timestamp=first_ts + timedelta(seconds=35),
                user_id=victim_user_id,
                user_principal_name=victim_upn,
                session_id=first_session_id,
                trace_id=trace_id,
                correlation_id=correlation_id,
                attack_family="impossible_travel",
                scenario_phase="impossible_travel",
                action="session_start",
                result="success",
                result_code="A2301",
                result_reason="baseline_session_started",
                risk_level="low",
                message=f"Baseline session established for {victim_upn} from {home_geo}",
                context=home_context,
            ),
            self._build_event(
                timestamp=second_ts,
                user_id=victim_user_id,
                user_principal_name=victim_upn,
                session_id=second_session_id,
                trace_id=trace_id,
                correlation_id=correlation_id,
                attack_family="impossible_travel",
                scenario_phase="impossible_travel",
                action="sign_in_interactive",
                result="success",
                result_code="A1000",
                result_reason="same_user_success_from_distant_geo",
                risk_level="critical",
                message=f"Impossible travel alert: successful sign-in for {victim_upn} from distant geo {attacker_geo}",
                context=attacker_context,
            ),
            self._build_event(
                timestamp=second_ts + timedelta(seconds=20),
                user_id=victim_user_id,
                user_principal_name=victim_upn,
                session_id=second_session_id,
                trace_id=trace_id,
                correlation_id=correlation_id,
                attack_family="impossible_travel",
                scenario_phase="impossible_travel",
                action="conditional_access_eval",
                result="success",
                result_code="A3003",
                result_reason="impossible_travel_risk_flagged_but_allowed",
                policy_decision="allow",
                risk_level="critical",
                message=f"Conditional access evaluated impossible travel risk for {victim_upn}",
                context=attacker_context,
            ),
            self._build_event(
                timestamp=second_ts + timedelta(seconds=45),
                user_id=victim_user_id,
                user_principal_name=victim_upn,
                session_id=second_session_id,
                trace_id=trace_id,
                correlation_id=correlation_id,
                attack_family="impossible_travel",
                scenario_phase="impossible_travel",
                action="token_issue",
                result="success",
                result_code="A2100",
                result_reason="token_issued_after_impossible_travel_sign_in",
                risk_level="critical",
                message=f"Token issued after impossible travel sign-in for {victim_upn}",
                context=attacker_context,
            ),
            self._build_event(
                timestamp=second_ts + timedelta(seconds=80),
                user_id=victim_user_id,
                user_principal_name=victim_upn,
                session_id=second_session_id,
                trace_id=trace_id,
                correlation_id=correlation_id,
                attack_family="impossible_travel",
                scenario_phase="impossible_travel",
                action="app_resource_access",
                result="success",
                result_code="A2200",
                result_reason="resource_access_from_impossible_travel_session",
                risk_level="critical",
                message=f"Resource access followed impossible travel sign-in for {victim_upn}",
                context=attacker_context,
            ),
        ]

        return [event for event in events if event["TimeCreated"] <= end.isoformat()]

    def _generate_mfa_fatigue_sequence(self, start: datetime, end: datetime) -> list[dict[str, str]]:
        self._end_time = end
        victim_user_id, victim_upn = self._pick_member_user()
        app = self.random.choice(self.apps)
        attacker_ip = self.random.choice(self.external_ips)
        attacker_geo = self.random.choice(self.external_geos)
        context = self._build_attack_context(app, geo_country=attacker_geo, source_ip=attacker_ip)

        session_id = uuid4().hex
        trace_id = uuid4().hex
        correlation_id = self.factory.correlation_id()
        events: list[dict[str, str]] = []

        initial_sign_in_time = start
        events.append(
            self._build_event(
                timestamp=initial_sign_in_time,
                user_id=victim_user_id,
                user_principal_name=victim_upn,
                session_id=session_id,
                trace_id=trace_id,
                correlation_id=correlation_id,
                attack_family="mfa_fatigue",
                scenario_phase="mfa_fatigue",
                action="sign_in_interactive",
                result="success",
                result_code="A1000",
                result_reason="valid_credentials_prior_to_mfa_abuse",
                policy_decision="allow",
                risk_level="high",
                message=f"MFA fatigue setup: valid credential use observed for {victim_upn}",
                context=context,
            )
        )
        events.append(
            self._build_event(
                timestamp=initial_sign_in_time + timedelta(seconds=15),
                user_id=victim_user_id,
                user_principal_name=victim_upn,
                session_id=session_id,
                trace_id=trace_id,
                correlation_id=correlation_id,
                attack_family="mfa_fatigue",
                scenario_phase="mfa_fatigue",
                action="conditional_access_eval",
                result="success",
                result_code="A3001",
                result_reason="mfa_required_for_high_risk_session",
                policy_decision="challenge",
                risk_level="high",
                message=f"Conditional access required MFA for risky session tied to {victim_upn}",
                context=context,
            )
        )

        for prompt in range(8):
            ts = initial_sign_in_time + timedelta(seconds=40 + (prompt * 25))
            events.append(
                self._build_event(
                    timestamp=ts,
                    user_id=victim_user_id,
                    user_principal_name=victim_upn,
                    session_id=session_id,
                    trace_id=trace_id,
                    correlation_id=correlation_id,
                    attack_family="mfa_fatigue",
                    scenario_phase="mfa_fatigue",
                    action="mfa_challenge",
                    result="failure",
                    result_code="A2005",
                    result_reason="user_denied_or_ignored_push_prompt",
                    failure_stage="mfa",
                    policy_decision="challenge",
                    risk_level="high",
                    auth_strength="multi_factor",
                    mfa_method="push",
                    message=f"MFA fatigue pattern: repeated push prompt denied or ignored for {victim_upn}",
                    context=context,
                )
            )

        approval_time = initial_sign_in_time + timedelta(minutes=5)
        events.append(
            self._build_event(
                timestamp=approval_time,
                user_id=victim_user_id,
                user_principal_name=victim_upn,
                session_id=session_id,
                trace_id=trace_id,
                correlation_id=correlation_id,
                attack_family="mfa_fatigue",
                scenario_phase="mfa_fatigue",
                action="mfa_approve",
                result="success",
                result_code="A2000",
                result_reason="unexpected_push_approval",
                policy_decision="allow",
                risk_level="critical",
                auth_strength="multi_factor",
                mfa_method="push",
                message=f"MFA fatigue success: unexpected prompt approval observed for {victim_upn}",
                context=context,
            )
        )
        events.append(
            self._build_event(
                timestamp=approval_time + timedelta(seconds=25),
                user_id=victim_user_id,
                user_principal_name=victim_upn,
                session_id=session_id,
                trace_id=trace_id,
                correlation_id=correlation_id,
                attack_family="mfa_fatigue",
                scenario_phase="mfa_fatigue",
                action="token_issue",
                result="success",
                result_code="A2100",
                result_reason="token_issued_after_mfa_fatigue_success",
                policy_decision="allow",
                risk_level="critical",
                auth_strength="multi_factor",
                mfa_method="push",
                message=f"Token issued after MFA fatigue approval for {victim_upn}",
                context=context,
            )
        )
        events.append(
            self._build_event(
                timestamp=approval_time + timedelta(seconds=55),
                user_id=victim_user_id,
                user_principal_name=victim_upn,
                session_id=session_id,
                trace_id=trace_id,
                correlation_id=correlation_id,
                attack_family="mfa_fatigue",
                scenario_phase="mfa_fatigue",
                action="session_start",
                result="success",
                result_code="A2301",
                result_reason="malicious_session_started_after_mfa_fatigue",
                policy_decision="allow",
                risk_level="critical",
                auth_strength="multi_factor",
                mfa_method="push",
                message=f"Malicious session established after MFA fatigue approval for {victim_upn}",
                context=context,
            )
        )
        events.append(
            self._build_event(
                timestamp=approval_time + timedelta(seconds=85),
                user_id=victim_user_id,
                user_principal_name=victim_upn,
                session_id=session_id,
                trace_id=trace_id,
                correlation_id=correlation_id,
                attack_family="mfa_fatigue",
                scenario_phase="mfa_fatigue",
                action="app_resource_access",
                result="success",
                result_code="A2200",
                result_reason="resource_access_after_fatigue_approval",
                policy_decision="allow",
                risk_level="critical",
                auth_strength="multi_factor",
                mfa_method="push",
                message=f"Suspicious resource access followed MFA fatigue approval for {victim_upn}",
                context=context,
            )
        )

        return [event for event in events if event["TimeCreated"] <= end.isoformat()]

    def _generate_token_replay_sequence(self, start: datetime, end: datetime) -> list[dict[str, str]]:
        self._end_time = end
        victim_user_id, victim_upn = self._pick_member_user()
        app = self.random.choice(self.apps)

        baseline_context = self._build_attack_context(
            app,
            geo_country=self.random.choice(self.geos),
            source_ip=self.random.choice(self.source_ips),
        )
        baseline_context["network_type"] = "corporate"
        baseline_context["proxy_type"] = "none"
        baseline_context["device_trust_type"] = "registered"
        baseline_context["device_compliance_state"] = "compliant"
        baseline_context["device_managed"] = "true"
        baseline_context["device_risk_score"] = str(self.random.randint(0, 15))

        replay_context = self._build_attack_context(
            app,
            geo_country=self.random.choice(self.external_geos),
            source_ip=self.random.choice(self.external_ips),
        )

        initial_session_id = uuid4().hex
        replay_session_id = uuid4().hex
        trace_id = uuid4().hex
        correlation_id = self.factory.correlation_id()

        issue_time = start
        replay_time = start + timedelta(minutes=35)
        events = [
            self._build_event(
                timestamp=issue_time,
                user_id=victim_user_id,
                user_principal_name=victim_upn,
                session_id=initial_session_id,
                trace_id=trace_id,
                correlation_id=correlation_id,
                attack_family="token_theft_replay",
                scenario_phase="token_theft_replay",
                action="sign_in_interactive",
                result="success",
                result_code="A1000",
                result_reason="legitimate_sign_in_preceding_token_theft",
                risk_level="low",
                message=f"Legitimate sign-in issued reusable token for {victim_upn}",
                context=baseline_context,
            ),
            self._build_event(
                timestamp=issue_time + timedelta(seconds=20),
                user_id=victim_user_id,
                user_principal_name=victim_upn,
                session_id=initial_session_id,
                trace_id=trace_id,
                correlation_id=correlation_id,
                attack_family="token_theft_replay",
                scenario_phase="token_theft_replay",
                action="token_issue",
                result="success",
                result_code="A2100",
                result_reason="primary_token_issued_to_legitimate_session",
                risk_level="low",
                message=f"Primary token issued to legitimate session for {victim_upn}",
                context=baseline_context,
            ),
            self._build_event(
                timestamp=replay_time,
                user_id=victim_user_id,
                user_principal_name=victim_upn,
                session_id=replay_session_id,
                trace_id=trace_id,
                correlation_id=correlation_id,
                attack_family="token_theft_replay",
                scenario_phase="token_theft_replay",
                action="token_redeem",
                result="success",
                result_code="A2102",
                result_reason="stolen_token_redeemed_from_new_context",
                risk_level="critical",
                token_type="bearer",
                grant_type="refresh_token",
                message=f"Token replay suspected: previously issued token redeemed from new device for {victim_upn}",
                context=replay_context,
                parent_session_id=initial_session_id,
            ),
            self._build_event(
                timestamp=replay_time + timedelta(seconds=18),
                user_id=victim_user_id,
                user_principal_name=victim_upn,
                session_id=replay_session_id,
                trace_id=trace_id,
                correlation_id=correlation_id,
                attack_family="token_theft_replay",
                scenario_phase="token_theft_replay",
                action="conditional_access_eval",
                result="success",
                result_code="A3004",
                result_reason="session_context_mismatch_detected_after_token_redeem",
                risk_level="critical",
                policy_decision="allow",
                message=f"Conditional access observed token replay indicators for {victim_upn}",
                context=replay_context,
                parent_session_id=initial_session_id,
            ),
            self._build_event(
                timestamp=replay_time + timedelta(seconds=40),
                user_id=victim_user_id,
                user_principal_name=victim_upn,
                session_id=replay_session_id,
                trace_id=trace_id,
                correlation_id=correlation_id,
                attack_family="token_theft_replay",
                scenario_phase="token_theft_replay",
                action="app_resource_access",
                result="success",
                result_code="A2200",
                result_reason="resource_access_with_replayed_token",
                risk_level="critical",
                token_type="bearer",
                grant_type="refresh_token",
                message=f"Suspicious resource access used replayed token for {victim_upn}",
                context=replay_context,
                parent_session_id=initial_session_id,
            ),
            self._build_event(
                timestamp=replay_time + timedelta(seconds=70),
                user_id=victim_user_id,
                user_principal_name=victim_upn,
                session_id=replay_session_id,
                trace_id=trace_id,
                correlation_id=correlation_id,
                attack_family="token_theft_replay",
                scenario_phase="token_theft_replay",
                action="token_refresh",
                result="success",
                result_code="A2101",
                result_reason="replayed_session_refreshed_token_after_access",
                risk_level="critical",
                token_type="bearer",
                grant_type="refresh_token",
                message=f"Replay session refreshed token after suspicious access for {victim_upn}",
                context=replay_context,
                parent_session_id=initial_session_id,
            ),
        ]

        return [event for event in events if event["TimeCreated"] <= end.isoformat()]
