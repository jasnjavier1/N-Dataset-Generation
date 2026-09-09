from __future__ import annotations

from datetime import datetime, timedelta
from random import Random
from uuid import uuid4

try:
    from .event_factory import EventFactory
except ImportError:  # pragma: no cover - script-mode fallback
    from event_factory import EventFactory


class BaselineScenario:
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
        self.regions = ("east", "west", "central")
        self.cities = ("Seattle", "Toronto", "Berlin", "London", "Bangalore")
        self.device_platforms = ("windows", "macos", "ios", "android")

    def _sample_session_start(self, start: datetime, end: datetime) -> datetime:
        # Business-hour weighted distribution with occasional off-hours activity.
        while True:
            ts = self.factory.random_time(start, end)
            if self.random.random() < 0.80:
                if 7 <= ts.hour <= 19:
                    return ts
                continue
            return ts

    def _choose_user_profile(self) -> dict[str, object]:
        user_id, upn = self.random.choice(self.users)
        is_service = upn.startswith("svc-") or upn.startswith("svc_")

        preferred_apps = tuple(self.random.sample(self.apps, k=min(3, len(self.apps))))
        home_geo = self.random.choice(self.geos)
        source_ip = self.random.choice(self.source_ips)
        device_platform = self.random.choices(self.device_platforms, weights=(50, 20, 15, 15), k=1)[0]
        managed = "true" if device_platform in ("windows", "macos") else "false"

        return {
            "user_id": user_id,
            "upn": upn,
            "user_type": "service" if is_service else "member",
            "auth_method": "client_secret" if is_service else "password",
            "auth_strength": "single_factor" if is_service else "single_factor",
            "preferred_apps": preferred_apps,
            "home_geo": home_geo,
            "source_ip": source_ip,
            "device_platform": device_platform,
            "device_trust_type": "registered" if managed == "true" else "unregistered",
            "device_compliance_state": "compliant" if managed == "true" else "unknown",
            "device_managed": managed,
        }

    def _session_actions(self, user_type: str) -> list[str]:
        actions: list[str] = []
        if user_type == "service":
            actions.append("sign_in_noninteractive")
        else:
            actions.append("sign_in_interactive")

        actions.append("conditional_access_eval")

        if user_type != "service" and self.random.random() < 0.65:
            actions.extend(("mfa_challenge", "mfa_approve"))

        actions.append("token_issue")
        if self.random.random() < 0.35:
            actions.append("token_redeem")
        actions.append("session_start")
        actions.append("app_launch")

        access_events = self.random.randint(1, 4)
        actions.extend("app_resource_access" for _ in range(access_events))

        if self.random.random() < 0.45:
            actions.append("token_refresh")

        if user_type != "service":
            actions.append("sign_out")
        actions.append("session_terminate")
        return actions

    def _action_defaults(self, action: str, user_type: str) -> dict[str, str]:
        token_type = "client_credentials" if user_type == "service" else "bearer"
        grant_type = "client_credentials" if user_type == "service" else "authorization_code"

        defaults = {
            "result": "success",
            "result_code": "A0000",
            "result_reason": "completed",
            "failure_stage": "",
            "policy_decision": "allow",
            "risk_level": "low",
            "auth_strength": "single_factor",
            "mfa_method": "",
            "token_type": token_type,
            "grant_type": grant_type,
        }

        if action == "conditional_access_eval":
            defaults.update(
                {
                    "result": "success",
                    "result_code": "A3000",
                    "result_reason": "policy_satisfied",
                }
            )

        if action == "mfa_challenge":
            defaults.update(
                {
                    "result": "challenge",
                    "result_code": "A2001",
                    "result_reason": "additional_authentication_required",
                    "failure_stage": "mfa",
                    "policy_decision": "challenge",
                    "auth_strength": "multi_factor",
                    "mfa_method": "push",
                    "risk_level": "medium",
                }
            )

        if action == "mfa_approve":
            defaults.update(
                {
                    "result": "success",
                    "result_code": "A2000",
                    "result_reason": "mfa_satisfied",
                    "auth_strength": "multi_factor",
                    "mfa_method": "push",
                }
            )

        if action in ("token_issue", "token_refresh", "token_redeem"):
            defaults.update(
                {
                    "result_code": (
                        "A2100"
                        if action == "token_issue"
                        else "A2101"
                        if action == "token_refresh"
                        else "A2102"
                    ),
                    "result_reason": (
                        "token_granted"
                        if action == "token_issue"
                        else "token_refreshed"
                        if action == "token_refresh"
                        else "token_redeemed"
                    ),
                }
            )

        if action in ("app_launch", "app_resource_access"):
            defaults.update(
                {
                    "result_code": "A2201" if action == "app_launch" else "A2200",
                    "result_reason": "application_opened" if action == "app_launch" else "resource_access_granted",
                }
            )

        if action in ("sign_out", "session_terminate"):
            defaults.update(
                {
                    "result_code": "A2300",
                    "result_reason": "session_closed",
                }
            )

        return defaults

    def generate(
        self,
        *,
        start: datetime,
        end: datetime,
        duration_hours: int,
        benign_events_per_hour: int,
    ) -> list[dict[str, str]]:
        total = max(1, duration_hours * benign_events_per_hour)
        events: list[dict[str, str]] = []

        while len(events) < total:
            profile = self._choose_user_profile()
            preferred_apps = profile["preferred_apps"]
            app = self.random.choice(preferred_apps) if isinstance(preferred_apps, tuple) else str(preferred_apps)
            session_start = self._sample_session_start(start=start, end=end)
            session_id = uuid4().hex
            trace_id = uuid4().hex
            correlation_id = self.factory.correlation_id()
            parent_session_id = ""

            geo_country = str(profile["home_geo"])
            geo_region = self.random.choice(self.regions)
            geo_city = self.random.choice(self.cities)
            asn = f"AS{self.random.randint(1200, 64500)}"
            network_type = self.random.choices(("corporate", "home", "mobile"), weights=(50, 35, 15), k=1)[0]
            proxy_type = self.random.choices(("none", "vpn", "ztn"), weights=(75, 20, 5), k=1)[0]
            device_id = f"dev-{self.random.randint(1000, 9999)}"
            device_risk_score = str(self.random.randint(0, 25))
            user_agent = self.factory.pick_user_agent()
            application_id = f"app-{app.lower()}"
            resource_id = f"res-{app.lower()}-{self.random.randint(10, 99)}"
            actions = self._session_actions(user_type=str(profile["user_type"]))

            ts = session_start
            for action in actions:
                defaults = self._action_defaults(action=action, user_type=str(profile["user_type"]))

                message = (
                    f"Baseline access session event {action} for {profile['upn']} "
                    f"on {app} from {geo_country}"
                )

                events.append(
                    self.factory.event(
                        timestamp=self.factory.clamp_to_end(ts, end),
                        user_id=str(profile["user_id"]),
                        user_principal_name=str(profile["upn"]),
                        user_type=str(profile["user_type"]),
                        account_status="enabled",
                        identity_provider="entra_id",
                        action=action,
                        result=defaults["result"],
                        result_code=defaults["result_code"],
                        result_reason=defaults["result_reason"],
                        failure_stage=defaults["failure_stage"],
                        application=app,
                        application_id=application_id,
                        resource_id=resource_id,
                        resource_type="application",
                        source_ip=str(profile["source_ip"]),
                        asn=asn,
                        network_type=network_type,
                        proxy_type=proxy_type,
                        geo_country=geo_country,
                        geo_region=geo_region,
                        geo_city=geo_city,
                        device_id=device_id,
                        device_platform=str(profile["device_platform"]),
                        device_trust_type=str(profile["device_trust_type"]),
                        device_compliance_state=str(profile["device_compliance_state"]),
                        device_managed=str(profile["device_managed"]),
                        device_risk_score=device_risk_score,
                        user_agent=user_agent,
                        auth_method=str(profile["auth_method"]),
                        auth_strength=defaults["auth_strength"],
                        mfa_method=defaults["mfa_method"],
                        token_type=defaults["token_type"],
                        grant_type=defaults["grant_type"],
                        policy_set="default_access_policy",
                        policy_rule_id="rule-allow-low-risk",
                        policy_version="2026.08",
                        session_id=session_id,
                        parent_session_id=parent_session_id,
                        trace_id=trace_id,
                        correlation_id=correlation_id,
                        request_id=self.factory.request_id(),
                        risk_level=defaults["risk_level"],
                        policy_decision=defaults["policy_decision"],
                        scenario_id="access_baseline_v2",
                        scenario_phase="baseline",
                        attack_family="none",
                        message=message,
                        label="benign",
                    )
                )

                if action == "session_start":
                    parent_session_id = session_id

                ts += timedelta(seconds=self.random.randint(20, 240))
                if len(events) >= total:
                    break

        return events
