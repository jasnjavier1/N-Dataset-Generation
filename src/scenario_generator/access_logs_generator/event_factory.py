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
    "EventId",
    "EventType",
    "EventCategory",
    "SchemaVersion",
    "IngestSource",
    "TenantId",
    "TenantRegion",
    "UserId",
    "UserPrincipalName",
    "UserType",
    "AccountStatus",
    "IdentityProvider",
    "ApplicationId",
    "Action",
    "ActionFamily",
    "Result",
    "ResultCode",
    "ResultReason",
    "FailureStage",
    "Application",
    "ResourceId",
    "ResourceType",
    "SourceIp",
    "Asn",
    "NetworkType",
    "ProxyType",
    "GeoCountry",
    "GeoRegion",
    "GeoCity",
    "DeviceId",
    "DevicePlatform",
    "DeviceTrustType",
    "DeviceComplianceState",
    "DeviceManaged",
    "DeviceRiskScore",
    "UserAgent",
    "AuthMethod",
    "AuthStrength",
    "MfaMethod",
    "TokenType",
    "GrantType",
    "PolicySet",
    "PolicyRuleId",
    "PolicyVersion",
    "CorrelationId",
    "RequestId",
    "SessionId",
    "ParentSessionId",
    "TraceId",
    "RiskLevel",
    "PolicyDecision",
    "ScenarioId",
    "ScenarioPhase",
    "AttackFamily",
    "Message",
    "Label",
)


class EventFactory:
    def __init__(self, config: GeneratorConfig, random: Random) -> None:
        self.config = config
        self.random = random

    def event_id(self) -> str:
        return f"evt-{uuid4().hex[:12]}"

    def request_id(self) -> str:
        return f"req-{uuid4().hex[:12]}"

    def correlation_id(self) -> str:
        return f"corr-{uuid4().hex[:12]}"

    def action_family(self, action: str) -> str:
        if action in ("sign_in_interactive", "sign_in_noninteractive", "password_reset_request", "password_reset_complete"):
            return "authentication"
        if action in ("mfa_challenge", "mfa_approve", "mfa_deny"):
            return "mfa"
        if action in ("token_issue", "token_refresh", "token_redeem", "token_revocation"):
            return "token"
        if action in ("session_start", "session_resume", "session_terminate", "sign_out"):
            return "session"
        if action in ("conditional_access_eval", "policy_challenge", "policy_block"):
            return "policy"
        if action in ("app_launch", "app_resource_access", "app_admin_action"):
            return "application"
        if action in ("role_assignment", "consent_grant", "service_principal_auth"):
            return "identity_admin"
        return "other"

    def normalize_outcome(
        self,
        *,
        action: str,
        result: str,
        result_code: str = "",
        result_reason: str = "",
        failure_stage: str = "",
        policy_decision: str = "",
        risk_level: str = "",
        auth_strength: str = "",
        mfa_method: str = "",
    ) -> dict[str, str]:
        normalized_result = result or "success"
        normalized_result_code = result_code
        normalized_result_reason = result_reason
        normalized_failure_stage = failure_stage
        normalized_policy_decision = policy_decision or "allow"
        normalized_risk_level = risk_level or "low"
        normalized_auth_strength = auth_strength or "single_factor"
        normalized_mfa_method = mfa_method

        if action == "mfa_challenge":
            normalized_result = normalized_result or "challenge"
            normalized_result_code = normalized_result_code or "A2001"
            normalized_result_reason = normalized_result_reason or "additional_authentication_required"
            normalized_failure_stage = normalized_failure_stage or "mfa"
            normalized_policy_decision = normalized_policy_decision or "challenge"
            normalized_auth_strength = "multi_factor"
            normalized_mfa_method = normalized_mfa_method or "push"

        if action == "policy_challenge":
            normalized_result = "challenge"
            normalized_result_code = normalized_result_code or "A3101"
            normalized_result_reason = normalized_result_reason or "policy_additional_controls_required"
            normalized_failure_stage = normalized_failure_stage or "policy_evaluation"
            normalized_policy_decision = "challenge"
            normalized_risk_level = normalized_risk_level if normalized_risk_level != "low" else "medium"

        if action == "policy_block":
            normalized_result = "blocked"
            normalized_result_code = normalized_result_code or "A3403"
            normalized_result_reason = normalized_result_reason or "risk_policy_block"
            normalized_failure_stage = normalized_failure_stage or "policy_evaluation"
            normalized_policy_decision = "deny"
            normalized_risk_level = normalized_risk_level if normalized_risk_level != "low" else "high"

        if normalized_result == "failure":
            normalized_result_code = normalized_result_code or "A1003"
            normalized_result_reason = normalized_result_reason or "invalid_or_expired_credentials"
            normalized_failure_stage = normalized_failure_stage or "credential_validation"
            normalized_risk_level = normalized_risk_level if normalized_risk_level != "low" else "medium"

        if normalized_result == "blocked":
            normalized_policy_decision = "deny"

        return {
            "Result": normalized_result,
            "ResultCode": normalized_result_code,
            "ResultReason": normalized_result_reason,
            "FailureStage": normalized_failure_stage,
            "PolicyDecision": normalized_policy_decision,
            "RiskLevel": normalized_risk_level,
            "AuthStrength": normalized_auth_strength,
            "MfaMethod": normalized_mfa_method,
        }

    def event(
        self,
        *,
        timestamp: datetime,
        user_id: str,
        user_principal_name: str,
        action: str,
        result: str,
        application: str,
        application_id: str,
        source_ip: str,
        geo_country: str,
        geo_region: str,
        geo_city: str,
        asn: str,
        network_type: str,
        proxy_type: str,
        device_id: str,
        device_platform: str,
        device_trust_type: str,
        device_compliance_state: str,
        device_managed: str,
        device_risk_score: str,
        user_agent: str,
        auth_method: str,
        token_type: str,
        grant_type: str,
        policy_set: str,
        policy_rule_id: str,
        policy_version: str,
        event_type: str = "access_event",
        event_category: str = "identity_access",
        ingest_source: str = "synthetic_generator",
        tenant_region: str = "global",
        user_type: str = "member",
        account_status: str = "enabled",
        identity_provider: str = "entra_id",
        result_code: str = "",
        result_reason: str = "",
        failure_stage: str = "",
        session_id: str,
        parent_session_id: str = "",
        trace_id: str,
        correlation_id: str = "",
        request_id: str = "",
        risk_level: str = "low",
        policy_decision: str = "allow",
        auth_strength: str = "single_factor",
        mfa_method: str = "",
        resource_id: str = "",
        resource_type: str = "application",
        scenario_id: str = "baseline_access",
        scenario_phase: str = "baseline",
        attack_family: str = "none",
        message: str,
        label: str,
    ) -> dict[str, str]:
        normalized = self.normalize_outcome(
            action=action,
            result=result,
            result_code=result_code,
            result_reason=result_reason,
            failure_stage=failure_stage,
            policy_decision=policy_decision,
            risk_level=risk_level,
            auth_strength=auth_strength,
            mfa_method=mfa_method,
        )
        action_family = self.action_family(action)

        return {
            "TimeCreated": timestamp.isoformat(),
            "EventId": self.event_id(),
            "EventType": event_type,
            "EventCategory": event_category,
            "SchemaVersion": "2.0",
            "IngestSource": ingest_source,
            "TenantId": self.config.tenant_id,
            "TenantRegion": tenant_region,
            "UserId": user_id,
            "UserPrincipalName": user_principal_name,
            "UserType": user_type,
            "AccountStatus": account_status,
            "IdentityProvider": identity_provider,
            "ApplicationId": application_id,
            "Action": action,
            "ActionFamily": action_family,
            "Result": normalized["Result"],
            "ResultCode": normalized["ResultCode"],
            "ResultReason": normalized["ResultReason"],
            "FailureStage": normalized["FailureStage"],
            "Application": application,
            "ResourceId": resource_id,
            "ResourceType": resource_type,
            "SourceIp": source_ip,
            "Asn": asn,
            "NetworkType": network_type,
            "ProxyType": proxy_type,
            "GeoCountry": geo_country,
            "GeoRegion": geo_region,
            "GeoCity": geo_city,
            "DeviceId": device_id,
            "DevicePlatform": device_platform,
            "DeviceTrustType": device_trust_type,
            "DeviceComplianceState": device_compliance_state,
            "DeviceManaged": device_managed,
            "DeviceRiskScore": device_risk_score,
            "UserAgent": user_agent,
            "AuthMethod": auth_method,
            "AuthStrength": normalized["AuthStrength"],
            "MfaMethod": normalized["MfaMethod"],
            "TokenType": token_type,
            "GrantType": grant_type,
            "PolicySet": policy_set,
            "PolicyRuleId": policy_rule_id,
            "PolicyVersion": policy_version,
            "CorrelationId": correlation_id or self.correlation_id(),
            "RequestId": request_id or self.request_id(),
            "SessionId": session_id,
            "ParentSessionId": parent_session_id,
            "TraceId": trace_id,
            "RiskLevel": normalized["RiskLevel"],
            "PolicyDecision": normalized["PolicyDecision"],
            "ScenarioId": scenario_id,
            "ScenarioPhase": scenario_phase,
            "AttackFamily": attack_family,
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

    def pick_user_agent(self) -> str:
        return self._pick_user_agent()

    def _pick_user_agent(self) -> str:
        ua_pool = (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_5)",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X)",
            "Mozilla/5.0 (Linux; Android 14)",
        )
        return self.random.choice(ua_pool)
