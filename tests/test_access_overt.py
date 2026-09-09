from __future__ import annotations

import csv
import os
import unittest
from collections import Counter
from datetime import datetime
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DATASET = REPO_ROOT / "output" / "access_logs_overt_v2.csv"


class TestAccessOvertDatasetQuality(unittest.TestCase):
    CHECK_ORDER = (
        "Overt Coverage and Malicious Ratio",
        "Credential Stuffing Chain Integrity",
        "MFA Fatigue Burst Then Success",
        "Impossible Travel Consistency",
        "Token Theft Replay Linkage",
    )

    @classmethod
    def setUpClass(cls) -> None:
        dataset_path = Path(os.getenv("ACCESS_OVERT_LOG_DATASET") or os.getenv("ACCESS_LOG_DATASET") or str(DEFAULT_DATASET))
        if not dataset_path.is_absolute():
            dataset_path = REPO_ROOT / dataset_path

        if not dataset_path.exists():
            raise FileNotFoundError(
                f"Dataset not found at {dataset_path}. Generate it first or set ACCESS_OVERT_LOG_DATASET."
            )

        with dataset_path.open("r", encoding="utf-8", newline="") as handle:
            cls.events = list(csv.DictReader(handle))

        if not cls.events:
            raise ValueError(f"Dataset is empty: {dataset_path}")

        cls.dataset_path = dataset_path
        cls.total = len(cls.events)
        cls.check_details: dict[str, str] = {}

        cls.label_counts = Counter(event["Label"] for event in cls.events)
        cls.family_counts = Counter(event["AttackFamily"] for event in cls.events)
        cls.phase_counts = Counter(event["ScenarioPhase"] for event in cls.events)

        cls.malicious_events = [event for event in cls.events if event["Label"] == "malicious"]
        cls.malicious_ratio = len(cls.malicious_events) / max(1, cls.total)

        print("\n" + "=" * 78)
        print("            ACCESS OVERT DATASET VALIDATION REPORT")
        print("=" * 78)
        print(f"Dataset: {cls.dataset_path}")
        print(f"Rows   : {cls.total:,}")
        print("Goal   : Validate realism and chain integrity of overt access attack signals")

    @classmethod
    def tearDownClass(cls) -> None:
        print("\n" + "-" * 78)
        print("CHECK RESULTS")
        print("-" * 78)

        passed = 0
        for check_name in cls.CHECK_ORDER:
            detail = cls.check_details.get(check_name)
            if detail is None:
                status = "FAIL"
                detail = "Check did not complete (assertion likely failed)."
            else:
                status = "PASS"
                passed += 1

            print(f"[{status}] {check_name}")
            print(f"       {detail}")

        print("\n" + "-" * 78)
        print("KEY METRICS")
        print("-" * 78)
        print(f"Labels                     : {dict(cls.label_counts)}")
        print(f"Attack Families            : {dict(cls.family_counts)}")
        print(f"Scenario Phases            : {dict(cls.phase_counts)}")
        print(f"Malicious Event Ratio      : {cls.malicious_ratio:.2%}")

        print("\n" + "-" * 78)
        print("EXECUTIVE SUMMARY")
        print("-" * 78)
        print(f"Checks Passed: {passed}/{len(cls.CHECK_ORDER)}")
        if passed == len(cls.CHECK_ORDER):
            print("Result: PASS - Overt access attack patterns are present and sequence-valid.")
        else:
            print("Result: FAIL - Review failed checks above for overt realism gaps.")
        print("=" * 78 + "\n")

    def test_overt_coverage_and_malicious_ratio(self) -> None:
        self.assertGreater(len(self.malicious_events), 0)
        self.assertGreater(self.malicious_ratio, 0.005)
        self.assertLess(self.malicious_ratio, 0.20)

        expected_families = {
            "credential_stuffing",
            "mfa_fatigue",
            "impossible_travel",
            "token_theft_replay",
        }
        malicious_families = {event["AttackFamily"] for event in self.malicious_events}
        self.assertTrue(expected_families.issubset(malicious_families))

        for event in self.malicious_events:
            self.assertEqual(event["ScenarioId"], "access_overt_v1")
            self.assertNotEqual(event["ScenarioPhase"], "baseline")
            self.assertNotEqual(event["AttackFamily"], "none")

        malicious_risk_counts = Counter(event["RiskLevel"] for event in self.malicious_events)
        elevated_ratio = (
            (malicious_risk_counts.get("high", 0) + malicious_risk_counts.get("critical", 0))
            / max(1, len(self.malicious_events))
        )
        self.assertGreater(elevated_ratio, 0.60)

        self.__class__.check_details["Overt Coverage and Malicious Ratio"] = (
            f"Malicious events={len(self.malicious_events)} ({self.malicious_ratio:.2%}); all 4 overt attack families are present with elevated-risk majority ({elevated_ratio:.1%})."
        )

    def test_credential_stuffing_chain_integrity(self) -> None:
        stuffing = [event for event in self.malicious_events if event["AttackFamily"] == "credential_stuffing"]
        self.assertGreater(len(stuffing), 0)

        failed_signins = [
            event for event in stuffing
            if event["Action"] == "sign_in_interactive" and event["Result"] == "failure"
        ]
        success_signins = [
            event for event in stuffing
            if event["Action"] == "sign_in_interactive" and event["Result"] == "success"
        ]
        token_issues = [event for event in stuffing if event["Action"] == "token_issue"]
        app_accesses = [event for event in stuffing if event["Action"] == "app_resource_access"]

        self.assertGreaterEqual(len(failed_signins), 6)
        self.assertGreaterEqual(len(success_signins), 1)
        self.assertGreaterEqual(len(token_issues), 1)
        self.assertGreaterEqual(len(app_accesses), 1)

        distinct_targets = {event["UserPrincipalName"] for event in failed_signins}
        self.assertGreaterEqual(len(distinct_targets), 2)

        first_failure_ts = min(datetime.fromisoformat(event["TimeCreated"]) for event in failed_signins)
        first_success_ts = min(datetime.fromisoformat(event["TimeCreated"]) for event in success_signins)
        self.assertGreater(first_success_ts, first_failure_ts)

        self.__class__.check_details["Credential Stuffing Chain Integrity"] = (
            f"Failures={len(failed_signins)} across {len(distinct_targets)} users; successes={len(success_signins)} with follow-on token/resource activity."
        )

    def test_mfa_fatigue_burst_then_success(self) -> None:
        fatigue = [event for event in self.malicious_events if event["AttackFamily"] == "mfa_fatigue"]
        self.assertGreater(len(fatigue), 0)

        prompts = [event for event in fatigue if event["Action"] == "mfa_challenge"]
        approvals = [event for event in fatigue if event["Action"] == "mfa_approve"]
        token_issues = [event for event in fatigue if event["Action"] == "token_issue"]

        self.assertGreaterEqual(len(prompts), 6)
        self.assertGreaterEqual(len(approvals), 1)
        self.assertGreaterEqual(len(token_issues), 1)

        for event in prompts:
            self.assertEqual(event["PolicyDecision"], "challenge")
            self.assertEqual(event["AuthStrength"], "multi_factor")
            self.assertEqual(event["MfaMethod"], "push")

        first_prompt_ts = min(datetime.fromisoformat(event["TimeCreated"]) for event in prompts)
        approval_ts = min(datetime.fromisoformat(event["TimeCreated"]) for event in approvals)
        self.assertGreater(approval_ts, first_prompt_ts)
        self.assertLessEqual((approval_ts - first_prompt_ts).total_seconds(), 20 * 60)

        self.__class__.check_details["MFA Fatigue Burst Then Success"] = (
            f"Prompts={len(prompts)} in compact window with approval and token issuance follow-on."
        )

    def test_impossible_travel_consistency(self) -> None:
        travel = [event for event in self.malicious_events if event["AttackFamily"] == "impossible_travel"]
        self.assertGreaterEqual(len(travel), 4)

        signins = [event for event in travel if event["Action"] == "sign_in_interactive" and event["Result"] == "success"]
        self.assertGreaterEqual(len(signins), 2)

        first, second = sorted(signins, key=lambda event: datetime.fromisoformat(event["TimeCreated"]))[:2]
        self.assertEqual(first["UserPrincipalName"], second["UserPrincipalName"])
        self.assertNotEqual(first["GeoCountry"], second["GeoCountry"])
        self.assertNotEqual(first["SourceIp"], second["SourceIp"])

        first_ts = datetime.fromisoformat(first["TimeCreated"])
        second_ts = datetime.fromisoformat(second["TimeCreated"])
        self.assertGreater(second_ts, first_ts)
        self.assertLessEqual((second_ts - first_ts).total_seconds(), 60 * 60)

        self.assertTrue(any(event["Action"] in {"token_issue", "app_resource_access"} for event in travel))

        self.__class__.check_details["Impossible Travel Consistency"] = (
            "Same user shows close-in-time successful sign-ins from distinct geo/IP contexts with valid follow-on activity."
        )

    def test_token_theft_replay_linkage(self) -> None:
        replay = [event for event in self.malicious_events if event["AttackFamily"] == "token_theft_replay"]
        self.assertGreaterEqual(len(replay), 5)

        token_issues = [event for event in replay if event["Action"] == "token_issue"]
        token_redeems = [event for event in replay if event["Action"] == "token_redeem"]
        refreshes = [event for event in replay if event["Action"] == "token_refresh"]
        app_accesses = [event for event in replay if event["Action"] == "app_resource_access"]

        self.assertGreaterEqual(len(token_issues), 1)
        self.assertGreaterEqual(len(token_redeems), 1)
        self.assertGreaterEqual(len(refreshes), 1)
        self.assertGreaterEqual(len(app_accesses), 1)

        redeem = token_redeems[0]
        self.assertNotEqual(redeem["ParentSessionId"], "")

        parent_session = redeem["ParentSessionId"]
        parent_candidates = [event for event in replay if event["SessionId"] == parent_session]
        self.assertTrue(parent_candidates)

        issue_ts = min(datetime.fromisoformat(event["TimeCreated"]) for event in token_issues)
        redeem_ts = datetime.fromisoformat(redeem["TimeCreated"])
        self.assertGreater(redeem_ts, issue_ts)

        parent_context = next(event for event in parent_candidates if event["Action"] in {"sign_in_interactive", "token_issue"})
        context_changed = any(
            redeem[field] != parent_context[field]
            for field in ("SourceIp", "GeoCountry", "DeviceId")
        )
        self.assertTrue(context_changed)

        self.__class__.check_details["Token Theft Replay Linkage"] = (
            "Token replay events link to a parent session and occur from a changed context with post-replay activity."
        )


if __name__ == "__main__":
    unittest.main()
