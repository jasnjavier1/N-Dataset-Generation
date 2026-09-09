from __future__ import annotations

import csv
import os
import unittest
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DATASET = REPO_ROOT / "output" / "access_logs_baseline_v1.csv"


class TestAccessBaselineDatasetQuality(unittest.TestCase):
    CHECK_ORDER = (
        "Label Integrity and Schema Completeness",
        "Dataset Ordering and Session Chronology",
        "User, App, and Geo Diversity",
        "Session Sequence Sanity",
        "Token and MFA Lifecycle",
        "Per-Session Context Stability",
    )

    @classmethod
    def setUpClass(cls) -> None:
        dataset_path = Path(os.getenv("ACCESS_LOG_DATASET", str(DEFAULT_DATASET)))
        if not dataset_path.is_absolute():
            dataset_path = REPO_ROOT / dataset_path

        if not dataset_path.exists():
            raise FileNotFoundError(
                f"Dataset not found at {dataset_path}. Generate it first or set ACCESS_LOG_DATASET."
            )

        with dataset_path.open("r", encoding="utf-8", newline="") as handle:
            cls.events = list(csv.DictReader(handle))

        if not cls.events:
            raise ValueError(f"Dataset is empty: {dataset_path}")

        cls.dataset_path = dataset_path
        cls.total = len(cls.events)
        cls.check_details: dict[str, str] = {}

        cls.timestamps = [datetime.fromisoformat(event["TimeCreated"]) for event in cls.events]
        cls.label_counts = Counter(event["Label"] for event in cls.events)
        cls.result_counts = Counter(event["Result"] for event in cls.events)
        cls.policy_counts = Counter(event["PolicyDecision"] for event in cls.events)
        cls.user_counts = Counter(event["UserPrincipalName"] for event in cls.events)
        cls.app_counts = Counter(event["Application"] for event in cls.events)
        cls.geo_counts = Counter(event["GeoCountry"] for event in cls.events)
        cls.session_counts = Counter(event["SessionId"] for event in cls.events)

        print("\n" + "=" * 78)
        print("          ACCESS BASELINE DATASET VALIDATION REPORT")
        print("=" * 78)
        print(f"Dataset: {cls.dataset_path}")
        print(f"Rows   : {cls.total:,}")
        print("Goal   : Validate realism and consistency of benign baseline access logs")

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
        print(f"Labels        : {dict(cls.label_counts)}")
        print(f"Top Results   : {dict(cls.result_counts.most_common(5))}")
        print(f"Top Policies   : {dict(cls.policy_counts.most_common(5))}")
        print(f"Top Users     : {dict(cls.user_counts.most_common(5))}")
        print(f"Top Apps      : {dict(cls.app_counts.most_common(5))}")
        print(f"Top Geos      : {dict(cls.geo_counts.most_common(5))}")

        print("\n" + "-" * 78)
        print("EXECUTIVE SUMMARY")
        print("-" * 78)
        print(f"Checks Passed: {passed}/{len(cls.CHECK_ORDER)}")
        if passed == len(cls.CHECK_ORDER):
            print("Result: PASS - Access baseline dataset appears realistic and internally consistent.")
        else:
            print("Result: FAIL - Review failed checks above for access realism gaps.")
        print("=" * 78 + "\n")

    def test_label_integrity_and_schema_completeness(self) -> None:
        required_fields = {
            "TimeCreated",
            "UserPrincipalName",
            "Action",
            "ActionFamily",
            "Result",
            "ResultCode",
            "ResultReason",
            "Application",
            "ApplicationId",
            "SourceIp",
            "GeoCountry",
            "DeviceId",
            "SessionId",
            "TraceId",
            "CorrelationId",
            "PolicyDecision",
            "ScenarioId",
            "ScenarioPhase",
            "AttackFamily",
            "Label",
        }

        for event in self.events:
            self.assertEqual(event["Label"], "benign")
            self.assertEqual(event["AttackFamily"], "none")
            self.assertEqual(event["ScenarioPhase"], "baseline")
            self.assertNotEqual(event["ResultReason"], "")
            self.assertNotEqual(event["ResultCode"], "")

            self.assertNotEqual(event["PolicyDecision"], "deny")
            if event["Result"] == "challenge":
                self.assertEqual(event["PolicyDecision"], "challenge")
            else:
                self.assertEqual(event["PolicyDecision"], "allow")

            for field in required_fields:
                self.assertIn(field, event)
                self.assertNotEqual(event[field], "")

        self.assertNotIn("deny", self.policy_counts)
        self.__class__.check_details["Label Integrity and Schema Completeness"] = (
            "All rows are benign, schema-required fields are present, and no deny decisions appear."
        )

    def test_dataset_ordering_and_session_chronology(self) -> None:
        self.assertEqual(self.timestamps, sorted(self.timestamps))

        per_session_timestamps: dict[str, list[datetime]] = defaultdict(list)
        for event in self.events:
            per_session_timestamps[event["SessionId"]].append(datetime.fromisoformat(event["TimeCreated"]))

        for timestamps in per_session_timestamps.values():
            self.assertEqual(timestamps, sorted(timestamps))

        unique_hours = {timestamp.hour for timestamp in self.timestamps}
        self.assertGreaterEqual(len(unique_hours), 6)

        self.__class__.check_details["Dataset Ordering and Session Chronology"] = (
            f"Events are globally sorted and cover {len(unique_hours)} distinct hours."
        )

    def test_user_app_and_geo_diversity(self) -> None:
        self.assertGreaterEqual(len(self.user_counts), 4)
        self.assertGreaterEqual(len(self.app_counts), 3)
        self.assertGreaterEqual(len(self.geo_counts), 2)

        total = self.total
        self.assertLess(max(self.user_counts.values()) / total, 0.60)
        self.assertLess(max(self.app_counts.values()) / total, 0.70)

        self.assertTrue(any(user.startswith("svc-") or user.startswith("svc_") for user in self.user_counts))
        self.assertTrue(any(not (user.startswith("svc-") or user.startswith("svc_")) for user in self.user_counts))

        self.__class__.check_details["User, App, and Geo Diversity"] = (
            f"Users={len(self.user_counts)}, Apps={len(self.app_counts)}, Geos={len(self.geo_counts)} with no single actor dominating."
        )

    def test_session_sequence_sanity(self) -> None:
        for session_id in self.session_counts:
            session_events = [event for event in self.events if event["SessionId"] == session_id]
            actions = [event["Action"] for event in session_events]

            self.assertGreaterEqual(len(actions), 4)

            sign_in_indexes = [idx for idx, action in enumerate(actions) if action in ("sign_in_interactive", "sign_in_noninteractive")]
            token_issue_indexes = [idx for idx, action in enumerate(actions) if action == "token_issue"]
            session_start_indexes = [idx for idx, action in enumerate(actions) if action == "session_start"]
            app_launch_indexes = [idx for idx, action in enumerate(actions) if action == "app_launch"]

            self.assertTrue(sign_in_indexes)
            self.assertTrue(token_issue_indexes)
            self.assertTrue(session_start_indexes)

            self.assertLess(min(sign_in_indexes), min(token_issue_indexes))
            self.assertLess(min(token_issue_indexes), min(session_start_indexes))

            if app_launch_indexes:
                self.assertLess(min(session_start_indexes), min(app_launch_indexes))

        self.__class__.check_details["Session Sequence Sanity"] = (
            "Sessions show plausible access order: sign-in, token issuance, session start, and app activity."
        )

    def test_token_and_mfa_lifecycle(self) -> None:
        for session_id in self.session_counts:
            session_events = [event for event in self.events if event["SessionId"] == session_id]
            actions = [event["Action"] for event in session_events]

            if "mfa_approve" in actions:
                self.assertIn("mfa_challenge", actions)
                self.assertLess(actions.index("mfa_challenge"), actions.index("mfa_approve"))

            if "token_refresh" in actions:
                self.assertIn("token_issue", actions)
                self.assertLess(actions.index("token_issue"), actions.index("token_refresh"))

            if "token_redeem" in actions:
                self.assertIn("token_issue", actions)
                self.assertLess(actions.index("token_issue"), actions.index("token_redeem"))

            for event in session_events:
                if event["Action"] in ("mfa_challenge", "mfa_approve"):
                    self.assertEqual(event["AuthStrength"], "multi_factor")
                    self.assertEqual(event["MfaMethod"], "push")
                if event["Action"] not in ("mfa_challenge", "mfa_approve"):
                    self.assertIn(event["MfaMethod"], ("", "push"))

        self.__class__.check_details["Token and MFA Lifecycle"] = (
            "MFA approvals follow challenges, and token refresh/redeem events follow token issuance."
        )

    def test_per_session_context_stability(self) -> None:
        stable_fields = (
            "UserPrincipalName",
            "UserId",
            "Application",
            "ApplicationId",
            "SourceIp",
            "GeoCountry",
            "DeviceId",
            "CorrelationId",
            "TraceId",
            "TenantId",
        )

        for session_id in self.session_counts:
            session_events = [event for event in self.events if event["SessionId"] == session_id]
            for field in stable_fields:
                values = {event[field] for event in session_events}
                self.assertEqual(len(values), 1, msg=f"Field {field} varied within session {session_id}")

        self.__class__.check_details["Per-Session Context Stability"] = (
            "Stable per-session identity, app, geo, device, and correlation fields remain coherent throughout each session."
        )


if __name__ == "__main__":
    unittest.main()