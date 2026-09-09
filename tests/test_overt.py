# Attack coverage: attack families must appear in dataset with realistic ratios and sequences
# Credential stuffing: repeated failures should lead to a later success
# MFA fatigue: many failed prompts in a small window eventually leading to a success
# Impossible travel: two logons from same user with impossible travel/time
# Ransomeware: Process chain tampering, believable pattern



from __future__ import annotations

import csv
import os
import unittest
from collections import Counter
from datetime import datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DATASET = REPO_ROOT / "output" / "windows_security_overt.csv"


class TestOvertDatasetQuality(unittest.TestCase):
	CHECK_ORDER = (
		"Overt Attack Coverage",
		"Credential Stuffing Chain Integrity",
		"MFA Fatigue Burst Then Success",
		"Impossible Travel Consistency",
		"Ransomware Process Chain and Tampering",
	)

	@classmethod
	def setUpClass(cls) -> None:
		dataset_env = os.getenv("OVERT_WINDOWS_LOG_DATASET") or os.getenv("WINDOWS_LOG_DATASET")
		dataset_path = Path(dataset_env) if dataset_env else DEFAULT_DATASET

		if not dataset_path.is_absolute():
			dataset_path = REPO_ROOT / dataset_path

		if not dataset_path.exists():
			raise FileNotFoundError(
				f"Dataset not found at {dataset_path}. Generate it first or set OVERT_WINDOWS_LOG_DATASET."
			)

		with dataset_path.open("r", encoding="utf-8", newline="") as handle:
			cls.events = list(csv.DictReader(handle))

		if not cls.events:
			raise ValueError(f"Dataset is empty: {dataset_path}")

		cls.dataset_path = dataset_path
		cls.total = len(cls.events)
		cls.check_details: dict[str, str] = {}

		cls.label_counts = Counter(event["Label"] for event in cls.events)
		cls.event_id_counts = Counter(event["EventID"] for event in cls.events)
		cls.malicious_events = [event for event in cls.events if event["Label"] == "malicious"]

		print("\n" + "=" * 78)
		print("             OVERT WINDOWS ATTACK DATASET VALIDATION REPORT")
		print("=" * 78)
		print(f"Dataset: {cls.dataset_path}")
		print(f"Rows   : {cls.total:,}")
		print("Goal   : Validate realism and integrity of overt breach attack chains")

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

		malicious_ratio = len(cls.malicious_events) / max(1, cls.total)

		print("\n" + "-" * 78)
		print("KEY METRICS")
		print("-" * 78)
		print(f"Labels                     : {dict(cls.label_counts)}")
		print(f"Top Event IDs              : {dict(cls.event_id_counts.most_common(8))}")
		print(f"Malicious Event Ratio      : {malicious_ratio:.2%}")

		print("\n" + "-" * 78)
		print("EXECUTIVE SUMMARY")
		print("-" * 78)
		print(f"Checks Passed: {passed}/{len(cls.CHECK_ORDER)}")
		if passed == len(cls.CHECK_ORDER):
			print("Result: PASS - Overt attack patterns are present and sequence-valid.")
		else:
			print("Result: FAIL - Review failed checks above for attack realism issues.")
		print("=" * 78 + "\n")

	def test_overt_attack_coverage(self) -> None:
		self.assertGreater(len(self.malicious_events), 0)

		malicious_ratio = len(self.malicious_events) / self.total
		self.assertGreater(malicious_ratio, 0.005)
		self.assertLess(malicious_ratio, 0.20)

		malicious_messages = [event["Message"] for event in self.malicious_events]
		self.assertTrue(any("Credential stuffing" in message for message in malicious_messages))
		self.assertTrue(any("MFA fatigue" in message for message in malicious_messages))
		self.assertTrue(any("Impossible travel" in message for message in malicious_messages))
		self.assertTrue(any("Ransomware behavior" in message for message in malicious_messages))

		expected_ids = {"4625", "4624", "4648", "4672", "4688", "4663", "1102"}
		malicious_ids = {event["EventID"] for event in self.malicious_events}
		self.assertTrue(expected_ids.issubset(malicious_ids))

		self.__class__.check_details["Overt Attack Coverage"] = (
			f"Malicious events={len(self.malicious_events)} ({malicious_ratio:.2%}); "
			"all 4 overt attack families detected with expected event IDs."
		)

	def test_credential_stuffing_chain_integrity(self) -> None:
		stuffing_events = [
			event
			for event in self.malicious_events
			if "Credential stuffing" in event["Message"] or "Post-compromise credential use" in event["Message"]
		]
		self.assertGreater(len(stuffing_events), 0)

		failed_events = [
			event
			for event in stuffing_events
			if event["EventID"] == "4625" and "failed sign-in burst" in event["Message"]
		]
		success_events = [
			event
			for event in stuffing_events
			if event["EventID"] == "4624" and "Credential stuffing success" in event["Message"]
		]
		reuse_events = [event for event in stuffing_events if event["EventID"] == "4648"]

		self.assertGreaterEqual(len(failed_events), 6)
		self.assertGreaterEqual(len(success_events), 1)
		self.assertGreaterEqual(len(reuse_events), 1)

		first_failure_ts = min(datetime.fromisoformat(event["TimeCreated"]) for event in failed_events)
		success_ts = min(datetime.fromisoformat(event["TimeCreated"]) for event in success_events)
		self.assertGreater(success_ts, first_failure_ts)

		self.__class__.check_details["Credential Stuffing Chain Integrity"] = (
			f"Failures={len(failed_events)}, Successes={len(success_events)}, Follow-on credential use={len(reuse_events)}."
		)

	def test_mfa_fatigue_burst_then_success(self) -> None:
		mfa_events = [event for event in self.malicious_events if "MFA fatigue" in event["Message"]]
		self.assertGreater(len(mfa_events), 0)

		prompt_failures = [event for event in mfa_events if event["EventID"] == "4625" and "pattern" in event["Message"]]
		approval_success = [event for event in mfa_events if event["EventID"] == "4624" and "success" in event["Message"]]
		follow_on = [event for event in mfa_events if event["EventID"] == "4672"]

		self.assertGreaterEqual(len(prompt_failures), 6)
		self.assertGreaterEqual(len(approval_success), 1)
		self.assertGreaterEqual(len(follow_on), 1)

		first_prompt_ts = min(datetime.fromisoformat(event["TimeCreated"]) for event in prompt_failures)
		last_prompt_ts = max(datetime.fromisoformat(event["TimeCreated"]) for event in prompt_failures)
		approval_ts = min(datetime.fromisoformat(event["TimeCreated"]) for event in approval_success)

		self.assertLessEqual((last_prompt_ts - first_prompt_ts).total_seconds(), 15 * 60)
		self.assertGreater(approval_ts, first_prompt_ts)

		self.__class__.check_details["MFA Fatigue Burst Then Success"] = (
			f"Prompt failures={len(prompt_failures)} in compact window; approvals={len(approval_success)}; follow-on={len(follow_on)}."
		)

	def test_impossible_travel_consistency(self) -> None:
		impossible_events = [event for event in self.malicious_events if "Impossible travel" in event["Message"]]
		self.assertGreaterEqual(len(impossible_events), 2)

		baseline_events = [event for event in impossible_events if "baseline login" in event["Message"]]
		alert_events = [event for event in impossible_events if "alert" in event["Message"]]
		self.assertEqual(len(baseline_events), 1)
		self.assertEqual(len(alert_events), 1)

		baseline_event = baseline_events[0]
		alert_event = alert_events[0]

		self.assertEqual(baseline_event["TargetUserName"], alert_event["TargetUserName"])
		self.assertNotEqual(baseline_event["IpAddress"], alert_event["IpAddress"])

		baseline_ts = datetime.fromisoformat(baseline_event["TimeCreated"])
		alert_ts = datetime.fromisoformat(alert_event["TimeCreated"])
		self.assertGreater(alert_ts, baseline_ts)
		self.assertLessEqual((alert_ts - baseline_ts).total_seconds(), 60 * 60)

		self.__class__.check_details["Impossible Travel Consistency"] = (
			"Two close-in-time logons for same user from different IP contexts with correct temporal ordering."
		)

	def test_ransomware_process_chain_and_tampering(self) -> None:
		ransomware_events = [event for event in self.malicious_events if "Ransomware behavior" in event["Message"]]
		self.assertGreaterEqual(len(ransomware_events), 5)

		ids = Counter(event["EventID"] for event in ransomware_events)
		self.assertGreaterEqual(ids["4688"], 3)
		self.assertGreaterEqual(ids["4663"], 1)
		self.assertGreaterEqual(ids["1102"], 1)

		has_shadow_delete = any("vssadmin" in event["Message"].lower() for event in ransomware_events)
		has_log_clear = any(event["EventID"] == "1102" for event in ransomware_events)
		self.assertTrue(has_shadow_delete)
		self.assertTrue(has_log_clear)

		first_exec_ts = min(
			datetime.fromisoformat(event["TimeCreated"])
			for event in ransomware_events
			if event["EventID"] == "4688"
		)
		log_clear_ts = max(
			datetime.fromisoformat(event["TimeCreated"])
			for event in ransomware_events
			if event["EventID"] == "1102"
		)
		self.assertGreater(log_clear_ts, first_exec_ts)

		self.__class__.check_details["Ransomware Process Chain and Tampering"] = (
			f"4688={ids['4688']}, 4663={ids['4663']}, 1102={ids['1102']}; "
			"includes shadow-copy and log-clear behavior."
		)


if __name__ == "__main__":
	unittest.main()

