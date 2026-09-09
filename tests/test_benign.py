# User and host diversity test: benign environment should not look like one user on one machine doing everything
# Authentication and event distribution test: benign environment should have a realistic 
# mix of event IDs and logon types
# Sequence and temporal realism: Activity should roughly cluster into working hours 9-5
# Cross-field consistency and success status: consistent values in rows and even specific fields
# Credential reuse stability: LogonId values should be unique in a benign run


from __future__ import annotations

import csv
import os
import unittest
from collections import Counter
from datetime import datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DATASET = REPO_ROOT / "output" / "windows_security_baseline.csv"


class TestBenignDatasetQuality(unittest.TestCase):
	CHECK_ORDER = (
		"User and Host Diversity",
		"Authentication and Event Distribution",
		"Sequence and Temporal Realism",
		"Cross-Field Consistency and Success Status",
		"Credential Reuse Stability",
	)

	@classmethod
	def setUpClass(cls) -> None:
		dataset_path = Path(os.getenv("WINDOWS_LOG_DATASET", str(DEFAULT_DATASET)))
		if not dataset_path.is_absolute():
			dataset_path = REPO_ROOT / dataset_path

		if not dataset_path.exists():
			raise FileNotFoundError(
				f"Dataset not found at {dataset_path}. Generate it first or set WINDOWS_LOG_DATASET."
			)

		with dataset_path.open("r", encoding="utf-8", newline="") as handle:
			cls.events = list(csv.DictReader(handle))

		if not cls.events:
			raise ValueError(f"Dataset is empty: {dataset_path}")

		cls.dataset_path = dataset_path
		cls.total = len(cls.events)
		cls.check_details: dict[str, str] = {}

		cls.event_id_counts = Counter(event["EventID"] for event in cls.events)
		cls.label_counts = Counter(event["Label"] for event in cls.events)
		cls.logon_type_counts = Counter(event["LogonType"] for event in cls.events)
		cls.timestamps = [datetime.fromisoformat(event["TimeCreated"]) for event in cls.events]

		cls.business_hours_events = [ts for ts in cls.timestamps if 9 <= ts.hour < 17]
		cls.business_hours_ratio = len(cls.business_hours_events) / cls.total

		print("\n" + "=" * 78)
		print("            BENIGN WINDOWS SECURITY DATASET VALIDATION REPORT")
		print("=" * 78)
		print(f"Dataset: {cls.dataset_path}")
		print(f"Rows   : {cls.total:,}")
		print("Goal   : Validate realism and consistency of benign baseline logs")

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
		print(f"Top Event IDs              : {dict(cls.event_id_counts.most_common(5))}")
		print(f"Logon Types                : {dict(cls.logon_type_counts)}")
		print(f"Business Hours Activity    : {cls.business_hours_ratio:.1%} (9:00-16:59)")

		print("\n" + "-" * 78)
		print("EXECUTIVE SUMMARY")
		print("-" * 78)
		print(f"Checks Passed: {passed}/{len(cls.CHECK_ORDER)}")
		if passed == len(cls.CHECK_ORDER):
			print("Result: PASS - Dataset appears consistent with benign baseline expectations.")
		else:
			print("Result: FAIL - Review failed checks above for details.")
		print("=" * 78 + "\n")

	def test_user_variability_and_host_role_differentiation(self) -> None:
		users = {event["TargetUserName"] for event in self.events}
		hosts = {event["Computer"] for event in self.events}

		self.assertGreaterEqual(len(users), 4)
		self.assertTrue(any(host.startswith("WIN10-") for host in hosts))
		self.assertTrue(any(host.startswith("SRV-") for host in hosts))

		per_user_counts = Counter(event["TargetUserName"] for event in self.events)
		self.assertTrue(all(count > 0 for count in per_user_counts.values()))

		self.__class__.check_details["User and Host Diversity"] = (
			f"Users={len(users)}, Hosts={len(hosts)}; both workstation and server patterns detected."
		)

	def test_auth_distribution_event_id_frequency_and_logon_type_distribution(self) -> None:
		allowed_ids = {"4624", "4634", "4648", "4672", "4688"}
		self.assertTrue(set(self.event_id_counts).issubset(allowed_ids))

		self.assertGreater(self.event_id_counts["4624"], self.event_id_counts["4634"])
		self.assertGreater(self.event_id_counts["4634"], self.event_id_counts["4648"])

		ratio_4624 = self.event_id_counts["4624"] / self.total
		ratio_4688 = self.event_id_counts["4688"] / self.total
		self.assertGreater(ratio_4624, 0.45)
		self.assertLess(ratio_4624, 0.65)
		self.assertGreater(ratio_4688, 0.01)

		self.assertGreater(self.logon_type_counts["3"], self.logon_type_counts["2"])
		self.assertEqual(self.logon_type_counts["2"], self.event_id_counts["4688"])

		self.__class__.check_details["Authentication and Event Distribution"] = (
			f"4624={ratio_4624:.1%}, 4688={ratio_4688:.1%}, "
			f"LogonType3={self.logon_type_counts['3']}, LogonType2={self.logon_type_counts['2']}."
		)

	def test_event_sequence_coherence_and_temporal_behavior(self) -> None:
		self.assertEqual(self.timestamps, sorted(self.timestamps))

		self.assertGreater(self.business_hours_ratio, 0.20)
		self.assertLess(self.business_hours_ratio, 0.50)

		self.__class__.check_details["Sequence and Temporal Realism"] = (
			f"Events are time-ordered; business-hours ratio={self.business_hours_ratio:.1%}."
		)

	def test_cross_field_consistency_and_success_rate(self) -> None:
		for event in self.events:
			self.assertEqual(event["Label"], "benign")
			self.assertEqual(event["Status"], "0x0")
			self.assertEqual(event["SubStatus"], "0x0")

			event_id = event["EventID"]
			if event_id == "4624":
				self.assertEqual(event["SubjectUserName"], "SYSTEM")
				self.assertEqual(event["ProcessName"], "C:\\Windows\\System32\\lsass.exe")

			if event_id == "4688":
				self.assertEqual(event["LogonType"], "2")

		self.__class__.check_details["Cross-Field Consistency and Success Status"] = (
			"All rows are benign/successful and key event-specific field relationships are valid."
		)

	def test_credential_reuse_stability(self) -> None:
		logon_ids = [event["LogonId"] for event in self.events]
		self.assertEqual(len(logon_ids), len(set(logon_ids)))

		self.__class__.check_details["Credential Reuse Stability"] = (
			"All LogonId values are unique in this baseline run."
		)


if __name__ == "__main__":
	unittest.main()

