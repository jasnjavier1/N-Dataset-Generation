# Subtle attack coverage and low ratio: patterns must exist but be a small ratio
# Low and slow spray: failures are spaced out over time, eventually leading to a success
# Unusual worstation login: login from a different workstation, but still have plausible session activity
# Lateral movement via admin tools: using admin tools to move laterally, but not in a bursty way
# Cross-field and temporal stealth consistency: timestamps are ordered, status/substatus semantics
# are coherent, and subtle maliciou  s events are not densely bursty


from __future__ import annotations

import csv
import os
import unittest
from collections import Counter
from datetime import datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DATASET = REPO_ROOT / "output" / "windows_security_with_subtle_signals_v1.csv"


class TestSubtleDatasetQuality(unittest.TestCase):
	CHECK_ORDER = (
		"Subtle Attack Coverage and Ratio",
		"Low-and-Slow Password Spray Realism",
		"Unusual Workstation Logon Realism",
		"Lateral Movement via Admin Tools",
		"Cross-Field and Temporal Stealth Consistency",
	)

	@classmethod
	def setUpClass(cls) -> None:
		dataset_env = os.getenv("SUBTLE_WINDOWS_LOG_DATASET") or os.getenv("WINDOWS_LOG_DATASET")
		dataset_path = Path(dataset_env) if dataset_env else DEFAULT_DATASET

		if not dataset_path.is_absolute():
			dataset_path = REPO_ROOT / dataset_path

		if not dataset_path.exists():
			raise FileNotFoundError(
				f"Dataset not found at {dataset_path}. Generate it first or set SUBTLE_WINDOWS_LOG_DATASET."
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
		cls.timestamps = [datetime.fromisoformat(event["TimeCreated"]) for event in cls.events]

		print("\n" + "=" * 78)
		print("            SUBTLE WINDOWS ATTACK DATASET VALIDATION REPORT")
		print("=" * 78)
		print(f"Dataset: {cls.dataset_path}")
		print(f"Rows   : {cls.total:,}")
		print("Goal   : Validate realism and stealth characteristics of subtle breach signals")

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
			print("Result: PASS - Subtle attack patterns are present and behaviorally coherent.")
		else:
			print("Result: FAIL - Review failed checks above for subtle-pattern realism gaps.")
		print("=" * 78 + "\n")

	def test_subtle_attack_coverage_and_ratio(self) -> None:
		self.assertGreater(len(self.malicious_events), 0)

		malicious_ratio = len(self.malicious_events) / self.total
		self.assertGreater(malicious_ratio, 0.003)
		self.assertLess(malicious_ratio, 0.10)

		malicious_messages = [event["Message"] for event in self.malicious_events]
		self.assertTrue(any("Low-and-slow password spray" in message for message in malicious_messages))
		self.assertTrue(any("unusual workstation" in message.lower() for message in malicious_messages))
		self.assertTrue(any("Lateral movement via legitimate admin tooling" in message for message in malicious_messages))

		self.__class__.check_details["Subtle Attack Coverage and Ratio"] = (
			f"Malicious events={len(self.malicious_events)} ({malicious_ratio:.2%}); "
			"all 3 subtle attack families detected."
		)

	def test_low_and_slow_password_spray_realism(self) -> None:
		spray_events = [
			event
			for event in self.malicious_events
			if "Low-and-slow password spray" in event["Message"] or "Low-and-slow spray success" in event["Message"]
		]
		self.assertGreaterEqual(len(spray_events), 5)

		failed_events = [event for event in spray_events if event["EventID"] == "4625"]
		success_events = [event for event in spray_events if event["EventID"] == "4624"]

		self.assertGreaterEqual(len(failed_events), 4)
		self.assertGreaterEqual(len(success_events), 1)

		failure_targets = {event["TargetUserName"] for event in failed_events}
		self.assertGreaterEqual(len(failure_targets), 3)

		failure_times = sorted(datetime.fromisoformat(event["TimeCreated"]) for event in failed_events)
		if len(failure_times) >= 2:
			deltas = [
				int((failure_times[index + 1] - failure_times[index]).total_seconds())
				for index in range(len(failure_times) - 1)
			]
			self.assertTrue(all(delta >= 20 * 60 for delta in deltas))

		first_failure_ts = min(datetime.fromisoformat(event["TimeCreated"]) for event in failed_events)
		success_ts = min(datetime.fromisoformat(event["TimeCreated"]) for event in success_events)
		self.assertGreater(success_ts, first_failure_ts)

		self.__class__.check_details["Low-and-Slow Password Spray Realism"] = (
			f"Failures={len(failed_events)} across {len(failure_targets)} users with slow spacing; "
			f"successes={len(success_events)} after failures."
		)

	def test_unusual_workstation_logon_realism(self) -> None:
		unusual_logons = [
			event
			for event in self.malicious_events
			if "Login from unusual workstation" in event["Message"]
		]
		follow_on = [
			event
			for event in self.malicious_events
			if "Suspicious follow-on activity after unusual workstation logon" in event["Message"]
		]

		self.assertGreaterEqual(len(unusual_logons), 1)
		self.assertGreaterEqual(len(follow_on), 1)

		logon_event = unusual_logons[0]
		self.assertEqual(logon_event["EventID"], "4624")
		self.assertNotIn(logon_event["WorkstationName"], {"WKSTN-01", "WKSTN-02", "WKSTN-03"})

		follow_event = follow_on[0]
		self.assertEqual(follow_event["EventID"], "4688")
		self.assertEqual(follow_event["TargetUserName"], logon_event["TargetUserName"])

		logon_ts = datetime.fromisoformat(logon_event["TimeCreated"])
		follow_ts = datetime.fromisoformat(follow_event["TimeCreated"])
		self.assertGreater(follow_ts, logon_ts)
		self.assertLessEqual((follow_ts - logon_ts).total_seconds(), 15 * 60)

		self.__class__.check_details["Unusual Workstation Logon Realism"] = (
			f"Detected unusual workstation login on {logon_event['WorkstationName']} with coherent follow-on activity."
		)

	def test_lateral_movement_via_admin_tools(self) -> None:
		lateral_events = [
			event
			for event in self.malicious_events
			if "Administrative logon to" in event["Message"]
			or "Special privileges assigned during admin session" in event["Message"]
			or "Remote admin tool usage detected" in event["Message"]
			or "Lateral movement via legitimate admin tooling" in event["Message"]
			or "Scheduled task created during remote admin activity" in event["Message"]
		]
		self.assertGreaterEqual(len(lateral_events), 5)

		counts = Counter(event["EventID"] for event in lateral_events)
		self.assertGreaterEqual(counts["4624"], 1)
		self.assertGreaterEqual(counts["4672"], 1)
		self.assertGreaterEqual(counts["4688"], 3)

		tool_names = {event["ProcessName"].lower() for event in lateral_events if event["EventID"] == "4688"}
		self.assertTrue(any("powershell.exe" in name for name in tool_names))
		self.assertTrue(any("wmic.exe" in name for name in tool_names))
		self.assertTrue(any("schtasks.exe" in name for name in tool_names))

		sequence_times = [datetime.fromisoformat(event["TimeCreated"]) for event in lateral_events]
		self.assertEqual(sequence_times, sorted(sequence_times))

		self.__class__.check_details["Lateral Movement via Admin Tools"] = (
			f"Detected admin sequence with event mix 4624/4672/4688 and tools {sorted(tool_names)}."
		)

	def test_cross_field_and_temporal_stealth_consistency(self) -> None:
		self.assertEqual(self.timestamps, sorted(self.timestamps))

		for event in self.malicious_events:
			event_id = event["EventID"]
			status = event["Status"]
			sub_status = event["SubStatus"]

			if event_id == "4625":
				self.assertNotEqual(status, "0x0")
			else:
				self.assertEqual(status, "0x0")

			if event_id == "4625":
				self.assertNotEqual(sub_status, "0x0")
			else:
				self.assertEqual(sub_status, "0x0")

		# Stealth heuristic: subtle malicious events should not be densely bursty.
		minute_buckets: Counter[str] = Counter(
			datetime.fromisoformat(event["TimeCreated"]).strftime("%Y-%m-%d %H:%M")
			for event in self.malicious_events
		)
		self.assertLessEqual(max(minute_buckets.values()), 3)

		self.__class__.check_details["Cross-Field and Temporal Stealth Consistency"] = (
			f"Status/substatus semantics are coherent; max malicious events in one minute bucket={max(minute_buckets.values())}."
		)


if __name__ == "__main__":
	unittest.main()