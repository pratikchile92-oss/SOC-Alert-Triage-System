import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from soc_triage import run_triage


class TestSOCTriage(unittest.TestCase):
    def setUp(self):
        self.rules = {
            "failed_login_burst": {"severity": "High"},
            "malware_detection": {"severity": "Critical"},
        }

    def test_duplicate_events_are_grouped(self):
        alerts = [
            {"event_type":"failed_login_burst","source_ip":"1.2.3.4","username":"u","host":"h","timestamp":"1"},
            {"event_type":"failed_login_burst","source_ip":"1.2.3.4","username":"u","host":"h","timestamp":"2"},
        ]
        result = run_triage(alerts, self.rules)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["occurrences"], 2)

    def test_different_source_ip_not_merged(self):
        alerts = [
            {"event_type":"failed_login_burst","source_ip":"1.2.3.4","username":"u","host":"h","timestamp":"1"},
            {"event_type":"failed_login_burst","source_ip":"5.6.7.8","username":"u","host":"h","timestamp":"2"},
        ]
        self.assertEqual(len(run_triage(alerts, self.rules)), 2)

    def test_critical_severity(self):
        alerts = [{"event_type":"malware_detection","source_ip":"1","username":"u","host":"h","timestamp":"1"}]
        self.assertEqual(run_triage(alerts, self.rules)[0]["severity"], "Critical")

    def test_response_is_non_destructive(self):
        alerts = [{"event_type":"malware_detection","source_ip":"1","username":"u","host":"h","timestamp":"1"}]
        result = run_triage(alerts, self.rules)
        self.assertIn("no system changes", result[0]["response_mode"].lower())


if __name__ == "__main__":
    unittest.main()
