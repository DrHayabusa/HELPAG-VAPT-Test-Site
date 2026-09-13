import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from app import create_app


class TestSiteTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        base = Path(self.temp.name)
        self.log_path = base / "events.jsonl"
        self.app = create_app({
            "TESTING": True,
            "LAB_MODE": True,
            "DATABASE_PATH": str(base / "lab.db"),
            "EVENT_LOG_PATH": str(self.log_path),
            "SPLUNK_HEC_URL": "",
            "SPLUNK_HEC_TOKEN": "",
        })
        self.client = self.app.test_client()

    def tearDown(self):
        self.temp.cleanup()

    def events(self):
        return [json.loads(line) for line in self.log_path.read_text().splitlines()]

    def test_lab_guard(self):
        guarded = create_app({
            "TESTING": True,
            "LAB_MODE": False,
            "DATABASE_PATH": str(Path(self.temp.name) / "guard.db"),
            "EVENT_LOG_PATH": str(Path(self.temp.name) / "guard.jsonl"),
        }).test_client()
        self.assertEqual(guarded.get("/").status_code, 503)
        self.assertEqual(guarded.get("/health").status_code, 200)

    def test_all_training_events(self):
        self.client.get("/api/users/2")
        self.client.get("/api/backup")
        injection = self.client.get("/api/products/search", query_string={"q": "' OR 1=1--"})
        self.client.get("/reflect", query_string={"name": "<script>alert(1)</script>"})
        self.client.post("/api/checkout", json={"quantity": -5, "unit_price": 100})
        self.client.get("/api/debug/config")
        self.client.get("/api/components")
        self.client.post("/api/login", json={"username": "admin", "password": "admin"})
        self.client.post("/api/preferences/import", json={"role": "admin"})
        self.client.post("/api/quiet-transfer", json={"amount": 9999})
        self.assertEqual(injection.status_code, 200)
        event_types = {item["event_type"] for item in self.events()}
        expected = {
            "broken_access_attempt", "sensitive_data_exposure", "sql_query", "xss_probe",
            "business_logic_abuse", "debug_endpoint_access", "outdated_component_inventory",
            "authentication_attempt", "unsigned_data_import", "monitoring_gap_simulated",
        }
        self.assertTrue(expected.issubset(event_types))

    @patch("app.requests.get")
    def test_ssrf_boundary(self, mock_get):
        mock_get.return_value = Mock(status_code=200, text="synthetic")
        self.assertEqual(self.client.get("/api/fetch", query_string={"url": "http://metadata:8080/"}).status_code, 200)
        self.assertEqual(self.client.get("/api/fetch", query_string={"url": "https://example.com/"}).status_code, 403)

    @patch("app.requests.post")
    def test_hec_shape(self, mock_post):
        mock_post.return_value.raise_for_status.return_value = None
        app = create_app({
            "TESTING": True,
            "LAB_MODE": True,
            "DATABASE_PATH": str(Path(self.temp.name) / "hec.db"),
            "EVENT_LOG_PATH": str(Path(self.temp.name) / "hec.jsonl"),
            "SPLUNK_HEC_URL": "https://splunk.invalid:8088/services/collector/event",
            "SPLUNK_HEC_TOKEN": "test-token",
        })
        app.test_client().get("/api/backup")
        payload = mock_post.call_args.kwargs["json"]
        self.assertEqual(payload["sourcetype"], "helpag:owasp:json")
        self.assertIn("event", payload)


if __name__ == "__main__":
    unittest.main()

