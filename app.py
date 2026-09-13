#!/usr/bin/env python3
"""OWASP Top 10 training target. Never expose this application to the Internet."""

from __future__ import annotations

import json
import os
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import requests
from flask import Flask, Response, g, jsonify, render_template, request, session


def create_app(test_config: dict | None = None) -> Flask:
    app = Flask(__name__)
    app.config.update(
        LAB_MODE=os.getenv("LAB_MODE", "false").lower() == "true",
        DATABASE_PATH=os.getenv("LAB_DATABASE", "/tmp/owasp_lab.db"),
        EVENT_LOG_PATH=os.getenv("LAB_EVENT_LOG", "/tmp/owasp-events.jsonl"),
        SPLUNK_HEC_URL=os.getenv("SPLUNK_HEC_URL", ""),
        SPLUNK_HEC_TOKEN=os.getenv("SPLUNK_HEC_TOKEN", ""),
        SPLUNK_INDEX=os.getenv("SPLUNK_INDEX", "vapt_lab"),
        SPLUNK_SOURCETYPE=os.getenv("SPLUNK_SOURCETYPE", "helpag:owasp:json"),
        SPLUNK_VERIFY_TLS=os.getenv("SPLUNK_VERIFY_TLS", "true").lower() == "true",
        SECRET_KEY=os.getenv("LAB_SESSION_SECRET", "deliberately-weak-lab-secret"),
    )
    if test_config:
        app.config.update(test_config)

    initialize_database(app.config["DATABASE_PATH"])

    def emit_event(event_type: str, severity: str = "info", **fields) -> dict:
        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": event_type,
            "severity": severity,
            "app": "owasp-top10-lab",
            "source_ip": request.headers.get("X-Forwarded-For", request.remote_addr),
            "method": request.method,
            "path": request.path,
            "user_agent": request.headers.get("User-Agent", ""),
            "test_id": request.headers.get("X-Lab-Test-ID", ""),
            **fields,
        }
        line = json.dumps(event, default=str, separators=(",", ":"))
        log_path = Path(app.config["EVENT_LOG_PATH"])
        log_path.parent.mkdir(parents=True, exist_ok=True)
        with log_path.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")

        if app.config["SPLUNK_HEC_URL"] and app.config["SPLUNK_HEC_TOKEN"]:
            payload = {
                "time": time.time(),
                "host": "owasp-lab",
                "source": "vulnerable-web",
                "sourcetype": app.config["SPLUNK_SOURCETYPE"],
                "index": app.config["SPLUNK_INDEX"],
                "event": event,
            }
            try:
                requests.post(
                    app.config["SPLUNK_HEC_URL"],
                    headers={"Authorization": f"Splunk {app.config['SPLUNK_HEC_TOKEN']}"},
                    json=payload,
                    timeout=2,
                    verify=app.config["SPLUNK_VERIFY_TLS"],
                ).raise_for_status()
            except requests.RequestException as exc:
                app.logger.warning("Splunk HEC delivery failed: %s", exc)
        return event

    @app.before_request
    def enforce_lab_mode():
        g.started_at = time.perf_counter()
        if not app.config["LAB_MODE"] and request.path != "/health":
            return jsonify({
                "error": "Lab mode is disabled",
                "fix": "Set LAB_MODE=true only inside an isolated training environment.",
            }), 503

    @app.after_request
    def record_http_request(response):
        if app.config["LAB_MODE"]:
            emit_event(
                "http_request",
                status=response.status_code,
                duration_ms=round((time.perf_counter() - g.started_at) * 1000, 2),
            )
        response.headers["X-Lab-Only"] = "OWASP training target - never expose publicly"
        return response

    @app.get("/health")
    def health():
        return jsonify({"status": "healthy", "lab_mode": app.config["LAB_MODE"]})

    @app.get("/")
    def index():
        return render_template("index.html")

    # A01: Broken Access Control - no authentication or ownership check.
    @app.get("/api/users/<int:user_id>")
    def user_record(user_id: int):
        with database(app.config["DATABASE_PATH"]) as connection:
            row = connection.execute(
                "SELECT id, username, email, role, synthetic_token FROM users WHERE id = ?",
                (user_id,),
            ).fetchone()
        emit_event("broken_access_attempt", "high", object_id=user_id, allowed=True)
        return jsonify(dict(row) if row else {"error": "not found"}), 200 if row else 404

    # A02: Cryptographic Failures - synthetic secrets exposed in a backup response.
    @app.get("/api/backup")
    def exposed_backup():
        emit_event("sensitive_data_exposure", "high", artifact="backup.json")
        return jsonify({
            "warning": "synthetic lab data",
            "password_hash": "5f4dcc3b5aa765d61d8327deb882cf99",
            "api_token": "lab_tok_do_not_use_8fd8a1",
            "encryption": "MD5 / no transport policy",
        })

    # A03: Injection - deliberately concatenates attacker input into SQL.
    @app.get("/api/products/search")
    def product_search():
        query_text = request.args.get("q", "")
        query = f"SELECT id, name, price FROM products WHERE name LIKE '%{query_text}%'"
        try:
            with database(app.config["DATABASE_PATH"]) as connection:
                rows = connection.execute(query).fetchall()
            suspicious = any(token in query_text.lower() for token in ("'", "--", " union ", " or "))
            emit_event("sql_query", "high" if suspicious else "info", query_input=query_text, suspicious=suspicious)
            return jsonify({"query": query, "results": [dict(row) for row in rows]})
        except sqlite3.Error as exc:
            emit_event("sql_error", "high", query_input=query_text, error=str(exc))
            return jsonify({"error": str(exc), "query": query}), 500

    @app.get("/reflect")
    def reflected_xss():
        value = request.args.get("name", "guest")
        emit_event("xss_probe", "high", reflected_input=value)
        return Response(f"<h1>Hello {value}</h1>", mimetype="text/html")

    # A04: Insecure Design - accepts negative quantities and arbitrary prices.
    @app.post("/api/checkout")
    def checkout():
        data = request.get_json(silent=True) or {}
        quantity = float(data.get("quantity", 1))
        unit_price = float(data.get("unit_price", 10))
        total = quantity * unit_price
        emit_event("business_logic_abuse", "high" if total < 0 else "info", quantity=quantity, unit_price=unit_price, total=total)
        return jsonify({"accepted": True, "total": total, "message": "No server-side business-rule validation"})

    # A05: Security Misconfiguration - exposes a synthetic debug configuration.
    @app.get("/api/debug/config")
    def debug_config():
        emit_event("debug_endpoint_access", "medium")
        return jsonify({
            "debug": True,
            "environment": "training",
            "database": app.config["DATABASE_PATH"],
            "fake_cloud_key": "AKIA-LAB-ONLY-NOT-VALID",
            "directory_listing": True,
        })

    # A06: Vulnerable and Outdated Components - inventory is simulated, not installed.
    @app.get("/api/components")
    def components():
        emit_event("outdated_component_inventory", "medium")
        return jsonify({"components": [
            {"name": "log4j-core", "version": "2.14.1", "status": "simulated-vulnerable"},
            {"name": "jquery", "version": "1.12.4", "status": "simulated-vulnerable"},
        ]})

    # A07: Identification and Authentication Failures - weak credentials/no lockout.
    @app.post("/api/login")
    def login():
        data = request.get_json(silent=True) or {}
        username = str(data.get("username", ""))
        password = str(data.get("password", ""))
        success = username == "admin" and password == "admin"
        emit_event("authentication_attempt", "high" if not success else "medium", username=username, success=success)
        if success:
            session["user"] = "admin"
            return jsonify({"authenticated": True, "role": "admin", "warning": "weak lab credentials"})
        return jsonify({"authenticated": False}), 401

    # A08: Software and Data Integrity Failures - trusts unsigned role data.
    @app.post("/api/preferences/import")
    def import_preferences():
        data = request.get_json(silent=True) or {}
        session["role"] = data.get("role", "user")
        emit_event("unsigned_data_import", "high", imported_role=session["role"], signature_checked=False)
        return jsonify({"imported": True, "effective_role": session["role"], "signature_checked": False})

    # A09: Security Logging and Monitoring Failures - intentionally low-context event.
    @app.post("/api/quiet-transfer")
    def quiet_transfer():
        data = request.get_json(silent=True) or {}
        amount = data.get("amount", 0)
        emit_event("monitoring_gap_simulated", "high", amount=amount, actor=None, destination=None)
        return jsonify({"accepted": True, "amount": amount, "audit_context": "intentionally incomplete"})

    # A10: SSRF - bounded to the lab metadata service to avoid arbitrary egress.
    @app.get("/api/fetch")
    def fetch_url():
        target = request.args.get("url", "")
        parsed = urlparse(target)
        allowed = parsed.scheme == "http" and parsed.hostname in {"metadata", "127.0.0.1", "localhost"}
        emit_event("ssrf_probe", "critical" if allowed else "medium", target=target, allowed=allowed)
        if not allowed:
            return jsonify({"error": "This training build bounds SSRF to the local lab service."}), 403
        try:
            response = requests.get(target, timeout=3)
            return jsonify({"status": response.status_code, "body": response.text[:2000]})
        except requests.RequestException as exc:
            return jsonify({"error": str(exc)}), 502

    return app


def database(path: str) -> sqlite3.Connection:
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_database(path: str) -> None:
    with database(path) as connection:
        connection.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT,
                email TEXT,
                role TEXT,
                synthetic_token TEXT
            );
            CREATE TABLE IF NOT EXISTS products (
                id INTEGER PRIMARY KEY,
                name TEXT,
                price REAL
            );
            INSERT OR IGNORE INTO users VALUES
                (1, 'alice', 'alice@lab.invalid', 'user', 'lab_user_001'),
                (2, 'admin', 'admin@lab.invalid', 'admin', 'lab_admin_002');
            INSERT OR IGNORE INTO products VALUES
                (1, 'Training laptop', 900.0),
                (2, 'Security key', 35.0),
                (3, 'Lab router', 75.0);
        """)


app = create_app()

if __name__ == "__main__":
    if not app.config["LAB_MODE"]:
        raise SystemExit("Refusing to start: set LAB_MODE=true inside an isolated lab.")
    app.run(host=os.getenv("LAB_HOST", "127.0.0.1"), port=int(os.getenv("LAB_PORT", "5005")), debug=False)
