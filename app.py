#!/usr/bin/env python3
"""HELP AG VAPT range - CTF entrypoint.

An intentionally vulnerable application. Never expose it to the Internet or to a
production network. Every identity, secret and token in this build is synthetic.
"""

from __future__ import annotations

import os
import time
from pathlib import Path

from flask import Flask, g, jsonify, render_template, request

from labsite import db
from labsite.challenges import vuln
from labsite.ctf import ctf
from labsite.events import emit_event

BASE_DIR = Path(__file__).resolve().parent


def create_app(test_config: dict | None = None) -> Flask:
    app = Flask(__name__)
    app.config.update(
        LAB_MODE=os.getenv("LAB_MODE", "false").lower() == "true",
        DATABASE_PATH=os.getenv("LAB_DATABASE", "/tmp/ctf_lab.db"),
        EVENT_LOG_PATH=os.getenv("LAB_EVENT_LOG", "/tmp/helpag-events.jsonl"),
        DOCUMENT_DIR=os.getenv("LAB_DOCUMENT_DIR", str(BASE_DIR / "public_docs")),
        UPLOAD_DIR=os.getenv("LAB_UPLOAD_DIR", str(BASE_DIR / "uploads")),
        BACKUP_DIR=os.getenv("LAB_BACKUP_DIR", str(BASE_DIR / "backups")),
        SPLUNK_HEC_URL=os.getenv("SPLUNK_HEC_URL", ""),
        SPLUNK_HEC_TOKEN=os.getenv("SPLUNK_HEC_TOKEN", ""),
        SPLUNK_INDEX=os.getenv("SPLUNK_INDEX", "vapt_lab"),
        SPLUNK_SOURCETYPE=os.getenv("SPLUNK_SOURCETYPE", "helpag:owasp:json"),
        SPLUNK_VERIFY_TLS=os.getenv("SPLUNK_VERIFY_TLS", "true").lower() == "true",
        # Deliberately weak and deliberately published: challenge auth-weak-secret
        # expects a player to recover this from a wordlist.
        SECRET_KEY=os.getenv("LAB_SESSION_SECRET", "deliberately-weak-lab-secret"),
        JWT_KEY=os.getenv("LAB_JWT_KEY", "labkey"),
        MAX_CONTENT_LENGTH=8 * 1024 * 1024,
    )
    if test_config:
        app.config.update(test_config)

    db.initialize(app.config["DATABASE_PATH"])
    app.register_blueprint(ctf)
    app.register_blueprint(vuln)

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
            emit_event("http_request", "info", status=response.status_code,
                       duration_ms=round((time.perf_counter() - g.started_at) * 1000, 2),
                       query_string=request.query_string.decode("utf-8", "replace")[:512])
        response.headers["X-Lab-Only"] = "HELP AG VAPT range - never expose publicly"
        return response

    @app.errorhandler(404)
    def not_found(_):
        emit_event("http_not_found", "low",
                   query_string=request.query_string.decode("utf-8", "replace")[:256])
        return jsonify({"error": "not found", "path": request.path}), 404

    @app.get("/health")
    def health():
        return jsonify({"status": "healthy", "lab_mode": app.config["LAB_MODE"]})

    @app.get("/rules")
    def rules():
        return render_template("rules.html")

    return app


app = create_app()

if __name__ == "__main__":
    if not app.config["LAB_MODE"]:
        raise SystemExit("Refusing to start: set LAB_MODE=true inside an isolated lab.")
    app.run(host=os.getenv("LAB_HOST", "127.0.0.1"),
            port=int(os.getenv("LAB_PORT", "5005")), debug=False)
