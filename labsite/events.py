"""Structured event emission for Splunk / SIEM detection use cases."""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path

import requests
from flask import current_app, request, session


def client_ip() -> str:
    """The originating client address.

    Behind IIS/ARR or any reverse proxy, X-Forwarded-For is a comma-separated
    chain and the original client is the first entry. Every detection use case
    groups by this field, so getting it wrong makes the whole pack useless.
    """
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "unknown"


def emit_event(event_type: str, severity: str = "info", **fields) -> dict:
    """Write one JSON event to the lab event log and optionally to Splunk HEC."""
    app = current_app
    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": event_type,
        "severity": severity,
        "app": "helpag-ctf-lab",
        "source_ip": client_ip(),
        "method": request.method,
        "path": request.path,
        "user_agent": request.headers.get("User-Agent", ""),
        "referer": request.headers.get("Referer", ""),
        "test_id": request.headers.get("X-Lab-Test-ID", ""),
        "team": session.get("team", ""),
        **fields,
    }
    line = json.dumps(event, default=str, separators=(",", ":"))
    log_path = Path(app.config["EVENT_LOG_PATH"])
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("a", encoding="utf-8") as handle:
        handle.write(line + "\n")

    if app.config.get("SPLUNK_HEC_URL") and app.config.get("SPLUNK_HEC_TOKEN"):
        payload = {
            "time": time.time(),
            "host": "helpag-ctf-lab",
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


ATTACK_SIGNATURES = {
    "sqli": ("'", '"', " union ", " or 1=1", "--", "/*", "sleep(", "benchmark(", "0x"),
    "xss": ("<script", "javascript:", "onerror=", "onload=", "<img", "<svg", "alert("),
    "traversal": ("../", "..\\", "%2e%2e", "....//", "/etc/passwd", "boot.ini"),
    "cmdi": (";", "|", "&", "`", "$(", "\n", "%0a"),  # & covers Windows cmd chaining
    "ssti": ("{{", "}}", "{%", "__class__", "__globals__"),
    "xxe": ("<!doctype", "<!entity", "system ", "file://"),
    "jndi": ("${jndi:", "${lower:", "${::-"),
}


def classify_payload(value: str) -> list[str]:
    """Return the attack classes a raw input string looks like. Used for alerting."""
    lowered = (value or "").lower()
    return [name for name, tokens in ATTACK_SIGNATURES.items() if any(t in lowered for t in tokens)]
