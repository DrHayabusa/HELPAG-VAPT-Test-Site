"""Meridian Freight Solutions - application endpoints.

Every function here backs a plausible business feature. Several are insecure by
design; none of them announce it. Proof of exploitation is whatever data the
feature gives up, not a response field.

Guarded by LAB_MODE. Never deploy on a network that is not an isolated range.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import sqlite3
import subprocess
import time
from collections import defaultdict, deque
from pathlib import Path

from flask import (Blueprint, Response, current_app, jsonify, redirect,
                   render_template, render_template_string, request, session)

from labsite.catalog import FINDINGS_BY_ID as F
from labsite.db import connect, reset_token_for
from labsite.events import classify_payload, emit_event

site = Blueprint("site", __name__)

# In-memory failure tracking. Feeds the brute-force detection use case only -
# it deliberately does not lock the account out.
LOGIN_FAILURES: dict[str, deque] = defaultdict(lambda: deque(maxlen=200))


def db():
    return connect(current_app.config["DATABASE_PATH"])


def proof(finding_id: str) -> str:
    """The proof value for a finding, for embedding in a data artifact."""
    return F[finding_id]["flag"]


def note_disclosure(finding_id: str, **fields):
    """Record that an artifact carrying a proof value was disclosed.

    Operator-side telemetry only. Nothing about this reaches the response.
    """
    finding = F[finding_id]
    emit_event("artifact_disclosed", "critical", finding_id=finding_id,
               finding_title=finding["title"], proof_artifact=finding["artifact"],
               owasp=finding["owasp"],
               mitre_techniques=[t[0] for t in finding["mitre"]], **fields)


def current_account():
    return session.get("account")


# ==========================================================================
# Public marketing site
# ==========================================================================

@site.get("/")
def home():
    return render_template("home.html")


@site.get("/about")
def about():
    return render_template("about.html")


@site.get("/services")
def services():
    with db() as connection:
        rates = connection.execute(
            "SELECT lane, service, price_per_kg FROM rates ORDER BY lane").fetchall()
    return render_template("services.html", rates=rates)


@site.get("/news")
def news():
    return render_template("news.html")


@site.get("/careers")
def careers():
    return render_template("careers.html")


@site.route("/contact", methods=["GET", "POST"])
def contact():
    """Stored XSS: enquiries are persisted raw and rendered raw to staff."""
    if request.method == "POST":
        data = request.get_json(silent=True) or request.form
        name = str(data.get("name", ""))[:80]
        company = str(data.get("company", ""))[:80]
        email = str(data.get("email", ""))[:120]
        message = str(data.get("message", ""))[:4000]
        classes = classify_payload(message + name)
        with db() as connection:
            connection.execute(
                "INSERT INTO enquiries (name, company, email, message) VALUES (?,?,?,?)",
                (name, company, email, message))
        emit_event("stored_xss_persisted" if "xss" in classes else "enquiry_received",
                   "high" if "xss" in classes else "info",
                   sender=name, sender_email=email,
                   payload=message if "xss" in classes else "", attack_classes=classes)
        if request.is_json:
            return jsonify({"received": True,
                            "message": "Thank you. A member of the team will respond within one business day."})
        return render_template("contact.html", sent=True)
    return render_template("contact.html", sent=False)


@site.get("/search")
def search():
    """Reflected XSS: the search term is written into the page unencoded."""
    term = request.args.get("q", "")
    classes = classify_payload(term)
    emit_event("xss_probe" if "xss" in classes else "site_search",
               "high" if "xss" in classes else "info",
               search_term=term, attack_classes=classes)
    results = []
    if term:
        with db() as connection:
            results = connection.execute(
                "SELECT lane, service, price_per_kg FROM rates WHERE lane LIKE ?",
                (f"%{term}%",)).fetchall()
    return render_template("search.html", term=term, results=results)


@site.get("/support/shared-search")
def shared_search():
    """A support agent opening a search link a customer sent them.

    Simulates the agent's browser rendering the page. If the shared term
    contains script, the agent's session is treated as compromised and the
    captured cookie is returned - which is what a real attacker would receive
    on their collector.
    """
    term = request.args.get("q", "")
    classes = classify_payload(term)
    executed = "xss" in classes
    emit_event("agent_session_compromised" if executed else "shared_search_opened",
               "critical" if executed else "info",
               search_term=term, attack_classes=classes,
               simulated_victim="support-agent@meridianfreight.example")
    if executed:
        note_disclosure("xss-reflected", victim="support-agent@meridianfreight.example")
        cookie = base64.b64encode(
            json.dumps({"agent": "support-agent", "token": proof("xss-reflected")}).encode()
        ).decode()
        return jsonify({
            "agent_view": "rendered",
            "captured": {"cookie": f"mfs_agent_session={cookie}"},
            "note": "Agent browser executed the shared content.",
        })
    return jsonify({"agent_view": "rendered", "term": term, "captured": None})


@site.get("/robots.txt")
def robots():
    body = (
        "User-agent: *\n"
        "Disallow: /internal/\n"
        "Disallow: /backups/\n"
        "Disallow: /admin/\n"
        "Disallow: /portal/\n"
        "Disallow: /status/\n"
        "Sitemap: /sitemap.xml\n"
    )
    emit_event("recon_robots_read", "low")
    return Response(body, mimetype="text/plain")


@site.get("/sitemap.xml")
def sitemap():
    paths = ["/", "/about", "/services", "/news", "/careers", "/contact"]
    urls = "".join(f"<url><loc>{p}</loc></url>" for p in paths)
    return Response(f'<?xml version="1.0" encoding="UTF-8"?><urlset>{urls}</urlset>',
                    mimetype="application/xml")


@site.get("/internal/<path:name>")
def internal_document(name: str):
    """No access control on a directory robots.txt advertises."""
    target = Path(current_app.config["INTERNAL_DIR"]) / os.path.basename(name)
    if not target.is_file():
        return jsonify({"error": "not found"}), 404
    emit_event("recon_hidden_path", "medium", artifact=target.name)
    emit_event("sensitive_file_access", "high", artifact=target.name)
    if target.name == "it-runbook.txt":
        note_disclosure("recon-runbook", artifact=target.name)
    return Response(target.read_text(encoding="utf-8", errors="replace"), mimetype="text/plain")


@site.get("/.env")
def dotenv():
    """Deployment environment file left inside the document root."""
    body = (
        "APP_ENV=production\n"
        "APP_NAME=meridian-portal\n"
        "SESSION_SIGNING_KEY=meridian-default-signing-key\n"
        "PARTNER_JWT_KEY=mfs-partner-hs256\n"
        "EDI_SERVICE_PASSWORD=autumn2024\n"
        "AWS_ACCESS_KEY_ID=AKIAMFSLABONLYNOTVALID\n"
        f"LEGACY_MIGRATION_KEY={proof('misconfig-dotenv')}\n"
    )
    emit_event("sensitive_file_access", "high", artifact=".env")
    note_disclosure("misconfig-dotenv", artifact=".env")
    return Response(body, mimetype="text/plain")


@site.get("/backups/")
def backup_index():
    base = Path(current_app.config["BACKUP_DIR"])
    names = sorted(p.name for p in base.glob("*")) if base.is_dir() else []
    emit_event("directory_listing_access", "medium", artifact="backups", entries=len(names))
    rows = "".join(
        f'<tr><td><a href="/backups/{n}">{n}</a></td>'
        f'<td>{(base / n).stat().st_size}</td></tr>' for n in names)
    return Response(
        "<html><head><title>Index of /backups/</title></head><body>"
        f"<h1>Index of /backups/</h1><table>{rows}</table></body></html>",
        mimetype="text/html")


@site.get("/backups/<path:name>")
def backup_file(name: str):
    base = Path(current_app.config["BACKUP_DIR"])
    target = base / os.path.basename(name)
    if not target.is_file():
        return jsonify({"error": "not found"}), 404
    emit_event("sensitive_file_access", "high", artifact=target.name)
    if target.name.endswith(".sql"):
        note_disclosure("misconfig-backups", artifact=target.name)
    return Response(target.read_text(encoding="utf-8", errors="replace"), mimetype="text/plain")


@site.get("/status/diagnostics")
def status_diagnostics():
    """Developer status page that shipped in the production profile."""
    emit_event("debug_endpoint_access", "medium")
    note_disclosure("misconfig-debug", artifact="status/diagnostics")
    return jsonify({
        "service": "meridian-portal",
        "build": "2026.9.3",
        "environment": "production",
        "uptime_seconds": 184213,
        "database": current_app.config["DATABASE_PATH"],
        "token_algorithms_accepted": ["HS256", "none"],
        "feature_flags": {"legacy_login": True, "autoindex_backups": True},
        "support_bypass_code": proof("misconfig-debug"),
        "components": [
            {"name": "log4j-core", "version": "2.14.1", "component": "legacy audit shim"},
            {"name": "jquery", "version": "1.12.4", "component": "portal UI"},
            {"name": "openssl", "version": "1.0.2u", "component": "edi transfer"},
        ],
    })


# ==========================================================================
# Customer portal
# ==========================================================================

@site.route("/portal/login", methods=["GET", "POST"])
def portal_login():
    """Two sign-in paths. The legacy one was never converted to parameters."""
    legacy = request.args.get("legacy") == "1"
    if request.method == "GET":
        return render_template("portal_login.html", legacy=legacy)

    data = request.get_json(silent=True) or request.form
    username = str(data.get("username", ""))
    password = str(data.get("password", ""))
    source = request.headers.get("X-Forwarded-For", request.remote_addr or "unknown")
    source = source.split(",")[0].strip()

    if legacy:
        query = ("SELECT id, username, account_type, internal_notes FROM accounts "
                 f"WHERE username = '{username}' AND password = '{password}'")
        classes = classify_payload(username + password)
        try:
            with db() as connection:
                rows = connection.execute(query).fetchall()
        except sqlite3.Error as exc:
            emit_event("sql_error", "high", statement=query, error=str(exc),
                       attack_classes=classes)
            return jsonify({"error": "Sign-in temporarily unavailable.",
                            "detail": str(exc)}), 500
        emit_event("sql_query", "high" if "sqli" in classes else "info",
                   statement=query, suspicious="sqli" in classes, attack_classes=classes,
                   rows_returned=len(rows))
        emit_event("authentication_attempt", "high" if "sqli" in classes else "medium",
                   username=username, success=bool(rows), endpoint="legacy",
                   injection="sqli" in classes, source=source)
        if not rows:
            return jsonify({"authenticated": False}), 401
        row = rows[0]
        session["account"] = row["username"]
        session["account_type"] = row["account_type"]
        if "sqli" in classes:
            note_disclosure("sqli-authbypass", signed_in_as=row["username"])
        return jsonify({"authenticated": True, "username": row["username"],
                        "account_type": row["account_type"],
                        "notice": row["internal_notes"]})

    # Current sign-in path: parameterised, but with no rate limiting or lockout.
    with db() as connection:
        row = connection.execute(
            "SELECT id, username, account_type, internal_notes FROM accounts "
            "WHERE username = ? AND password = ?", (username, password)).fetchone()

    now = time.time()
    window = LOGIN_FAILURES[source]
    if row is None:
        window.append(now)
    recent = sum(1 for t in window if now - t <= 60)
    if recent >= 5:
        emit_event("brute_force_suspected", "critical", source=source,
                   failures_last_60s=recent, username=username, lockout_applied=False)
    emit_event("authentication_attempt", "medium" if row else "high",
               username=username, success=bool(row), endpoint="portal",
               failures_last_60s=recent, lockout_applied=False, source=source)
    if row is None:
        return jsonify({"authenticated": False,
                        "message": "Incorrect username or password."}), 401

    session["account"] = row["username"]
    session["account_type"] = row["account_type"]
    if row["username"] == "svc_edi":
        note_disclosure("auth-bruteforce", username=row["username"],
                        failures_before_success=recent)
    return jsonify({"authenticated": True, "username": row["username"],
                    "account_type": row["account_type"],
                    "notice": row["internal_notes"]})


@site.get("/portal")
@site.get("/portal/dashboard")
def portal_dashboard():
    account = current_account()
    if not account:
        return redirect("/portal/login")
    with db() as connection:
        row = connection.execute(
            "SELECT * FROM accounts WHERE username = ?", (account,)).fetchone()
        shipments = connection.execute(
            "SELECT reference, origin, destination, service, status FROM shipments "
            "WHERE account_id = ? ORDER BY reference", (row["id"] if row else 0,)).fetchall()
    return render_template("portal_dashboard.html", account=row, shipments=shipments,
                           staff=session.get("account_type") in {"staff", "operations", "admin"})


@site.get("/portal/shipments")
def portal_shipments():
    return render_template("portal_shipments.html")


@site.get("/api/v1/shipments/<reference>")
def shipment_detail(reference: str):
    """IDOR: references are sequential and ownership is never checked."""
    with db() as connection:
        row = connection.execute(
            "SELECT reference, origin, destination, service, status, declared_value,"
            " contents, handling_notes, account_id FROM shipments WHERE reference = ?",
            (reference,)).fetchone()
    emit_event("broken_access_attempt", "high", object_id=reference, allowed=True,
               found=bool(row), authenticated_as=current_account() or "anonymous")
    if not row:
        return jsonify({"error": "Consignment not found."}), 404
    record = dict(row)
    if reference == "MFS-2026-4471":
        note_disclosure("idor-shipment", object_id=reference)
    return jsonify(record)


@site.post("/portal/profile")
def portal_profile():
    """Mass assignment: every submitted field is bound to the record."""
    data = request.get_json(silent=True) or request.form
    allowed_by_ui = {"contact_name", "email", "phone"}
    submitted = {k: v for k, v in data.items()}
    sensitive = {k: v for k, v in submitted.items() if k not in allowed_by_ui}
    emit_event("mass_assignment_attempt", "high" if sensitive else "info",
               submitted_fields=sorted(submitted), sensitive_fields=sorted(sensitive))
    session["profile"] = submitted
    account_type = str(submitted.get("account_type", "")).lower()
    if account_type in {"staff", "operations", "admin"}:
        session["account_type"] = account_type
        emit_event("privilege_change", "critical", new_role=account_type,
                   mechanism="mass_assignment")
        note_disclosure("access-massassign", new_role=account_type)
        return jsonify({
            "updated": True, "account_type": account_type,
            "operations_dashboard": {
                "open_exceptions": 4, "depots": ["Rotterdam", "Hamburg", "Felixstowe"],
                "dispatch_authorisation_code": proof("access-massassign"),
            },
        })
    return jsonify({"updated": True, "fields": sorted(submitted)})


@site.route("/portal/reset", methods=["GET", "POST"])
def portal_reset():
    if request.method == "GET":
        return render_template("portal_reset.html")
    data = request.get_json(silent=True) or request.form
    username = str(data.get("username", ""))
    with db() as connection:
        row = connection.execute("SELECT username FROM accounts WHERE username = ?",
                                 (username,)).fetchone()
        if row:
            connection.execute(
                "INSERT OR REPLACE INTO reset_tokens (username, token) VALUES (?,?)",
                (username, reset_token_for(username)))
    emit_event("password_reset_request", "medium", target_user=username, user_exists=bool(row))
    if not row:
        return jsonify({"sent": False, "message": "No account matches that username."}), 404
    body = {"sent": True,
            "message": "A reset link has been sent to the address on file."}
    if username == "dokafor":  # only your own link is shown in this demo tenant
        body["reset_link"] = f"/portal/reset/confirm?u={username}&t={reset_token_for(username)}"
    return jsonify(body)


@site.post("/api/v1/account/reset")
def reset_confirm():
    """Reset tokens are md5(username), so any account can be taken over."""
    data = request.get_json(silent=True) or request.form
    username = str(data.get("username", ""))
    token = str(data.get("token", "")).strip().lower()
    valid = hmac.compare_digest(token, reset_token_for(username))
    foreign = valid and username != "dokafor"
    emit_event("password_reset_consume", "critical" if foreign else "medium",
               target_user=username, token_valid=valid, token_predictable=True)
    if not valid:
        return jsonify({"reset": False, "message": "That link is not valid."}), 403
    with db() as connection:
        row = connection.execute(
            "SELECT account_ref, company, contact_name, email, account_type, internal_notes"
            " FROM accounts WHERE username = ?", (username,)).fetchone()
    if foreign:
        emit_event("account_takeover", "critical", target_user=username,
                   mechanism="predictable_reset_token")
        note_disclosure("reset-token", target_user=username)
    session["account"] = username
    return jsonify({"reset": True, "username": username,
                    "temporary_password": "Meridian#Temp1",
                    "account": dict(row) if row else {}})


# ==========================================================================
# Quotes, rates, invoices, careers
# ==========================================================================

@site.get("/api/v1/rates/search")
def rate_search():
    """SQL injection: the lane filter is concatenated into the statement."""
    term = request.args.get("q", "")
    query = f"SELECT id, lane, service FROM rates WHERE lane LIKE '%{term}%'"
    classes = classify_payload(term)
    try:
        with db() as connection:
            rows = connection.execute(query).fetchall()
    except sqlite3.Error as exc:
        emit_event("sql_error", "high", query_input=term, statement=query,
                   error=str(exc), attack_classes=classes)
        return jsonify({"error": "Rate lookup failed.", "detail": str(exc),
                        "query": query}), 500
    emit_event("sql_query", "high" if "sqli" in classes else "info",
               query_input=term, statement=query, suspicious="sqli" in classes,
               attack_classes=classes, rows_returned=len(rows))
    results = [dict(r) for r in rows]
    if any(proof("sqli-union") in str(r) for r in results):
        note_disclosure("sqli-union", technique="union_select")
    return jsonify({"query": query, "results": results})


@site.route("/services/quote", methods=["GET", "POST"])
def quote():
    """No server-side validation of quantity or declared value."""
    if request.method == "GET":
        return render_template("quote.html")
    data = request.get_json(silent=True) or request.form
    try:
        weight = float(data.get("weight_kg", 1))
        rate = float(data.get("rate_per_kg", 0.42))
    except (TypeError, ValueError):
        return jsonify({"error": "weight_kg and rate_per_kg must be numeric"}), 400
    total = round(weight * rate, 2)
    emit_event("business_logic_abuse" if total < 0 else "quote_generated",
               "high" if total < 0 else "info",
               weight_kg=weight, rate_per_kg=rate, total=total, negative_total=total < 0)
    if total < 0:
        note_disclosure("logic-negative-quote", total=total)
        return jsonify({
            "quote_accepted": True, "total": total,
            "credit_note": {
                "issued": True, "amount": abs(total),
                "authorisation_reference": proof("logic-negative-quote"),
            },
        })
    return jsonify({"quote_accepted": True, "total": total, "currency": "EUR"})


@site.get("/api/v1/invoices/download")
def invoice_download():
    """Path traversal: the document name is joined onto a base path."""
    name = request.args.get("document", "terms-of-carriage.txt")
    classes = classify_payload(name)
    base = current_app.config["DOCUMENT_DIR"]
    target = os.path.join(base, name)  # no normalisation, no realpath check
    emit_event("path_traversal_attempt" if "traversal" in classes else "invoice_download",
               "high" if "traversal" in classes else "info",
               requested_document=name, resolved_path=target, attack_classes=classes)
    try:
        content = Path(target).read_text(encoding="utf-8", errors="replace")[:6000]
    except OSError as exc:
        return jsonify({"error": "Document not available.",
                        "detail": str(exc), "resolved": target}), 404
    if "traversal" in classes:
        emit_event("sensitive_file_access", "high", artifact=target)
    if proof("traversal-invoice") in content:
        note_disclosure("traversal-invoice", resolved_path=target)
    return Response(content, mimetype="text/plain")


@site.post("/careers/apply")
def careers_apply():
    """No extension allow-list, no content inspection, browsable store."""
    upload_dir = Path(current_app.config["UPLOAD_DIR"])
    upload_dir.mkdir(parents=True, exist_ok=True)
    handle = request.files.get("cv") or request.files.get("file")
    if handle is None:
        return jsonify({"error": "Attach your CV in the 'cv' field."}), 400
    name = os.path.basename(handle.filename or "application")
    target = upload_dir / name
    handle.save(target)
    extension = target.suffix.lower().lstrip(".")
    dangerous = extension in {"php", "phtml", "jsp", "jspx", "asp", "aspx",
                              "sh", "py", "exe", "dll", "war"}
    emit_event("file_upload", "high" if dangerous else "info",
               filename=name, extension=extension, size_bytes=target.stat().st_size,
               content_type=handle.content_type, dangerous=dangerous)
    if dangerous:
        emit_event("dangerous_upload", "critical", filename=name, extension=extension)
    return jsonify({"received": True, "filename": name,
                    "reference": f"MFS-APP-{abs(hash(name)) % 100000:05d}",
                    "message": "Thank you. Your application is stored with our recruitment team.",
                    "location": f"/uploads/{name}"})


@site.get("/uploads/")
def upload_index():
    """The applicant document store lists its own contents."""
    base = Path(current_app.config["UPLOAD_DIR"])
    names = sorted(p.name for p in base.glob("*") if p.is_file() and p.name != ".gitkeep")
    emit_event("directory_listing_access", "medium", artifact="uploads", entries=len(names))
    rows = "".join(f'<li><a href="/uploads/{n}">{n}</a></li>' for n in names)
    return Response(f"<html><body><h1>Index of /uploads/</h1><ul>{rows}</ul></body></html>",
                    mimetype="text/html")


@site.get("/uploads/<path:name>")
def serve_upload(name: str):
    """Uploaded documents are served back, always as inert text/plain.

    The range stops short of executing uploaded code: the finding is the
    unrestricted write plus the browsable store, and a shared range should not
    hand every tester persistent execution.
    """
    target = Path(current_app.config["UPLOAD_DIR"]) / os.path.basename(name)
    if not target.is_file():
        return jsonify({"error": "not found"}), 404
    emit_event("uploaded_file_served", "medium", filename=target.name)
    content = target.read_bytes()[:8000]
    if proof("upload-unrestricted").encode() in content:
        note_disclosure("upload-unrestricted", filename=target.name)
    return Response(content, mimetype="text/plain")


# ==========================================================================
# Partner API
# ==========================================================================

def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


@site.get("/api/v1/auth/token")
def issue_token():
    """Issues an HS256 bearer token for a partner integration."""
    partner = request.args.get("partner", "harborline")
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {"sub": partner, "scope": "shipments:read", "role": "partner",
               "iat": int(time.time())}
    signing_input = f"{b64url(json.dumps(header).encode())}.{b64url(json.dumps(payload).encode())}"
    signature = hmac.new(current_app.config["JWT_KEY"].encode(),
                         signing_input.encode(), hashlib.sha256).digest()
    emit_event("jwt_issued", "info", subject=partner, role="partner", algorithm="HS256")
    return jsonify({"access_token": f"{signing_input}.{b64url(signature)}",
                    "token_type": "Bearer", "expires_in": 3600, "scope": "shipments:read"})


def verify_token(token: str) -> tuple[dict | None, str]:
    """Honours the algorithm declared in the token, including 'none'."""
    try:
        header_b64, payload_b64, signature_b64 = token.split(".")
        header = json.loads(b64url_decode(header_b64))
        payload = json.loads(b64url_decode(payload_b64))
    except Exception:
        return None, "malformed"
    algorithm = str(header.get("alg", "")).lower()
    if algorithm == "none":
        return payload, "none"
    expected = hmac.new(current_app.config["JWT_KEY"].encode(),
                        f"{header_b64}.{payload_b64}".encode(), hashlib.sha256).digest()
    if hmac.compare_digest(b64url(expected), signature_b64):
        return payload, "HS256"
    return None, "bad-signature"


@site.get("/api/v1/reports/financial")
def financial_report():
    token = request.headers.get("Authorization", "").removeprefix("Bearer ").strip()
    payload, algorithm = verify_token(token)
    emit_event("jwt_verify", "critical" if algorithm == "none" else "info",
               algorithm=algorithm, subject=(payload or {}).get("sub"),
               claimed_role=(payload or {}).get("role"), accepted=payload is not None)
    if payload is None:
        return jsonify({"error": "Invalid credentials."}), 401
    if str(payload.get("role")) not in {"finance", "admin"}:
        return jsonify({"error": "Insufficient scope for this report.",
                        "your_role": payload.get("role")}), 403
    report = {
        "period": "FY2026 Q3",
        "revenue_eur": 48291330,
        "operating_margin": 0.114,
        "top_lanes": ["Jebel Ali - Rotterdam", "Rotterdam - Felixstowe"],
    }
    if algorithm == "none":
        emit_event("jwt_unsigned_accepted", "critical", subject=payload.get("sub"))
        emit_event("privilege_change", "critical", new_role=payload.get("role"),
                   mechanism="jwt_alg_none")
        note_disclosure("jwt-none", subject=payload.get("sub"))
        report["distribution_reference"] = proof("jwt-none")
    return jsonify(report)


@site.post("/api/v1/edi/manifest")
def edi_manifest():
    """XXE: the EDI parser has DTD loading and entity resolution enabled."""
    raw = request.get_data(as_text=True)
    classes = classify_payload(raw)
    emit_event("xxe_attempt" if "xxe" in classes else "xml_import",
               "critical" if "xxe" in classes else "info",
               payload_bytes=len(raw), attack_classes=classes,
               declares_doctype="<!doctype" in raw.lower())
    try:
        from lxml import etree
        parser = etree.XMLParser(resolve_entities=True, load_dtd=True, no_network=True)
        root = etree.fromstring(raw.encode("utf-8"), parser)
        text = etree.tostring(root, encoding="unicode", method="text")[:6000]
    except Exception as exc:
        emit_event("xml_parse_error", "high", error=str(exc))
        return jsonify({"accepted": False, "error": f"{type(exc).__name__}: {exc}"}), 400
    if proof("xxe-edi") in text:
        note_disclosure("xxe-edi", payload_bytes=len(raw))
    return jsonify({"accepted": True, "parsed": text})


@site.route("/api/v1/audit/event", methods=["GET", "POST"])
def audit_event():
    """Legacy audit shim that still expands lookup expressions in headers.

    No JNDI resolution, LDAP connection or class loading happens. The range
    records the attempt so the detection use case has something real to match.
    """
    agent = request.headers.get("X-Tracking-Agent", request.headers.get("User-Agent", ""))
    classes = classify_payload(agent)
    triggered = "jndi" in classes
    emit_event("jndi_lookup_detected" if triggered else "audit_event",
               "critical" if triggered else "info",
               tracking_agent=agent, attack_classes=classes,
               component="log4j-core 2.14.1", lookup_performed=False)
    emit_event("outdated_component_inventory", "medium", component="log4j-core 2.14.1")
    body = {"logged": True, "component": "meridian-audit-shim 1.4 (log4j-core 2.14.1)"}
    if triggered:
        note_disclosure("jndi-audit", tracking_agent=agent)
        body["resolved"] = {"lookup": "expanded by the logging shim",
                            "service_token": proof("jndi-audit")}
    return jsonify(body)


# ==========================================================================
# Staff administration area
# ==========================================================================

def staff_session() -> bool:
    """Access is decided entirely by the signed session cookie."""
    return bool(session.get("is_staff")) or \
        session.get("account_type") in {"staff", "operations", "admin"}


@site.get("/admin")
@site.get("/admin/")
def admin_home():
    granted = staff_session()
    emit_event("admin_panel_access", "critical" if granted else "medium",
               granted=granted, session_account=session.get("account"),
               session_type=session.get("account_type"))
    if not granted:
        return render_template("admin_denied.html"), 403
    if session.get("is_staff") and not session.get("account"):
        # is_staff set without any sign-in having happened on this session.
        emit_event("forged_session_detected", "critical",
                   reason="staff flag present with no preceding authentication event")
        note_disclosure("weak-session-secret", session_account=session.get("account"))
    return render_template("admin_home.html",
                           recovery_code=proof("weak-session-secret"))


@site.get("/admin/messages")
def admin_messages():
    """Staff message queue. Enquiries are rendered exactly as received."""
    with db() as connection:
        rows = connection.execute(
            "SELECT name, company, email, message, received_at FROM enquiries"
            " ORDER BY id DESC LIMIT 50").fetchall()
    triggered = [r for r in rows if "xss" in classify_payload(r["message"])]
    emit_event("staff_session_compromised" if triggered else "message_queue_viewed",
               "critical" if triggered else "info",
               entries=len(rows), payloads_executed=len(triggered),
               simulated_victim="ops-manager@meridianfreight.example")
    captured = None
    if triggered:
        note_disclosure("xss-stored", payloads=len(triggered))
        captured = base64.b64encode(json.dumps({
            "user": "ops-manager", "token": proof("xss-stored")}).encode()).decode()
    return render_template("admin_messages.html", enquiries=rows, captured=captured)


@site.route("/admin/diagnostics", methods=["GET", "POST"])
def admin_diagnostics():
    """Depot connectivity check. The host field reaches a shell."""
    if request.method == "GET":
        return render_template("admin_diagnostics.html", output=None, host="")
    data = request.get_json(silent=True) or request.form
    host = str(data.get("host", "127.0.0.1"))
    classes = classify_payload(host)
    ping_flags = "-n 1 -w 1000" if os.name == "nt" else "-c 1 -W 1"
    command = f"ping {ping_flags} {host}"
    emit_event("command_injection_attempt" if "cmdi" in classes else "diagnostics_request",
               "critical" if "cmdi" in classes else "info",
               host_input=host, command_line=command, attack_classes=classes)
    try:
        completed = subprocess.run(command, shell=True, capture_output=True,
                                   text=True, timeout=10)
        output = (completed.stdout + completed.stderr)[:6000]
        code = completed.returncode
    except subprocess.TimeoutExpired:
        output, code = "Request timed out.", 124
    emit_event("command_execution", "critical" if "cmdi" in classes else "info",
               command_line=command, exit_code=code, output_bytes=len(output),
               process="cmd.exe" if os.name == "nt" else "sh", parent_process="python")
    if proof("rce-cmdi") in output:
        note_disclosure("rce-cmdi", command_line=command)
    if request.is_json:
        return jsonify({"host": host, "exit_code": code, "output": output})
    return render_template("admin_diagnostics.html", output=output, host=host)


@site.route("/admin/campaigns/preview", methods=["GET", "POST"])
def campaign_preview():
    """Campaign bodies are compiled by the template engine, not passed as data."""
    if request.method == "GET":
        body = request.args.get("body", "")
    else:
        data = request.get_json(silent=True) or request.form
        body = str(data.get("body", ""))
    if not body:
        return render_template("admin_campaigns.html", rendered=None, body="")

    classes = classify_payload(body)
    emit_event("ssti_attempt" if "ssti" in classes else "template_render",
               "critical" if "ssti" in classes else "info",
               template_input=body, attack_classes=classes)
    try:
        rendered = render_template_string(
            body, customer_name="Dana Okafor", account_ref="MFS-AC-1001")[:6000]
    except Exception as exc:
        emit_event("template_error", "high", template_input=body, error=str(exc))
        return jsonify({"error": f"{type(exc).__name__}: {exc}"}), 500
    if proof("rce-ssti") in rendered:
        note_disclosure("rce-ssti", template_input=body)
    if request.is_json or request.method == "GET":
        return Response(rendered, mimetype="text/html")
    return render_template("admin_campaigns.html", rendered=rendered, body=body)


@site.get("/admin/integrations/preview")
def link_preview():
    """SSRF, bounded to lab-internal destinations so the range cannot egress."""
    import requests as http
    from urllib.parse import urlparse

    target = request.args.get("url", "")
    parsed = urlparse(target)
    allowed_hosts = {"metadata", "127.0.0.1", "localhost", "169.254.169.254",
                     "mfs-metadata", "meridian-metadata"}
    internal = parsed.hostname in allowed_hosts
    allowed = parsed.scheme in {"http", "https"} and internal
    emit_event("ssrf_probe", "critical" if internal else "medium",
               target=target, target_host=parsed.hostname,
               target_scheme=parsed.scheme, allowed=allowed)
    if not allowed:
        return jsonify({
            "error": "Preview unavailable for that destination.",
            "reachable_hosts": sorted(allowed_hosts),
        }), 403
    try:
        response = http.get(target, timeout=3)
        body = response.text[:3000]
    except http.RequestException as exc:
        return jsonify({"error": "Preview failed.", "detail": str(exc)}), 502
    if proof("ssrf-metadata") in body:
        note_disclosure("ssrf-metadata", target=target)
    return jsonify({"url": target, "status": response.status_code, "preview": body})
