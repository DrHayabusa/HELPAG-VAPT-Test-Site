"""Deliberately vulnerable endpoints. Every function here is insecure on purpose.

Guarded by LAB_MODE. Never deploy on a network that is not an isolated range.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import shlex
import sqlite3
import subprocess
import time
from collections import defaultdict, deque
from pathlib import Path

from flask import (Blueprint, Response, current_app, jsonify, redirect,
                   render_template, render_template_string, request, session)

from labsite.catalog import CHALLENGES_BY_ID as C
from labsite.db import connect, reset_token_for
from labsite.events import classify_payload, emit_event

vuln = Blueprint("vuln", __name__)

# In-memory failure tracking. Powers the brute-force detection use case only -
# it deliberately does NOT lock the account out.
LOGIN_FAILURES: dict[str, deque] = defaultdict(lambda: deque(maxlen=200))


def db():
    return connect(current_app.config["DATABASE_PATH"])


def flag(challenge_id: str) -> str:
    return C[challenge_id]["flag"]


def award(challenge_id: str, **fields):
    """Emit the capture-relevant event and return the flag payload."""
    challenge = C[challenge_id]
    emit_event("challenge_flag_disclosed", "critical", challenge_id=challenge_id,
               challenge_title=challenge["title"], owasp=challenge["owasp"],
               mitre_techniques=[t[0] for t in challenge["mitre"]], **fields)
    return challenge["flag"]


# --------------------------------------------------------------------------
# Recon and misconfiguration
# --------------------------------------------------------------------------

@vuln.get("/robots.txt")
def robots():
    body = (
        "User-agent: *\n"
        "Disallow: /internal/\n"
        "Disallow: /backups/\n"
        "Disallow: /api/debug/\n"
        "Disallow: /admin/\n"
        "# engineering notes moved to /internal/engineering-notes.txt\n"
    )
    emit_event("recon_robots_read", "low")
    return Response(body, mimetype="text/plain")


@vuln.get("/internal/engineering-notes.txt")
def engineering_notes():
    body = (
        "HELP AG range - engineering notes (synthetic)\n"
        "=============================================\n"
        "- Session secret is still the default from the scaffold.\n"
        "- Legacy login at /api/legacy/login has not been migrated to parameters yet.\n"
        "- Diagnostics tool at /api/diagnostics/ping shells out. Ticket OPS-4412 open.\n"
        f"- Onboarding flag for the range: {flag('recon-robots')}\n"
    )
    award("recon-robots", artifact="engineering-notes.txt")
    emit_event("recon_hidden_path", "medium", artifact="engineering-notes.txt")
    return Response(body, mimetype="text/plain")


@vuln.get("/.env")
def dotenv():
    body = (
        "APP_ENV=training\n"
        "LAB_SESSION_SECRET=deliberately-weak-lab-secret\n"
        "JWT_SIGNING_KEY=labkey\n"
        "SVC_BACKUP_PASSWORD=summer2024\n"
        "AWS_ACCESS_KEY_ID=AKIA-LAB-ONLY-NOT-VALID\n"
        f"RANGE_FLAG={flag('misconfig-dotenv')}\n"
    )
    award("misconfig-dotenv", artifact=".env")
    emit_event("sensitive_file_access", "high", artifact=".env")
    return Response(body, mimetype="text/plain")


@vuln.get("/backups/")
def backup_listing():
    base = Path(current_app.config["BACKUP_DIR"])
    names = sorted(p.name for p in base.glob("*")) if base.is_dir() else []
    emit_event("directory_listing_access", "medium", artifact="backups", entries=len(names))
    links = "".join(f'<li><a href="/backups/{n}">{n}</a></li>' for n in names)
    return Response(f"<h1>Index of /backups/</h1><ul>{links}</ul>", mimetype="text/html")


@vuln.get("/backups/<path:name>")
def backup_file(name: str):
    base = Path(current_app.config["BACKUP_DIR"])
    target = base / name
    if not target.is_file():
        return jsonify({"error": "not found"}), 404
    if name.endswith(".bak"):
        award("misconfig-backups", artifact=name)
    emit_event("sensitive_file_access", "high", artifact=name)
    return Response(target.read_text(encoding="utf-8", errors="replace"), mimetype="text/plain")


@vuln.get("/api/debug/config")
def debug_config():
    emit_event("debug_endpoint_access", "medium")
    award("misconfig-debug", artifact="debug-config")
    return jsonify({
        "debug": True,
        "environment": "training",
        "database": current_app.config["DATABASE_PATH"],
        "session_secret_source": "LAB_SESSION_SECRET env var",
        "jwt_algorithms_accepted": ["HS256", "none"],
        "fake_cloud_key": "AKIA-LAB-ONLY-NOT-VALID",
        "directory_listing": True,
        "flag": flag("misconfig-debug"),
    })


@vuln.get("/api/components")
def components():
    emit_event("outdated_component_inventory", "medium")
    return jsonify({"components": [
        {"name": "log4j-core", "version": "2.14.1", "status": "simulated-vulnerable",
         "cve": "CVE-2021-44228", "used_by": "/api/legacy/audit"},
        {"name": "jquery", "version": "1.12.4", "status": "simulated-vulnerable", "cve": "CVE-2020-11022"},
        {"name": "openssl", "version": "1.0.2u", "status": "simulated-vulnerable", "cve": "CVE-2016-2107"},
    ]})


# --------------------------------------------------------------------------
# Access control
# --------------------------------------------------------------------------

@vuln.get("/api/users/<int:user_id>")
def user_record(user_id: int):
    """A01: no authentication, no ownership check, sequential identifiers."""
    with db() as connection:
        row = connection.execute(
            "SELECT id, username, email, role, synthetic_token, note FROM users WHERE id = ?",
            (user_id,)).fetchone()
    emit_event("broken_access_attempt", "high", object_id=user_id, allowed=True, found=bool(row))
    if not row:
        return jsonify({"error": "not found"}), 404
    if user_id == 1337:
        award("access-idor", object_id=user_id)
    return jsonify(dict(row))


@vuln.post("/api/profile/update")
def profile_update():
    """A01: mass assignment - every submitted key is bound to the record."""
    data = request.get_json(silent=True) or {}
    fields = {k: v for k, v in data.items() if k in {"email", "note", "role", "username"}}
    sensitive = {k: v for k, v in fields.items() if k in {"role", "username"}}
    emit_event("mass_assignment_attempt", "high" if sensitive else "info",
               submitted_fields=sorted(fields), sensitive_fields=sorted(sensitive))
    session["profile"] = fields
    if str(fields.get("role", "")).lower() in {"admin", "administrator", "root"}:
        session["role"] = "admin"
        emit_event("privilege_change", "critical", new_role="admin", mechanism="mass_assignment")
        return jsonify({"updated": True, "effective_role": "admin",
                        "flag": award("access-massassign", new_role="admin")})
    return jsonify({"updated": True, "effective_role": fields.get("role", "user"),
                    "bound_fields": sorted(fields)})


# --------------------------------------------------------------------------
# Injection
# --------------------------------------------------------------------------

@vuln.get("/api/products/search")
def product_search():
    """A03: raw string concatenation into SQL."""
    query_text = request.args.get("q", "")
    query = f"SELECT id, name, price FROM products WHERE name LIKE '%{query_text}%'"
    classes = classify_payload(query_text)
    try:
        with db() as connection:
            rows = connection.execute(query).fetchall()
        emit_event("sql_query", "high" if "sqli" in classes else "info",
                   query_input=query_text, statement=query, suspicious="sqli" in classes,
                   attack_classes=classes, rows_returned=len(rows))
        if any(flag("inject-sqli-union") in str(dict(r)) for r in rows):
            award("inject-sqli-union", technique="union_select")
        return jsonify({"query": query, "results": [dict(row) for row in rows]})
    except sqlite3.Error as exc:
        emit_event("sql_error", "high", query_input=query_text, statement=query,
                   error=str(exc), attack_classes=classes)
        return jsonify({"error": str(exc), "query": query}), 500


@vuln.post("/api/legacy/login")
def legacy_login():
    """A03: authentication built from a concatenated WHERE clause."""
    data = request.get_json(silent=True) or request.form
    username = str(data.get("username", ""))
    password = str(data.get("password", ""))
    query = (f"SELECT id, username, role FROM users WHERE username = '{username}'"
             f" AND password = '{password}'")
    classes = classify_payload(username + password)
    try:
        with db() as connection:
            rows = connection.execute(query).fetchall()
    except sqlite3.Error as exc:
        emit_event("sql_error", "high", statement=query, error=str(exc), attack_classes=classes)
        return jsonify({"error": str(exc), "query": query}), 500

    success = bool(rows)
    emit_event("sql_query", "high" if "sqli" in classes else "info", statement=query,
               suspicious="sqli" in classes, attack_classes=classes, rows_returned=len(rows))
    emit_event("authentication_attempt", "high" if "sqli" in classes else "medium",
               username=username, success=success, endpoint="legacy", injection="sqli" in classes)
    if not success:
        return jsonify({"authenticated": False, "query": query}), 401
    body = {"authenticated": True, "identities": [dict(r) for r in rows], "query": query}
    if "sqli" in classes:
        session["user"] = rows[0]["username"]
        body["flag"] = award("inject-sqli-auth", bypassed_as=rows[0]["username"])
    return jsonify(body)


@vuln.get("/reflect")
def reflected_xss():
    """A03: attacker input written into the response with no output encoding."""
    value = request.args.get("name", "guest")
    classes = classify_payload(value)
    emit_event("xss_probe", "high" if "xss" in classes else "info",
               reflected_input=value, attack_classes=classes)
    banner = ""
    if "xss" in classes:
        banner = f"<p id='flag'>{award('xss-reflected', payload=value)}</p>"
    return Response(
        f"<!doctype html><html><body><h1>Hello {value}</h1>{banner}</body></html>",
        mimetype="text/html")


@vuln.route("/guestbook", methods=["GET", "POST"])
def guestbook():
    """A03: stored XSS - entries are written raw and rendered raw."""
    if request.method == "POST":
        data = request.get_json(silent=True) or request.form
        author = str(data.get("author", "anonymous"))[:64]
        message = str(data.get("message", ""))[:2000]
        classes = classify_payload(message)
        with db() as connection:
            connection.execute("INSERT INTO guestbook (author, message) VALUES (?,?)",
                               (author, message))
        emit_event("stored_xss_persisted" if "xss" in classes else "guestbook_post",
                   "high" if "xss" in classes else "info",
                   author=author, payload=message if "xss" in classes else "",
                   attack_classes=classes)
        if request.is_json:
            return jsonify({"stored": True, "author": author,
                            "note": "Entries are rendered without encoding at /admin/review"})
        return redirect("/guestbook")

    with db() as connection:
        rows = connection.execute(
            "SELECT author, message, created_at FROM guestbook ORDER BY id DESC LIMIT 50").fetchall()
    entries = "".join(
        f"<li><b>{r['author']}</b>: {r['message']} <small>{r['created_at']}</small></li>"
        for r in rows)
    return render_template("guestbook.html", entries=entries)


@vuln.get("/admin/review")
def admin_review():
    """Simulates the administrator opening the moderation queue in a browser.

    If a stored entry contains script, the simulated admin session is treated as
    compromised and the flag is released.
    """
    with db() as connection:
        rows = connection.execute("SELECT author, message FROM guestbook").fetchall()
    triggered = [r for r in rows if "xss" in classify_payload(r["message"])]
    emit_event("admin_review_render", "critical" if triggered else "info",
               entries=len(rows), payloads_executed=len(triggered),
               simulated_victim="admin@lab.invalid")
    if triggered:
        return jsonify({
            "simulated_admin_session": "compromised",
            "payloads_executed": len(triggered),
            "stolen_cookie": "session=eyJyb2xlIjoiYWRtaW4ifQ",
            "flag": award("xss-stored", payloads=len(triggered)),
        })
    return jsonify({"simulated_admin_session": "clean", "entries": len(rows),
                    "hint": "Store a payload in /guestbook first."})


# --------------------------------------------------------------------------
# Path traversal and file handling
# --------------------------------------------------------------------------

@vuln.get("/api/documents/download")
def document_download():
    """A01: user-controlled filename joined onto a base path with no containment."""
    name = request.args.get("file", "welcome.txt")
    classes = classify_payload(name)
    base = current_app.config["DOCUMENT_DIR"]
    target = os.path.join(base, name)  # no normalisation, no realpath check
    emit_event("path_traversal_attempt" if "traversal" in classes else "document_download",
               "high" if "traversal" in classes else "info",
               requested_file=name, resolved_path=target, attack_classes=classes)
    try:
        content = Path(target).read_text(encoding="utf-8", errors="replace")[:4000]
    except OSError as exc:
        return jsonify({"error": str(exc), "resolved": target}), 404
    if flag("file-traversal") in content:
        award("file-traversal", resolved_path=target)
    emit_event("sensitive_file_access", "high" if "traversal" in classes else "info",
               artifact=target)
    return Response(content, mimetype="text/plain")


@vuln.post("/api/upload")
def upload():
    """A04: no extension allow-list, no content inspection, no size policy."""
    upload_dir = Path(current_app.config["UPLOAD_DIR"])
    upload_dir.mkdir(parents=True, exist_ok=True)
    handle = request.files.get("file")
    if handle is None:
        return jsonify({"error": "multipart field 'file' required"}), 400
    name = os.path.basename(handle.filename or "unnamed")
    target = upload_dir / name
    handle.save(target)
    size = target.stat().st_size
    extension = target.suffix.lower().lstrip(".")
    dangerous = extension in {"php", "phtml", "jsp", "jspx", "asp", "aspx", "sh", "py", "exe", "dll", "war"}
    emit_event("file_upload", "high" if dangerous else "info",
               filename=name, extension=extension, size_bytes=size,
               content_type=handle.content_type, dangerous=dangerous)
    body = {"stored": True, "filename": name, "size": size, "served_at": f"/uploads/{name}"}
    if dangerous:
        emit_event("dangerous_upload", "critical", filename=name, extension=extension)
        body["flag"] = award("upload-unrestricted", filename=name, extension=extension)
    return jsonify(body)


@vuln.get("/uploads/<path:name>")
def serve_upload(name: str):
    """Uploaded files are served back, but always as inert text/plain.

    The lab intentionally stops short of executing uploaded code: the finding is
    the unrestricted write, and the detection value is the upload event itself.
    """
    target = Path(current_app.config["UPLOAD_DIR"]) / os.path.basename(name)
    if not target.is_file():
        return jsonify({"error": "not found"}), 404
    emit_event("uploaded_file_served", "medium", filename=target.name)
    return Response(target.read_bytes()[:8000], mimetype="text/plain")


# --------------------------------------------------------------------------
# Remote code execution
# --------------------------------------------------------------------------

@vuln.get("/api/diagnostics/ping")
def diagnostics_ping():
    """A03: attacker input concatenated into a shell command line."""
    host = request.args.get("host", "127.0.0.1")
    classes = classify_payload(host)
    command = f"ping -c 1 -W 1 {host}"
    emit_event("command_injection_attempt" if "cmdi" in classes else "diagnostics_request",
               "critical" if "cmdi" in classes else "info",
               host_input=host, command_line=command, attack_classes=classes)
    try:
        completed = subprocess.run(command, shell=True, capture_output=True,
                                   text=True, timeout=10)
        output = (completed.stdout + completed.stderr)[:4000]
        code = completed.returncode
    except subprocess.TimeoutExpired:
        output, code = "timed out", 124
    emit_event("command_execution", "critical" if "cmdi" in classes else "info",
               command_line=command, exit_code=code, output_bytes=len(output),
               process="sh", parent_process="python")
    if flag("rce-cmdi") in output:
        award("rce-cmdi", command_line=command)
    return Response(output or "(no output)", mimetype="text/plain")


@vuln.get("/api/newsletter/preview")
def newsletter_preview():
    """A03: user input compiled as a Jinja2 template (server-side template injection)."""
    template = request.args.get("template", "Hello {{ name }}")
    classes = classify_payload(template)
    emit_event("ssti_attempt" if "ssti" in classes else "template_render",
               "critical" if "ssti" in classes else "info",
               template_input=template, attack_classes=classes)
    try:
        rendered = render_template_string(template, name="subscriber")[:4000]
    except Exception as exc:  # deliberately surfaces the engine error to the player
        emit_event("template_error", "high", template_input=template, error=str(exc))
        return jsonify({"error": f"{type(exc).__name__}: {exc}"}), 500
    if flag("rce-ssti") in rendered:
        award("rce-ssti", template_input=template)
    return Response(rendered, mimetype="text/html")


@vuln.post("/api/suppliers/import")
def supplier_import():
    """A05: XML parsed with DTD loading and external entity resolution enabled."""
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
        text = etree.tostring(root, encoding="unicode", method="text")[:4000]
    except Exception as exc:
        emit_event("xml_parse_error", "high", error=str(exc))
        return jsonify({"error": f"{type(exc).__name__}: {exc}"}), 400
    if flag("inject-xxe") in text:
        award("inject-xxe", payload_bytes=len(raw))
    return Response(text, mimetype="text/plain")


# --------------------------------------------------------------------------
# Authentication and session handling
# --------------------------------------------------------------------------

def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


@vuln.get("/api/token")
def issue_token():
    """Issues an HS256 JWT for a low-privilege role using a weak signing key."""
    username = request.args.get("username", "alice")
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {"sub": username, "role": "user", "iat": int(time.time())}
    signing_input = f"{b64url(json.dumps(header).encode())}.{b64url(json.dumps(payload).encode())}"
    signature = hmac.new(current_app.config["JWT_KEY"].encode(), signing_input.encode(),
                         hashlib.sha256).digest()
    token = f"{signing_input}.{b64url(signature)}"
    emit_event("jwt_issued", "info", subject=username, role="user", algorithm="HS256")
    return jsonify({"token": token, "role": "user",
                    "usage": "Authorization: Bearer <token> against /api/admin/report"})


def verify_jwt(token: str) -> tuple[dict | None, str]:
    """A07: honours the algorithm declared in the token, including 'none'."""
    try:
        header_b64, payload_b64, signature_b64 = token.split(".")
        header = json.loads(b64url_decode(header_b64))
        payload = json.loads(b64url_decode(payload_b64))
    except Exception:
        return None, "malformed"
    algorithm = str(header.get("alg", "")).lower()
    if algorithm == "none":
        return payload, "none"  # the vulnerability: unsigned tokens are trusted
    expected = hmac.new(current_app.config["JWT_KEY"].encode(),
                        f"{header_b64}.{payload_b64}".encode(), hashlib.sha256).digest()
    if hmac.compare_digest(b64url(expected), signature_b64):
        return payload, "HS256"
    return None, "bad-signature"


@vuln.get("/api/admin/report")
def admin_report():
    token = request.headers.get("Authorization", "").removeprefix("Bearer ").strip()
    payload, algorithm = verify_jwt(token)
    emit_event("jwt_verify", "critical" if algorithm == "none" else "info",
               algorithm=algorithm, subject=(payload or {}).get("sub"),
               claimed_role=(payload or {}).get("role"), accepted=payload is not None)
    if payload is None:
        return jsonify({"error": f"token rejected ({algorithm})"}), 401
    if str(payload.get("role")) != "admin":
        return jsonify({"error": "admin role required", "your_role": payload.get("role")}), 403
    if algorithm == "none":
        emit_event("jwt_unsigned_accepted", "critical", subject=payload.get("sub"))
        emit_event("privilege_change", "critical", new_role="admin", mechanism="jwt_alg_none")
        return jsonify({"report": "quarterly-synthetic", "role": "admin",
                        "flag": award("auth-jwt-none", subject=payload.get("sub"))})
    return jsonify({"report": "quarterly-synthetic", "role": "admin",
                    "note": "Signed admin token - the flag is only released for an unsigned one."})


@vuln.post("/api/login")
def login():
    """A07: unlimited attempts, no lockout, no delay, weak service password."""
    data = request.get_json(silent=True) or request.form
    username = str(data.get("username", ""))
    password = str(data.get("password", ""))
    with db() as connection:
        row = connection.execute(
            "SELECT id, username, role FROM users WHERE username = ? AND password = ?",
            (username, password)).fetchone()

    source = request.headers.get("X-Forwarded-For", request.remote_addr or "unknown")
    now = time.time()
    window = LOGIN_FAILURES[source]
    if row is None:
        window.append(now)
    recent = sum(1 for t in window if now - t <= 60)
    if recent >= 5:
        emit_event("brute_force_suspected", "critical", source=source,
                   failures_last_60s=recent, username=username, lockout_applied=False)

    emit_event("authentication_attempt", "medium" if row else "high",
               username=username, success=bool(row), endpoint="primary",
               failures_last_60s=recent, lockout_applied=False)
    if row is None:
        return jsonify({"authenticated": False}), 401

    session["user"] = row["username"]
    session["role"] = row["role"]
    body = {"authenticated": True, "username": row["username"], "role": row["role"]}
    if row["username"] == "svc_backup":
        body["flag"] = award("auth-bruteforce", username=row["username"],
                             failures_before_success=recent)
    return jsonify(body)


@vuln.post("/api/password-reset/request")
def reset_request():
    data = request.get_json(silent=True) or request.form
    username = str(data.get("username", ""))
    with db() as connection:
        row = connection.execute("SELECT username FROM users WHERE username = ?",
                                 (username,)).fetchone()
        if row:
            connection.execute(
                "INSERT OR REPLACE INTO reset_tokens (username, token) VALUES (?,?)",
                (username, reset_token_for(username)))
    emit_event("password_reset_request", "medium", target_user=username, user_exists=bool(row))
    if not row:
        return jsonify({"sent": False, "error": "unknown user"}), 404
    body = {"sent": True, "delivery": "simulated-email",
            "note": "Token generation is deterministic in this build."}
    if username == "alice":  # only your own token is echoed back
        body["token"] = reset_token_for(username)
    return jsonify(body)


@vuln.post("/api/password-reset/consume")
def reset_consume():
    """A02: reset tokens are md5(username) - guessable for any account."""
    data = request.get_json(silent=True) or request.form
    username = str(data.get("username", ""))
    token = str(data.get("token", "")).strip().lower()
    valid = hmac.compare_digest(token, reset_token_for(username))
    emit_event("password_reset_consume", "critical" if valid and username != "alice" else "medium",
               target_user=username, token_valid=valid,
               token_predictable=True, self_service=username == "alice")
    if not valid:
        return jsonify({"reset": False, "error": "invalid token"}), 403
    body = {"reset": True, "username": username, "new_password": "ChangeMe!123"}
    if username != "alice":
        emit_event("account_takeover", "critical", target_user=username,
                   mechanism="predictable_reset_token")
        body["flag"] = award("auth-reset-token", target_user=username)
    return jsonify(body)


@vuln.get("/admin/panel")
def admin_panel():
    """A02: access decided by a Flask session cookie signed with a guessable secret."""
    is_admin = bool(session.get("is_admin"))
    emit_event("admin_panel_access", "critical" if is_admin else "medium",
               granted=is_admin, session_role=session.get("role"),
               session_user=session.get("user"))
    if not is_admin:
        return jsonify({
            "error": "administrator session required",
            "hint": "This gate reads is_admin from the signed Flask session cookie.",
        }), 403
    emit_event("forged_session_detected", "critical",
               reason="is_admin set without an interactive administrator login")
    return jsonify({"panel": "range-administration",
                    "flag": award("auth-weak-secret", session_user=session.get("user"))})


# --------------------------------------------------------------------------
# SSRF, business logic and vulnerable components
# --------------------------------------------------------------------------

@vuln.get("/api/fetch")
def fetch_url():
    """A10: SSRF, bounded to lab-internal destinations so the range cannot egress."""
    import requests as http
    from urllib.parse import urlparse

    target = request.args.get("url", "")
    parsed = urlparse(target)
    allowed_hosts = {"metadata", "127.0.0.1", "localhost", "169.254.169.254", "helpag-metadata"}
    allowed = parsed.scheme in {"http", "https"} and parsed.hostname in allowed_hosts
    internal = parsed.hostname in allowed_hosts
    emit_event("ssrf_probe", "critical" if internal else "medium",
               target=target, target_host=parsed.hostname, target_scheme=parsed.scheme,
               allowed=allowed)
    if not allowed:
        return jsonify({
            "error": "This training build bounds SSRF to lab-internal services.",
            "allowed_hosts": sorted(allowed_hosts),
        }), 403
    try:
        response = http.get(target, timeout=3)
        body = response.text[:2000]
    except http.RequestException as exc:
        return jsonify({"error": str(exc)}), 502
    if flag("ssrf-metadata") in body:
        award("ssrf-metadata", target=target)
    return jsonify({"status": response.status_code, "body": body})


@vuln.post("/api/checkout")
def checkout():
    """A04: no server-side business rule validation on quantity or price."""
    data = request.get_json(silent=True) or {}
    try:
        quantity = float(data.get("quantity", 1))
        unit_price = float(data.get("unit_price", 10))
    except (TypeError, ValueError):
        return jsonify({"error": "quantity and unit_price must be numeric"}), 400
    total = quantity * unit_price
    emit_event("business_logic_abuse", "high" if total < 0 else "info",
               quantity=quantity, unit_price=unit_price, total=total,
               negative_total=total < 0)
    body = {"accepted": True, "total": total,
            "message": "No server-side business-rule validation"}
    if total < 0:
        body["credit_issued"] = abs(total)
        body["flag"] = award("logic-negative", total=total)
    return jsonify(body)


@vuln.route("/api/legacy/audit", methods=["GET", "POST"])
def legacy_audit():
    """A06: simulates a Log4Shell-class lookup in a logging shim.

    No JNDI or LDAP call is ever made. The lab records the attempt so the
    detection use case has something real to match on.
    """
    agent = request.headers.get("X-Audit-Agent", request.headers.get("User-Agent", ""))
    classes = classify_payload(agent)
    triggered = "jndi" in classes
    emit_event("jndi_lookup_detected" if triggered else "legacy_audit",
               "critical" if triggered else "info",
               audit_agent=agent, attack_classes=classes,
               component="log4j-core 2.14.1", lookup_performed=False)
    body = {"logged": True, "component": "log4j-core 2.14.1 (simulated)",
            "logged_value": agent}
    if triggered:
        body["lookup"] = "simulated - no outbound JNDI request was made"
        body["flag"] = award("inject-jndi", audit_agent=agent)
    return jsonify(body)


@vuln.get("/api/backup")
def exposed_backup():
    """A02: synthetic secrets returned by an unauthenticated endpoint."""
    emit_event("sensitive_data_exposure", "high", artifact="backup.json")
    return jsonify({
        "warning": "synthetic lab data",
        "password_hash": "5f4dcc3b5aa765d61d8327deb882cf99",
        "api_token": "lab_tok_do_not_use_8fd8a1",
        "encryption": "MD5 / no transport policy",
    })


@vuln.post("/api/preferences/import")
def import_preferences():
    """A08: unsigned client data is trusted to set the effective role."""
    data = request.get_json(silent=True) or {}
    session["role"] = data.get("role", "user")
    emit_event("unsigned_data_import", "high", imported_role=session["role"],
               signature_checked=False)
    return jsonify({"imported": True, "effective_role": session["role"],
                    "signature_checked": False})


@vuln.post("/api/quiet-transfer")
def quiet_transfer():
    """A09: a high-value action logged without actor or destination context."""
    data = request.get_json(silent=True) or {}
    amount = data.get("amount", 0)
    emit_event("monitoring_gap_simulated", "high", amount=amount, actor=None, destination=None)
    return jsonify({"accepted": True, "amount": amount,
                    "audit_context": "intentionally incomplete"})
