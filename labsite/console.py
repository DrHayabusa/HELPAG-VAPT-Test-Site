"""Operator console - the range's scoring and progress view.

Deliberately separate from the target site. The Meridian pages never link here,
never mention it, and never expose a finding, a hint or a proof value. Testers
work against the site as they would a real engagement; the console is where an
instructor tracks progress and where a team records what it found.

Gated by an operator token so a tester who stumbles on the path cannot read the
finding list. Set RANGE_CONSOLE_TOKEN; it defaults to an obvious lab value.
"""

from __future__ import annotations

import re

from flask import (Blueprint, current_app, jsonify, render_template, request,
                   session)

from labsite.catalog import (FINDINGS_BY_ID, TOTAL_POINTS, identify,
                             operator_catalog)
from labsite.db import connect
from labsite.events import emit_event

console = Blueprint("console", __name__, url_prefix="/range")
TEAM_PATTERN = re.compile(r"^[A-Za-z0-9 _.\-]{2,32}$")


def db():
    return connect(current_app.config["DATABASE_PATH"])


def authorised() -> bool:
    supplied = (request.headers.get("X-Range-Token")
                or request.args.get("token")
                or session.get("range_token", ""))
    expected = current_app.config["RANGE_CONSOLE_TOKEN"]
    if supplied and supplied == expected:
        session["range_token"] = supplied
        return True
    return False


@console.before_request
def gate():
    if not authorised():
        emit_event("console_access_denied", "medium", path=request.path)
        if request.path.startswith("/range/api/"):
            return jsonify({"error": "Operator token required.",
                            "how": "Send X-Range-Token, or open /range/console?token=..."}), 403
        return render_template("console_locked.html"), 403


def current_team() -> str:
    return session.get("team", "")


def solved_ids(team: str) -> set[str]:
    if not team:
        return set()
    with db() as connection:
        rows = connection.execute(
            "SELECT finding_id FROM range_solves WHERE team = ?", (team,)).fetchall()
    return {row["finding_id"] for row in rows}


@console.get("/console")
def board():
    return render_template("console.html")


@console.get("/scoreboard")
def scoreboard_page():
    return render_template("console_scoreboard.html")


@console.post("/api/team")
def register_team():
    data = request.get_json(silent=True) or request.form
    name = str(data.get("team", "")).strip()
    if not TEAM_PATTERN.match(name):
        return jsonify({"error": "Team name must be 2-32 characters: letters, digits, space . _ -"}), 400
    with db() as connection:
        connection.execute("INSERT OR IGNORE INTO range_teams (name) VALUES (?)", (name,))
    session["team"] = name
    emit_event("range_team_registered", "info", team_name=name)
    return jsonify({"team": name, "registered": True})


@console.get("/api/findings")
def findings():
    team = current_team()
    done = solved_ids(team)
    items = [dict(f, found=f["id"] in done) for f in operator_catalog()]
    return jsonify({
        "team": team,
        "total_points": TOTAL_POINTS,
        "earned": sum(FINDINGS_BY_ID[i]["points"] for i in done),
        "found_count": len(done),
        "finding_count": len(items),
        "findings": items,
    })


@console.post("/api/submit")
def submit():
    data = request.get_json(silent=True) or request.form
    submitted = str(data.get("value", data.get("flag", ""))).strip()
    team = current_team()
    if not team:
        return jsonify({"error": "Register a team name first."}), 400
    if not submitted:
        return jsonify({"error": "Nothing submitted."}), 400

    finding_id = identify(submitted)
    if finding_id is None:
        emit_event("range_proof_rejected", "low", submitted_length=len(submitted))
        return jsonify({"correct": False, "message": "That value does not match any finding."})

    finding = FINDINGS_BY_ID[finding_id]
    with db() as connection:
        already = connection.execute(
            "SELECT 1 FROM range_solves WHERE team = ? AND finding_id = ?",
            (team, finding_id)).fetchone()
        first = connection.execute(
            "SELECT 1 FROM range_solves WHERE finding_id = ?", (finding_id,)).fetchone() is None
        if not already:
            connection.execute(
                "INSERT INTO range_solves (team, finding_id, points) VALUES (?,?,?)",
                (team, finding_id, finding["points"]))

    emit_event("range_finding_confirmed", "high", finding_id=finding_id,
               finding_title=finding["title"], category=finding["category"],
               points=0 if already else finding["points"], duplicate=bool(already),
               first_to_find=first and not already,
               mitre_techniques=[t[0] for t in finding["mitre"]], owasp=finding["owasp"])

    done = solved_ids(team)
    return jsonify({
        "correct": True, "duplicate": bool(already),
        "first_to_find": first and not already,
        "finding": {"id": finding_id, "title": finding["title"],
                    "points": finding["points"], "category": finding["category"],
                    "owasp": finding["owasp"], "feature": finding["feature"]},
        "earned": sum(FINDINGS_BY_ID[i]["points"] for i in done),
        "found_count": len(done),
        "message": "Already recorded for your team." if already else f"Confirmed: {finding['title']}",
    })


@console.get("/api/scoreboard")
def scoreboard():
    with db() as connection:
        rows = connection.execute(
            "SELECT team, COUNT(*) AS findings, SUM(points) AS points,"
            " MAX(solved_at) AS last_find FROM range_solves GROUP BY team"
            " ORDER BY points DESC, last_find ASC").fetchall()
    return jsonify({"total_points": TOTAL_POINTS, "teams": [
        {"rank": i, "team": r["team"], "findings": r["findings"],
         "points": r["points"] or 0, "last_find": r["last_find"]}
        for i, r in enumerate(rows, start=1)]})


@console.get("/api/progress")
def progress():
    with db() as connection:
        rows = connection.execute(
            "SELECT finding_id, COUNT(*) AS teams FROM range_solves GROUP BY finding_id").fetchall()
    counts = {r["finding_id"]: r["teams"] for r in rows}
    return jsonify({"progress": [
        {"id": f["id"], "title": f["title"], "points": f["points"],
         "category": f["category"], "feature": f["feature"],
         "teams_found": counts.get(f["id"], 0)}
        for f in operator_catalog()]})
