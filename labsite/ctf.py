"""Scoreboard, flag submission and challenge board. This part is NOT vulnerable."""

from __future__ import annotations

import re
from flask import Blueprint, current_app, jsonify, render_template, request, session

from labsite.catalog import CHALLENGES_BY_ID, TOTAL_POINTS, identify, public_catalog
from labsite.db import connect
from labsite.events import emit_event

ctf = Blueprint("ctf", __name__)
TEAM_PATTERN = re.compile(r"^[A-Za-z0-9 _.\-]{2,32}$")


def db():
    return connect(current_app.config["DATABASE_PATH"])


def current_team() -> str:
    return session.get("team", "")


def solved_ids(team: str) -> set[str]:
    if not team:
        return set()
    with db() as connection:
        rows = connection.execute("SELECT challenge_id FROM solves WHERE team = ?", (team,)).fetchall()
    return {row["challenge_id"] for row in rows}


@ctf.get("/")
def board():
    return render_template("board.html")


@ctf.get("/scoreboard")
def scoreboard_page():
    return render_template("scoreboard.html")


@ctf.post("/api/ctf/team")
def register_team():
    data = request.get_json(silent=True) or request.form
    name = str(data.get("team", "")).strip()
    if not TEAM_PATTERN.match(name):
        return jsonify({"error": "Team name must be 2-32 characters: letters, digits, space . _ -"}), 400
    with db() as connection:
        connection.execute("INSERT OR IGNORE INTO teams (name) VALUES (?)", (name,))
    session["team"] = name
    emit_event("ctf_team_registered", "info", team_name=name)
    return jsonify({"team": name, "registered": True})

@ctf.get("/api/ctf/challenges")
def challenges():
    team = current_team()
    done = solved_ids(team)
    items = [dict(c, solved=c["id"] in done) for c in public_catalog()]
    return jsonify({
        "team": team,
        "total_points": TOTAL_POINTS,
        "earned": sum(CHALLENGES_BY_ID[i]["points"] for i in done),
        "solved_count": len(done),
        "challenge_count": len(items),
        "challenges": items,
    })


@ctf.post("/api/ctf/submit")
def submit_flag():
    data = request.get_json(silent=True) or request.form
    submitted = str(data.get("flag", "")).strip()
    team = current_team()
    if not team:
        return jsonify({"error": "Register a team name first."}), 400
    if not submitted:
        return jsonify({"error": "No flag submitted."}), 400

    challenge_id = identify(submitted)
    if challenge_id is None:
        emit_event("ctf_flag_rejected", "low", submitted_length=len(submitted),
                   looks_like_flag=submitted.upper().startswith("HELPAG{"))
        return jsonify({"correct": False, "message": "Incorrect flag."}), 200

    challenge = CHALLENGES_BY_ID[challenge_id]
    with db() as connection:
        already = connection.execute(
            "SELECT 1 FROM solves WHERE team = ? AND challenge_id = ?", (team, challenge_id)).fetchone()
        first_blood = connection.execute(
            "SELECT 1 FROM solves WHERE challenge_id = ?", (challenge_id,)).fetchone() is None
        if not already:
            connection.execute(
                "INSERT INTO solves (team, challenge_id, points) VALUES (?,?,?)",
                (team, challenge_id, challenge["points"]))

    emit_event("ctf_flag_captured", "high", challenge_id=challenge_id,
               challenge_title=challenge["title"], category=challenge["category"],
               points=0 if already else challenge["points"], duplicate=bool(already),
               first_blood=first_blood and not already,
               mitre_techniques=[t[0] for t in challenge["mitre"]], owasp=challenge["owasp"])

    done = solved_ids(team)
    return jsonify({
        "correct": True,
        "duplicate": bool(already),
        "first_blood": first_blood and not already,
        "challenge": {"id": challenge_id, "title": challenge["title"], "points": challenge["points"]},
        "earned": sum(CHALLENGES_BY_ID[i]["points"] for i in done),
        "solved_count": len(done),
        "message": "Already solved by your team." if already else f"Correct: {challenge['title']}",
    })


@ctf.get("/api/ctf/scoreboard")
def scoreboard():
    with db() as connection:
        rows = connection.execute(
            "SELECT team, COUNT(*) AS solves, SUM(points) AS points, MAX(solved_at) AS last_solve"
            " FROM solves GROUP BY team ORDER BY points DESC, last_solve ASC").fetchall()
    return jsonify({
        "total_points": TOTAL_POINTS,
        "teams": [
            {"rank": i, "team": r["team"], "solves": r["solves"],
             "points": r["points"] or 0, "last_solve": r["last_solve"]}
            for i, r in enumerate(rows, start=1)
        ],
    })


@ctf.get("/api/ctf/progress")
def progress():
    """Per-challenge solve counts. Useful for instructors watching a live range."""
    with db() as connection:
        rows = connection.execute(
            "SELECT challenge_id, COUNT(*) AS solves FROM solves GROUP BY challenge_id").fetchall()
    counts = {r["challenge_id"]: r["solves"] for r in rows}
    return jsonify({"progress": [
        {"id": c["id"], "title": c["title"], "points": c["points"],
         "category": c["category"], "solves": counts.get(c["id"], 0)}
        for c in public_catalog()
    ]})
