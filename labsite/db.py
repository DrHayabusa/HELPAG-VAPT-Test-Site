"""SQLite schema and seed data for the CTF lab."""

from __future__ import annotations

import hashlib
import sqlite3
from contextlib import contextmanager
from pathlib import Path

from labsite.catalog import CHALLENGES_BY_ID

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    username TEXT UNIQUE,
    email TEXT,
    role TEXT,
    password TEXT,
    synthetic_token TEXT,
    note TEXT
);
CREATE TABLE IF NOT EXISTS products (
    id INTEGER PRIMARY KEY,
    name TEXT,
    price REAL
);
CREATE TABLE IF NOT EXISTS flags (
    id INTEGER PRIMARY KEY,
    label TEXT,
    value TEXT
);
CREATE TABLE IF NOT EXISTS guestbook (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    author TEXT,
    message TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS teams (
    name TEXT PRIMARY KEY,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS solves (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    team TEXT,
    challenge_id TEXT,
    points INTEGER,
    solved_at TEXT DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(team, challenge_id)
);
CREATE TABLE IF NOT EXISTS reset_tokens (
    username TEXT PRIMARY KEY,
    token TEXT,
    issued_at TEXT DEFAULT CURRENT_TIMESTAMP
);
"""

# Synthetic training identities only. Nothing here is a real credential.
SEED_USERS = [
    (1, "alice", "alice@lab.invalid", "user", "Password1", "lab_user_001", "Standard demo account."),
    (2, "admin", "admin@lab.invalid", "admin", "admin", "lab_admin_002", "Default credentials never rotated."),
    (3, "bob", "bob@lab.invalid", "user", "hunter2", "lab_user_003", "Marketing contractor."),
    (7, "svc_backup", "svc@lab.invalid", "service", "summer2024", "lab_svc_007",
     "Service account for nightly export. Password chosen by the on-call engineer."),
    (1337, "j.ellison", "j.ellison@lab.invalid", "finance", "Tr0ub4dour&3", "lab_fin_1337",
     "HR record - onboarding flag: HELPAG{1d0r_h0r1z0nt4l_3num3r4t10n}"),
]

SEED_PRODUCTS = [
    (1, "Training laptop", 900.0),
    (2, "Security key", 35.0),
    (3, "Lab router", 75.0),
    (4, "Packet capture appliance", 4200.0),
]


@contextmanager
def connect(path: str):
    """Open a row-factory connection, commit on clean exit, always close.

    sqlite3's own context manager commits but does not close, which leaks a
    handle per request in a long-running server.
    """
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    try:
        yield connection
        connection.commit()
    finally:
        connection.close()


def initialize(path: str) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with connect(path) as connection:
        connection.executescript(SCHEMA)
        connection.executemany(
            "INSERT OR IGNORE INTO users (id,username,email,role,password,synthetic_token,note)"
            " VALUES (?,?,?,?,?,?,?)", SEED_USERS)
        connection.executemany(
            "INSERT OR IGNORE INTO products (id,name,price) VALUES (?,?,?)", SEED_PRODUCTS)
        # Only the SQL injection flag lives in the database. Every other flag is
        # verified by hash so that one UNION SELECT cannot dump the whole event.
        connection.execute(
            "INSERT OR IGNORE INTO flags (id,label,value) VALUES (1,?,?)",
            ("inject-sqli-union", CHALLENGES_BY_ID["inject-sqli-union"]["flag"]))
        connection.execute(
            "INSERT OR IGNORE INTO guestbook (id,author,message) VALUES (1,?,?)",
            ("lab", "Welcome to the HELP AG range. Be excellent to each other."))


def reset_token_for(username: str) -> str:
    """Deliberately predictable: md5 of the username. Challenge auth-reset-token."""
    return hashlib.md5(username.encode("utf-8")).hexdigest()
