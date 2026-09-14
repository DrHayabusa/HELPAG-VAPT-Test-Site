"""Schema and seed data for the Meridian Freight Solutions target.

All companies, people, references and credentials below are fictional.
"""

from __future__ import annotations

import hashlib
import sqlite3
from contextlib import contextmanager
from pathlib import Path

from labsite.catalog import FINDINGS_BY_ID as F

SCHEMA = """
CREATE TABLE IF NOT EXISTS accounts (
    id INTEGER PRIMARY KEY,
    account_ref TEXT UNIQUE,
    company TEXT,
    contact_name TEXT,
    email TEXT,
    username TEXT UNIQUE,
    password TEXT,
    account_type TEXT,
    internal_notes TEXT
);
CREATE TABLE IF NOT EXISTS shipments (
    id INTEGER PRIMARY KEY,
    reference TEXT UNIQUE,
    account_id INTEGER,
    origin TEXT,
    destination TEXT,
    service TEXT,
    status TEXT,
    declared_value REAL,
    contents TEXT,
    handling_notes TEXT
);
CREATE TABLE IF NOT EXISTS rates (
    id INTEGER PRIMARY KEY,
    lane TEXT,
    service TEXT,
    price_per_kg REAL
);
CREATE TABLE IF NOT EXISTS integration_credentials (
    id INTEGER PRIMARY KEY,
    partner TEXT,
    api_key TEXT
);
CREATE TABLE IF NOT EXISTS enquiries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    company TEXT,
    email TEXT,
    message TEXT,
    received_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS reset_tokens (
    username TEXT PRIMARY KEY,
    token TEXT,
    issued_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS range_teams (
    name TEXT PRIMARY KEY,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS range_solves (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    team TEXT,
    finding_id TEXT,
    points INTEGER,
    solved_at TEXT DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(team, finding_id)
);
"""


def _accounts():
    return [
        # id, ref, company, contact, email, username, password, type, internal_notes
        (1, "MFS-AC-1001", "Harborline Trading", "Dana Okafor", "dana.okafor@harborline.example",
         "dokafor", "Harbor2024!", "customer",
         "Standard contract. Portal demo account used in sales calls."),
        (2, "MFS-AC-1002", "Northgate Components", "Ravi Menon", "r.menon@northgate.example",
         "rmenon", "Spring2025", "customer", "Net-30 terms. Two depots."),
        (3, "MFS-AC-1003", "Calder & Sons", "Iris Calder", "iris@calderandsons.example",
         "icalder", "letmein123", "customer", "Seasonal shipper."),
        (7, "MFS-SV-0007", "Meridian Freight Solutions", "EDI Integration Service",
         "edi-service@meridianfreight.example", "svc_edi", "autumn2024", "service",
         "Service account for nightly EDI exchange. "
         f"Transfer key {F['auth-bruteforce']['flag']} - rotate at contract renewal."),
        (11, "MFS-ST-0011", "Meridian Freight Solutions", "Tomas Brandt",
         "t.brandt@meridianfreight.example", "tbrandt", "Dispatch!2025", "staff",
         "Operations supervisor, Rotterdam hub."),
        (12, "MFS-ST-0012", "Meridian Freight Solutions", "Alina Voss",
         "a.voss@meridianfreight.example", "avoss", "Tr0ub4dour&3", "finance",
         "Finance contact for supplier payments. "
         f"Banking amendment reference {F['reset-token']['flag']}."),
        (13, "MFS-ST-0013", "Meridian Freight Solutions", "Operations Console",
         "ops@meridianfreight.example", "ops_console", "Meridian#Ops1", "operations",
         "Shared operations console login. "
         f"Treasury reconciliation key {F['sqli-authbypass']['flag']}."),
    ]


def _shipments():
    return [
        (1, "MFS-2026-4468", 1, "Rotterdam NL", "Felixstowe UK", "Sea LCL", "In transit",
         18400.0, "Packaged industrial fasteners, 12 pallets", "Standard handling."),
        (2, "MFS-2026-4469", 1, "Felixstowe UK", "Dublin IE", "Road FTL", "Delivered",
         9100.0, "Retail fixtures, 6 pallets", "Tail lift required at destination."),
        (3, "MFS-2026-4470", 2, "Hamburg DE", "Gdansk PL", "Road LTL", "In transit",
         4300.0, "Electronic components, 2 pallets", "Keep dry."),
        # The high-value consignment belongs to another customer entirely.
        (4, "MFS-2026-4471", 3, "Jebel Ali AE", "Rotterdam NL", "Sea FCL", "Customs hold",
         742000.0, "High-value instrumentation, sealed container",
         "Customs escalation. Release authorisation held by finance. "
         f"Consignment release reference {F['idor-shipment']['flag']}"),
        (5, "MFS-2026-4472", 2, "Gdansk PL", "Hamburg DE", "Road LTL", "Booked",
         2750.0, "Returned packaging", "No special handling."),
    ]


def _rates():
    return [
        (1, "Rotterdam - Felixstowe", "Sea LCL", 0.42),
        (2, "Felixstowe - Dublin", "Road FTL", 0.68),
        (3, "Hamburg - Gdansk", "Road LTL", 0.55),
        (4, "Jebel Ali - Rotterdam", "Sea FCL", 0.31),
        (5, "Rotterdam - Milan", "Rail", 0.47),
    ]


def _integration_credentials():
    return [
        (1, "Harborline WMS", "hlw_live_4e1c9a77b2"),
        (2, "Northgate ERP", "ng_erp_8823ffce01"),
        # Partner key that a schema dump exposes.
        (3, "Meridian Partner Gateway", F["sqli-union"]["flag"]),
    ]


@contextmanager
def connect(path: str):
    """Row-factory connection that commits on clean exit and always closes.

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
            "INSERT OR IGNORE INTO accounts (id,account_ref,company,contact_name,email,"
            "username,password,account_type,internal_notes) VALUES (?,?,?,?,?,?,?,?,?)",
            _accounts())
        connection.executemany(
            "INSERT OR IGNORE INTO shipments (id,reference,account_id,origin,destination,"
            "service,status,declared_value,contents,handling_notes) VALUES (?,?,?,?,?,?,?,?,?,?)",
            _shipments())
        connection.executemany(
            "INSERT OR IGNORE INTO rates (id,lane,service,price_per_kg) VALUES (?,?,?,?)",
            _rates())
        connection.executemany(
            "INSERT OR IGNORE INTO integration_credentials (id,partner,api_key) VALUES (?,?,?)",
            _integration_credentials())
        connection.execute(
            "INSERT OR IGNORE INTO enquiries (id,name,company,email,message) VALUES (?,?,?,?,?)",
            (1, "Priya Raman", "Lockwood Retail", "priya@lockwood.example",
             "Could someone send updated LCL rates for the Rotterdam lane? Thanks."))


def reset_token_for(username: str) -> str:
    """Deliberately predictable: md5 of the account name. Finding reset-token."""
    return hashlib.md5(username.encode("utf-8")).hexdigest()
