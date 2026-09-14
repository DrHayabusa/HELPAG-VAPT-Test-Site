#!/usr/bin/env python3
"""Fail if ASSESSMENT_PLAYBOOK.md has drifted from labsite/catalog.py.

Checks that every finding id and every proof value in the catalogue appears in
the playbook, and that the playbook references no value the catalogue does not know.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from labsite.catalog import FINDINGS  # noqa: E402

playbook = (ROOT / "ASSESSMENT_PLAYBOOK.md").read_text(encoding="utf-8")
problems: list[str] = []

for challenge in FINDINGS:
    if challenge["id"] not in playbook:
        problems.append(f"finding id missing from playbook: {challenge['id']}")
    if challenge["flag"] not in playbook:
        problems.append(f"proof value missing from playbook: {challenge['id']} -> {challenge['flag']}")

known = {f["flag"] for f in FINDINGS}
placeholders = {"MERIDIAN{...}"}
for found in set(re.findall(r"MERIDIAN\{[^}]*\}", playbook)) - placeholders:
    if found not in known:
        problems.append(f"playbook references an unknown flag: {found}")

if problems:
    print("\n".join(problems))
    raise SystemExit(f"{len(problems)} problem(s) found")
print(f"playbook is in sync with {len(FINDINGS)} findings")
