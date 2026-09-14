#!/usr/bin/env python3
"""Fail if CTF_PLAYBOOK.md has drifted from labsite/catalog.py.

Checks that every challenge id and every flag value in the catalogue appears in
the playbook, and that the playbook contains no flag the catalogue does not know.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from labsite.catalog import CHALLENGES  # noqa: E402

playbook = (ROOT / "CTF_PLAYBOOK.md").read_text(encoding="utf-8")
problems: list[str] = []

for challenge in CHALLENGES:
    if challenge["id"] not in playbook:
        problems.append(f"challenge id missing from playbook: {challenge['id']}")
    if challenge["flag"] not in playbook:
        problems.append(f"flag missing from playbook: {challenge['id']} -> {challenge['flag']}")

known = {c["flag"] for c in CHALLENGES}
placeholders = {"HELPAG{...}"}
for found in set(re.findall(r"HELPAG\{[^}]*\}", playbook)) - placeholders:
    if found not in known:
        problems.append(f"playbook references an unknown flag: {found}")

if problems:
    print("\n".join(problems))
    raise SystemExit(f"{len(problems)} problem(s) found")
print(f"playbook is in sync with {len(CHALLENGES)} challenges")
