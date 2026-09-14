#!/usr/bin/env python3
"""Regenerate every on-disk fixture from labsite/catalog.py.

Run after changing a flag value so the flag store, backup files and metadata
service stay in sync with the catalogue.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from labsite.catalog import CHALLENGES_BY_ID as C  # noqa: E402


def write(relative: str, content: str) -> None:
    path = ROOT / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    print(f"wrote {relative}")


write("flagstore/traversal.flag", C["file-traversal"]["flag"] + "\n")
write("flagstore/cmdi.flag", C["rce-cmdi"]["flag"] + "\n")
write("flagstore/ssti.flag", C["rce-ssti"]["flag"] + "\n")
write("flagstore/xxe.flag", C["inject-xxe"]["flag"] + "\n")
write("flagstore/README.md",
      "# Flag store\n\nFiles read by the traversal, command injection, SSTI and XXE\n"
      "challenges. Players are meant to reach these through a vulnerability, not by\n"
      "browsing the repository. Regenerate with tools/seed_fixtures.py.\n")

write("public_docs/welcome.txt",
      "HELP AG VAPT range - public document root.\nNothing sensitive here.\n")
write("public_docs/price-list.txt",
      "Training laptop,900\nSecurity key,35\nLab router,75\n")

write("backups/site-config.bak",
      "# nightly export - do not ship\n"
      "db_path=/app/logs/ctf_lab.db\n"
      "session_secret=deliberately-weak-lab-secret\n"
      "svc_backup_password=summer2024\n"
      f"archive_flag={C['misconfig-backups']['flag']}\n")
write("backups/users-export.csv",
      "id,username,role\n1,alice,user\n2,admin,admin\n7,svc_backup,service\n1337,j.ellison,finance\n")

write("metadata/index.html",
      '<h1>Lab metadata service</h1><p>Synthetic instance metadata. '
      '<a href="latest/meta-data/">latest/meta-data/</a></p>\n')
write("metadata/latest/meta-data/index.html",
      '<a href="iam/">iam/</a>\n<a href="hostname">hostname</a>\n')
write("metadata/latest/meta-data/hostname", "helpag-range-node-01.lab.invalid\n")
write("metadata/latest/meta-data/iam/index.html",
      '<a href="security-credentials/">security-credentials/</a>\n')
write("metadata/latest/meta-data/iam/security-credentials/index.html", "lab-instance-role\n")
write("metadata/latest/meta-data/iam/security-credentials/lab-instance-role",
      json.dumps({
          "Code": "Success", "Type": "AWS-HMAC",
          "AccessKeyId": "AKIA-LAB-ONLY-NOT-VALID",
          "SecretAccessKey": "lab/synthetic/secret/not-a-real-key",
          "Token": "lab-session-token-synthetic",
          "Expiration": "2099-01-01T00:00:00Z",
          "flag": C["ssrf-metadata"]["flag"],
      }, indent=2) + "\n")
