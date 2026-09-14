# HELP AG VAPT Range

A capture-the-flag web target for an isolated security lab. Twenty-two
deliberately vulnerable challenges across recon, injection, access control,
authentication, file handling, SSRF and business logic — each one wired to a
structured detection event so you can prove your SIEM use cases actually fire.

> **Never expose this application to the Internet or to a production network.**
> It contains genuine command execution, server-side template injection and
> arbitrary file read. Every identity, secret and token in it is synthetic.
> The app refuses all traffic unless `LAB_MODE=true`.

## What you get

| | |
|---|---|
| **22 challenges** | 2800 points, easy through hard, mapped to OWASP Top 10 2021 |
| **Scoreboard** | Team registration, flag submission, first bloods, live progress |
| **Detection content** | 21 Splunk use cases (UC-01 … UC-21) as disabled saved searches |
| **MITRE ATT&CK mapping** | 13 techniques across 8 tactics, per challenge |
| **Validation harness** | Solves all 22 challenges and reports pass/fail |
| **Instructor playbook** | Full solutions, commands, SPL and remediation |

## Quick start

```bash
git clone https://github.com/DrHayabusa/HELPAG-VAPT-Test-Site.git
cd HELPAG-VAPT-Test-Site
cp .env.example .env
docker compose up --build -d
curl -s http://127.0.0.1:5005/health
```

Open <http://127.0.0.1:5005/>, register a team name, and start hunting. Flags
look like `HELPAG{...}` and are submitted on the same page.

To reach the range from other machines on an isolated lab segment, set
`LAB_BIND=0.0.0.0` in `.env`. Do that only on a segment you control.

### Native Python

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
LAB_MODE=true .venv/bin/python app.py &
.venv/bin/python -m http.server 8080 --directory metadata &   # SSRF target
```

### Windows / IIS

See [`WINDOWS_IIS_DEPLOYMENT_GUIDE.md`](WINDOWS_IIS_DEPLOYMENT_GUIDE.md). IIS
listens on the lab port and reverse-proxies to a Waitress backend bound to
`127.0.0.1:5005`.

## Player rules

1. Scope is this host only. Do not pivot elsewhere on the lab network.
2. No destructive actions — other teams share the instance.
3. **Do not read the source.** This repository contains every flag. Solving by
   `git clone` teaches nothing.
4. Automated scanning is encouraged; it is what the detection use cases exist to catch.

The in-app `/rules` page carries the same list, and every challenge card on the
board has free hints.

## Sending events to your SIEM

Every request and every exploit attempt emits a structured JSON event. Configure
HEC in `.env`:

```bash
SPLUNK_HEC_URL=https://splunk.lab.invalid:8088/services/collector
SPLUNK_HEC_TOKEN=<token>
SPLUNK_INDEX=vapt_lab
SPLUNK_SOURCETYPE=helpag:owasp:json
```

Without HEC, events land in `logs/helpag-events.jsonl` — point a Universal
Forwarder at it instead. Setup details in [`splunk/README.md`](splunk/README.md);
the use cases are in
[`splunk/TA-helpag-vapt/`](splunk/TA-helpag-vapt/default/savedsearches.conf).

## Verify the deployment

```bash
./tools/validate_range.sh http://127.0.0.1:5005      # expects: 22 passed, 0 failed
.venv/bin/python -m unittest discover -s tests       # 39 tests
```

On Windows:

```powershell
.\tools\Validate-Range.ps1 -BaseUrl http://localhost:8080 -MetadataPort 8081
```

The harness solves every challenge end to end, which also produces a complete
event set (~140 events, 35 distinct event types) for tuning detections.

## Documentation

| File | Audience | Contents |
|---|---|---|
| [`CTF_PLAYBOOK.md`](CTF_PLAYBOOK.md) | **Instructors** — contains every flag | Solutions, commands, SPL, MITRE mapping, remediation |
| [`OWASP_TOP10_TEST_COMMANDS.md`](OWASP_TOP10_TEST_COMMANDS.md) | Testers | One command per OWASP category |
| [`BURP_SUITE_TEST_GUIDE.md`](BURP_SUITE_TEST_GUIDE.md) | Testers | Manual Repeater/Intruder procedure |
| [`splunk/USE_CASES.md`](splunk/USE_CASES.md) | Detection engineers | Validation searches |
| [`WINDOWS_IIS_DEPLOYMENT_GUIDE.md`](WINDOWS_IIS_DEPLOYMENT_GUIDE.md) | Lab admins | Full Windows Server / IIS build, operations, troubleshooting |
| [`SPLUNK_INTEGRATION_GUIDE.md`](SPLUNK_INTEGRATION_GUIDE.md) | Lab admins | Index, forwarder/HEC, TA placement, enabling the 21 detections |

## Layout

```
app.py                     Flask factory, LAB_MODE guard, request telemetry
labsite/catalog.py         Challenge definitions: flags, points, MITRE, detections
labsite/challenges.py      The vulnerable endpoints
labsite/ctf.py             Scoreboard and flag submission (not vulnerable)
labsite/events.py          Event emission and payload classification
labsite/db.py              Schema and synthetic seed data
tools/validate_range.sh    Solves every challenge, submits every flag (bash)
tools/Validate-Range.ps1   The same harness for Windows (PowerShell)
tools/seed_fixtures.py     Regenerates flag store from the catalogue
tools/check_playbook.py    Fails if the playbook drifts from the catalogue
splunk/TA-helpag-vapt/     Field extraction and 21 detection use cases
```

Adding a challenge is a catalogue entry plus an endpoint — the board, scoreboard,
progress API and MITRE matrix all read from `labsite/catalog.py`. Step-by-step in
section 10 of the playbook.
