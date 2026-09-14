# Meridian Freight Solutions — security test target

A deliberately vulnerable corporate website and customer portal for an isolated
security lab. It looks and behaves like a real logistics company's web estate:
marketing pages, a customer portal, a partner API and a staff administration
area. Twenty-two vulnerabilities live inside ordinary business features, and
every exploitation writes a structured detection event so you can prove your
SIEM use cases actually fire.

Meridian Freight Solutions is fictional. Every identity, reference, key and
credential in this build is synthetic.

> **Never expose this to the Internet or to a production network.** It contains
> genuine command execution, server-side template injection and arbitrary file
> read. The application refuses all traffic unless `LAB_MODE=true`.

## How it differs from a CTF

There is no challenge board on the target, no hints, no score display and no
mention of the range. A tester approaches it the way they would a real
engagement. **Proof of exploitation is the data itself** — a credential file, an
HR document, an internal runbook, a cloud token, another customer's consignment
record. No endpoint returns a field called `flag`; a test enforces that.

The scoring board and scoreboard live in a **separate operator console** at
`/range/console`, gated by a token. The target site never links to it.

| Audience | Where they go |
|---|---|
| Tester | `http://<range>/` — the Meridian site, nothing else |
| Instructor | `http://<range>/range/console?token=…` |
| Detection engineer | Splunk, plus [`ASSESSMENT_PLAYBOOK.md`](ASSESSMENT_PLAYBOOK.md) |

## Quick start

```bash
git clone https://github.com/DrHayabusa/HELPAG-VAPT-Test-Site.git
cd HELPAG-VAPT-Test-Site
cp .env.example .env
docker compose up --build -d
curl -s http://127.0.0.1:5005/health
```

Open <http://127.0.0.1:5005/> — you should get a freight company's homepage.
The operator console is at <http://127.0.0.1:5005/range/console?token=range-operator>.

**Before a live exercise, change `RANGE_CONSOLE_TOKEN` in `.env`** — the default
is published in this repository. Set `LAB_BIND=0.0.0.0` to reach the range from
an isolated lab segment.

### Native Python

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
LAB_MODE=true .venv/bin/python app.py &
.venv/bin/python -m http.server 8080 --directory metadata &   # SSRF destination
```

### Windows / IIS

See [`WINDOWS_IIS_DEPLOYMENT_GUIDE.md`](WINDOWS_IIS_DEPLOYMENT_GUIDE.md).

## What's in it

| | |
|---|---|
| **22 findings** | 2800 points, mapped to OWASP Top 10 2021 |
| **Attack surface** | Marketing site, customer portal, partner API, staff admin area |
| **Detection content** | 22 Splunk use cases (UC-01 … UC-22), shipped disabled |
| **MITRE ATT&CK** | 13 techniques across 8 tactics, per finding |
| **Operator console** | Findings, hints, scoring, scoreboard — token-gated, separate |
| **Validation** | Recovers all 22 artifacts and reports pass/fail |

Findings cover recon and exposed files, IDOR, mass assignment, SQL injection
(union and auth bypass), reflected and stored XSS, path traversal, command
injection, SSTI, XXE, unrestricted upload, JWT `alg:none`, forged sessions,
brute force, predictable reset tokens, SSRF to cloud metadata, business logic
abuse, and a Log4Shell-class lookup.

They chain: `/robots.txt` leads to a runbook naming three other findings, and
`/.env` hands over the session key, the JWT key and a service password.

## Verify the deployment

```bash
./tools/validate_range.sh http://127.0.0.1:5005      # expects: 22 passed, 0 failed
.venv/bin/python -m unittest discover -s tests       # 45 tests
```

On Windows:

```powershell
.\tools\Validate-Range.ps1 -BaseUrl http://localhost:8080 -MetadataPort 8081
```

Run a full staged intrusion (recon → exfiltration) to exercise the SIEM:

```bash
./tools/simulate_attack.sh http://127.0.0.1:5005
```

## Send events to your SIEM

Every request and exploitation attempt emits structured JSON. Configure HEC in
`.env`, or point a Universal Forwarder at `logs/meridian-events.jsonl`. Full
instructions in [`SPLUNK_INTEGRATION_GUIDE.md`](SPLUNK_INTEGRATION_GUIDE.md).

The highest-value detections are **UC-21** (kill-chain correlation, which
separates a scanner from a human working the chain) and **UC-22** (a real data
artifact actually left the application).

## Documentation

| File | Audience | Contents |
|---|---|---|
| [`ARCHITECTURE.md`](ARCHITECTURE.md) | Everyone | Components, request flow, route map, data model, trust boundaries, telemetry |
| [`ATTACK_SIMULATION.md`](ATTACK_SIMULATION.md) | Testers & detection engineers | Five-stage intrusion, commands, MITRE mapping, per-step detections |
| [`ASSESSMENT_PLAYBOOK.md`](ASSESSMENT_PLAYBOOK.md) | **Operators** — contains every proof value | Per-finding walkthroughs, commands, SPL, MITRE, remediation |
| [`OWASP_TOP10_TEST_COMMANDS.md`](OWASP_TOP10_TEST_COMMANDS.md) | Testers | One command per OWASP category |
| [`BURP_SUITE_TEST_GUIDE.md`](BURP_SUITE_TEST_GUIDE.md) | Testers | Manual Repeater/Intruder procedure |
| [`WINDOWS_IIS_DEPLOYMENT_GUIDE.md`](WINDOWS_IIS_DEPLOYMENT_GUIDE.md) | Lab admins | Windows Server / IIS build and operations |
| [`SPLUNK_INTEGRATION_GUIDE.md`](SPLUNK_INTEGRATION_GUIDE.md) | Lab admins | Index, forwarder/HEC, TA placement, alerts |
| [`splunk/USE_CASES.md`](splunk/USE_CASES.md) | Detection engineers | Validation searches |

## Layout

```
app.py                      Flask factory, LAB_MODE guard, request telemetry
labsite/catalog.py          Findings: proof values, points, MITRE, detections
labsite/business.py         The site, portal, partner API and staff area
labsite/console.py          Operator console (token-gated, not vulnerable)
labsite/events.py           Event emission and payload classification
labsite/db.py               Schema and synthetic business data
templates/                  Corporate site; console templates kept separate
instance/                   Server-side secrets - the file-read targets
documents/ backups/ internal/ uploads/   Artifact stores the findings reach
tools/validate_range.sh     Recovers every artifact (bash)
tools/simulate_attack.sh    Staged adversary simulation, one source, SIEM-paced
tools/Validate-Range.ps1    The same for Windows (PowerShell)
tools/seed_fixtures.py      Regenerates on-disk artifacts from the catalogue
tools/check_playbook.py     Fails if the playbook drifts from the catalogue
splunk/TA-helpag-vapt/      Field extraction and 22 detection use cases
```

Adding a finding is a catalogue entry plus a business feature — section 9 of the
playbook has the steps.
