# Continuation handoff

Starting point for the next agent or engineer working on this repository.

## Current state

- **Realistic target.** The site is Meridian Freight Solutions, a fictional
  logistics company: marketing pages, customer portal, partner API and staff
  admin area. 22 findings live inside ordinary business features.
- **Proof is data, not a field.** Each finding yields a realistic artifact
  containing a `MERIDIAN{...}` reference. No endpoint returns a field called
  `flag` - `tests/test_app.py` enforces this, along with the other realism
  properties (no range vocabulary on public pages, no link to the console).
- **The console is a separate application** at `/range/console`, gated by
  `RANGE_CONSOLE_TOKEN`. It holds the finding list, hints, scoring and the
  scoreboard. Change the token before a live exercise.
- **Findings catalogue is the single source of truth.** `labsite/catalog.py`
  holds every proof value, point value, MITRE technique and detection event
  name. The console, scoreboard, progress API, MITRE matrix and validation
  harness all read from it.
- **Vulnerabilities live in `labsite/business.py`**, the scoring layer in
  `labsite/console.py` (which is deliberately *not* vulnerable).
- `LAB_MODE=true` is mandatory; every path except `/health` is refused otherwise.
- Events are JSONL and optionally forwarded to Splunk HEC. 37 distinct
  `event_type` values; 22 packaged detection use cases (UC-01 … UC-22).
- Docker compose brings up the app plus a synthetic metadata service for SSRF.
- IIS deployment uses ARR/URL Rewrite to proxy to Waitress on localhost.
- 45 unit tests in `tests/test_app.py`; `tools/validate_range.sh` recovers all
  22 artifacts end to end.

## Safety posture — read before changing anything

This build contains **real** command execution (`/admin/diagnostics`), real
SSTI (`/admin/campaigns/preview`) and real arbitrary file read (invoice
traversal and EDI XXE). That is a deliberate change from the earlier "no command-execution
examples" stance: a CTF that only simulates execution cannot exercise the
process-level telemetry the range exists to validate.

The containment that makes this acceptable, all of which must stay:

| Control | Where |
|---|---|
| `LAB_MODE` guard refuses all traffic by default | `app.py` |
| Binds to `127.0.0.1` unless `LAB_BIND` is changed | `docker-compose.yml` |
| Runs as unprivileged `lab` user in the container | `Dockerfile` |
| SSRF bounded to an allow-list of lab-internal hosts | `labsite/business.py` |
| XXE parser has `no_network=True` — no out-of-band exfiltration | `labsite/business.py` |
| Uploaded files are always served as `text/plain`, never executed | `labsite/business.py` |
| JNDI/Log4Shell is recorded, never resolved | `labsite/business.py` |

Do not relax any of these. Do not add an outbound-capable challenge.

## Verification commands

```bash
python -m unittest discover -s tests -v      # 45 tests
python tools/check_playbook.py               # playbook vs catalogue drift
python -m py_compile app.py labsite/*.py
./tools/validate_range.sh http://127.0.0.1:5005   # expects 22 passed, 0 failed
```

## Adding a challenge

1. Append to `FINDINGS` in `labsite/catalog.py`.
2. Implement the business feature in `labsite/business.py`. Embed the proof
   value in a realistic artifact, call `note_disclosure("<id>")` when it is
   handed over, and `emit_event(...)` on both attempt and success. Never return
   a field called `flag` — a test enforces this.
3. Add a detection stanza to `splunk/TA-helpag-vapt/default/savedsearches.conf`.
4. Add a walkthrough to section 7 of `ASSESSMENT_PLAYBOOK.md`.
5. Add a case to `tools/validate_range.sh` and `tools/Validate-Range.ps1`.

`tools/check_playbook.py` fails the build if step 4 is skipped.

## Next safe improvements

1. Splunk dashboard XML, after validating field names in the target lab.
2. A per-team event view so instructors can replay one team's kill chain.
3. Time-decaying dynamic scoring, if the range is used competitively.
4. PowerShell static analysis job in CI alongside the Python tests.
