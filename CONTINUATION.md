# Continuation handoff

Starting point for the next agent or engineer working on this repository.

## Current state

- **CTF range.** 22 challenges, 2800 points, flag format `HELPAG{...}`, with a
  scoreboard (team registration, first bloods, live progress) at `/`.
- **Challenge catalogue is the single source of truth.** `labsite/catalog.py`
  holds every flag, point value, MITRE technique and detection event name. The
  board, scoreboard, progress API, MITRE matrix and validation harness all read
  from it.
- **Vulnerabilities live in `labsite/challenges.py`**, the scoring layer in
  `labsite/ctf.py` (which is deliberately *not* vulnerable).
- `LAB_MODE=true` is mandatory; every path except `/health` is refused otherwise.
- Events are JSONL and optionally forwarded to Splunk HEC. 35 distinct
  `event_type` values; 21 packaged detection use cases (UC-01 … UC-21).
- Docker compose brings up the app plus a synthetic metadata service for SSRF.
- IIS deployment uses ARR/URL Rewrite to proxy to Waitress on localhost.
- 37 unit tests in `tests/test_app.py`; `tools/validate_range.sh` solves all 22
  challenges end to end.

## Safety posture — read before changing anything

This build contains **real** command execution (`/api/diagnostics/ping`), real
SSTI (`/api/newsletter/preview`) and real arbitrary file read (path traversal and
XXE). That is a deliberate change from the earlier "no command-execution
examples" stance: a CTF that only simulates execution cannot exercise the
process-level telemetry the range exists to validate.

The containment that makes this acceptable, all of which must stay:

| Control | Where |
|---|---|
| `LAB_MODE` guard refuses all traffic by default | `app.py` |
| Binds to `127.0.0.1` unless `LAB_BIND` is changed | `docker-compose.yml` |
| Runs as unprivileged `lab` user in the container | `Dockerfile` |
| SSRF bounded to an allow-list of lab-internal hosts | `labsite/challenges.py` |
| XXE parser has `no_network=True` — no out-of-band exfiltration | `labsite/challenges.py` |
| Uploaded files are always served as `text/plain`, never executed | `labsite/challenges.py` |
| JNDI/Log4Shell is recorded, never resolved | `labsite/challenges.py` |

Do not relax any of these. Do not add an outbound-capable challenge.

## Verification commands

```bash
python -m unittest discover -s tests -v      # 37 tests
python tools/check_playbook.py               # playbook vs catalogue drift
python -m py_compile app.py labsite/*.py
./tools/validate_range.sh http://127.0.0.1:5005   # expects 22 passed, 0 failed
```

## Adding a challenge

1. Append to `CHALLENGES` in `labsite/catalog.py`.
2. Implement the endpoint in `labsite/challenges.py`; call `award("<id>")` on
   success and `emit_event(...)` on both attempt and success.
3. Add a detection stanza to `splunk/TA-helpag-vapt/default/savedsearches.conf`.
4. Add a walkthrough to section 7 of `CTF_PLAYBOOK.md`.
5. Add a case to `tools/validate_range.sh`; re-run it and the tests.

`tools/check_playbook.py` fails the build if step 4 is skipped.

## Next safe improvements

1. Splunk dashboard XML, after validating field names in the target lab.
2. A per-team event view so instructors can replay one team's kill chain.
3. Time-decaying dynamic scoring, if the range is used competitively.
4. PowerShell static analysis job in CI alongside the Python tests.
