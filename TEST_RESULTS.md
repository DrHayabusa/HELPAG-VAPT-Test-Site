# Validation record

Executed against this build on 2026-09-14. Every result below was produced by
running the commands shown, not reasoned about.

## Environment

| | |
|---|---|
| Deployment | `docker compose up --build -d` (app + metadata service) |
| Target | `http://127.0.0.1:5005` |
| Image base | `python:3.11-slim` + `iputils-ping`, app runs as unprivileged `lab` |
| Host | macOS 22.6.0, Docker Desktop |

## Results

| Check | Command | Result |
|---|---|---|
| Health | `curl -s $BASE/health` | `{"lab_mode":true,"status":"healthy"}` |
| **All 22 challenges solved** | `./tools/validate_range.sh http://127.0.0.1:5005` | **22 passed, 0 failed** |
| Unit tests | `python -m unittest discover -s tests` | **37 tests, OK** |
| Playbook drift | `python tools/check_playbook.py` | in sync with 22 challenges |
| Scoreboard total | `curl -s $BASE/api/ctf/scoreboard` | 22 solves, 2800 points |
| Event volume | one full validation run | **145 events, 34 distinct event types** |

## Lab-mode guard

With `LAB_MODE` unset or false, every path except `/health` is refused:

| Path | Status |
|---|---|
| `/` | 503 |
| `/api/diagnostics/ping?host=1;id` | 503 |
| `/health` | 200 |

## Per-challenge result

All twenty-two returned their flag and the scoreboard accepted it:

```
PASS recon-robots           PASS misconfig-debug       PASS misconfig-dotenv
PASS misconfig-backups      PASS access-idor           PASS access-massassign
PASS inject-sqli-union      PASS inject-sqli-auth      PASS xss-reflected
PASS xss-stored             PASS inject-jndi           PASS file-traversal
PASS rce-cmdi               PASS rce-ssti              PASS inject-xxe
PASS upload-unrestricted    PASS auth-bruteforce       PASS auth-jwt-none
PASS auth-reset-token       PASS auth-weak-secret      PASS ssrf-metadata
PASS logic-negative

== 22 passed, 0 failed ==
```

## Browser verification

The challenge board, team registration, flag submission and scoreboard were
driven through a real browser against the running container:

- Team registration persists to the session and the header.
- A correct flag turns the card green, increments the progress bar
  (`1/22 challenges · 50/2800 points`) and reports `Correct: <title>`.
- Enter-to-submit and the Submit button both work.
- The scoreboard lists teams by points and shows per-challenge solve counts.
- `/api/ctf/challenges` was asserted to contain no flag value (unit test
  `test_public_catalog_never_leaks_a_flag`).

## Not verified here

- **Splunk HEC delivery and the 21 saved searches.** No Splunk instance was
  available. The events are emitted and the JSON shape is asserted by
  `TestTelemetry`, but the SPL in `savedsearches.conf` has not been executed
  against a real index. Validate field mappings before enabling any alert.
- **Windows/IIS deployment.** The IIS scripts were updated for the new log and
  database filenames but were not run; no Windows host was available. Note that
  the command-injection challenge needs `&` and `type` rather than `;` and `cat`
  under `cmd.exe` — see the playbook.

## Reproduce

```bash
cp .env.example .env
docker compose up --build -d
./tools/validate_range.sh http://127.0.0.1:5005
python -m unittest discover -s tests -v
```
