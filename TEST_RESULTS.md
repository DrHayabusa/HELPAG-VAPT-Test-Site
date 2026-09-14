# Validation record

Executed against this build on 2026-09-14.

## Environment

| | |
|---|---|
| Deployment | `docker compose up --build -d` (target + metadata service) |
| Target | `http://127.0.0.1:5005` |
| Image | `python:3.11-slim` + `iputils-ping`, running as unprivileged `lab` |
| Host | macOS 22.6.0, Docker Desktop |

## Results

| Check | Command | Result |
|---|---|---|
| Health | `curl -s $BASE/health` | `{"lab_mode":true,"status":"healthy"}` |
| **All 22 findings reachable** | `./tools/validate_range.sh` | **22 passed, 0 failed** |
| Unit tests | `python -m unittest discover -s tests` | **45 tests, OK** |
| Playbook drift | `python tools/check_playbook.py` | in sync with 22 findings |
| Event volume | one full validation run | **146 events, 37 distinct types** |
| Artifact disclosures | `artifact_disclosed` events | **22** — one per finding |

## Realism properties (asserted by tests)

| Property | How it is checked |
|---|---|
| No public page discloses a proof value | `test_public_pages_disclose_no_proof_value` |
| No public page mentions range mechanics | `test_public_pages_do_not_mention_range_mechanics` (checks for "challenge", "ctf", "vulnerab", "exploit", "owasp") |
| The site never links to the console | `test_site_never_links_to_the_operator_console` |
| No exploited endpoint returns a field named `flag` | `test_exploited_endpoints_do_not_return_a_field_called_flag` |
| The console discloses nothing without a token | `test_locked_console_discloses_nothing` |
| The console API never carries proof values | `test_console_findings_carry_no_proof_values` |

Verified manually against the running container as well: all ten public pages
return no `MERIDIAN{` value, `/range/console` returns 403 without a token and
200 with one.

## Lab-mode guard

With `LAB_MODE` unset or false, every path except `/health` is refused:

| Path | Status |
|---|---|
| `/` | 503 |
| `/admin/diagnostics` | 503 |
| `/range/console` | 503 |
| `/health` | 200 |

## Per-finding result

```
PASS recon-runbook        PASS misconfig-debug      PASS misconfig-dotenv
PASS misconfig-backups    PASS idor-shipment        PASS access-massassign
PASS sqli-union           PASS sqli-authbypass      PASS xss-reflected
PASS xss-stored           PASS traversal-invoice    PASS rce-cmdi
PASS rce-ssti             PASS xxe-edi              PASS upload-unrestricted
PASS auth-bruteforce      PASS jwt-none             PASS reset-token
PASS weak-session-secret  PASS ssrf-metadata        PASS logic-negative-quote
PASS jndi-audit

== 22 passed, 0 failed ==
```

## Browser verification

The site was driven through a real browser against the running container:
homepage, services with the live rate table, and the operator console. The site
renders as a freight company's web estate with no indication it is a range; the
console is a visually and structurally separate application.

## Not verified here

- **Splunk HEC delivery and the 22 saved searches.** No Splunk instance was
  available. Events are emitted and their JSON shape is asserted by
  `TestTelemetry`, but the SPL has not run against a real index. Validate field
  mappings before enabling any alert.
- **Windows/IIS deployment and the PowerShell scripts.** No Windows host was
  available and `pwsh` would not install on the build machine, so the four
  PowerShell scripts are reviewed by hand and brace-balance checked, not executed.
- **`.env` drift.** `.env` is gitignored, so an existing deployment upgrading to
  this build keeps its old values. Re-copy `.env.example` after pulling, or the
  session-secret finding will not reproduce.

## Reproduce

```bash
cp .env.example .env
docker compose up --build -d
./tools/validate_range.sh http://127.0.0.1:5005
python -m unittest discover -s tests -v
```
