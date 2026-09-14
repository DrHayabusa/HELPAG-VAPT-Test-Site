# Architecture — Meridian Freight Solutions test target

How the range is built: components, request flow, route map, data model, trust
boundaries, telemetry pipeline and the controls that keep an intentionally
vulnerable application containable.

Meridian Freight Solutions is a fictional logistics company. Every identity,
reference, key and credential in this build is synthetic.

---

## 1. At a glance

| | |
|---|---|
| Application | Python 3.11 / Flask, served by Waitress (IIS) or the Flask server (Docker) |
| Storage | SQLite, single file, recreated from seed on first start |
| Templating | Jinja2 |
| XML | lxml, deliberately configured with DTD loading and entity resolution |
| Telemetry | Newline-delimited JSON, optional Splunk HEC |
| Deployment | Docker Compose, or IIS + ARR reverse proxy on Windows Server |
| Surfaces | Public site, customer portal, partner API, staff admin, operator console |
| Findings | 22, worth 2800 points, mapped to OWASP Top 10 2021 and MITRE ATT&CK |

---

## 2. Component topology

```
                          ┌──────────────────────────────┐
   testers                │   Meridian target (5005)     │
      │                   │                              │
      │  HTTP             │  ┌────────────────────────┐  │
      ▼                   │  │ app.py                 │  │
 ┌──────────┐             │  │  LAB_MODE guard        │  │
 │  IIS     │  rewrite    │  │  request telemetry     │  │
 │  ARR     │────────────►│  │  404 handler           │  │
 │  (8080)  │  127.0.0.1  │  └───────────┬────────────┘  │
 └──────────┘             │              │                │
      │                   │   ┌──────────┴──────────┐     │
      │ W3C logs          │   │                     │     │
      ▼                   │   ▼                     ▼     │
 inetpub/logs        ┌─────────────────┐   ┌──────────────────┐
                     │ business.py     │   │ console.py       │
                     │ (vulnerable)    │   │ (NOT vulnerable) │
                     │ /, /portal,     │   │ /range/*         │
                     │ /api/v1, /admin │   │ token-gated      │
                     └────────┬────────┘   └────────┬─────────┘
                              │                     │
                     ┌────────┴─────────────────────┴────────┐
                     │  db.py (SQLite)   events.py (JSONL)   │
                     └────────┬─────────────────────┬────────┘
                              │                     │
              ┌───────────────┘                     └──────────────┐
              ▼                                                    ▼
   ┌─────────────────────┐                             ┌────────────────────┐
   │ on-disk artifacts   │                             │ Splunk             │
   │ instance/ internal/ │                             │ HEC or forwarder   │
   │ documents/ backups/ │                             │ index=vapt_lab     │
   │ uploads/            │                             └────────────────────┘
   └─────────────────────┘
              ▲
              │ SSRF destination only
   ┌──────────┴───────────┐
   │ metadata service     │   python -m http.server, loopback / lab network
   │ 8080, static files   │   synthetic instance metadata
   └──────────────────────┘
```

Only one listener is ever reachable from the lab segment: IIS on Windows, or the
published Docker port. The application and the metadata service both bind to
loopback or to the internal compose network.

---

## 3. Module map

| Module | Responsibility | Vulnerable? |
|---|---|---|
| `app.py` | App factory, configuration, `LAB_MODE` guard, request/404 telemetry | No |
| `labsite/catalog.py` | The 22 findings: proof values, points, features, artifacts, MITRE, detection events | No — data only |
| `labsite/business.py` | Every business feature: site, portal, partner API, staff admin | **Yes, by design** |
| `labsite/console.py` | Operator console: findings, scoring, scoreboard | No — deliberately hardened |
| `labsite/db.py` | Schema, synthetic seed data, connection lifecycle | No |
| `labsite/events.py` | Event emission, payload classification, client IP resolution | No |

`catalog.py` is the single source of truth. The console, scoreboard, progress
API, MITRE matrix, fixture generator and both validation harnesses all read from
it, so a finding is added in one place.

---

## 4. Request lifecycle

```
1. IIS / ARR         rewrites to 127.0.0.1:5005, sets X-Forwarded-For
2. before_request    starts the timer; refuses everything but /health
                     unless LAB_MODE=true
3. blueprint         console (/range/*) is matched first and token-gated;
                     otherwise business.py handles the route
4. handler           does the work — insecurely, where that is the point
5. emit_event        writes a JSON event: exploitation attempt, execution,
                     artifact disclosure
6. after_request     writes the http_request event and the X-Lab-Only header
```

**Client IP.** `events.py::client_ip()` takes the **first** entry of
`X-Forwarded-For`, falling back to `remote_addr`. Behind a reverse proxy every
request otherwise appears to come from `127.0.0.1`, and since every detection in
the pack groups by `source_ip`, that single detail decides whether the Splunk
content works at all.

**Payload classification.** `events.py::classify_payload()` tags raw input
against signature sets for `sqli`, `xss`, `traversal`, `cmdi`, `ssti`, `xxe` and
`jndi`. Handlers use the tags to set event severity and to choose the event type
(`sql_query` vs `sql_error`, `template_render` vs `ssti_attempt`), which is what
lets the detections separate a probe from normal traffic.

---

## 5. Route map

### Public site — anonymous

| Route | Purpose | Finding |
|---|---|---|
| `GET /` | Homepage, consignment tracking widget | — |
| `GET /about` `GET /news` | Company pages | — |
| `GET /services` | Lane rate table | — |
| `GET /search?q=` | Site search | `xss-reflected` |
| `GET /support/shared-search?q=` | Simulated support-agent render | `xss-reflected` |
| `GET/POST /contact` | Enquiry form | `xss-stored` |
| `GET /careers` · `POST /careers/apply` | CV submission | `upload-unrestricted` |
| `GET /uploads/` · `GET /uploads/<name>` | Applicant document store | `upload-unrestricted` |
| `GET/POST /services/quote` | Instant quote | `logic-negative-quote` |
| `GET /robots.txt` `GET /sitemap.xml` | Crawler directives | `recon-runbook` |
| `GET /internal/<name>` | Internal documents, no auth | `recon-runbook` |
| `GET /.env` | Deployment environment file | `misconfig-dotenv` |
| `GET /backups/` · `GET /backups/<name>` | Nightly export, autoindex on | `misconfig-backups` |
| `GET /status/diagnostics` | Developer status page | `misconfig-debug` |
| `GET /health` | Health probe — the only route allowed when `LAB_MODE=false` | — |

### Customer portal — session cookie

| Route | Purpose | Finding |
|---|---|---|
| `GET/POST /portal/login` | Sign in (parameterised) | `auth-bruteforce` |
| `POST /portal/login?legacy=1` | Pre-migration sign in (concatenated) | `sqli-authbypass` |
| `GET /portal/dashboard` | Account overview | — |
| `GET /portal/shipments` | Tracking UI | — |
| `GET /api/v1/shipments/<ref>` | Consignment record | `idor-shipment` |
| `POST /portal/profile` | Profile update | `access-massassign` |
| `GET/POST /portal/reset` · `POST /api/v1/account/reset` | Password reset | `reset-token` |
| `GET /api/v1/invoices/download?document=` | Invoice download | `traversal-invoice` |
| `GET /api/v1/rates/search?q=` | Rate lookup | `sqli-union` |

### Partner API — bearer token

| Route | Purpose | Finding |
|---|---|---|
| `GET /api/v1/auth/token` | Issues an HS256 token | — |
| `GET /api/v1/reports/financial` | Restricted report | `jwt-none` |
| `POST /api/v1/edi/manifest` | Supplier EDI import | `xxe-edi` |
| `GET/POST /api/v1/audit/event` | Legacy tracking shim | `jndi-audit` |

### Staff admin — session cookie

| Route | Purpose | Finding |
|---|---|---|
| `GET /admin` | Administration home, DR code | `weak-session-secret` |
| `GET /admin/messages` | Enquiry queue, rendered raw | `xss-stored` |
| `GET/POST /admin/diagnostics` | Depot connectivity check | `rce-cmdi` |
| `GET/POST /admin/campaigns/preview` | Campaign preview | `rce-ssti` |
| `GET /admin/integrations/preview?url=` | Link preview | `ssrf-metadata` |

### Operator console — `RANGE_CONSOLE_TOKEN`

| Route | Purpose |
|---|---|
| `GET /range/console` | Findings board with hints and artifacts |
| `GET /range/scoreboard` | Live standings and per-finding coverage |
| `POST /range/api/team` | Register a team |
| `POST /range/api/submit` | Record a recovered value |
| `GET /range/api/findings` `…/scoreboard` `…/progress` | JSON for the UI |

Blueprint order matters: `console` is registered before `business`, so
`/range/*` is always gated even though `business.py` owns the catch-all site.

---

## 6. Data model

```
accounts                  shipments                 integration_credentials
 id                        id                        id
 account_ref               reference  ◄── IDOR       partner
 company                   account_id                api_key  ◄── UNION SELECT
 contact_name              origin / destination
 email                     service / status         rates
 username                  declared_value            id / lane
 password                  contents                  service
 account_type ◄── mass     handling_notes ◄── proof  price_per_kg
 internal_notes ◄── proof

enquiries                 reset_tokens              range_teams / range_solves
 name / company            username                  console scoring only,
 email                     token ◄── md5(username)   never read by the site
 message   ◄── stored XSS  issued_at
```

Seven accounts, five consignments, three partner credentials. Three proof values
live in database columns (`internal_notes`, `handling_notes`, `api_key`); the
rest live in files or are synthesised at response time.

### On-disk artifact stores

| Directory | Served at | Reached by |
|---|---|---|
| `internal/` | `/internal/<name>` | Direct request — no auth |
| `backups/` | `/backups/<name>` | Direct request — autoindex |
| `documents/` | `/api/v1/invoices/download` | Path traversal escapes it |
| `uploads/` | `/uploads/<name>` | Unrestricted upload, browsable |
| `instance/` | **not served** | Traversal, command injection, SSTI, XXE |
| `metadata/` | separate service | SSRF only |

`instance/` is the important one: it is outside the document root, so reaching
it is proof that a file-read primitive worked rather than that a URL was guessed.

---

## 7. Trust boundaries

```
┌─ Internet ──────────────── NEVER. LAB_MODE + loopback binding enforce this.
│
├─ Lab segment ───────────── IIS :8080 or the published Docker port
│   │
│   ├─ Anonymous ─────────── public site, /api/v1/rates, /api/v1/shipments (broken)
│   ├─ Customer session ──── /portal/* — ownership never checked (broken)
│   ├─ Partner token ─────── /api/v1/* — algorithm honoured from the token (broken)
│   ├─ Staff session ─────── /admin/* — signed with a known secret (broken)
│   └─ Operator token ────── /range/* — the one boundary that actually holds
│
└─ Loopback only ────────── app :5005, metadata :8080
```

Five of the six boundaries are meant to fail; that is the syllabus. The sixth —
the operator console — is the one place where the code is written carefully:
parameterised queries, a strict team-name pattern, no proof values in any API
response, and a `before_request` gate on the whole blueprint.

---

## 8. Telemetry pipeline

Every event is one JSON object per line:

```json
{
  "timestamp": "2026-09-14T15:25:23.481903+00:00",
  "event_type": "command_execution",
  "severity": "critical",
  "app": "helpag-ctf-lab",
  "source_ip": "10.10.5.42",
  "method": "POST",
  "path": "/admin/diagnostics",
  "user_agent": "curl/8.4.0",
  "referer": "",
  "test_id": "purple-run-1",
  "team": "",
  "command_line": "ping -c 1 -W 1 127.0.0.1; cat instance/keys/depot-transfer.key",
  "exit_code": 0,
  "process": "sh",
  "parent_process": "python"
}
```

37 distinct `event_type` values. They fall into four groups:

| Group | Examples | Use |
|---|---|---|
| Baseline | `http_request`, `http_not_found`, `site_search` | Volume, scanner rate |
| Attempt | `sql_query suspicious=true`, `ssti_attempt`, `xxe_attempt`, `command_injection_attempt` | The probe |
| Outcome | `command_execution`, `privilege_change`, `jwt_unsigned_accepted`, `account_takeover` | It worked |
| Operator | `artifact_disclosed`, `range_finding_confirmed` | Real data left the building |

`artifact_disclosed` (UC-22) is the highest-severity event the target emits and
exists only in this build: it fires when a genuine data asset is handed over,
which is the event a SOC actually cares about, as distinct from the probe before it.

Two sinks, never both at once:

| Sink | Configured by | Notes |
|---|---|---|
| File | always on — `LAB_EVENT_LOG` | `logs/meridian-events.jsonl`; forwarder reads it |
| Splunk HEC | `SPLUNK_HEC_URL` + `SPLUNK_HEC_TOKEN` | Best effort, 2s timeout, never retried |

Enabling both double-indexes every event and invalidates every count-based
threshold. See [`SPLUNK_INTEGRATION_GUIDE.md`](SPLUNK_INTEGRATION_GUIDE.md).

---

## 9. Containment

The target has real command execution, real SSTI and real arbitrary file read.
These controls are what make that acceptable, and none of them may be relaxed:

| Control | Where | Effect |
|---|---|---|
| `LAB_MODE` guard | `app.py` | Every path but `/health` returns 503 by default |
| Loopback binding | `docker-compose.yml`, `Start-LabSite.ps1` | `LAB_BIND` must be changed deliberately |
| Unprivileged user | `Dockerfile` | Runs as `lab`, not root |
| SSRF allow-list | `business.py::link_preview` | Only lab-internal hosts; cannot scan your network |
| `no_network=True` | `business.py::edi_manifest` | XXE cannot exfiltrate out-of-band |
| Inert upload serving | `business.py::serve_upload` | Always `text/plain`; no live web shell |
| Simulated JNDI | `business.py::audit_event` | Lookup recorded, never resolved |
| Proof-value hashing | `catalog.py` | Console verifies SHA-256; the list never reaches a browser |

---

## 10. Deployment topologies

### Docker

```
meridian-lab network
├── meridian-web       127.0.0.1:5005 → published   app + artifacts
└── meridian-metadata  metadata:8080  → internal    SSRF destination
    volumes: ./logs (events, database), ./metadata (read-only)
```

### Windows / IIS

```
IIS :8080  ──rewrite──►  Waitress 127.0.0.1:5005   (scheduled task, SYSTEM)
                         http.server 127.0.0.1:8081 (scheduled task, SYSTEM)
W3C logs → C:\inetpub\logs\LogFiles → Universal Forwarder → index=vapt_lab
```

Two IIS settings are load-bearing rather than cosmetic:

- **`X-Forwarded-For`** must be set by the rewrite rule, or every event records
  `127.0.0.1` and the whole detection pack is useless.
- **Relaxed request filtering** (`allowDoubleEscaping`, cleared `hiddenSegments`),
  or IIS 404s `../` before the backend sees it and the traversal finding produces
  neither an exploit nor telemetry.

Full procedure: [`WINDOWS_IIS_DEPLOYMENT_GUIDE.md`](WINDOWS_IIS_DEPLOYMENT_GUIDE.md).

---

## 11. Configuration

| Variable | Default | Purpose |
|---|---|---|
| `LAB_MODE` | `false` | Master guard. Must be `true` to serve anything |
| `LAB_HOST` / `LAB_PORT` | `127.0.0.1` / `5005` | Application bind |
| `LAB_BIND` | `127.0.0.1` | Docker publish address |
| `LAB_DATABASE` | `/tmp/meridian.db` | SQLite path |
| `LAB_EVENT_LOG` | `/tmp/meridian-events.jsonl` | Event sink |
| `LAB_DOCUMENT_DIR` / `LAB_UPLOAD_DIR` / `LAB_BACKUP_DIR` / `LAB_INTERNAL_DIR` | repo dirs | Artifact stores |
| `LAB_SESSION_SECRET` | `meridian-default-signing-key` | **Deliberately weak** — finding `weak-session-secret` |
| `LAB_JWT_KEY` | `mfs-partner-hs256` | Partner token HS256 key |
| `RANGE_CONSOLE_TOKEN` | `range-operator` | Console gate — **change before a live exercise** |
| `SPLUNK_HEC_URL` / `_TOKEN` / `_INDEX` / `_SOURCETYPE` / `_VERIFY_TLS` | empty / `vapt_lab` | HEC delivery |

`.env` is gitignored. After pulling a new build, re-copy `.env.example` or an
existing deployment keeps its old values and the session-secret finding stops
reproducing.

---

## 12. Extending it

1. Append a finding to `FINDINGS` in `labsite/catalog.py`.
2. Implement the business feature in `labsite/business.py`. Embed the proof value
   in a realistic artifact, call `note_disclosure("<id>")` when it is handed
   over, and `emit_event(...)` on both attempt and outcome. **Never return a
   field called `flag`** — a test enforces this.
3. Add a detection stanza to `splunk/TA-helpag-vapt/default/savedsearches.conf`.
4. Add a walkthrough to section 6 of [`ASSESSMENT_PLAYBOOK.md`](ASSESSMENT_PLAYBOOK.md).
5. Add a case to `tools/validate_range.sh` and `tools/Validate-Range.ps1`.

`tools/check_playbook.py` fails the build if step 4 is skipped;
`tools/seed_fixtures.py` regenerates on-disk artifacts from the catalogue.
