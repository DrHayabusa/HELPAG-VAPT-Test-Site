# OWASP Top 10 authorized lab test commands

Run these commands only against the isolated HELPAG training site. Set the IIS
address once; every example below remains scoped to that host.

```bash
export TARGET="http://iis-lab.internal:8080"
curl -fsS "$TARGET/health"
```

## A01 — Broken Access Control

```bash
curl -sS "$TARGET/api/users/2"
```

Expected Splunk event: `event_type=broken_access_attempt allowed=true`.

## A02 — Cryptographic Failures

```bash
curl -sS "$TARGET/api/backup"
```

Expected event: `event_type=sensitive_data_exposure`.

## A03 — Injection

```bash
curl -sS --get --data-urlencode "q=' OR 1=1--" "$TARGET/api/products/search"
curl -sS --get --data-urlencode 'name=<script>alert(1)</script>' "$TARGET/reflect"
```

Expected events: suspicious `sql_query` and `xss_probe`.

## A04 — Insecure Design

```bash
curl -sS -X POST "$TARGET/api/checkout" -H 'Content-Type: application/json' \
  -d '{"quantity":-5,"unit_price":100}'
```

Expected event: `event_type=business_logic_abuse total<0`.

## A05 — Security Misconfiguration

```bash
curl -sS "$TARGET/api/debug/config"
```

Expected event: `event_type=debug_endpoint_access`.

## A06 — Vulnerable and Outdated Components

```bash
curl -sS "$TARGET/api/components"
```

The returned versions are simulated and are not installed dependencies.

## A07 — Identification and Authentication Failures

```bash
for i in 1 2 3 4 5; do
  curl -sS -X POST "$TARGET/api/login" -H 'Content-Type: application/json' \
    -d '{"username":"admin","password":"wrong"}'
done
curl -sS -X POST "$TARGET/api/login" -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"admin"}'
```

Expected events: repeated failed `authentication_attempt` followed by success.

## A08 — Software and Data Integrity Failures

```bash
curl -sS -X POST "$TARGET/api/preferences/import" -H 'Content-Type: application/json' \
  -d '{"role":"admin"}'
```

Expected event: `event_type=unsigned_data_import signature_checked=false`.

## A09 — Security Logging and Monitoring Failures

```bash
curl -sS -X POST "$TARGET/api/quiet-transfer" -H 'Content-Type: application/json' \
  -d '{"amount":9999}'
```

Expected event: `event_type=monitoring_gap_simulated` with deliberately missing
actor and destination context.

## A10 — Server-Side Request Forgery

The SSRF demonstration is intentionally bounded to the Docker metadata service.

```bash
curl -sS --get --data-urlencode 'url=http://metadata:8080/' "$TARGET/api/fetch"
```

If IIS is installed without Docker, the request returns a controlled 502 but
still produces the `ssrf_probe` detection event.

## Scanner commands

```bash
nuclei -u "$TARGET" -severity low,medium,high,critical -jsonl -o nuclei.jsonl
katana -u "$TARGET" -jc -d 3 -o katana-urls.txt
httpx -u "$TARGET" -status-code -title -tech-detect
ffuf -u "$TARGET/FUZZ" -w wordlists/helpag-paths.txt -mc all -of json -o ffuf.json
gobuster dir -u "$TARGET" -w wordlists/helpag-paths.txt -o gobuster.txt
```

## VAPT Agent workflow

1. Open the VAPT Agent GUI.
2. Enter the IIS URL in **Assessment**.
3. Select **Web application** and confirm authorization.
4. Run target analysis, then the smart scan.
5. Attach the result in **AI copilot** and ask for prioritized findings.
6. In Splunk, run the searches in `splunk/USE_CASES.md` and confirm that both
   `iis` and `helpag:owasp:json` events are present.

