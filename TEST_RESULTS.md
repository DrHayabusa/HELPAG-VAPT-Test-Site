# HELPAG VAPT Test Site — executed test results

Test date: 13 September 2026  
Environment: macOS Apple Silicon, Python 3.11 test client and localhost services  
Target used for live checks: `http://127.0.0.1:5005`

## Summary

| Area | Result | Evidence |
|---|---:|---|
| Application unit tests | PASS | 4/4 tests |
| VAPT Agent unit tests | PASS | 7/7 tests |
| GitHub Actions | PASS | Two successful workflow runs |
| Clean GitHub clone | PASS | Both private repositories cloned and tests rerun |
| Lab safety guard | PASS | `/` returns HTTP 503 when `LAB_MODE` is disabled |
| Docker Compose syntax | PASS | `docker compose config` completed successfully |
| IIS configuration XML | PASS | `xmllint` validation completed successfully |
| VAPT target analysis | PASS | Target classified as `web_application`, risk `high` |
| HTTPX verification | PASS | HTTP 200 and title `OWASP Range / VAPT Agent` |
| Ollama integration | PASS | Qwen replied `MULTI PROVIDER READY` through VAPT API |
| Hosted-provider adapter | PASS | OpenAI-compatible request and response mocked successfully |
| Splunk HEC format | PASS | URL, authorization request, index, sourcetype, and event envelope mocked |
| Real IIS deployment | NOT RUN | Requires the Windows lab server |
| Real Splunk ingestion/search | NOT RUN | Requires the lab indexer, HEC token, and/or Universal Forwarder |

## OWASP endpoint checks performed

| ID | Request tested | Expected weakness | Resulting security event | Result |
|---|---|---|---|---:|
| A01 | `GET /api/users/2` | Object returned without authentication | `broken_access_attempt` | PASS |
| A02 | `GET /api/backup` | Synthetic secret material disclosed | `sensitive_data_exposure` | PASS |
| A03 | `GET /api/products/search?q=' OR 1=1--` | SQL predicate altered | `sql_query suspicious=true` | PASS |
| A03 | `GET /reflect?name=<script>…` | Input reflected as HTML | `xss_probe` | PASS |
| A04 | `POST /api/checkout` with negative quantity | Negative total accepted | `business_logic_abuse` | PASS |
| A05 | `GET /api/debug/config` | Debug configuration disclosed | `debug_endpoint_access` | PASS |
| A06 | `GET /api/components` | Simulated old versions returned | `outdated_component_inventory` | PASS |
| A07 | `POST /api/login` with `admin/admin` | Weak credential accepted | `authentication_attempt` | PASS |
| A08 | `POST /api/preferences/import` with role `admin` | Unsigned role trusted | `unsigned_data_import` | PASS |
| A09 | `POST /api/quiet-transfer` | Audit event lacks actor/destination | `monitoring_gap_simulated` | PASS |
| A10 | `GET /api/fetch?url=http://metadata:8080/` | Server attempts bounded internal fetch | `ssrf_probe` | PASS |

The live exercise produced 24 structured events: the security events above plus
the corresponding `http_request` telemetry. Event data was written as JSONL and
contained timestamps, request paths, source IP, HTTP method, status, duration,
user agent, and security-specific fields.

## Important limitations

IIS reverse proxying and actual Splunk indexing cannot be honestly marked as
passed until run inside the Windows/Splunk lab. The supplied IIS installer,
Universal Forwarder input, HEC support, field extraction, and saved searches are
deployment artifacts—not evidence of a completed Windows acceptance test.

Use `BURP_SUITE_TEST_GUIDE.md` for the lab acceptance run. Record the IIS host,
Splunk search job link, Burp request/response export, timestamp, tester, and
result for every case.

