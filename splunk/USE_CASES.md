# Splunk validation use cases

Run a command from [`OWASP_TOP10_TEST_COMMANDS.md`](../OWASP_TOP10_TEST_COMMANDS.md)
or the full [`tools/validate_range.sh`](../tools/validate_range.sh), then execute
the SPL below. Complete per-challenge detections, with MITRE mapping and
remediation, are in [`ASSESSMENT_PLAYBOOK.md`](../ASSESSMENT_PLAYBOOK.md).

## Is anything arriving?

```spl
index=vapt_lab sourcetype=helpag:owasp:json earliest=-15m
| stats count values(path) as paths by event_type severity source_ip
| sort - count
```

## Coverage check — did every category fire?

A full `validate_range.sh` run produces roughly 140 events across 35 distinct
`event_type` values. This search confirms the high-signal ones are present:

```spl
index=vapt_lab sourcetype=helpag:owasp:json earliest=-15m
| search event_type IN (
    recon_hidden_path, sensitive_file_access, directory_listing_access,
    debug_endpoint_access, broken_access_attempt, mass_assignment_attempt,
    privilege_change, sql_query, sql_error, xss_probe, stored_xss_persisted,
    path_traversal_attempt, command_injection_attempt, command_execution,
    ssti_attempt, xxe_attempt, dangerous_upload, authentication_attempt,
    brute_force_suspected, jwt_unsigned_accepted, forged_session_detected,
    account_takeover, ssrf_probe, business_logic_abuse, jndi_lookup_detected)
| stats count by event_type
| sort event_type
```

Twenty-five rows means full coverage. A missing row means either the test was
not run or the pipeline dropped it.

## Isolate one test run

Every request honours an `X-Lab-Test-ID` header:

```spl
index=vapt_lab sourcetype=helpag:owasp:json test_id="purple-run-2026-09-14"
| table _time source_ip event_type severity path
| sort _time
```

## Severity triage

```spl
index=vapt_lab sourcetype=helpag:owasp:json earliest=-1h severity IN (high,critical)
| stats count values(event_type) as events by source_ip severity
| sort - count
```

## Kill chain correlation — the highest-value search in the pack

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

A source touching three or more stages inside an hour is an intrusion, not a
scan. A vulnerability scanner generates enormous volume but rarely passes stage 2.

## CTF scoring telemetry

```spl
index=vapt_lab sourcetype=helpag:owasp:json event_type=ctf_flag_captured duplicate=false
| stats sum(points) as points values(challenge_title) as challenges
        values(mitre_techniques) as techniques by team source_ip
| sort - points
```

Correlate a team's captures with the exploit events from the same `source_ip` to
replay exactly how each flag was taken.

## IIS scanner rate

```spl
index=vapt_lab sourcetype=iis earliest=-15m
| bin _time span=1m
| stats count dc(cs_uri_stem) as unique_paths values(cs_User_Agent) as user_agents by _time c_ip
| where count>=30 OR unique_paths>=15
```

## Packaged alerts

[`TA-helpag-vapt/default/savedsearches.conf`](TA-helpag-vapt/default/savedsearches.conf)
contains 21 saved searches (UC-01 … UC-21), one per detection use case, all
shipped **disabled**. Validate the field mappings against your own data, tune the
thresholds to your range's traffic, then enable the ones your notification policy
allows.
