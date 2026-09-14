# Splunk integration guide

Connecting the Meridian target to a Splunk lab: index, ingestion, field
extraction, verification, and turning on the 21 detection use cases.

Assumes the range is already deployed — see
[`WINDOWS_IIS_DEPLOYMENT_GUIDE.md`](WINDOWS_IIS_DEPLOYMENT_GUIDE.md) for IIS or
[`README.md`](README.md) for Docker.

---

## 1. What the range produces

| Source | Sourcetype | Content |
|---|---|---|
| `logs\meridian-events.jsonl` | `helpag:owasp:json` | Structured security events — one JSON object per line |
| `C:\inetpub\logs\LogFiles\W3SVC*\u_ex*.log` | `iis` | W3C access logs (IIS deployments only) |

A full validation run produces roughly **145 events across 34 distinct
`event_type` values**. Every event carries these correlation fields:

```json
{
  "timestamp": "2026-09-14T15:25:23.481903+00:00",
  "event_type": "command_execution",
  "severity": "critical",
  "app": "helpag-ctf-lab",
  "source_ip": "10.10.5.42",
  "method": "GET",
  "path": "/api/diagnostics/ping",
  "user_agent": "curl/8.4.0",
  "referer": "",
  "test_id": "purple-run-1",
  "team": "red-team-1",
  "command_line": "ping -c 1 -W 1 127.0.0.1; cat flagstore/cmdi.flag",
  "exit_code": 0
}
```

`source_ip`, `test_id` and `team` are what make this useful: they let you group a
whole attack chain by attacker, by test run, or by CTF team.

---

## 2. Choose one ingestion method

**Do not enable both.** Every event would be indexed twice and every
count-based alert threshold would be wrong.

| | Universal Forwarder | HTTP Event Collector |
|---|---|---|
| Ships IIS logs too | **Yes** | No |
| Survives Splunk being down | Yes (file is the buffer) | No (events are dropped, logged as a warning) |
| Needs an agent on the range | Yes | No |
| Best for | **IIS deployments** | Docker, or a quick proof of concept |

For a Windows/IIS lab, use the Universal Forwarder — you want the IIS access
logs for the scanner-rate and volume use cases.

---

## 3. Splunk server setup (both methods)

### 3.1 Create the index

Splunk Web → **Settings → Indexes → New Index**, name `vapt_lab`.

Or from the CLI on the indexer:

```bash
$SPLUNK_HOME/bin/splunk add index vapt_lab -auth admin:<password>
```

### 3.2 Install the TA

Copy `splunk/TA-helpag-vapt` from the repository to:

```
$SPLUNK_HOME/etc/apps/TA-helpag-vapt
```

Deploy it to **the search head** (for the saved searches and macros) **and to
whichever tier parses the data**:

| Ingestion | TA must be installed on |
|---|---|
| Universal Forwarder | search head, indexer, **and the forwarder** |
| HEC | search head and indexer |

> **This is the step people get wrong.** `INDEXED_EXTRACTIONS = json` is a
> parsing-time setting. For file-monitored data, parsing happens on the
> forwarder. If the TA is only on the search head, events arrive as raw text with
> no extracted fields and every detection silently matches nothing.

Restart Splunk on each tier you copied it to.

---

## 4. Method A — Universal Forwarder (recommended for IIS)

### 4.1 Install the forwarder on the range host

Download the Universal Forwarder for Windows and install it, then point it at
your indexer:

```powershell
$splunk = "$env:ProgramFiles\SplunkUniversalForwarder\bin\splunk.exe"
& $splunk add forward-server splunk.lab.invalid:9997 -auth admin:<password>
```

### 4.2 Configure the inputs

Copy the example inputs file into the TA's `local` directory on the forwarder:

```powershell
$ta = "$env:ProgramFiles\SplunkUniversalForwarder\etc\apps\TA-helpag-vapt"
New-Item -ItemType Directory -Force -Path "$ta\local" | Out-Null
Copy-Item C:\Lab\HELPAG-VAPT-Test-Site\splunk\universal-forwarder\inputs.conf.example `
          "$ta\local\inputs.conf"
```

Edit `$ta\local\inputs.conf` if you cloned somewhere other than `C:\Lab`. It
monitors both sources:

```ini
[monitor://C:\inetpub\logs\LogFiles\W3SVC*\u_ex*.log]
disabled = 0
index = vapt_lab
sourcetype = iis

[monitor://C:\Lab\HELPAG-VAPT-Test-Site\logs\meridian-events.jsonl]
disabled = 0
index = vapt_lab
sourcetype = helpag:owasp:json
```

### 4.3 Grant the forwarder read access

The forwarder runs as Local System by default and can read both paths. If you
changed it to a service account, grant that account read on
`C:\Lab\HELPAG-VAPT-Test-Site\logs` and `C:\inetpub\logs\LogFiles`.

### 4.4 Restart

```powershell
& "$env:ProgramFiles\SplunkUniversalForwarder\bin\splunk.exe" restart
```

---

## 5. Method B — HTTP Event Collector

### 5.1 Create the token

Splunk Web → **Settings → Data inputs → HTTP Event Collector → New Token**

- Name: `helpag-vapt-range`
- Source type: `helpag:owasp:json`
- Index: `vapt_lab`
- Then **Global Settings → All Tokens → Enabled**

### 5.2 Point the range at it

**Docker** — in `.env`:

```bash
SPLUNK_HEC_URL=https://splunk.lab.invalid:8088/services/collector
SPLUNK_HEC_TOKEN=<your token>
SPLUNK_INDEX=vapt_lab
SPLUNK_SOURCETYPE=helpag:owasp:json
SPLUNK_VERIFY_TLS=false
```

```bash
docker compose up -d
```

**Windows/IIS** — set machine-scope variables, then restart the task:

```powershell
[Environment]::SetEnvironmentVariable("SPLUNK_HEC_URL","https://splunk.lab.invalid:8088/services/collector","Machine")
[Environment]::SetEnvironmentVariable("SPLUNK_HEC_TOKEN","<your token>","Machine")
[Environment]::SetEnvironmentVariable("SPLUNK_INDEX","vapt_lab","Machine")
[Environment]::SetEnvironmentVariable("SPLUNK_SOURCETYPE","helpag:owasp:json","Machine")
[Environment]::SetEnvironmentVariable("SPLUNK_VERIFY_TLS","false","Machine")

Stop-ScheduledTask  -TaskName HELPAG-VAPT-Test-Site
Start-ScheduledTask -TaskName HELPAG-VAPT-Test-Site
```

`SPLUNK_VERIFY_TLS=false` accepts the self-signed certificate typical of a lab
Splunk. Set it to `true` with a proper CA anywhere else.

HEC delivery is best-effort: if Splunk is unreachable the event is still written
to the local JSONL file and a warning is logged. It is never retried.

---

## 6. Generate data and verify

Run the full validation harness — it solves all 22 challenges and exercises
every detection at once:

```powershell
.\tools\Validate-Range.ps1 -BaseUrl http://localhost:8080 -MetadataPort 8081 -TestId splunk-onboarding
```

```bash
./tools/validate_range.sh http://127.0.0.1:5005      # Linux/Docker
```

### 6.1 Is anything arriving?

```spl
index=vapt_lab earliest=-15m | stats count by sourcetype
```

Both `helpag:owasp:json` and (on IIS) `iis` should appear.

### 6.2 Did fields extract?

This is the check that catches a misplaced TA:

```spl
index=vapt_lab sourcetype=helpag:owasp:json earliest=-15m
| stats count by event_type severity
| sort - count
```

If `event_type` is missing or shows as `NULL`, the TA is not on the parsing
tier. Revisit section 3.2.

### 6.3 Is the client IP correct?

```spl
index=vapt_lab sourcetype=helpag:owasp:json earliest=-15m
| stats count by source_ip
```

On an IIS deployment this must show real client addresses. If everything is
`127.0.0.1`, the `X-Forwarded-For` rewrite is not working — see the
troubleshooting section of the IIS guide.

### 6.4 Coverage check

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
| stats count by event_type | sort event_type
```

**25 rows means full coverage.** Fewer means either the test did not run or the
pipeline dropped something.

### 6.5 Isolate one run

```spl
index=vapt_lab sourcetype=helpag:owasp:json test_id="splunk-onboarding"
| table _time source_ip event_type severity path | sort _time
```

---

## 7. Turn on the detections

All 21 use cases ship in `TA-helpag-vapt/default/savedsearches.conf` with
`enableSched = 0` — **disabled deliberately**. Do not bulk-enable them.

### 7.1 Validate before enabling

For each search, run its SPL manually over a window that contains a known attack
and confirm it returns the rows you expect. The fields referenced in the pack
(`event_type`, `source_ip`, `suspicious`, `algorithm`, `dangerous`,
`negative_total`, …) come from the JSON and will only exist if section 6.2 passed.

### 7.2 Enable selectively

Splunk Web → **Settings → Searches, reports and alerts** → filter by `HELPAG` →
**Edit → Enable** on the ones you want, and attach your notification action.

Start with the high-fidelity ones, which have essentially no benign case:

| UC | Why start here |
|---|---|
| **UC-09** Command Injection and Execution | Shell metacharacters reaching a shell |
| **UC-14** Unsigned or Forged Token Accepted | `alg=none` is never legitimate |
| **UC-18** JNDI Lookup String | Log4Shell syntax in a header |
| **UC-08** Path Traversal | Real traffic does not contain `../` |
| **UC-21** Kill Chain Correlation | The one to take to a SOC review |

Leave the volume-based ones (**UC-01** Hidden Path Discovery, **UC-13** Brute
Force) disabled until you have tuned their thresholds against your own range
traffic — defaults are a starting point, not a recommendation.

### 7.3 Tune the thresholds

Run a vulnerability scanner against the range and compare:

```bash
nuclei -u http://<server>:8080 -severity low,medium,high,critical
```

A scanner floods stages 1–2 of UC-21 and rarely reaches stage 3. A human working
through `ASSESSMENT_PLAYBOOK.md` moves cleanly through all four. If your alerting cannot
separate those two, that is your finding — and the most valuable output of this
whole lab.

---

## 8. Searches worth saving

### Attacker summary

```spl
index=vapt_lab sourcetype=helpag:owasp:json earliest=-24h
| stats count dc(event_type) as techniques values(event_type) as events
        min(_time) as first_seen max(_time) as last_seen by source_ip
| where techniques>=3
| convert ctime(first_seen) ctime(last_seen)
| sort - techniques
```

### Kill chain correlation (UC-21)

```spl
index=vapt_lab sourcetype=helpag:owasp:json
| `helpag_kill_chain_stage`
| search stage=*
| stats dc(stage) as stages values(stage) as observed values(event_type) as events
        min(_time) as first max(_time) as last by source_ip
| where stages>=3
```

### CTF scoring correlated with technique

```spl
index=vapt_lab sourcetype=helpag:owasp:json event_type=ctf_flag_captured duplicate=false
| stats sum(points) as points values(challenge_title) as challenges
        values(mitre_techniques) as techniques by team source_ip
| sort - points
```

### IIS scanner rate

```spl
index=vapt_lab sourcetype=iis earliest=-15m
| bin _time span=1m
| stats count dc(cs_uri_stem) as unique_paths values(cs_User_Agent) as user_agents by _time c_ip
| where count>=30 OR unique_paths>=15
```

### Correlate the web event with the host process

If you also collect Windows Security / Sysmon from the range host, this is the
exercise worth doing — proving the application-layer detection and the host
telemetry describe the same action:

```spl
index=vapt_lab sourcetype=helpag:owasp:json event_type=command_execution
| eval window=_time
| append [ search index=windows (EventCode=4688 OR source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational")
           ParentImage="*python.exe" ]
| sort _time
| table _time source_ip event_type command_line ParentImage NewProcessName
```

---

## 9. Troubleshooting

### No events at all

```spl
index=_internal sourcetype=splunkd component=TailReader OR component=WatchedFile
| search "meridian-events" | tail 20
```

Check the forwarder is connected:

```powershell
& "$env:ProgramFiles\SplunkUniversalForwarder\bin\splunk.exe" list forward-server
```

### Events arrive but have no fields

The TA is not on the parsing tier. See section 3.2 — for file monitoring it must
be on the **forwarder**. Confirm what Splunk actually applied:

```spl
index=vapt_lab sourcetype=helpag:owasp:json | head 1 | table _raw
```

If `_raw` is a JSON blob and no `event_type` field exists alongside it,
`INDEXED_EXTRACTIONS` never ran.

### Timestamps are wrong or events cluster at index time

The application writes ISO-8601 UTC with microseconds. Confirm
`TIMESTAMP_FIELDS = timestamp` and `TIME_FORMAT` in `props.conf` reached the
parsing tier. IIS writes UTC — the `[iis]` stanza sets `TZ = UTC` to match.

### Every event is duplicated

Both HEC and the file monitor are enabled. Turn one off (section 2).

### `source_ip` is always `127.0.0.1`

IIS is not forwarding the client address. See the IIS guide's troubleshooting
section — this breaks every detection in the pack.

### HEC returns 403

The token is disabled, not allowed to write to `vapt_lab`, or HEC itself is
globally disabled. Test it directly:

```bash
curl -k https://splunk.lab.invalid:8088/services/collector \
  -H 'Authorization: Splunk <token>' \
  -d '{"event":"test","sourcetype":"helpag:owasp:json","index":"vapt_lab"}'
```

Expected: `{"text":"Success","code":0}`.

---

## 10. Reference

| File | Contents |
|---|---|
| `splunk/TA-helpag-vapt/default/props.conf` | Field extraction for both sourcetypes |
| `splunk/TA-helpag-vapt/default/savedsearches.conf` | 21 detection use cases, all disabled |
| `splunk/TA-helpag-vapt/default/macros.conf` | Search shorthands used in the docs |
| `splunk/universal-forwarder/inputs.conf.example` | Monitor stanzas for both sources |
| [`splunk/USE_CASES.md`](splunk/USE_CASES.md) | Validation searches |
| [`ASSESSMENT_PLAYBOOK.md`](ASSESSMENT_PLAYBOOK.md) | Per-challenge SPL, MITRE mapping, remediation |
