# Splunk content

Full setup instructions live in
[`SPLUNK_INTEGRATION_GUIDE.md`](../SPLUNK_INTEGRATION_GUIDE.md) — index creation,
Universal Forwarder vs HEC, TA placement, verification and alert enablement.

This directory contains the content itself:

| Path | Contents |
|---|---|
| `TA-helpag-vapt/default/props.conf` | Field extraction for `helpag:owasp:json` and `iis` |
| `TA-helpag-vapt/default/savedsearches.conf` | 21 detection use cases (UC-01 … UC-21), all shipped **disabled** |
| `TA-helpag-vapt/default/macros.conf` | Search shorthands used throughout the documentation |
| `universal-forwarder/inputs.conf.example` | Monitor stanzas for the app events and IIS logs |
| [`USE_CASES.md`](USE_CASES.md) | Validation searches to run after a test |

## The one thing to get right

`INDEXED_EXTRACTIONS = json` is a **parsing-time** setting. For file-monitored
data, parsing happens on the forwarder — so the TA must be installed on the
Universal Forwarder as well as the search head. Install it only on the search
head and events arrive as raw text with no fields, and every detection silently
matches nothing.

## Quick verification

```spl
index=vapt_lab earliest=-15m | stats count by sourcetype
index=vapt_lab sourcetype=helpag:owasp:json earliest=-15m | stats count by event_type severity
```

If `event_type` does not exist as a field, revisit TA placement above.
