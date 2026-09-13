# Splunk integration

The site writes newline-delimited JSON to `logs/owasp-events.jsonl`. IIS writes
W3C access logs under `C:\inetpub\logs\LogFiles`. Send both to the `vapt_lab`
index with a Splunk Universal Forwarder, or send application events directly
through HTTP Event Collector (HEC).

## Universal Forwarder method (recommended for IIS)

1. Create the `vapt_lab` index in Splunk.
2. Install a Universal Forwarder on the IIS server and configure its receiving
   indexer or deployment server.
3. Copy `universal-forwarder/inputs.conf.example` to
   `$SPLUNK_HOME\etc\system\local\inputs.conf` and correct the clone path.
4. Copy `TA-helpag-vapt` to `$SPLUNK_HOME\etc\apps\TA-helpag-vapt` on the
   parsing tier/search head as appropriate for your Splunk topology.
5. Restart Splunk/Universal Forwarder and verify:

```spl
index=vapt_lab (sourcetype=iis OR sourcetype=helpag:owasp:json)
| stats count by sourcetype
```

## Direct HEC method

Create an enabled HEC token restricted to the `vapt_lab` index. Set these
variables for the backend service:

```powershell
[Environment]::SetEnvironmentVariable("SPLUNK_HEC_URL", "https://splunk.lab:8088/services/collector/event", "Machine")
[Environment]::SetEnvironmentVariable("SPLUNK_HEC_TOKEN", "REPLACE_ME", "Machine")
[Environment]::SetEnvironmentVariable("SPLUNK_INDEX", "vapt_lab", "Machine")
[Environment]::SetEnvironmentVariable("SPLUNK_SOURCETYPE", "helpag:owasp:json", "Machine")
```

Restart the scheduled task after setting the variables. Do not enable both HEC
and file monitoring for application JSON unless duplicate events are desired.

