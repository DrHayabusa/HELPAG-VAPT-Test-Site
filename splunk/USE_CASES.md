# Splunk validation use cases

Run the associated command from `OWASP_TOP10_TEST_COMMANDS.md`, then execute the
SPL below over the last 15 minutes.

```spl
index=vapt_lab sourcetype=helpag:owasp:json earliest=-15m
| stats count values(path) as paths by event_type severity source_ip
| sort - count
```

Coverage check:

```spl
index=vapt_lab sourcetype=helpag:owasp:json earliest=-15m
| search event_type IN (broken_access_attempt,sensitive_data_exposure,sql_query,xss_probe,business_logic_abuse,debug_endpoint_access,outdated_component_inventory,authentication_attempt,unsigned_data_import,monitoring_gap_simulated,ssrf_probe)
| stats count by event_type
```

IIS scanner-rate use case:

```spl
index=vapt_lab sourcetype=iis earliest=-15m
| bin _time span=1m
| stats count dc(cs_uri_stem) as unique_paths values(cs_User_Agent) as user_agents by _time c_ip
| where count>=30 OR unique_paths>=15
```

The packaged `TA-helpag-vapt/default/savedsearches.conf` contains disabled saved
searches for each OWASP category. Validate the field mappings first, then enable
scheduled alerts in Splunk Web according to your lab's notification policy.

