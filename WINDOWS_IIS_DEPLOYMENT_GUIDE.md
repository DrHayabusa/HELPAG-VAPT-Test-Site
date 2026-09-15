# Windows IIS deployment guide

End-to-end build of the Meridian Freight Solutions target on Windows Server, behind IIS,
with Splunk integration. Follow [`SPLUNK_INTEGRATION_GUIDE.md`](SPLUNK_INTEGRATION_GUIDE.md)
after step 6.

> **This host becomes intentionally vulnerable.** It has real OS command
> execution, real server-side template injection and real arbitrary file read.
> Build it on an isolated lab segment with no route to production and no
> Internet-facing rule. Do not domain-join it to a production domain.

---

## Architecture

```
   lab clients                Windows Server
        |
        |  http://<server>:8080
        v
   +----------+      rewrite      +---------------------------+
   |   IIS    | ----------------> | Waitress  127.0.0.1:5005  |  the app
   | ARR/URL  |                   +---------------------------+
   | Rewrite  |                                |
   +----------+                                | SSRF destination
        |                                      v
        | W3C access logs           +---------------------------+
        v                           | http.server 127.0.0.1:8081|  metadata service
   C:\inetpub\logs\LogFiles         +---------------------------+
        |                                      |
        |                   logs\meridian-events.jsonl (JSON security events)
        +--------------------+-----------------+
                             v
                    Splunk Universal Forwarder  ->  index=vapt_lab
```

Only IIS listens on a routable address. Both Python services bind to loopback.

---

## 1. Prerequisites

| Requirement | Notes |
|---|---|
| Windows Server 2019 or 2022 | 2 vCPU / 4 GB RAM is plenty |
| Python 3.11+ with the `py` launcher | Tick **Add Python to PATH** during install |
| Git for Windows | Or copy the repository across manually |
| IIS | The installer adds the required features |
| **URL Rewrite 2.1** | <https://www.iis.net/downloads/microsoft/url-rewrite> |
| **Application Request Routing 3.0** | <https://www.iis.net/downloads/microsoft/application-request-routing> |
| Splunk Universal Forwarder | Only if shipping logs — see the Splunk guide |

Install URL Rewrite **and** ARR before running the installer. Reboot afterwards
if the installer prompts for one; `Get-WebGlobalModule` will not see the modules
until IIS has restarted.

---

## 2. Clone the repository

From an **elevated** PowerShell prompt:

```powershell
New-Item -ItemType Directory -Force -Path C:\Lab | Out-Null
git clone https://github.com/DrHayabusa/HELPAG-VAPT-Test-Site.git C:\Lab\HELPAG-VAPT-Test-Site
Set-Location C:\Lab\HELPAG-VAPT-Test-Site
```

Keep the path short and free of spaces. Several findings read artifact files by
relative path from the repository root.

---

## 3. Run the installer

```powershell
Set-ExecutionPolicy -Scope Process Bypass -Force
.\iis\Install-IIS-LabSite.ps1 -IisPort 8080
```

To let other machines on the isolated lab segment reach the range, add
`-OpenFirewall`:

```powershell
.\iis\Install-IIS-LabSite.ps1 -IisPort 8080 -OpenFirewall
```

The installer performs eight steps and prints each one:

1. Installs IIS features (`Web-Server`, `Web-Http-Logging`, `Web-Mgmt-Tools`, `Web-Filtering`).
2. Verifies URL Rewrite and ARR are present.
3. Enables the ARR proxy, allows the rewrite rule to set `X-Forwarded-For`, and
   unlocks request filtering so `web.config` can relax it.
4. Creates `.venv` and installs `requirements.txt`.
5. Creates `logs\` and `uploads\`.
6. Creates the IIS app pool and site, and configures W3C logging with the fields
   the Splunk searches expect.
7. Registers two scheduled tasks that start at boot and restart on failure:
   - `HELPAG-VAPT-Test-Site` — the application on `127.0.0.1:5005`
   - `HELPAG-VAPT-Test-Site-Metadata` — the SSRF target on `127.0.0.1:8081`
8. Waits for `/health` and reports.

Expected final output:

```
HELP AG VAPT range installed: http://localhost:8080
Backend bound to 127.0.0.1:5005; metadata service to 127.0.0.1:8081. IIS is the only lab-facing listener.
```

---

## 4. Why the IIS configuration matters

Two settings in `iis/web.config` are not cosmetic:

**`X-Forwarded-For`.** Behind a reverse proxy every request reaches the backend
from `127.0.0.1`. Every Splunk detection in this pack groups by `source_ip`, so
without the forwarded header the whole detection pack sees one client and
becomes useless. The rewrite rule sets it and the application reads the first
entry in the chain.

**Relaxed request filtering.** IIS rejects `..`, double-encoded sequences and
unusual verbs with a 404 *before* the request reaches the backend. Left at the
defaults, the path traversal finding and several encoded payloads are
unsolvable and generate no telemetry. `allowDoubleEscaping="true"` and the
cleared `hiddenSegments` list deliberately let them through.

That second setting is a genuine weakening of IIS. It is correct for a range and
wrong for anything else.

---

## 5. Verify the deployment

```powershell
Invoke-RestMethod http://localhost:8080/health
```

Expected: `status healthy`, `lab_mode True`.

Then solve every challenge automatically:

```powershell
.\tools\Validate-Range.ps1 -BaseUrl http://localhost:8080 -MetadataPort 8081
```

Expected final line:

```
== 22 passed, 0 failed ==
```

Check the forwarded client address is arriving — this is the single most common
IIS misconfiguration for this range:

```powershell
Get-Content .\logs\meridian-events.jsonl -Tail 1 | ConvertFrom-Json | Select-Object source_ip, event_type
```

`source_ip` must be the **client's** address, not `127.0.0.1`. If it shows
`127.0.0.1`, see Troubleshooting below.

Browse to `http://<server>:8080/` from a lab client — you should get the Meridian
Freight Solutions homepage with no sign the host is a range. Confirm the operator
console separately at `http://<server>:8080/range/console?token=range-operator`;
the target site never links to it.

---

## 6. Day-to-day operations

### Start, stop, restart

```powershell
# Application backend
Start-ScheduledTask   -TaskName HELPAG-VAPT-Test-Site
Stop-ScheduledTask    -TaskName HELPAG-VAPT-Test-Site

# SSRF metadata service
Start-ScheduledTask   -TaskName HELPAG-VAPT-Test-Site-Metadata
Stop-ScheduledTask    -TaskName HELPAG-VAPT-Test-Site-Metadata

# IIS front end
Start-Website -Name HELPAG-VAPT-Test-Site
Stop-Website  -Name HELPAG-VAPT-Test-Site
Restart-WebAppPool -Name HELPAG-VAPT-Test-Site
```

### Reset the range between sessions

Clears the scoreboard, guestbook, uploads and event log. Proof values do not change.

```powershell
Stop-ScheduledTask -TaskName HELPAG-VAPT-Test-Site
Remove-Item .\logs\meridian.db, .\logs\meridian-events.jsonl -ErrorAction SilentlyContinue
Get-ChildItem .\uploads\ -Exclude .gitkeep | Remove-Item -Force
Start-ScheduledTask -TaskName HELPAG-VAPT-Test-Site
```

### Change the operator console token

The console at `/range/console` falls back to `range-operator`, which is
published in this repository. Before a live exercise set a Machine-scope
variable — the scheduled task runs as SYSTEM and picks it up on restart:

```powershell
[Environment]::SetEnvironmentVariable("RANGE_CONSOLE_TOKEN", "<your-token>", "Machine")
Stop-ScheduledTask  -TaskName HELPAG-VAPT-Test-Site
Start-ScheduledTask -TaskName HELPAG-VAPT-Test-Site
```

Pass the same value to the validator with `-ConsoleToken <your-token>`.

### Watch the range live

```powershell
Get-Content .\logs\meridian-events.jsonl -Wait -Tail 20 |
    ForEach-Object { $_ | ConvertFrom-Json | Select-Object timestamp, source_ip, event_type, severity }

Invoke-RestMethod http://localhost:8080/range/api/scoreboard -Headers @{ "X-Range-Token" = $env:RANGE_CONSOLE_TOKEN } |
    Select-Object -ExpandProperty teams | Format-Table rank, team, solves, points
```

### Update to a newer build

```powershell
Stop-ScheduledTask -TaskName HELPAG-VAPT-Test-Site
git pull
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
Start-ScheduledTask -TaskName HELPAG-VAPT-Test-Site
.\tools\Validate-Range.ps1 -BaseUrl http://localhost:8080 -MetadataPort 8081
```

---

## 7. Windows-specific challenge differences

Two challenges need different payloads under `cmd.exe`. Both are noted in
[`ASSESSMENT_PLAYBOOK.md`](ASSESSMENT_PLAYBOOK.md); tell players if you are running a
Windows range.

| Challenge | Linux payload | Windows payload |
|---|---|---|
| `rce-cmdi` | `host=127.0.0.1; cat instance/keys/depot-transfer.key` | `host=127.0.0.1 & type instance\keys\depot-transfer.key` |
| `rce-ssti` | `os.popen('cat instance/keys/campaign-signing.key').read()` | `__builtins__.open('instance/keys/campaign-signing.key').read()` |

`cmd.exe` chains with `&`, not `;`, and its `type` command rejects forward
slashes. The SSTI payload avoids the shell entirely and works on both platforms.
The application selects the correct `ping` flags for the platform automatically.

---

## 8. Troubleshooting

### `source_ip` is `127.0.0.1` for every event

The rewrite rule is not setting the forwarded header. Confirm the server
variable is allowed:

```powershell
& $env:windir\System32\inetsrv\appcmd.exe list config `
  -section:system.webServer/rewrite/allowedServerVariables
```

`HTTP_X_FORWARDED_FOR` must appear. If it does not:

```powershell
& $env:windir\System32\inetsrv\appcmd.exe set config `
  -section:system.webServer/rewrite/allowedServerVariables `
  /+"[name='HTTP_X_FORWARDED_FOR']" /commit:apphost
iisreset
```

### 502.3 or 500.52 from IIS

ARR is not installed or the proxy is disabled:

```powershell
& $env:windir\System32\inetsrv\appcmd.exe set config -section:system.webServer/proxy /enabled:"True" /commit:apphost
iisreset
```

### 503 with `"Lab mode is disabled"`

The backend is running without `LAB_MODE=true`. That is the safety guard, not a
bug. Restart through the scheduled task rather than by hand — `Start-LabSite.ps1`
sets the variable:

```powershell
Start-ScheduledTask -TaskName HELPAG-VAPT-Test-Site
```

### Path traversal challenge returns 404 from IIS, not the app

Request filtering is still blocking `..`. Confirm `web.config` is in the site's
physical path (`C:\Lab\HELPAG-VAPT-Test-Site\iis`) and that the section is
unlocked:

```powershell
& $env:windir\System32\inetsrv\appcmd.exe unlock config -section:system.webServer/security/requestFiltering
iisreset
```

### The SSRF challenge fails

The metadata service is not running. Check and restart:

```powershell
Invoke-WebRequest http://127.0.0.1:8081/latest/meta-data/ -UseBasicParsing
Start-ScheduledTask -TaskName HELPAG-VAPT-Test-Site-Metadata
```

Players must target the port the service is actually on — pass
`-MetadataPort` to the validator to match.

### The backend will not start

Run it in the foreground to see the error:

```powershell
Stop-ScheduledTask -TaskName HELPAG-VAPT-Test-Site
.\iis\Start-LabSite.ps1
```

A `lxml` build failure means pip could not fetch a wheel; confirm the server can
reach PyPI, or install `lxml` from a local wheel.

### Nothing is reaching the site from other lab hosts

The firewall rule was not created. Either rerun the installer with
`-OpenFirewall` or add it manually:

```powershell
New-NetFirewallRule -DisplayName "HELPAG lab" -Direction Inbound -Protocol TCP `
  -LocalPort 8080 -Action Allow -Profile Domain,Private
```

---

## 9. Uninstall

```powershell
Stop-Website -Name HELPAG-VAPT-Test-Site
Remove-Website -Name HELPAG-VAPT-Test-Site
Remove-WebAppPool -Name HELPAG-VAPT-Test-Site
Unregister-ScheduledTask -TaskName HELPAG-VAPT-Test-Site -Confirm:$false
Unregister-ScheduledTask -TaskName HELPAG-VAPT-Test-Site-Metadata -Confirm:$false
Remove-NetFirewallRule -DisplayName "HELPAG-VAPT-Test-Site (lab only)" -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force C:\Lab\HELPAG-VAPT-Test-Site
```

Rebuild the VM if you want to be certain nothing from the range persists.

---

Next: [`SPLUNK_INTEGRATION_GUIDE.md`](SPLUNK_INTEGRATION_GUIDE.md).
