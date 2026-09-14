# Windows Server IIS deployment guide

This guide deploys the intentionally vulnerable HELPAG site behind IIS for an
isolated, authorized lab. Never publish this site to the Internet or bridge it
to a production network.

## Architecture

```text
Burp / VAPT VM ---> http://WINDOWS_LAB_IP:8080 (IIS)
                                      |
                                      v
                         127.0.0.1:5005 (Waitress/Flask)
                                      |
                           JSONL events + IIS W3C logs
                                      |
                                      v
                              Splunk Forwarder/HEC
```

IIS is the only lab-facing listener. The Python backend binds to localhost.

## 1. Prepare the Windows Server

Install:

- Git for Windows.
- Python 3.11 or newer with the `py` launcher and `pip`.
- IIS (the included script enables its base role).
- Microsoft IIS URL Rewrite 2.
- IIS Application Request Routing (ARR).
- Splunk Universal Forwarder if this server will forward local log files.

Use an isolated VM snapshot. Give the server a static private lab IP and block
inbound traffic except from the VAPT/Burp and Splunk hosts. Port 5005 must never
be opened in Windows Firewall.

## 2. Clone and deploy

Open **PowerShell as Administrator**:

```powershell
New-Item -ItemType Directory -Force C:\Lab | Out-Null
git clone https://github.com/DrHayabusa/HELPAG-VAPT-Test-Site.git C:\Lab\HELPAG-VAPT-Test-Site
Set-Location C:\Lab\HELPAG-VAPT-Test-Site
Set-ExecutionPolicy -Scope Process Bypass
.\iis\Install-IIS-LabSite.ps1 -IisPort 8080
```

The installer enables IIS and logging, creates the Python environment, installs
dependencies, creates the IIS site, and registers a startup task for the local
Waitress backend. No real credentials or production data are required.

## 3. Validate the deployment

```powershell
Invoke-RestMethod http://localhost:8080/health
Get-Website -Name HELPAG-VAPT-Test-Site
Get-ScheduledTask -TaskName HELPAG-VAPT-Test-Site
Get-NetTCPConnection -LocalPort 8080,5005 -State Listen
```

Expected health response is `{"lab_mode":true,"status":"healthy"}`. Waitress
must listen on `127.0.0.1:5005` only. From the VAPT VM run:

```bash
curl -i http://WINDOWS_LAB_IP:8080/health
```

Do not continue until this succeeds and the lab firewall blocks unapproved
source networks.

## 4. Add Splunk

Follow `splunk/README.md`. The required inputs are IIS W3C logs with sourcetype
`iis` and `logs\helpag-events.jsonl` with sourcetype `helpag:owasp:json`. Create
the `vapt_lab` index first and validate `splunk/USE_CASES.md`. Add a unique
`X-Lab-Test-ID` header to every Burp request.

## 5. Test with Burp and VAPT Agent

1. Add only `http://WINDOWS_LAB_IP:8080` to Burp scope.
2. Follow `BURP_SUITE_TEST_GUIDE.md` for the manual OWASP Top 10 cases.
3. Follow `OWASP_TOP10_TEST_COMMANDS.md` for repeatable CLI requests.
4. In VAPT Agent, analyze the same IIS URL before any active scan.
5. Confirm authorization and the test window in **Integration hub**.
6. Keep concurrency low and exclude denial-of-service checks.
7. Confirm every `X-Lab-Test-ID` appears in Splunk.

## 6. Troubleshooting

If IIS returns 502:

```powershell
Get-ScheduledTaskInfo -TaskName HELPAG-VAPT-Test-Site
Start-ScheduledTask -TaskName HELPAG-VAPT-Test-Site
Invoke-RestMethod http://127.0.0.1:5005/health
```

If URL Rewrite fails, install URL Rewrite 2 and ARR, run `iisreset`, and rerun
the installer. If Python fails:

```powershell
py -3 --version
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

If Splunk has no events, check the source first:

```powershell
Get-Content .\logs\helpag-events.jsonl -Tail 10
```

## 7. Stop the lab

```powershell
Stop-Website -Name HELPAG-VAPT-Test-Site
Stop-ScheduledTask -TaskName HELPAG-VAPT-Test-Site
```

Preserve Burp exports, IIS logs, JSONL events, and Splunk searches with the
engagement record before reverting the VM snapshot.

