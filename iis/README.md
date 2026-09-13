# IIS deployment

This lab uses IIS as the front-end reverse proxy and Waitress on
`127.0.0.1:5005` as the Python application server. IIS produces standard W3C
access logs while the application produces structured JSON security events.

Prerequisites on Windows Server:

- Python 3.11 or newer, including the `py` launcher.
- IIS.
- IIS URL Rewrite 2 and Application Request Routing (ARR).
- A Splunk Universal Forwarder when IIS access logs should be shipped to Splunk.

From an elevated PowerShell prompt:

```powershell
git clone https://github.com/DrHayabusa/HELPAG-VAPT-Test-Site.git C:\Lab\HELPAG-VAPT-Test-Site
cd C:\Lab\HELPAG-VAPT-Test-Site
Set-ExecutionPolicy -Scope Process Bypass
.\iis\Install-IIS-LabSite.ps1 -IisPort 8080
Invoke-RestMethod http://localhost:8080/health
```

The installer creates an IIS site and a startup task for the localhost-only
Waitress backend. Do not create a public DNS record or Internet-facing firewall
rule for this intentionally vulnerable site.

