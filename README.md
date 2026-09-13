# HELPAG VAPT Test Site

An intentionally vulnerable OWASP Top 10 training target for an isolated lab.
It includes a web interface, structured JSON events, optional Splunk HEC output,
IIS reverse-proxy deployment, Splunk detection content, and repeatable test
commands.

> **Warning:** Never expose this application to the public Internet or place it
> on a production network. All identities, tokens, and secrets in the app are
> synthetic training data.

## Windows IIS deployment

```powershell
git clone https://github.com/DrHayabusa/HELPAG-VAPT-Test-Site.git C:\Lab\HELPAG-VAPT-Test-Site
cd C:\Lab\HELPAG-VAPT-Test-Site
Set-ExecutionPolicy -Scope Process Bypass
.\iis\Install-IIS-LabSite.ps1 -IisPort 8080
Invoke-RestMethod http://localhost:8080/health
```

IIS URL Rewrite 2 and Application Request Routing are required. IIS listens on
the lab port and reverse-proxies to a Waitress backend bound only to
`127.0.0.1:5005`.

## Docker deployment

```bash
cp .env.example .env
docker compose up --build -d
curl http://127.0.0.1:5005/health
```

## Direct Python development

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
LAB_MODE=true .venv/bin/python app.py
```

## Splunk and testing

- `splunk/README.md` — HEC and Universal Forwarder setup.
- `splunk/USE_CASES.md` — validation searches.
- `splunk/TA-helpag-vapt` — field extraction and disabled saved searches.
- `OWASP_TOP10_TEST_COMMANDS.md` — safe commands for every training use case.

The application refuses normal requests unless `LAB_MODE=true`.

