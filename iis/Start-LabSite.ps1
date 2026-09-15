<#
.SYNOPSIS
    Starts the CTF application on 127.0.0.1:5005 under Waitress.

.DESCRIPTION
    IIS reverse-proxies to this backend. The backend never binds to a routable
    address - IIS is the only lab-facing listener.
#>
param(
    [string]$RepositoryPath = (Split-Path -Parent $PSScriptRoot)
)

$ErrorActionPreference = "Stop"
$venvPython = Join-Path $RepositoryPath ".venv\Scripts\python.exe"
$logDirectory = Join-Path $RepositoryPath "logs"
$uploadDirectory = Join-Path $RepositoryPath "uploads"

if (-not (Test-Path $venvPython)) {
    throw "Python environment not found. Run Install-IIS-LabSite.ps1 first."
}

New-Item -ItemType Directory -Force -Path $logDirectory | Out-Null
New-Item -ItemType Directory -Force -Path $uploadDirectory | Out-Null

$env:LAB_MODE       = "true"
$env:LAB_HOST       = "127.0.0.1"
$env:LAB_PORT       = "5005"
$env:LAB_DATABASE   = Join-Path $logDirectory "meridian.db"
$env:LAB_EVENT_LOG  = Join-Path $logDirectory "meridian-events.jsonl"
$env:LAB_UPLOAD_DIR = $uploadDirectory

# Deliberately weak - findings weak-session-secret and jwt-none expect a
# tester to recover these from the estate. They must match the values the site
# leaks through /.env and instance\app-secrets.ini, or those findings break.
if (-not $env:LAB_SESSION_SECRET) { $env:LAB_SESSION_SECRET = "meridian-default-signing-key" }
if (-not $env:LAB_JWT_KEY)        { $env:LAB_JWT_KEY = "mfs-partner-hs256" }

# Splunk HEC (optional). Set these as Machine-scope variables; see splunk\README.md.
if ($env:SPLUNK_HEC_URL) {
    Write-Host "Splunk HEC configured: $env:SPLUNK_HEC_URL"
}

# Working directory matters: the traversal, SSTI and command-injection
# challenges read flag files by relative path.
Set-Location $RepositoryPath
# --trusted-proxy is not optional behind IIS. Waitress strips X-Forwarded-*
# from every request unless the proxy is declared trusted, so without it the
# app falls back to REMOTE_ADDR and records 127.0.0.1 as the source_ip for
# every tester - which makes every Splunk detection in the pack useless.
& $venvPython -m waitress --listen=127.0.0.1:5005 `
    --trusted-proxy=127.0.0.1 `
    --trusted-proxy-headers=x-forwarded-for `
    app:app
