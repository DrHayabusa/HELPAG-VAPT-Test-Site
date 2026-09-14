param(
    [string]$RepositoryPath = (Split-Path -Parent $PSScriptRoot)
)

$ErrorActionPreference = "Stop"
$venvPython = Join-Path $RepositoryPath ".venv\Scripts\python.exe"
$logDirectory = Join-Path $RepositoryPath "logs"

if (-not (Test-Path $venvPython)) {
    throw "Python environment not found. Run Install-IIS-LabSite.ps1 first."
}

New-Item -ItemType Directory -Force -Path $logDirectory | Out-Null
$env:LAB_MODE = "true"
$env:LAB_HOST = "127.0.0.1"
$env:LAB_PORT = "5005"
$env:LAB_DATABASE = Join-Path $logDirectory "ctf_lab.db"
$env:LAB_EVENT_LOG = Join-Path $logDirectory "helpag-events.jsonl"

Set-Location $RepositoryPath
& $venvPython -m waitress --listen=127.0.0.1:5005 app:app

