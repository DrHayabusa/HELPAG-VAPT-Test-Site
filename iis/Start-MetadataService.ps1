<#
.SYNOPSIS
    Serves the synthetic instance-metadata tree on 127.0.0.1:8080.

.DESCRIPTION
    The SSRF challenge (ssrf-metadata) needs an internal HTTP service to reach.
    Under Docker that is the `metadata` container; on IIS this scheduled task
    fills the same role. It binds to loopback only and serves static files from
    the repository's metadata\ folder - nothing else.
#>
param(
    [string]$RepositoryPath = (Split-Path -Parent $PSScriptRoot),
    [int]$Port = 8080
)

$ErrorActionPreference = "Stop"
$venvPython = Join-Path $RepositoryPath ".venv\Scripts\python.exe"
$metadataPath = Join-Path $RepositoryPath "metadata"

if (-not (Test-Path $venvPython)) {
    throw "Python environment not found. Run Install-IIS-LabSite.ps1 first."
}
if (-not (Test-Path $metadataPath)) {
    throw "metadata\ folder not found at $metadataPath."
}

& $venvPython -m http.server $Port --bind 127.0.0.1 --directory $metadataPath
