param(
    [string]$SiteName = "HELPAG-VAPT-Test-Site",
    [int]$IisPort = 8080,
    [string]$RepositoryPath = (Split-Path -Parent $PSScriptRoot)
)

$ErrorActionPreference = "Stop"
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this script from an elevated PowerShell window."
}

Import-Module ServerManager
Install-WindowsFeature Web-Server, Web-Http-Logging, Web-Mgmt-Tools | Out-Null
Import-Module WebAdministration

if (-not (Get-WebGlobalModule -Name RewriteModule -ErrorAction SilentlyContinue)) {
    throw "IIS URL Rewrite 2 is required. Install URL Rewrite and Application Request Routing, then rerun this script."
}

$appcmd = Join-Path $env:windir "System32\inetsrv\appcmd.exe"
& $appcmd set config -section:system.webServer/proxy /enabled:"True" /commit:apphost | Out-Null

if (-not (Get-Command py -ErrorAction SilentlyContinue)) {
    throw "Python 3.11+ with the Windows py launcher is required."
}

Set-Location $RepositoryPath
& py -3 -m venv .venv
& .\.venv\Scripts\python.exe -m pip install --upgrade pip
& .\.venv\Scripts\python.exe -m pip install -r requirements.txt
New-Item -ItemType Directory -Force -Path (Join-Path $RepositoryPath "logs") | Out-Null

$iisPath = Join-Path $RepositoryPath "iis"
if (-not (Test-Path "IIS:\AppPools\$SiteName")) {
    New-WebAppPool -Name $SiteName | Out-Null
}
Set-ItemProperty "IIS:\AppPools\$SiteName" -Name managedRuntimeVersion -Value ""

if (Test-Path "IIS:\Sites\$SiteName") {
    Remove-Website -Name $SiteName
}
New-Website -Name $SiteName -PhysicalPath $iisPath -Port $IisPort -ApplicationPool $SiteName | Out-Null

$starter = Join-Path $PSScriptRoot "Start-LabSite.ps1"
$action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$starter`" -RepositoryPath `"$RepositoryPath`""
$trigger = New-ScheduledTaskTrigger -AtStartup
$settings = New-ScheduledTaskSettingsSet -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
Register-ScheduledTask -TaskName $SiteName -Action $action -Trigger $trigger -Settings $settings -User "SYSTEM" -RunLevel Highest -Force | Out-Null
Start-ScheduledTask -TaskName $SiteName
Start-Website -Name $SiteName

Write-Host "HELPAG lab site installed: http://localhost:$IisPort"
Write-Host "Backend is bound only to 127.0.0.1:5005; IIS is the lab-facing endpoint."

