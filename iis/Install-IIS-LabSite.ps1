<#
.SYNOPSIS
    Installs the HELP AG VAPT CTF range behind IIS on Windows Server.

.DESCRIPTION
    IIS is the only lab-facing listener. It reverse-proxies to a Waitress
    backend on 127.0.0.1:5005 and to a loopback metadata service on
    127.0.0.1:8080 that the SSRF challenge targets.

    Run from an elevated PowerShell prompt.

.PARAMETER IisPort
    Port IIS listens on. Default 8080.

.PARAMETER OpenFirewall
    Also create an inbound firewall rule for -IisPort. Only pass this if the lab
    segment is isolated - the site is intentionally vulnerable and has real
    command execution.

.EXAMPLE
    .\iis\Install-IIS-LabSite.ps1 -IisPort 8080 -OpenFirewall
#>
param(
    [string]$SiteName = "HELPAG-VAPT-Test-Site",
    [int]$IisPort = 8080,
    [int]$MetadataPort = 8080,
    [string]$RepositoryPath = (Split-Path -Parent $PSScriptRoot),
    [switch]$OpenFirewall
)

$ErrorActionPreference = "Stop"
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this script from an elevated PowerShell window."
}

if ($IisPort -eq $MetadataPort) {
    # The metadata service is loopback-only, but a shared port would still collide.
    $MetadataPort = 8081
    Write-Warning "IIS port and metadata port collided; metadata service moved to 8081."
}

Write-Host "== 1/8 Installing IIS features =="
Import-Module ServerManager
Install-WindowsFeature Web-Server, Web-Http-Logging, Web-Mgmt-Tools, Web-Filtering | Out-Null
Import-Module WebAdministration

Write-Host "== 2/8 Checking URL Rewrite and ARR =="
if (-not (Get-WebGlobalModule -Name RewriteModule -ErrorAction SilentlyContinue)) {
    throw "IIS URL Rewrite 2 is required. Install URL Rewrite and Application Request Routing, then rerun."
}
if (-not (Get-WebGlobalModule -Name ApplicationRequestRouting -ErrorAction SilentlyContinue)) {
    Write-Warning "Application Request Routing module not detected. If proxying fails, install ARR 3.0 and rerun."
}

$appcmd = Join-Path $env:windir "System32\inetsrv\appcmd.exe"

# Enable the proxy, allow the rewrite rule to set X-Forwarded-For, and unlock
# request filtering so web.config can relax it.
& $appcmd set config -section:system.webServer/proxy /enabled:"True" /commit:apphost | Out-Null
& $appcmd set config -section:system.webServer/rewrite/allowedServerVariables `
    /+"[name='HTTP_X_FORWARDED_FOR']" /commit:apphost 2>$null | Out-Null
& $appcmd unlock config -section:system.webServer/security/requestFiltering | Out-Null

Write-Host "== 3/8 Building the Python environment =="
if (-not (Get-Command py -ErrorAction SilentlyContinue)) {
    throw "Python 3.11+ with the Windows py launcher is required."
}
Set-Location $RepositoryPath
if (-not (Test-Path (Join-Path $RepositoryPath ".venv"))) {
    & py -3 -m venv .venv
}
& .\.venv\Scripts\python.exe -m pip install --upgrade pip --quiet
& .\.venv\Scripts\python.exe -m pip install -r requirements.txt --quiet
if ($LASTEXITCODE -ne 0) { throw "pip install failed. Check requirements.txt and network access." }

Write-Host "== 4/8 Creating directories =="
New-Item -ItemType Directory -Force -Path (Join-Path $RepositoryPath "logs")    | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $RepositoryPath "uploads") | Out-Null

Write-Host "== 5/8 Creating the IIS site =="
$iisPath = Join-Path $RepositoryPath "iis"
if (-not (Test-Path "IIS:\AppPools\$SiteName")) {
    New-WebAppPool -Name $SiteName | Out-Null
}
Set-ItemProperty "IIS:\AppPools\$SiteName" -Name managedRuntimeVersion -Value ""

if (Test-Path "IIS:\Sites\$SiteName") {
    Remove-Website -Name $SiteName
}
New-Website -Name $SiteName -PhysicalPath $iisPath -Port $IisPort -ApplicationPool $SiteName | Out-Null

# W3C logging with the fields the Splunk IIS use cases expect.
Set-ItemProperty "IIS:\Sites\$SiteName" -Name logFile.logFormat -Value W3C
Set-ItemProperty "IIS:\Sites\$SiteName" -Name logFile.logExtFileFlags -Value `
    "Date,Time,ClientIP,UserName,SiteName,ComputerName,ServerIP,Method,UriStem,UriQuery,HttpStatus,Win32Status,BytesSent,BytesRecv,TimeTaken,ServerPort,UserAgent,Referer,HttpSubStatus"
Set-ItemProperty "IIS:\Sites\$SiteName" -Name logFile.period -Value Daily

Write-Host "== 6/8 Registering backend services =="
$settings = New-ScheduledTaskSettingsSet -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) `
            -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
$trigger  = New-ScheduledTaskTrigger -AtStartup

$appStarter = Join-Path $PSScriptRoot "Start-LabSite.ps1"
$appAction = New-ScheduledTaskAction -Execute "PowerShell.exe" `
    -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$appStarter`" -RepositoryPath `"$RepositoryPath`""
Register-ScheduledTask -TaskName $SiteName -Action $appAction -Trigger $trigger -Settings $settings `
    -User "SYSTEM" -RunLevel Highest -Force | Out-Null

$metaStarter = Join-Path $PSScriptRoot "Start-MetadataService.ps1"
$metaAction = New-ScheduledTaskAction -Execute "PowerShell.exe" `
    -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$metaStarter`" -RepositoryPath `"$RepositoryPath`" -Port $MetadataPort"
Register-ScheduledTask -TaskName "$SiteName-Metadata" -Action $metaAction -Trigger $trigger -Settings $settings `
    -User "SYSTEM" -RunLevel Highest -Force | Out-Null

Start-ScheduledTask -TaskName $SiteName
Start-ScheduledTask -TaskName "$SiteName-Metadata"
Start-Website -Name $SiteName

if ($OpenFirewall) {
    Write-Host "== 7/8 Opening the firewall for port $IisPort =="
    Write-Warning "This site is intentionally vulnerable and has real command execution. Only do this on an isolated lab segment."
    New-NetFirewallRule -DisplayName "$SiteName (lab only)" -Direction Inbound -Protocol TCP `
        -LocalPort $IisPort -Action Allow -Profile Domain,Private | Out-Null
} else {
    Write-Host "== 7/8 Firewall unchanged (pass -OpenFirewall to allow other lab hosts) =="
}

Write-Host "== 8/8 Verifying =="
$healthy = $false
foreach ($attempt in 1..15) {
    Start-Sleep -Seconds 2
    try {
        $health = Invoke-RestMethod "http://localhost:$IisPort/health" -TimeoutSec 3
        if ($health.status -eq "healthy" -and $health.lab_mode) { $healthy = $true; break }
    } catch { }
}
if (-not $healthy) {
    throw "Site did not become healthy. Check: Get-ScheduledTask -TaskName $SiteName; and logs\ in $RepositoryPath"
}

try {
    $metaOk = Invoke-WebRequest "http://127.0.0.1:$MetadataPort/latest/meta-data/" -TimeoutSec 3 -UseBasicParsing
    Write-Host "Metadata service responding on 127.0.0.1:$MetadataPort (SSRF challenge is solvable)."
} catch {
    Write-Warning "Metadata service is not responding on 127.0.0.1:$MetadataPort. The ssrf-metadata challenge will fail until it is."
}

Write-Host ""
Write-Host "HELP AG VAPT range installed: http://localhost:$IisPort"
Write-Host "Backend bound to 127.0.0.1:5005; metadata service to 127.0.0.1:$MetadataPort. IIS is the only lab-facing listener."
Write-Host "IIS access logs: $env:SystemDrive\inetpub\logs\LogFiles"
Write-Host "Application events: $(Join-Path $RepositoryPath 'logs\helpag-events.jsonl')"
Write-Host ""
Write-Host "Next: validate with .\tools\Validate-Range.ps1 -BaseUrl http://localhost:$IisPort"
