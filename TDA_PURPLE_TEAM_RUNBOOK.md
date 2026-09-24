# TDA Purple-Team Trigger Runbook

Authorized detection-validation runbook. Goal: deliberately generate the
activity each TDA use case is built to catch, so you can confirm the rule
fires in the SIEM/EDR. Everything here uses **safe, industry-standard test
artifacts** (nmap, netcat, the EICAR test file, Atomic Red Team). Nothing
here is real malware and nothing hides itself — the point is to be *seen*.

> Before you start: get written sign-off, agree a test window with the SOC,
> and tag your traffic so the blue team can find it (see "Tag every test").

---

## 0. One-time setup

### 0.1 Know your two attack positions
Your six use cases split into two groups:

| Where you run it | Use cases | Tool |
|---|---|---|
| **Kali** (network side) | UC0053, UC0054, UC0249 | `nmap`, `netcat` |
| **Windows endpoint** (with EDR agent) | UC0036, UC0182, UC0032 | PowerShell / Atomic Red Team / EICAR |

The port-scan and prohibited-port cases are **network/firewall** detections —
run from Kali. The process-creation and malware cases are **endpoint (EDR)**
detections — run **on the monitored Windows host itself**, not from Kali.

### 0.2 Fill in your lab values (write these down once)

```
KALI_IP        = <your kali ip>              e.g. 10.77.10.5
TARGET_HOST    = <single lab target ip>      e.g. 10.77.20.10
TARGET_RANGE   = <51 lab ips>                e.g. 10.77.20.51-101
WIN_ENDPOINT   = <windows host with EDR>     e.g. 10.77.20.20
```

Use only IPs your engagement explicitly authorizes.

### 0.3 Tag every test (do this so the SOC can find your activity)
Before each run, note the exact **UTC start time** and your **source IP**.
That timestamp + source IP is how you'll pull your own events out of the SIEM
afterward. Announce each test in the shared bridge/chat before you hit enter.

### 0.4 Install tools on Kali (usually already present)
```bash
sudo apt update
sudo apt install -y nmap ncat netcat-traditional
```

---

## UC0053 — Horizontal Port Scan
**What it detects:** one source hitting the **same port** across **many hosts**
(the runbook screenshot says >50 hosts, so use **51+ distinct IPs**).

**Run from:** Kali
**Tool:** nmap

### Steps
1. Pick one port that the detection watches (e.g. `445`, `3389`, or the
   `8443` used in the responder example). Here we use `8443`.
2. Point nmap at your **51-host range**, scanning that **single port**:

```bash
# Horizontal: ONE port, MANY hosts
sudo nmap -Pn -p 8443 --max-retries 1 10.77.20.51-101
```

3. `-Pn` = skip ping (treat all as up, so all 51 are actually probed).
   `-p 8443` = the one port. The IP range = the many hosts.
4. To make the fan-out even more obvious, add SYN scan + faster timing:

```bash
sudo nmap -sS -Pn -p 8443 -T4 10.77.20.51-101
```

### What should happen
The firewall/SIEM sees 1 source → 51 destinations → same dest port inside the
aggregation window, and raises the horizontal-scan alert.

### Confirm it fired (example SPL — adapt index/fields to your env)
```spl
index=firewall src_ip="10.77.10.5" dest_port=8443 earliest=-15m
| stats dc(dest_ip) as hosts_hit values(dest_ip) as targets by src_ip
| where hosts_hit >= 51
```
`hosts_hit >= 51` = the horizontal scan is visible.

---

## UC0054 — Vertical Port Scan
**What it detects:** one source hitting **many ports** on a **single target**.

**Run from:** Kali
**Tool:** nmap

### Steps
1. Choose your single target (`TARGET_HOST`).
2. Scan a wide port range against just that one host:

```bash
# Vertical: MANY ports, ONE host
sudo nmap -sS -Pn -p 1-1000 -T4 10.77.20.10
```

3. To exceed a higher unique-port threshold, scan all 65535 ports:

```bash
sudo nmap -sS -Pn -p- -T4 10.77.20.10
```

4. `-p-` = every port on that **one** host = the vertical pattern.

### What should happen
The detection sees 1 source → 1 destination → many unique dest ports in the
time window, and raises the vertical-scan alert.

### Confirm it fired
```spl
index=firewall src_ip="10.77.10.5" dest_ip="10.77.20.10" earliest=-15m
| stats dc(dest_port) as ports_probed by src_ip dest_ip
| where ports_probed >= 100
```

---

## UC0249 — Prohibited Port Activity Detected
**What it detects:** traffic to a **port that policy forbids** (e.g. IRC 6667,
Telnet 23, SMB 445 egress, a known-bad C2-style port). You don't need a scan —
a single connection attempt to the banned port is the trigger.

**Run from:** Kali
**Tool:** netcat / ncat (nmap also works)

### Steps
1. Confirm with the client which port(s) the rule flags. Common examples:
   `23` (telnet), `6667` (IRC), `4444`, `3389`, `445`.
2. Attempt a TCP connection to that port on the target:

```bash
# Single prohibited-port connection attempt (example: 6667)
ncat -v -w 3 10.77.20.10 6667
```

3. `-v` = verbose so you see the result, `-w 3` = 3-second timeout. Type a
   line of text and press Enter to push a few bytes, then Ctrl+C.
4. If the rule only triggers on a completed session, aim at a port where the
   target actually listens. To force an outbound attempt regardless:

```bash
# nmap alternative — attempt the banned port on the target
sudo nmap -Pn -p 6667 10.77.20.10
```

5. To generate a clearer signal, hit the banned port a few times:
```bash
for i in 1 2 3; do ncat -v -w 2 10.77.20.10 6667; done
```

### What should happen
The firewall/proxy logs a session on the prohibited port and the rule fires.

### Confirm it fired
```spl
index=firewall src_ip="10.77.10.5" dest_port=6667 earliest=-15m
| table _time src_ip dest_ip dest_port action
```

---

## UC0032 — Critical Malware Detected on EDR
**What it detects:** the EDR/AV flagging a malicious file. The safe, universal
way to trigger this is the **EICAR test file** — a harmless 68-byte string that
every AV/EDR vendor is required to detect *as if* it were malware. It cannot
do any damage; it only proves the engine and alert pipeline work.

**Run from:** the **Windows endpoint** with the EDR agent (WIN_ENDPOINT).
**Tool:** built-in shell + the EICAR string.

> Do this on a lab endpoint only. Real-time protection may quarantine the file
> instantly — that is exactly the detection you want.

### Steps
1. RDP / console onto the monitored Windows host.
2. Open **PowerShell** (or CMD). Create the EICAR test file. The string is
   split below so your own editor/AV doesn't grab it before EDR does — paste it
   as one line with no spaces where the `+` joins are:

```powershell
# Standard EICAR anti-malware test string
$e = 'X5O!P%@AP[4' + '\PZX54(P^)7CC)7}' + '$EICAR-STANDARD-' + 'ANTIVIRUS-TEST-FILE!$H+H*'
Set-Content -Path "$env:TEMP\eicar_test.com" -Value $e -Encoding Ascii
```

3. Force the EDR to scan / access the file (creation alone often triggers
   real-time protection; reading it makes sure):

```powershell
Get-Content "$env:TEMP\eicar_test.com"
```

4. If nothing fires (real-time protection disabled in lab), run an on-demand
   Defender scan of the temp folder:

```powershell
& "$env:ProgramFiles\Windows Defender\MpCmdRun.exe" -Scan -ScanType 3 -File "$env:TEMP\eicar_test.com"
```

### What should happen
The EDR raises a **critical malware** detection for EICAR and (usually)
quarantines/deletes it. That alert is your UC0032 trigger.

### Confirm it fired
Check the EDR console for a detection named like `EICAR-Test-File` /
`Virus:DOS/EICAR_Test_File` on `WIN_ENDPOINT`, then confirm it reached the SIEM:
```spl
index=edr host=WIN_ENDPOINT ("EICAR" OR "Test-File") earliest=-15m
| table _time host user threat_name action
```

---

## UC0182 — Application Parents Spawning Malicious Children
**What it detects:** a normal "productivity" app (Word, Excel, Outlook, a PDF
reader, a browser) launching a **command interpreter** (cmd.exe, powershell.exe,
wscript, mshta). Attackers do this after a malicious document; the detection
watches the **parent→child** relationship, not the child alone.

**Run from:** the **Windows endpoint** (WIN_ENDPOINT).
**Tool:** whatever "office-like" parent you have, plus a benign child command.
The child command below is harmless (`whoami` / `ipconfig`) — the *relationship*
is what triggers the rule, so you don't need anything dangerous.

### Option A — quickest, using a real Office app (if installed)
1. Open **Microsoft Word** on the endpoint.
2. Press `Alt+F11` to open the VBA editor → `Insert > Module`, paste:

```vba
Sub AutoOpen()
    Shell "cmd.exe /c whoami > %TEMP%\uc0182.txt", vbHide
End Sub
```

3. Save as a **macro-enabled** doc (`.docm`), close, reopen, enable macros.
   Word (parent) spawning `cmd.exe` (child) is the trigger.

### Option B — no Office needed (simulate the parent-child chain)
Use `mshta` / `wscript` as the "application" parent spawning a shell:

```powershell
# wscript (script host) spawns cmd -> powershell : classic malicious chain
mshta.exe "javascript:new ActiveXObject('WScript.Shell').Run('cmd.exe /c whoami');close();"
```

Or force an explicit anomalous tree from a browser-like parent:
```powershell
Start-Process -FilePath "cmd.exe" -ArgumentList "/c whoami"
```

### Option C — cleanest & repeatable: Atomic Red Team
See the Atomic setup box at the bottom, then:
```powershell
# T1204.002 / T1059 cover office & scripting-host child spawning
Invoke-AtomicTest T1059.001 -ShowDetailsBrief
Invoke-AtomicTest T1059.001 -TestNumbers 1
```

### What should happen
EDR records e.g. `winword.exe → cmd.exe → whoami` (or `mshta.exe → cmd.exe`)
and raises the suspicious parent-child alert.

### Confirm it fired
```spl
index=edr host=WIN_ENDPOINT earliest=-15m
  parent_process IN ("winword.exe","excel.exe","outlook.exe","mshta.exe","wscript.exe")
  process IN ("cmd.exe","powershell.exe")
| table _time host user parent_process process command_line
```

---

## UC0036 — APT Group Process Creation
**What it detects:** process-creation events matching **known APT tradecraft** —
specific binaries, arguments, or process chains that a named threat group uses
(e.g. renamed system tools, `rundll32`/`regsvr32` misuse, discovery command
bursts). The safe way to reproduce these patterns is **Atomic Red Team**, which
maps each test to the exact MITRE ATT&CK technique the APT rule keys on.

**Run from:** the **Windows endpoint** (WIN_ENDPOINT).
**Tool:** Atomic Red Team (benign, self-contained tests).

### Steps
1. Ask the client **which ATT&CK technique(s)** UC0036 maps to (the rule name
   or MITRE ID). Common APT-flavored process-creation techniques:
   - `T1059.001` PowerShell execution
   - `T1218.011` rundll32 / `T1218.010` regsvr32 (signed-binary proxy exec)
   - `T1036.003` masquerading (renamed system binary)
   - `T1057` / `T1082` / `T1016` discovery bursts
2. Install Atomic Red Team (one time — see box below).
3. Show what a test does before running it:
```powershell
Invoke-AtomicTest T1218.011 -ShowDetailsBrief
```
4. Run the specific test that matches the use case:
```powershell
Invoke-AtomicTest T1218.011 -TestNumbers 1
```
5. If UC0036 is about a **discovery burst** (many recon commands quickly),
   this benign sequence reproduces it:
```powershell
whoami /all; hostname; ipconfig /all; net user; net group "domain admins" /domain; systeminfo; tasklist
```

### What should happen
EDR logs the process-creation events matching the APT technique and raises the
UC0036 alert.

### Confirm it fired
```spl
index=edr host=WIN_ENDPOINT earliest=-15m
| search process IN ("rundll32.exe","regsvr32.exe","powershell.exe")
| table _time host user parent_process process command_line
```
(Adjust to the exact technique you ran; use your test start-time to isolate.)

---

## Appendix — Atomic Red Team one-time install (Windows lab host)
Atomic Red Team is the industry-standard, open-source library of small,
documented, **benign** detection tests. Install on the lab endpoint only.

```powershell
# Run PowerShell as Administrator on WIN_ENDPOINT
Set-ExecutionPolicy Bypass -Scope Process -Force
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
Install-AtomicRedTeam -getAtomics
Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1" -Force
```
Then per test: `-ShowDetailsBrief` to preview, run it, and `-Cleanup` after:
```powershell
Invoke-AtomicTest T1059.001 -TestNumbers 1 -Cleanup
```

---

## Run order & checklist

| # | Use case | Position | Command (short form) |
|---|---|---|---|
| 1 | UC0053 Horizontal scan | Kali | `sudo nmap -sS -Pn -p 8443 -T4 10.77.20.51-101` |
| 2 | UC0054 Vertical scan | Kali | `sudo nmap -sS -Pn -p- -T4 10.77.20.10` |
| 3 | UC0249 Prohibited port | Kali | `ncat -v -w 3 10.77.20.10 6667` |
| 4 | UC0032 EDR malware | Windows | create + read EICAR test file |
| 5 | UC0182 Parent→child | Windows | `mshta` / Word macro → `cmd.exe /c whoami` |
| 6 | UC0036 APT process | Windows | `Invoke-AtomicTest <TID>` |

For each: **(a)** note UTC start time + source, **(b)** announce to SOC,
**(c)** run, **(d)** pull your events with the SPL above, **(e)** record
pass/fail (did the rule fire?). Clean up EICAR and Atomic artifacts when done.
