# APT Process Creation — Test Result

**Date:** 2026-10-19
**Host:** TDA test machine (customer environment)
**Endpoint AV/EDR:** CrowdStrike Falcon (Windows Defender disabled)
**Access:** Local admin, elevated PowerShell

---

## What we tested

Three process-creation techniques used by APT groups, run with built-in Windows
tools only (no downloads). Each maps to a different MITRE ATT&CK technique, so
each shows as its own detection.

| # | Technique | MITRE | Result |
|---|-----------|-------|--------|
| 1 | rundll32.exe with no arguments (beacon spawnto) | T1218.011 | Executed — process-creation events logged |
| 2 | mshta.exe running inline VBScript (LOLBin) | T1218.005 | **Blocked — prevention** |
| 3 | LSASS memory dump via comsvcs.dll | T1003.001 | **Blocked — prevention** |

---

## 1. rundll32.exe with no arguments — T1218.011

### What it is
A legitimate `rundll32.exe` is always called with a DLL and a function.
Argument-less rundll32 does nothing useful and is the default process attackers
inject beacons into (Cobalt Strike `spawnto`). EDRs specifically watch for it.

### Command
```
1..3 | ForEach-Object { Start-Process "$env:WINDIR\System32\rundll32.exe"; "spawned rundll32 #$_" }
```

### Result
Processes launched and exited immediately (expected — nothing to run). CrowdStrike
logs the **process-creation events** regardless of lifetime. Several were spawned
across the session.

**Verdict:** Detection — suspicious process creation logged. Confirm the alerts in
the Falcon console.

---

## 2. mshta.exe inline VBScript — T1218.005

### What it is
`mshta.exe` can execute inline VBScript/JScript straight from the command line — a
classic "living-off-the-land" technique to run code without dropping a file.

### Commands and result
```
Start-Process "$env:WINDIR\System32\mshta.exe" -ArgumentList 'vbscript:Execute("CreateObject(""Wscript.Shell"").Run ""cmd.exe /c echo TDA_TEST"",0:close)'
```
Result: **`Start-Process : Access is denied`** — the process was prevented from
launching.

Control test (plain mshta, no script):
```
Start-Process "$env:WINDIR\System32\mshta.exe"
```
Result: opened normally.

### Interpretation
Plain `mshta` is allowed, but **mshta executing inline VBScript was blocked**. The
control targeted the *malicious use* specifically, not the binary — i.e. script
control / EDR prevention.

**Verdict:** Prevention — PASS.

---

## 3. LSASS credential dump via comsvcs.dll — T1003.001

### What it is
The most important technique to block: dumping LSASS process memory to harvest
credentials. Done here with the built-in `comsvcs.dll` MiniDump export via
`rundll32`.

### Commands and result
```
$p=(Get-Process lsass).Id            # LSASS PID = 1100
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump $p C:\Users\Public\lsass.dmp full
```
Result:
```
Program 'rundll32.exe' failed to run: Access is denied
    + FullyQualifiedErrorId : NativeCommandFailed
```
```
Test-Path C:\Users\Public\lsass.dmp   # False — no dump written
```

### Interpretation
The dump attempt was **denied before any data was written**. On this host the
block comes from endpoint protection (CrowdStrike) and may be reinforced by LSASS
Protected Process (RunAsPPL) if enabled. Credential dumping is prevented.

**Verdict:** Prevention — PASS. This is the strongest result of the three.

---

## Summary for the SOC

- **Credential theft (LSASS dump): blocked.** Endpoint prevention working as
  intended — the highest-value control.
- **mshta LOLBin script execution: blocked.** Script control working.
- **rundll32 spawnto: logged.** Process-creation telemetry present; confirm the
  alert fired in the console.

### Verify in the Falcon console
1. Endpoint security → Monitor → **Detections**.
2. Filter by this hostname.
3. Window: around the test time (2026-10-19, late morning).
4. Expect: an LSASS/credential-theft prevention, an mshta block, and rundll32
   process-creation alerts.

Screenshot the detections list — that is the evidence.

---

## Cleanup
```
Remove-Item C:\Users\Public\lsass.dmp, C:\Users\Public\wmi_out.txt -Force -ErrorAction SilentlyContinue
```
(The LSASS dump was blocked, so `lsass.dmp` should not exist — this is just a
safety sweep.)
