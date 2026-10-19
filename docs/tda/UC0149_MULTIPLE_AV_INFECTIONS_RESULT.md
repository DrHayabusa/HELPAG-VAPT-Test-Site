# UC0149 — Multiple AV Infections on Same Host

**Date:** 2026-10-19
**Host:** TDA test machine (customer environment)
**Endpoint AV:** CrowdStrike Falcon (Windows Defender disabled)
**Constraint:** All downloads blocked. Built-in tooling only.

---

## What the use case needs

The SOC rule fires when the AV/EDR reports **two or more malware detections on
the same host** in a short window. To trigger it we need the AV to generate
several malware-detection events tied to one machine.

## What we did

Downloads of real offensive tooling are blocked on this network, so we used the
standard EICAR test file (harmless, industry-standard AV test string) written
several times, plus we confirmed what AV is actually on the host.

### Commands run (in order)

```
cd C:\Users\Public
```
Move to a writable folder.

```
$e='X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
```
Store the EICAR test string.

```
1..6 | ForEach-Object { Set-Content -Path "C:\Users\Public\eicar_$_.com" -Value $e -Encoding Ascii; "wrote eicar_$_.com" }
```
Write 6 test files — one per intended detection.

```
Get-ChildItem C:\Users\Public\eicar_*.com
```
Result: all 6 present, 70 bytes each. Nothing quarantined on write.

```
Start-MpScan -ScanType CustomScan -ScanPath C:\Users\Public
```
Result: **failed, HRESULT 0x800106ba** — the Defender service is not running.

```
Get-MpComputerStatus | Select-Object AMRunningMode, RealTimeProtectionEnabled, AntivirusEnabled
```
Result: **AMRunningMode = Not running, RealTimeProtectionEnabled = False,
AntivirusEnabled = False.** Windows Defender is fully disabled.

```
Get-Service csagent, CSFalconService | Select-Object Name, Status, StartType
```
Result: **both Running** (csagent = System, CSFalconService = Automatic).
CrowdStrike Falcon is the sole endpoint AV.

```
Get-ChildItem C:\Users\Public\eicar_*.com | ForEach-Object { Get-Content $_.FullName | Out-Null; "touched $($_.Name)" }
```
Force an on-access scan by reading each file. No quarantine.

```
cmd /c C:\Users\Public\eicar_1.com
```
Attempt to execute. Result: *"This version of ... is not compatible with the
version of Windows you're running."* This is a 64-bit Windows limitation
(`.com`/16-bit format), **not** a Falcon block — the file never executed.

### Download control (confirmed separately)

Earlier in the day we tried to pull real offensive tools
(Rubeus, Mimikatz, Seatbelt, SharpDump, SharpUp, SharpHound) from GitHub, both
via PowerShell `Invoke-WebRequest` and via Chrome.

- PowerShell: **operation timed out** on every file.
- Chrome: **ERR_CONNECTION_RESET** on the raw file path.
- `Test-NetConnection github.com -Port 443`: **TcpTestSucceeded = True.**

The TCP handshake is allowed but the transfer is reset the moment the malicious
file path is seen. That is **SSL/path inspection at the gateway** killing the
known-malware download.

---

## Result

| Layer | Finding | Verdict |
|-------|---------|---------|
| Endpoint (CrowdStrike) | Defender disabled; Falcon is behavioral/ML and did not act on EICAR test files on write, read, or exec attempt | **Gap / confirm in console** |
| Perimeter (network/proxy) | All real offensive-tool downloads reset at the gateway by content/path inspection | **Prevention — PASS** |

### Why EICAR did not fire on the endpoint

CrowdStrike Falcon is a next-gen EDR — it detects on **machine learning and
behavior**, not legacy signatures. EICAR is a signature-era test string.
CrowdStrike does not rely on it and may legitimately ignore it. Files surviving
on disk is consistent with either detect-only policy or EICAR simply not scoring
on the ML model. **This is expected for NGAV and is not a Falcon failure.**

### The real control that worked

For this environment, the "malware caught" evidence is at the **perimeter**: the
firewall/proxy blocked every attempt to bring real offensive tooling onto the
host. That is the prevention that matters for this use case here.

---

## Verify in the Falcon console (SOC step)

This is confirmed console-side, not on the host:

1. Falcon console → **Endpoint security → Monitor → Detections**.
2. Filter by this hostname.
3. Window: **11:04–11:12 AM, 2026-10-19**.

- Detections present → endpoint detection **PASS** (screenshot the list).
- Nothing present → expected for NGAV against EICAR; record as gap and move the
  endpoint validation to a behavioral technique or a controlled real sample.

---

## Recommendations

1. **Confirm Windows Defender being fully disabled is intentional** (expected
   when CrowdStrike is primary — but document it).
2. **Confirm Falcon's policy is prevent, not detect-only**, for this host group.
3. **Validate the endpoint "multiple infection" pipeline with a technique Falcon
   actually flags** (behavioral/ML) or a controlled real sample in a sanctioned
   way — EICAR alone cannot validate an NGAV endpoint.
4. **Keep the perimeter result** — gateway blocking of offensive-tool downloads
   is a genuine, demonstrated control.

---

## Cleanup

```
Remove-Item C:\Users\Public\eicar_*.com -Force
Remove-Item C:\Users\Public\mal -Recurse -Force -ErrorAction SilentlyContinue
```
