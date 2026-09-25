# Atomic Red Team — Install & Run Guide (Getting Started)

A step-by-step guide for the team: from installing Atomic Red Team on a Windows
test machine to running your first attack simulation and validating it in Splunk.
Written for people with **no prior experience**.

> **What is Atomic Red Team?** A free, open-source library of small, safe security
> tests built by Red Canary. Each "atomic" test reproduces one real attacker
> technique (mapped to MITRE ATT&CK) so we can check whether our detections
> (EDR / SIEM) actually catch it. It is a *testing* tool, not malware.

> ⚠️ **Use only on authorized lab or test machines** with sign-off. Do not run on
> production or personal machines. Some tests create files, registry keys, or
> processes — always run the `-Cleanup` step afterward.

---

## Part 1 — Prerequisites (one time)

1. A **Windows test VM/host** with the EDR agent + Splunk forwarder installed.
2. **Administrator** access on that host.
3. Internet access on the host (to download Atomic). If blocked, see *Offline install* at the bottom.
4. **Process-creation logging must be ON** (many tests are invisible without it). Check:
   ```powershell
   auditpol /get /subcategory:"Process Creation"
   ```
   If it says **No Auditing**, enable it (with command-line capture):
   ```powershell
   auditpol /set /subcategory:"Process Creation" /success:enable
   reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
   ```

---

## Part 2 — Open PowerShell as Administrator

Start menu → type `PowerShell` → right-click **Windows PowerShell** → **Run as administrator**.

> The prompt should read `PS C:\...`. If it says just `C:\...>` you're in Command
> Prompt (cmd) — type `powershell` and press Enter to switch.

---

## Part 3 — Install Atomic Red Team (one time)

Copy-paste these lines one by one:

```powershell
# 1. Allow scripts to run for this window only
Set-ExecutionPolicy Bypass -Scope Process -Force

# 2. Download and run the official installer, and pull down all the atomic tests
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
Install-AtomicRedTeam -getAtomics

# 3. Load the module so its commands are available
Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1" -Force
```

**Verify it installed** (should print help without error):
```powershell
Invoke-AtomicTest -help
```
The tests live in `C:\AtomicRedTeam\atomics`.

> ℹ️ Every new PowerShell window needs the module loaded again — just re-run the
> `Import-Module ...` line (step 3). Installation itself is only done once.

---

## Part 4 — The 5-step run cycle (learn this once, use it for everything)

Every test follows the same pattern. We'll use **T1036.003** (masquerading) as the example.

### Step 1 — See what tests exist for a technique
```powershell
Invoke-AtomicTest T1036.003 -ShowDetailsBrief
```
This lists the test numbers and names, e.g. `T1036.003-1 Masquerading as Windows LSASS process`.

### Step 2 — Read exactly what one test will do (always do this first)
```powershell
Invoke-AtomicTest T1036.003 -TestNumbers 1 -ShowDetails
```
Shows the actual commands, any files it creates, and cleanup steps. Read before running.

### Step 3 — Install anything the test needs (prerequisites)
```powershell
Invoke-AtomicTest T1036.003 -TestNumbers 1 -GetPrereqs
```

### Step 4 — Run the test (the simulation / trigger)
First note the time and host so you can find it in Splunk:
```powershell
Get-Date -Format "yyyy-MM-dd HH:mm:ss" ; hostname
Invoke-AtomicTest T1036.003 -TestNumbers 1
```
> Some tests (like this one) "hang" for ~120 seconds by design, then time out. That is normal.

### Step 5 — Clean up (always)
```powershell
Invoke-AtomicTest T1036.003 -TestNumbers 1 -Cleanup
```

**Handy variations:**
```powershell
Invoke-AtomicTest T1036.003 -TestNumbers 1,3,5     # run several tests
Invoke-AtomicTest T1057                             # run ALL tests for a technique (careful!)
```

---

## Part 5 — Your first simulation (full example)

A safe, self-contained first run — masquerading a process as `lsass.exe`:

```powershell
Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1" -Force
Invoke-AtomicTest T1036.003 -TestNumbers 1 -ShowDetails
Get-Date -Format "yyyy-MM-dd HH:mm:ss" ; hostname
Invoke-AtomicTest T1036.003 -TestNumbers 1 -GetPrereqs
Invoke-AtomicTest T1036.003 -TestNumbers 1
# ... let it time out (~120s) ...
Invoke-AtomicTest T1036.003 -TestNumbers 1 -Cleanup
```

**Local proof it worked:**
```powershell
Get-Process lsass | Select-Object Id,Path,StartTime
```
You'll see the real `lsass.exe` (from `System32`) **and** a fake one from `C:\Windows\Temp` — that's the simulated attack.

---

## Part 6 — Validate in Splunk

Process-creation events show up as **Event ID 4688**. Example search (replace `<HOSTNAME>`):
```spl
index=* host="<HOSTNAME>" EventCode=4688 earliest=-30m
| table _time Creator_Process_Name New_Process_Name Process_Command_Line
| sort - _time
```
- Results appear under the **Statistics** tab (not Events) when you use `| table`.
- Cut normal system noise:
  ```spl
  | search NOT Creator_Process_Name IN ("*services.exe","*svchost.exe","*CompatTelRunner.exe","*splunkd.exe")
  ```
- Key fields: `Creator_Process_Name` (parent), `New_Process_Name` (child), `Process_Command_Line`.

**Reading the result:**
| Outcome | Meaning |
|---|---|
| Event in Splunk **and** an alert fired | ✅ Detection works |
| Event in Splunk, **no alert** | ⚠️ Logging OK, detection rule missing/mistuned |
| **No event** in Splunk | ⚠️ Visibility gap (e.g. auditing off, or not forwarding) |

---

## Part 7 — A few good starter techniques

| Technique | What it simulates | Notes |
|---|---|---|
| `T1036.003` | Masquerading (fake `lsass.exe`) | Self-contained, great first test |
| `T1059.001` | PowerShell execution | Very common signature |
| `T1218.010` | regsvr32 (Squiblydoo) | Signed-binary proxy execution |
| `T1218.011` | rundll32 execution | Signed-binary proxy execution |
| `T1057` | Process discovery (`tasklist`) | Simple recon burst |
| `T1053.005` | Scheduled task creation | Persistence via `schtasks` |

Preview any of them first with `-ShowDetailsBrief`.

---

## Useful commands cheat-sheet

```powershell
Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1" -Force   # load module (each new window)
Invoke-AtomicTest <TID> -ShowDetailsBrief      # list a technique's tests
Invoke-AtomicTest <TID> -TestNumbers 1 -ShowDetails   # see full detail of one test
Invoke-AtomicTest <TID> -TestNumbers 1 -GetPrereqs    # install prerequisites
Invoke-AtomicTest <TID> -TestNumbers 1                # run it
Invoke-AtomicTest <TID> -TestNumbers 1 -Cleanup       # clean up
```

---

## Offline install (if the host has no internet)

1. On an internet-connected machine, download the repos as ZIPs:
   - `github.com/redcanaryco/invoke-atomicredteam` (the runner)
   - `github.com/redcanaryco/atomic-red-team` (the tests, in `/atomics`)
2. Copy them to the test host, e.g. put the atomics under `C:\AtomicRedTeam\atomics`.
3. Import the module from the copied path:
   ```powershell
   Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1" -Force
   ```

---

## Golden rules
- Always `-ShowDetails` before you run.
- Always `-Cleanup` after.
- Run **one test at a time** and note the timestamp, so each alert maps to each action.
- Only on authorized test machines, within engagement scope.

---
*Reference: Red Canary Atomic Red Team — https://github.com/redcanaryco/atomic-red-team*
