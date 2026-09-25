# Atomic Red Team — Setup & Run

Run on an authorized Windows test host. Use **PowerShell as Administrator**.

## 1. Enable process logging (once)
```powershell
auditpol /set /subcategory:"Process Creation" /success:enable
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
```

## 2. Install Atomic Red Team (once)
```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
Install-AtomicRedTeam -getAtomics
Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1" -Force
```

## 3. Load module (every new window)
```powershell
Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1" -Force
```

## 4. Run a test
```powershell
Invoke-AtomicTest T1036.003 -ShowDetailsBrief          # list tests
Invoke-AtomicTest T1036.003 -TestNumbers 1 -ShowDetails # preview
Invoke-AtomicTest T1036.003 -TestNumbers 1 -GetPrereqs  # setup
Invoke-AtomicTest T1036.003 -TestNumbers 1              # run
Invoke-AtomicTest T1036.003 -TestNumbers 1 -Cleanup     # clean up
```

## 5. Validate in Splunk
```spl
index=* host="<HOSTNAME>" EventCode=4688 earliest=-30m
| table _time Creator_Process_Name New_Process_Name Process_Command_Line
```
Results show under the **Statistics** tab.

## Starter techniques
| ID | Simulates |
|---|---|
| T1036.003 | Masquerading (fake lsass.exe) |
| T1059.001 | PowerShell execution |
| T1218.010 | regsvr32 (Squiblydoo) |
| T1218.011 | rundll32 execution |
| T1057 | Process discovery |
| T1053.005 | Scheduled task creation |

Rules: preview before running, cleanup after, one test at a time, authorized hosts only.
