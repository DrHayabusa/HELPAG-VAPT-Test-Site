# TDA Use-Case Progress Tracker

**Customer:** aaagroup.com
**Updated:** 2026-10-20
**Endpoint:** Windows (CrowdStrike Falcon; Windows Defender disabled; Halcyon blocks downloads)

Legend: ✅ Done · 🟡 Executed – confirm in SOC · ⛔ Blocked (needs customer) · ⬜ Not started

---

## Completed from the TDA machine

| UC | Name | Status | Result / Notes |
|----|------|--------|----------------|
| UC0125 | Common Ransomware Extensions | ✅ | 20 files renamed to known ransomware extensions + ransom note. Behavioral trigger. |
| SPLUC0186 | Malicious Scheduled Task | ✅ | `schtasks` created a per-minute PowerShell task. Confirm Event 4698 collected. |
| UC0311 | PsExec Tool Execution | ✅ | `PsExec -s cmd` ran as `nt authority\system` (PSEXESVC). Confirm Event 7045. |
| UC0046 | Password Spray (DC / SMB) | ✅ | 11+ `aaagroup.com` accounts vs `AAM-VDC.aaagroup.com` via `net use IPC$`; all `1326` (failed logon). Threshold = 11. |
| SENUC0259 | Password Spray vs Azure AD | ✅ | `office.com` token endpoint, dummy password; `AADSTS50126` = valid accounts confirmed, failed sign-ins logged. |

## APT Process Creation (endpoint prevention tested)

| Technique | MITRE | Result |
|-----------|-------|--------|
| rundll32 with no arguments (beacon spawnto) | T1218.011 | Ran — process-creation events logged |
| mshta inline VBScript (LOLBin) | T1218.005 | **BLOCKED** (Access denied) = prevention |
| LSASS dump via comsvcs.dll | T1003.001 | **BLOCKED** (Access denied, no dump) = prevention |

## Executed – confirm in SOC console / logs

| UC | Name | Status | Notes |
|----|------|--------|-------|
| UC0149 | Multiple AV Infections | 🟡 | EICAR + 6 separate offensive-tool zips extracted. CrowdStrike is behavioral/detect-mode — confirm detections in Falcon console; perimeter also blocked direct tool downloads (prevention). |
| UC0141 | C2C Traffic | 🟡 | Palo Alto C2 test URL reached/blocked at perimeter. **If query filters `action=allow`, a block won't match** — ask customer to set the C2 URL category to **Alert** for the window, then re-run. |
| UC0249 | Prohibited Port Activity | 🟡 | PowerShell TCP to ports 6667/31337/12345/6969/23432. Confirm firewall logged (allow=detection, blocked=prevention). |
| UC0054 | Vertical Port Scan | 🟡 | `nmap -sS -p 1-150 <IP>`. Confirm IDS/firewall scan detection + threshold. |

## Blocked — need customer prerequisites

| UC | Name | Blocker |
|----|------|---------|
| SPLUC0107 | Suspected Phishing Email | No send method / monitored recipient mailbox |
| UC0222 | Suspicious Email Attachment | Same — no mail path |
| UC0575 | Multiple DLP / Malware by Mail | Same — no mail path |
| UC0215 | Explicit MFA Deny | No test account with MFA on a controlled phone |
| UC1147 | MFA Takeover | No test account |
| UC0458 | Azure Activity CRUD | Customer executes in tenant (call) |
| UC0327 | Entra Privileged Access Outside PIM | Customer executes in tenant (call) |

## Not started (doable, deferred)

| UC | Name | Notes |
|----|------|-------|
| UC0073 | Security/Audit Logs Cleared | One command `wevtutil cl Security` (admin). Deferred — wipes the Security log, so run last. |
| UC0053 | Horizontal Port Scan | `nmap -sS -p 8080 <subnet>`; needs a subnet with >200 live hosts. |

---

## Web application track (hcms.aaagroup.com)

Separate from the TDA detection UCs. Black-box findings documented in
`WEB_FINDINGS_HCMS.md`:
- Username enumeration (CWE-204)
- Outdated jQuery 3.0.0 (CVE-2020-11022/11023)
- Internal path disclosure (`D:\CIVILSOFT\...`)
- Verbose error / version disclosure
- Internal endpoint disclosure

---

## Cross-cutting prerequisites to confirm with customer

- **Command-line logging** (Event 4688 with command line)
- **Scheduled-task auditing** (4698), **service-creation logging** (7045)
- **SIEM log forwarding** from Palo Alto (threat/URL) and Windows hosts
- **Validate each detection query + threshold per customer before executing**

See `PENDING_USECASE_BLOCKERS.md` for the full customer ask.
