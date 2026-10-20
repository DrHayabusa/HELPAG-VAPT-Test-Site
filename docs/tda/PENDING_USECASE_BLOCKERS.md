# TDA Pending Use Cases — Blockers & Prerequisites

**Date:** 2026-10-20
**Context:** The use cases below could not be executed from the TDA Windows machine.
Each is blocked on a prerequisite that only the customer can provide (a mailbox,
a test account, or a customer-side action). This list is for requesting those
prerequisites so the remaining UCs can be completed.

---

## Email-based use cases — BLOCKED

No mailbox, SMTP relay, or recipient was available to send test email from/to.

| UC | What it needs | Request from customer |
|----|---------------|-----------------------|
| **SPLUC0107** — Suspected Phishing Email | A way to send mail + a monitored recipient | An allowed send method (internal SMTP relay **or** an external sender account) **and** the SOC-monitored recipient mailbox |
| **UC0222** — Suspicious Email Attachment (.docm) | Same as above | Same — plus confirm `.docm` isn't stripped before the detection point |
| **UC0575** — Multiple DLP Violations / Malware by Mail | Same as above | Same — recipient mailbox + send method; confirm DLP + mail-AV are in the path |

**To unblock:** customer provides (1) the SMTP relay or an allowed sender, and
(2) the monitored recipient address. Then all three send in minutes via PowerShell
`Send-MailMessage` (no Outlook needed).

---

## MFA / identity use cases — BLOCKED

No test user account with MFA was provided.

| UC | What it needs | Request from customer |
|----|---------------|-----------------------|
| **UC0215** — Explicit MFA Deny | Test account (correct password) + MFA enrolled on a controlled phone | A dedicated test account with Authenticator enrolled; confirm the deny-count threshold in the query |
| **UC1147** — MFA Takeover | Test account to register a new MFA method | A dedicated test account; confirm how many devices/methods the query needs |

**To unblock:** customer provides a dedicated test account (with correct password
and Authenticator on a phone the tester controls). Both are then done via the
browser + phone.

---

## Customer-executed use cases — needs a call

These are performed by the customer in their Azure/Entra tenant; the tester cannot
run them.

| UC | Action | Request from customer |
|----|--------|-----------------------|
| **UC0458** — Azure Activity CRUD | Perform a CRUD op (e.g. create a Network Security Group) | Schedule a call; customer creates/deletes an NSG while the detection is watched |
| **UC0327** — Azure AD Privileged Access Outside PIM | Direct (non-PIM) role assignment | On a call, a Global Admin assigns an Entra role to a test user as **Active / Permanently assigned** (not via PIM) |

---

## Completed, but with a query/prereq note

| UC | Status | Note |
|----|--------|------|
| **UC0046** — Password Spray (DC/SMB) | Executed | Sprayed 11+ `aaagroup.com` accounts against `AAM-VDC.aaagroup.com` via `net use IPC$`; each returned `1326` (failed logon). Confirm the 11-account threshold with the SOC query. |
| **UC0141** — C2C Traffic | Executed | Palo Alto C2 test URL reached/blocked at perimeter. **If the detection query filters on `action=allow`, a blocked session won't match** — request the customer set the C2 test URL category to **Alert** for the test window, then re-run. Confirm the query first. |

---

## Cross-cutting prerequisite (applies to endpoint UCs)

Per the HELP AG execution doc, confirm **detection prerequisites** are enabled on
the hosts **before** execution, especially:
- **Command-line process logging** (Event 4688 with command line).
- **Scheduled-task auditing** (Event 4698) — for the scheduled-task UC.
- **Service-creation logging** (Event 7045) — for the PsExec UC.
- **Log forwarding to the SIEM** — confirm firewall (Palo Alto threat/URL) and
  Windows security logs actually reach the SIEM, or detections won't fire even
  when the activity is generated.

**Always validate the detection query and its threshold per customer before
executing** (e.g. spray needs 11 accounts, port scan needs >200 hosts).

---

## Summary ask for the customer

1. **Email:** an SMTP relay (or allowed sender) + the monitored recipient mailbox.
2. **MFA:** one dedicated test account with MFA enrolled on a controlled phone.
3. **Azure:** a short call to run UC0458 and UC0327 in the tenant.
4. **UC0141:** temporarily set the C2 test URL category to Alert during the window.
5. **Prereqs:** confirm command-line logging, task/service auditing, and SIEM log
   forwarding are on for the target hosts.
