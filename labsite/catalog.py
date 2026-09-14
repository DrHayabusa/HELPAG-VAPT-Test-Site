"""Findings catalogue for the Meridian Freight Solutions test target.

Meridian Freight Solutions is a fictional logistics company. The application is
a normal-looking corporate website and customer portal; the vulnerabilities live
inside ordinary business features, and the proof of exploitation is a real data
asset - a credential file, an HR record, a database table, a cloud token - not a
response field labelled "flag".

Operators read this file. Testers should not: it names every finding and every
artifact. The site itself never exposes it.
"""

from __future__ import annotations

import hashlib

FLAG_PREFIX = "MERIDIAN"
COMPANY = "Meridian Freight Solutions"
DOMAIN = "meridianfreight.example"


def flag_hash(value: str) -> str:
    return hashlib.sha256(value.strip().encode("utf-8")).hexdigest()


# Each entry describes one finding.
#   id          stable identifier used by the console and the harness
#   feature     the business function the tester is looking at
#   artifact    the data asset that carries the proof value
#   flag        the proof value itself, embedded in that artifact
#   events      detection event types the exploitation produces
# fmt: off
FINDINGS: list[dict] = [
    {
        "id": "recon-runbook", "title": "IT runbook exposed to crawlers",
        "category": "Information Disclosure", "points": 50, "difficulty": "easy",
        "feature": "Crawler directives", "entrypoints": ["/robots.txt", "/internal/it-runbook.txt"],
        "artifact": "Internal IT runbook naming the out-of-hours access code",
        "flag": "MERIDIAN{0ut_0f_h0urs_4cc3ss_c0d3_1n_runb00k}",
        "summary": "robots.txt advertises an internal directory that has no access control.",
        "hints": ["Crawler directives are a map of what someone wanted hidden.",
                  "Disallow is not authorisation."],
        "owasp": "A01:2021 Broken Access Control",
        "mitre": [("T1595.003", "Active Scanning: Wordlist Scanning"),
                  ("T1592.002", "Gather Victim Host Information: Software")],
        "events": ["recon_hidden_path"],
    },
    {
        "id": "misconfig-debug", "title": "Diagnostic endpoint left enabled",
        "category": "Misconfiguration", "points": 50, "difficulty": "easy",
        "feature": "Platform status page", "entrypoints": ["/status/diagnostics"],
        "artifact": "Runtime configuration including the support bypass code",
        "flag": "MERIDIAN{supp0rt_byp4ss_c0d3_1n_d14gn0st1cs}",
        "summary": "A developer status page ships in the production profile and returns configuration.",
        "hints": ["Status and health endpoints are rarely as thin as they look."],
        "owasp": "A05:2021 Security Misconfiguration",
        "mitre": [("T1592", "Gather Victim Host Information"),
                  ("T1213", "Data from Information Repositories")],
        "events": ["debug_endpoint_access"],
    },
    {
        "id": "misconfig-dotenv", "title": "Environment file served from the web root",
        "category": "Information Disclosure", "points": 100, "difficulty": "easy",
        "feature": "Static file handling", "entrypoints": ["/.env"],
        "artifact": "Deployment environment file with the legacy migration key",
        "flag": "MERIDIAN{l3g4cy_m1gr4t10n_k3y_1n_d0t3nv}",
        "summary": "The deployment .env sits inside the document root and is world-readable.",
        "hints": ["Dotfiles are still files.", "Content discovery, not cleverness."],
        "owasp": "A05:2021 Security Misconfiguration",
        "mitre": [("T1552.001", "Unsecured Credentials: Credentials In Files"),
                  ("T1595.003", "Active Scanning: Wordlist Scanning")],
        "events": ["sensitive_file_access"],
    },
    {
        "id": "misconfig-backups", "title": "Database export in a browsable directory",
        "category": "Information Disclosure", "points": 75, "difficulty": "easy",
        "feature": "Nightly export job", "entrypoints": ["/backups/", "/backups/meridian-db-export.sql"],
        "artifact": "SQL export containing staff password hashes and the payroll reference",
        "flag": "MERIDIAN{p4yr0ll_r3f_1n_n1ghtly_db_3xp0rt}",
        "summary": "Directory listing is enabled over the folder the nightly export writes to.",
        "hints": ["Autoindex tells you what the operator forgot."],
        "owasp": "A05:2021 Security Misconfiguration",
        "mitre": [("T1595.003", "Active Scanning: Wordlist Scanning"),
                  ("T1530", "Data from Cloud Storage")],
        "events": ["directory_listing_access", "sensitive_file_access"],
    },
    {
        "id": "idor-shipment", "title": "Shipment records readable across customers",
        "category": "Broken Access Control", "points": 75, "difficulty": "easy",
        "feature": "Customer portal - shipment tracking",
        "entrypoints": ["/portal/shipments", "/api/v1/shipments/<reference>"],
        "artifact": "Another customer's consignment record, including its declared contents",
        "flag": "MERIDIAN{c0ns1gnm3nt_r3c0rd_cr0ss_t3n4nt}",
        "summary": "Tracking references are sequential and ownership is never checked.",
        "hints": ["Your own reference tells you the shape of everyone else's.",
                  "The high-value consignment is not one of yours."],
        "owasp": "A01:2021 Broken Access Control",
        "mitre": [("T1190", "Exploit Public-Facing Application"),
                  ("T1087", "Account Discovery")],
        "events": ["broken_access_attempt"],
    },
    {
        "id": "access-massassign", "title": "Account role settable from the profile form",
        "category": "Broken Access Control", "points": 125, "difficulty": "medium",
        "feature": "Customer portal - profile settings", "entrypoints": ["/portal/profile"],
        "artifact": "Staff-only operations dashboard and its dispatch authorisation code",
        "flag": "MERIDIAN{d1sp4tch_4uth_c0d3_st4ff_0nly}",
        "summary": "The profile endpoint binds every submitted field, including account_type.",
        "hints": ["Compare what the form sends with what the record holds.",
                  "Staff accounts see a different dashboard."],
        "owasp": "A01:2021 Broken Access Control",
        "mitre": [("T1548", "Abuse Elevation Control Mechanism"),
                  ("T1098", "Account Manipulation")],
        "events": ["mass_assignment_attempt", "privilege_change"],
    },
    {
        "id": "sqli-union", "title": "Rate lookup concatenates input into SQL",
        "category": "Injection", "points": 150, "difficulty": "medium",
        "feature": "Public freight rate search", "entrypoints": ["/services/rates", "/api/v1/rates/search"],
        "artifact": "integration_credentials table - partner API keys",
        "flag": "MERIDIAN{p4rtn3r_4p1_k3y_fr0m_1nt3gr4t10ns}",
        "summary": "The rate search builds its WHERE clause by string concatenation.",
        "hints": ["The result set has three columns.",
                  "sqlite_master lists every table in the schema."],
        "owasp": "A03:2021 Injection",
        "mitre": [("T1190", "Exploit Public-Facing Application"),
                  ("T1213", "Data from Information Repositories")],
        "events": ["sql_query", "sql_error"],
    },
    {
        "id": "sqli-authbypass", "title": "Legacy portal login vulnerable to injection",
        "category": "Injection", "points": 125, "difficulty": "medium",
        "feature": "Customer portal - legacy sign-in", "entrypoints": ["/portal/login?legacy=1"],
        "artifact": "Operations console session and the treasury reconciliation key",
        "flag": "MERIDIAN{tr34sury_r3c0nc1l14t10n_k3y}",
        "summary": "The pre-migration sign-in path was never converted to parameters.",
        "hints": ["The runbook mentions a login path that was never migrated.",
                  "Comment out the rest of the statement."],
        "owasp": "A03:2021 Injection",
        "mitre": [("T1190", "Exploit Public-Facing Application"), ("T1078", "Valid Accounts")],
        "events": ["sql_query", "authentication_attempt"],
    },
    {
        "id": "xss-reflected", "title": "Site search reflects input without encoding",
        "category": "Cross-Site Scripting", "points": 75, "difficulty": "easy",
        "feature": "Site search and 'send this to support'",
        "entrypoints": ["/search", "/support/shared-search"],
        "artifact": "A support agent's session cookie, captured when they open the shared link",
        "flag": "MERIDIAN{4g3nt_s3ss10n_st0l3n_v14_s34rch}",
        "summary": "The search term is written into the results page as raw HTML.",
        "hints": ["The page echoes your term.",
                  "There is a feature for sending a search to an agent."],
        "owasp": "A03:2021 Injection",
        "mitre": [("T1059.007", "Command and Scripting Interpreter: JavaScript"),
                  ("T1189", "Drive-by Compromise")],
        "events": ["xss_probe", "agent_session_compromised"],
    },
    {
        "id": "xss-stored", "title": "Contact messages rendered raw in the staff queue",
        "category": "Cross-Site Scripting", "points": 100, "difficulty": "medium",
        "feature": "Contact us form / staff message queue",
        "entrypoints": ["/contact", "/admin/messages"],
        "artifact": "An operations manager's session, captured when the queue is reviewed",
        "flag": "MERIDIAN{0ps_m4n4g3r_s3ss10n_fr0m_1nb0x}",
        "summary": "Enquiries are stored raw and rendered raw to whichever member of staff opens them.",
        "hints": ["Persistence beats reflection.", "Staff review enquiries internally."],
        "owasp": "A03:2021 Injection",
        "mitre": [("T1059.007", "Command and Scripting Interpreter: JavaScript"),
                  ("T1505.003", "Server Software Component: Web Shell")],
        "events": ["stored_xss_persisted", "staff_session_compromised"],
    },
    {
        "id": "traversal-invoice", "title": "Invoice download accepts arbitrary paths",
        "category": "Broken Access Control", "points": 125, "difficulty": "medium",
        "feature": "Customer portal - invoice download", "entrypoints": ["/api/v1/invoices/download"],
        "artifact": "Application secrets file outside the document root",
        "flag": "MERIDIAN{4pp_s3cr3ts_r34d_by_tr4v3rs4l}",
        "summary": "The document name is joined onto a base path with no containment check.",
        "hints": ["The error response tells you where it looked.",
                  "Application secrets do not live in the document root."],
        "owasp": "A01:2021 Broken Access Control",
        "mitre": [("T1083", "File and Directory Discovery"), ("T1005", "Data from Local System")],
        "events": ["path_traversal_attempt", "sensitive_file_access"],
    },
    {
        "id": "rce-cmdi", "title": "Network diagnostics passes input to a shell",
        "category": "Remote Code Execution", "points": 200, "difficulty": "hard",
        "feature": "Staff tools - depot connectivity check", "entrypoints": ["/admin/diagnostics"],
        "artifact": "Files on the application server, reachable as the service account",
        "flag": "MERIDIAN{d3p0t_t00l_g4v3_m3_4_sh3ll}",
        "summary": "The depot connectivity check concatenates the host field into a command line.",
        "hints": ["The tool shells out to ping.", "Shell metacharacters chain commands."],
        "owasp": "A03:2021 Injection",
        "mitre": [("T1059.004", "Command and Scripting Interpreter: Unix Shell"),
                  ("T1190", "Exploit Public-Facing Application"),
                  ("T1005", "Data from Local System")],
        "events": ["command_execution", "command_injection_attempt"],
    },
    {
        "id": "rce-ssti", "title": "Campaign editor compiles input as a template",
        "category": "Remote Code Execution", "points": 200, "difficulty": "hard",
        "feature": "Marketing - customer email campaign preview",
        "entrypoints": ["/admin/campaigns/preview"],
        "artifact": "Application secrets and runtime configuration via the template engine",
        "flag": "MERIDIAN{c4mp41gn_pr3v13w_r34ch3d_runt1m3}",
        "summary": "Campaign bodies are rendered with the template engine instead of passed as data.",
        "hints": ["Merge fields are evaluated server-side.", "Try arithmetic in the braces first."],
        "owasp": "A03:2021 Injection",
        "mitre": [("T1059.006", "Command and Scripting Interpreter: Python"),
                  ("T1190", "Exploit Public-Facing Application")],
        "events": ["template_render", "ssti_attempt"],
    },
    {
        "id": "xxe-edi", "title": "Supplier EDI import resolves external entities",
        "category": "Injection", "points": 175, "difficulty": "hard",
        "feature": "Supplier integration - EDI manifest upload",
        "entrypoints": ["/api/v1/edi/manifest"],
        "artifact": "Server-side files disclosed through entity expansion",
        "flag": "MERIDIAN{3d1_1mp0rt_r34d_l0c4l_f1l3s}",
        "summary": "The EDI parser has DTD loading and entity resolution enabled.",
        "hints": ["Manifests are XML.", "SYSTEM identifiers accept file://."],
        "owasp": "A05:2021 Security Misconfiguration",
        "mitre": [("T1190", "Exploit Public-Facing Application"), ("T1005", "Data from Local System")],
        "events": ["xml_import", "xxe_attempt"],
    },
    {
        "id": "upload-unrestricted", "title": "Applicant uploads land in a browsable store",
        "category": "Insecure Design", "points": 150, "difficulty": "medium",
        "feature": "Careers - CV submission", "entrypoints": ["/careers/apply", "/uploads/"],
        "artifact": "Other applicants' documents, including an internal HR onboarding pack",
        "flag": "MERIDIAN{hr_0nb04rd1ng_p4ck_fr0m_upl04ds}",
        "summary": "No extension allow-list, no content inspection, and the store lists its contents.",
        "hints": ["It accepts whatever extension you give it.",
                  "Where does the file go, and who else can see it?"],
        "owasp": "A04:2021 Insecure Design",
        "mitre": [("T1505.003", "Server Software Component: Web Shell"),
                  ("T1105", "Ingress Tool Transfer")],
        "events": ["file_upload", "dangerous_upload", "uploaded_file_served"],
    },
    {
        "id": "jwt-none", "title": "Partner API accepts unsigned tokens",
        "category": "Authentication", "points": 175, "difficulty": "hard",
        "feature": "Partner API", "entrypoints": ["/api/v1/auth/token", "/api/v1/reports/financial"],
        "artifact": "Restricted quarterly financial report",
        "flag": "MERIDIAN{qu4rt3rly_f1n4nc14ls_uns1gn3d_t0k3n}",
        "summary": "Token verification honours the algorithm declared inside the token.",
        "hints": ["Read the token header, not only the payload.",
                  "The status page lists the algorithms accepted."],
        "owasp": "A07:2021 Identification and Authentication Failures",
        "mitre": [("T1550.001", "Use Alternate Authentication Material: Application Access Token"),
                  ("T1548", "Abuse Elevation Control Mechanism")],
        "events": ["jwt_verify", "jwt_unsigned_accepted", "privilege_change"],
    },
    {
        "id": "weak-session-secret", "title": "Session cookies signed with a known secret",
        "category": "Cryptographic Failure", "points": 200, "difficulty": "hard",
        "feature": "Staff administration area", "entrypoints": ["/admin"],
        "artifact": "Administration console and the disaster-recovery master code",
        "flag": "MERIDIAN{d1s4st3r_r3c0v3ry_m4st3r_c0d3}",
        "summary": "The signing secret is a default that appears in three places on the estate.",
        "hints": ["Session cookies here are signed, not encrypted - read yours.",
                  "The secret is written down somewhere on this site."],
        "owasp": "A02:2021 Cryptographic Failures",
        "mitre": [("T1110.002", "Brute Force: Password Cracking"),
                  ("T1550.004", "Use Alternate Authentication Material: Web Session Cookie")],
        "events": ["admin_panel_access", "forged_session_detected"],
    },
    {
        "id": "auth-bruteforce", "title": "Sign-in has no rate limit or lockout",
        "category": "Authentication", "points": 100, "difficulty": "easy",
        "feature": "Customer portal - sign in", "entrypoints": ["/portal/login"],
        "artifact": "The integration service account and its EDI transfer key",
        "flag": "MERIDIAN{3d1_tr4nsf3r_k3y_s3rv1c3_4cc0unt}",
        "summary": "Unlimited attempts, no delay, and a service account with a seasonal password.",
        "hints": ["The database export lists the account names.",
                  "Nobody is counting the failures."],
        "owasp": "A07:2021 Identification and Authentication Failures",
        "mitre": [("T1110.001", "Brute Force: Password Guessing"),
                  ("T1078.003", "Valid Accounts: Local Accounts")],
        "events": ["authentication_attempt", "brute_force_suspected"],
    },
    {
        "id": "reset-token", "title": "Password reset tokens are derived from the username",
        "category": "Cryptographic Failure", "points": 150, "difficulty": "medium",
        "feature": "Customer portal - password reset",
        "entrypoints": ["/portal/reset", "/api/v1/account/reset"],
        "artifact": "A finance contact's account, holding the banking amendment reference",
        "flag": "MERIDIAN{b4nk1ng_4m3ndm3nt_r3f_t4k30v3r}",
        "summary": "Reset tokens are a hash of the account name, so any account can be taken over.",
        "hints": ["Request a reset for your own account and look closely at the token.",
                  "Then do the same arithmetic for somebody else."],
        "owasp": "A02:2021 Cryptographic Failures",
        "mitre": [("T1110", "Brute Force"), ("T1556", "Modify Authentication Process")],
        "events": ["password_reset_request", "password_reset_consume", "account_takeover"],
    },
    {
        "id": "ssrf-metadata", "title": "Link preview fetches any URL the server can reach",
        "category": "Server-Side Request Forgery", "points": 175, "difficulty": "medium",
        "feature": "Content management - link preview", "entrypoints": ["/admin/integrations/preview"],
        "artifact": "Cloud instance role credentials from the metadata service",
        "flag": "MERIDIAN{1nst4nc3_r0l3_cr3ds_v14_pr3v13w}",
        "summary": "The preview tool resolves and fetches a client-supplied URL server-side.",
        "hints": ["Internal service names resolve from the server, not from you.",
                  "Cloud metadata lives on a well-known address."],
        "owasp": "A10:2021 Server-Side Request Forgery",
        "mitre": [("T1090", "Proxy"),
                  ("T1552.005", "Unsecured Credentials: Cloud Instance Metadata API")],
        "events": ["ssrf_probe"],
    },
    {
        "id": "logic-negative-quote", "title": "Quote accepts negative quantities",
        "category": "Business Logic", "points": 100, "difficulty": "easy",
        "feature": "Instant freight quote", "entrypoints": ["/services/quote", "/api/v1/quotes"],
        "artifact": "A credit note issued against the account, carrying its authorisation reference",
        "flag": "MERIDIAN{cr3d1t_n0t3_1ssu3d_n3g4t1v3_qty}",
        "summary": "Quantity and declared value are multiplied with no server-side validation.",
        "hints": ["Nothing checks the sign of a number.",
                  "What does the system do when the total comes out below zero?"],
        "owasp": "A04:2021 Insecure Design",
        "mitre": [("T1190", "Exploit Public-Facing Application"),
                  ("T1565.001", "Data Manipulation: Stored Data Manipulation")],
        "events": ["business_logic_abuse"],
    },
    {
        "id": "jndi-audit", "title": "Legacy audit shim evaluates lookup syntax in headers",
        "category": "Vulnerable Component", "points": 125, "difficulty": "medium",
        "feature": "Legacy tracking integration", "entrypoints": ["/api/v1/audit/event"],
        "artifact": "Audit subsystem service token, disclosed by the lookup",
        "flag": "MERIDIAN{4ud1t_sh1m_l00kup_s3rv1c3_t0k3n}",
        "summary": "A Log4j-era logging shim still expands lookup expressions in request headers.",
        "hints": ["The status page lists component versions.",
                  "The header is logged, not the body."],
        "owasp": "A06:2021 Vulnerable and Outdated Components",
        "mitre": [("T1190", "Exploit Public-Facing Application"),
                  ("T1203", "Exploitation for Client Execution")],
        "events": ["jndi_lookup_detected", "outdated_component_inventory"],
    },
]
# fmt: on

# Backwards-compatible alias: the harness and console were written against
# CHALLENGES before the site was reskinned.
CHALLENGES = FINDINGS
FINDINGS_BY_ID = {f["id"]: f for f in FINDINGS}
CHALLENGES_BY_ID = FINDINGS_BY_ID
FLAG_HASHES = {flag_hash(f["flag"]): f["id"] for f in FINDINGS}
TOTAL_POINTS = sum(f["points"] for f in FINDINGS)


def operator_catalog() -> list[dict]:
    """Full finding metadata. Operator console only - never served to a tester."""
    return [
        {k: v for k, v in f.items() if k != "flag"}
        for f in FINDINGS
    ]


def identify(submitted: str) -> str | None:
    """Return the finding id a submitted proof value belongs to, or None."""
    return FLAG_HASHES.get(flag_hash(submitted))
