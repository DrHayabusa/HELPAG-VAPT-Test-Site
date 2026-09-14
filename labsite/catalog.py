"""Single source of truth for CTF challenges, flags, MITRE mapping and detections.

Every challenge entry drives the scoreboard UI, the flag checker, the generated
challenge index and the Splunk detection documentation. Add challenges here.
"""

from __future__ import annotations

import hashlib

FLAG_PREFIX = "HELPAG"


def flag_hash(value: str) -> str:
    return hashlib.sha256(value.strip().encode("utf-8")).hexdigest()


# fmt: off
CHALLENGES: list[dict] = [
    {
        "id": "recon-robots", "title": "Crawl Before You Walk", "category": "Recon",
        "points": 50, "difficulty": "easy",
        "flag": "HELPAG{r0b0ts_txt_1s_n0t_4cc3ss_c0ntr0l}",
        "blurb": "The site politely asks crawlers to stay out of somewhere interesting.",
        "hints": ["Well-behaved bots read one file first.", "Disallow is a signpost, not a lock."],
        "entrypoints": ["/robots.txt", "/internal/engineering-notes.txt"],
        "owasp": "A01:2021 Broken Access Control",
        "mitre": [("T1595.003", "Active Scanning: Wordlist Scanning"),
                  ("T1592.002", "Gather Victim Host Information: Software")],
        "events": ["recon_hidden_path"],
    },
    {
        "id": "misconfig-debug", "title": "Debug Mode Left On", "category": "Misconfiguration",
        "points": 50, "difficulty": "easy",
        "flag": "HELPAG{d3bug_3ndp01nt_sh1pp3d_t0_pr0d}",
        "blurb": "A developer convenience endpoint survived the release.",
        "hints": ["Try the paths a framework template would create.", "/api/debug/..."],
        "entrypoints": ["/api/debug/config"],
        "owasp": "A05:2021 Security Misconfiguration",
        "mitre": [("T1592", "Gather Victim Host Information"),
                  ("T1213", "Data from Information Repositories")],
        "events": ["debug_endpoint_access"],
    },
    {
        "id": "misconfig-dotenv", "title": "Twelve Factor, Zero Secrets", "category": "Misconfiguration",
        "points": 100, "difficulty": "easy",
        "flag": "HELPAG{d0t3nv_s3rv3d_fr0m_w3br00t}",
        "blurb": "Environment configuration is not meant to be a web asset.",
        "hints": ["Dotfiles are still files.", "Content negotiation will not save you."],
        "entrypoints": ["/.env"],
        "owasp": "A05:2021 Security Misconfiguration",
        "mitre": [("T1552.001", "Unsecured Credentials: Credentials In Files"),
                  ("T1595.003", "Active Scanning: Wordlist Scanning")],
        "events": ["sensitive_file_access"],
    },
    {
        "id": "misconfig-backups", "title": "Backup Season", "category": "Misconfiguration",
        "points": 75, "difficulty": "easy",
        "flag": "HELPAG{b4ckup_f1l3_l3ft_b3h1nd}",
        "blurb": "Someone made a copy before the migration and never cleaned up.",
        "hints": ["Directory listing is enabled somewhere.", "Look for an archive folder."],
        "entrypoints": ["/backups/", "/backups/site-config.bak"],
        "owasp": "A05:2021 Security Misconfiguration",
        "mitre": [("T1595.003", "Active Scanning: Wordlist Scanning"),
                  ("T1530", "Data from Cloud Storage")],
        "events": ["directory_listing_access", "sensitive_file_access"],
    },
    {
        "id": "access-idor", "title": "Someone Else's Record", "category": "Access Control",
        "points": 75, "difficulty": "easy",
        "flag": "HELPAG{1d0r_h0r1z0nt4l_3num3r4t10n}",
        "blurb": "User records are addressable by integer and nobody checks ownership.",
        "hints": ["Enumerate the id.", "The interesting account is not id 1 or 2."],
        "entrypoints": ["/api/users/<id>"],
        "owasp": "A01:2021 Broken Access Control",
        "mitre": [("T1190", "Exploit Public-Facing Application"),
                  ("T1087", "Account Discovery")],
        "events": ["broken_access_attempt"],
    },
    {
        "id": "access-massassign", "title": "Privilege By Parameter", "category": "Access Control",
        "points": 125, "difficulty": "medium",
        "flag": "HELPAG{m4ss_4ss1gnm3nt_r0l3_0v3rwr1t3}",
        "blurb": "The profile update endpoint binds whatever JSON you send.",
        "hints": ["What field would the server rather you did not control?",
                  "Send role alongside the fields the UI sends."],
        "entrypoints": ["/api/profile/update"],
        "owasp": "A01:2021 Broken Access Control",
        "mitre": [("T1548", "Abuse Elevation Control Mechanism"),
                  ("T1098", "Account Manipulation")],
        "events": ["mass_assignment_attempt", "privilege_change"],
    },
    {
        "id": "inject-sqli-union", "title": "Union of Concerned Tables", "category": "Injection",
        "points": 150, "difficulty": "medium",
        "flag": "HELPAG{un10n_s3l3ct_dump3d_th3_fl4g_t4bl3}",
        "blurb": "Product search concatenates your input straight into SQL.",
        "hints": ["Three columns come back.", "sqlite_master knows every table name."],
        "entrypoints": ["/api/products/search?q="],
        "owasp": "A03:2021 Injection",
        "mitre": [("T1190", "Exploit Public-Facing Application"),
                  ("T1213", "Data from Information Repositories")],
        "events": ["sql_query", "sql_error"],
    },
    {
        "id": "inject-sqli-auth", "title": "The Password Is Irrelevant", "category": "Injection",
        "points": 125, "difficulty": "medium",
        "flag": "HELPAG{sql_4uth_byp4ss_t4ut0l0gy}",
        "blurb": "The legacy login builds its WHERE clause by hand.",
        "hints": ["A tautology always matches.", "Comment out the rest of the statement."],
        "entrypoints": ["/api/legacy/login"],
        "owasp": "A03:2021 Injection",
        "mitre": [("T1190", "Exploit Public-Facing Application"),
                  ("T1078", "Valid Accounts")],
        "events": ["sql_query", "authentication_attempt"],
    },
    {
        "id": "xss-reflected", "title": "Mirror Mirror", "category": "Cross-Site Scripting",
        "points": 75, "difficulty": "easy",
        "flag": "HELPAG{r3fl3ct3d_xss_1nt0_th3_d0m}",
        "blurb": "Your name comes back in the page exactly as you typed it.",
        "hints": ["No encoding on output.", "A script tag or an event handler both work."],
        "entrypoints": ["/reflect?name="],
        "owasp": "A03:2021 Injection",
        "mitre": [("T1059.007", "Command and Scripting Interpreter: JavaScript"),
                  ("T1189", "Drive-by Compromise")],
        "events": ["xss_probe"],
    },
    {
        "id": "xss-stored", "title": "Message In A Bottle", "category": "Cross-Site Scripting",
        "points": 100, "difficulty": "medium",
        "flag": "HELPAG{st0r3d_xss_p3rs1sts_f0r_3v3ry0n3}",
        "blurb": "The guestbook renders every entry as raw HTML, forever.",
        "hints": ["Persistence beats reflection.", "The admin reviews entries at /admin/review."],
        "entrypoints": ["/guestbook"],
        "owasp": "A03:2021 Injection",
        "mitre": [("T1059.007", "Command and Scripting Interpreter: JavaScript"),
                  ("T1505.003", "Server Software Component: Web Shell")],
        "events": ["stored_xss_persisted"],
    },
    {
        "id": "file-traversal", "title": "Directory Climbing", "category": "Path Traversal",
        "points": 125, "difficulty": "medium",
        "flag": "HELPAG{p4th_tr4v3rs4l_0uts1d3_th3_r00t}",
        "blurb": "The document downloader joins your filename onto a base path.",
        "hints": ["Relative paths escape.", "The flag store sits next to the document root."],
        "entrypoints": ["/api/documents/download?file="],
        "owasp": "A01:2021 Broken Access Control",
        "mitre": [("T1083", "File and Directory Discovery"),
                  ("T1005", "Data from Local System")],
        "events": ["path_traversal_attempt", "sensitive_file_access"],
    },
    {
        "id": "rce-cmdi", "title": "Ping Of Truth", "category": "Remote Code Execution",
        "points": 200, "difficulty": "hard",
        "flag": "HELPAG{c0mm4nd_1nj3ct10n_g4v3_m3_4_sh3ll}",
        "blurb": "A network diagnostics tool shells out to ping.",
        "hints": ["The host parameter is not sanitised.", "Shell metacharacters chain commands."],
        "entrypoints": ["/api/diagnostics/ping?host="],
        "owasp": "A03:2021 Injection",
        "mitre": [("T1059.004", "Command and Scripting Interpreter: Unix Shell"),
                  ("T1190", "Exploit Public-Facing Application"),
                  ("T1005", "Data from Local System")],
        "events": ["command_execution", "command_injection_attempt"],
    },
    {
        "id": "rce-ssti", "title": "Template Of Doom", "category": "Remote Code Execution",
        "points": 200, "difficulty": "hard",
        "flag": "HELPAG{j1nj4_sst1_r34ch3d_th3_runt1m3}",
        "blurb": "The newsletter previewer compiles your input as a template.",
        "hints": ["Test with 7*7 in braces.", "Jinja objects expose __globals__."],
        "entrypoints": ["/api/newsletter/preview?template="],
        "owasp": "A03:2021 Injection",
        "mitre": [("T1059.006", "Command and Scripting Interpreter: Python"),
                  ("T1190", "Exploit Public-Facing Application")],
        "events": ["template_render", "ssti_attempt"],
    },
    {
        "id": "inject-xxe", "title": "Entity Of Interest", "category": "Injection",
        "points": 175, "difficulty": "hard",
        "flag": "HELPAG{xx3_3xt3rn4l_3nt1ty_f1l3_r34d}",
        "blurb": "The supplier import parser resolves external entities.",
        "hints": ["Declare a DOCTYPE.", "file:// is a valid SYSTEM identifier."],
        "entrypoints": ["/api/suppliers/import"],
        "owasp": "A05:2021 Security Misconfiguration",
        "mitre": [("T1190", "Exploit Public-Facing Application"),
                  ("T1005", "Data from Local System")],
        "events": ["xml_import", "xxe_attempt"],
    },
    {
        "id": "upload-unrestricted", "title": "Drop It Like It's Hot", "category": "File Upload",
        "points": 150, "difficulty": "medium",
        "flag": "HELPAG{unr3str1ct3d_upl04d_w3bsh3ll}",
        "blurb": "The avatar uploader trusts the extension you give it.",
        "hints": ["No allow-list, no content inspection.", "Server-side script extensions are accepted."],
        "entrypoints": ["/api/upload"],
        "owasp": "A04:2021 Insecure Design",
        "mitre": [("T1505.003", "Server Software Component: Web Shell"),
                  ("T1105", "Ingress Tool Transfer")],
        "events": ["file_upload", "dangerous_upload"],
    },
    {
        "id": "auth-jwt-none", "title": "Algorithm: None", "category": "Authentication",
        "points": 175, "difficulty": "hard",
        "flag": "HELPAG{jwt_4lg_n0n3_4cc3pt3d_by_th3_4p1}",
        "blurb": "The API verifies JWTs using whatever algorithm the token asks for.",
        "hints": ["Read the header, not just the payload.", "An unsigned token is still a token."],
        "entrypoints": ["/api/token", "/api/admin/report"],
        "owasp": "A07:2021 Identification and Authentication Failures",
        "mitre": [("T1550.001", "Use Alternate Authentication Material: Application Access Token"),
                  ("T1548", "Abuse Elevation Control Mechanism")],
        "events": ["jwt_verify", "jwt_unsigned_accepted", "privilege_change"],
    },
    {
        "id": "auth-weak-secret", "title": "Sign Here Please", "category": "Authentication",
        "points": 200, "difficulty": "hard",
        "flag": "HELPAG{fl4sk_s3cr3t_w4s_1n_th3_w0rdl1st}",
        "blurb": "Session cookies are signed with a secret a wordlist already knows.",
        "hints": ["Flask sessions are signed, not encrypted.", "flask-unsign has a --wordlist flag."],
        "entrypoints": ["/admin/panel"],
        "owasp": "A02:2021 Cryptographic Failures",
        "mitre": [("T1110.002", "Brute Force: Password Cracking"),
                  ("T1550.004", "Use Alternate Authentication Material: Web Session Cookie")],
        "events": ["admin_panel_access", "forged_session_detected"],
    },
    {
        "id": "auth-bruteforce", "title": "No Lockout Policy", "category": "Authentication",
        "points": 100, "difficulty": "easy",
        "flag": "HELPAG{n0_r4t3_l1m1t_n0_l0ck0ut}",
        "blurb": "The login endpoint will answer as many times as you ask it to.",
        "hints": ["The service account uses a top-100 password.", "Count the failures - nobody else is."],
        "entrypoints": ["/api/login"],
        "owasp": "A07:2021 Identification and Authentication Failures",
        "mitre": [("T1110.001", "Brute Force: Password Guessing"),
                  ("T1078.003", "Valid Accounts: Local Accounts")],
        "events": ["authentication_attempt", "brute_force_suspected"],
    },
    {
        "id": "auth-reset-token", "title": "Predictable Reset", "category": "Authentication",
        "points": 150, "difficulty": "medium",
        "flag": "HELPAG{r3s3t_t0k3n_w4s_just_4n_md5}",
        "blurb": "Password reset tokens are derived from data you already have.",
        "hints": ["Request a reset for your own account and study the token.",
                  "Hash the username and try again for someone else."],
        "entrypoints": ["/api/password-reset/request", "/api/password-reset/consume"],
        "owasp": "A02:2021 Cryptographic Failures",
        "mitre": [("T1110", "Brute Force"), ("T1556", "Modify Authentication Process")],
        "events": ["password_reset_request", "password_reset_consume"],
    },
    {
        "id": "ssrf-metadata", "title": "Ask The Neighbour", "category": "SSRF",
        "points": 175, "difficulty": "medium",
        "flag": "HELPAG{ssrf_r34ch3d_th3_m3t4d4t4_s3rv1c3}",
        "blurb": "The link previewer fetches any URL the lab network can reach.",
        "hints": ["Internal service names resolve inside the lab network.",
                  "Cloud metadata lives on a well-known path."],
        "entrypoints": ["/api/fetch?url="],
        "owasp": "A10:2021 Server-Side Request Forgery",
        "mitre": [("T1090", "Proxy"), ("T1552.005", "Unsecured Credentials: Cloud Instance Metadata API")],
        "events": ["ssrf_probe"],
    },
    {
        "id": "logic-negative", "title": "Negative Nancy", "category": "Business Logic",
        "points": 100, "difficulty": "easy",
        "flag": "HELPAG{n3g4t1v3_qu4nt1ty_cr3d1t3d_m3}",
        "blurb": "Checkout multiplies quantity by price and asks no further questions.",
        "hints": ["Nothing validates the sign of a number.", "A negative total is still a total."],
        "entrypoints": ["/api/checkout"],
        "owasp": "A04:2021 Insecure Design",
        "mitre": [("T1190", "Exploit Public-Facing Application"),
                  ("T1565.001", "Data Manipulation: Stored Data Manipulation")],
        "events": ["business_logic_abuse"],
    },
    {
        "id": "inject-jndi", "title": "Lookup Not Found", "category": "Injection",
        "points": 125, "difficulty": "medium",
        "flag": "HELPAG{jnd1_l00kup_r34ch3d_th3_l0gg3r}",
        "blurb": "A legacy Java shim logs request headers through a lookup-aware formatter.",
        "hints": ["The vulnerable component is in /api/components.",
                  "The header is logged, not the body. Think Log4Shell."],
        "entrypoints": ["/api/legacy/audit"],
        "owasp": "A06:2021 Vulnerable and Outdated Components",
        "mitre": [("T1190", "Exploit Public-Facing Application"),
                  ("T1203", "Exploitation for Client Execution")],
        "events": ["jndi_lookup_detected", "outdated_component_inventory"],
    },
]
# fmt: on

CHALLENGES_BY_ID = {c["id"]: c for c in CHALLENGES}
FLAG_HASHES = {flag_hash(c["flag"]): c["id"] for c in CHALLENGES}
TOTAL_POINTS = sum(c["points"] for c in CHALLENGES)


def public_catalog() -> list[dict]:
    """Challenge metadata safe to send to a player's browser (no flag values)."""
    return [
        {
            "id": c["id"], "title": c["title"], "category": c["category"],
            "points": c["points"], "difficulty": c["difficulty"], "blurb": c["blurb"],
            "hints": c["hints"], "entrypoints": c["entrypoints"], "owasp": c["owasp"],
        }
        for c in CHALLENGES
    ]


def identify(submitted: str) -> str | None:
    """Return the challenge id a submitted flag belongs to, or None."""
    return FLAG_HASHES.get(flag_hash(submitted))
