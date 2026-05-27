#!/usr/bin/env bash
set -euo pipefail
API_BASE="${API_BASE:-http://localhost:8000}"
EMAIL="${SMOKE_EMAIL:-admin@aisocmvp.com}"
PASS="${SMOKE_PASSWORD:-admin123}"

login_json=$(curl -sS -X POST "$API_BASE/api/v1/auth/login" -H 'Content-Type: application/json' -d "{\"email\":\"$EMAIL\",\"password\":\"$PASS\"}")
TOKEN=$(printf '%s' "$login_json" | python3 -c "import json,sys; print(json.load(sys.stdin).get('access_token',''))")
[ -n "$TOKEN" ] || { echo "login failed: $login_json"; exit 1; }
H=( -H "Authorization: Bearer $TOKEN" )

curl -sS "$API_BASE/api/v1/connectors" "${H[@]}" >/dev/null
curl -sS "$API_BASE/triage/sample" "${H[@]}" >/dev/null

incident_json=$(curl -sS -X POST "$API_BASE/api/v1/incidents" "${H[@]}" -H 'Content-Type: application/json' -d '{"title":"Smoke incident","severity":"medium","risk_score":55,"source_tool":"wazuh"}')
IID=$(printf '%s' "$incident_json" | python3 -c "import json,sys; print(json.load(sys.stdin).get('id',''))")
[ -n "$IID" ] || { echo "incident create failed: $incident_json"; exit 1; }

curl -sS -X PATCH "$API_BASE/api/v1/incidents/$IID/status" "${H[@]}" -H 'Content-Type: application/json' -d '{"status":"investigating","note":"smoke"}' >/dev/null
curl -sS "$API_BASE/api/v1/incidents/$IID/events" "${H[@]}" >/dev/null

echo "SMOKE_OK incident_id=$IID"
