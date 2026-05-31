# NetraShield Final Judge Demo Checklist

Use this when cloning the repo onto the Wazuh/n8n server at `5.189.170.179`.

## 1. Demo Story In 60 Seconds

NetraShield is a low-cost alert clarity layer for Wazuh-first SOC teams. It
reduces analyst noise by normalizing alerts, grouping duplicates, scoring
signal/noise, enriching public IOCs, using low-token LLM triage only where it
adds value, and turning real alerts into cases and approval-gated n8n SOAR
actions.

Target users:

- SMEs, MSMEs, startups, and small MSSPs.
- ISO 27001 readiness teams needing centralized logging and monitoring evidence.
- Indian businesses preparing for stronger privacy and security governance.

Core claim:

- Enterprise SIEM/SOAR AI is expensive and infrastructure-heavy.
- Smaller SOC teams need self-hostable, privacy-aware, low-token automation.
- NetraShield targets 70-80% L1 queue reduction for repetitive alert categories
  after analyst validation and tuning.

## 2. Clone And Configure

```bash
git clone https://github.com/cybermukesh/ai-soc-soar-mvp.git
cd ai-soc-soar-mvp
cp .env.example .env
```

In `.env`, set:

```bash
JWT_SECRET=<long-random-secret>
WAZUH_API_URL=https://5.189.170.179:55000
WAZUH_API_USER=<wazuh-api-user>
WAZUH_API_PASSWORD=<wazuh-api-password>
OPENSEARCH_URL=https://5.189.170.179:9200
OPENSEARCH_USER=<opensearch-user>
OPENSEARCH_PASSWORD=<opensearch-password>
N8N_WEBHOOK_URL=http://5.189.170.179:5679/webhook/netrashield-soar-action
VIRUSTOTAL_API_KEY=<optional>
ABUSEIPDB_API_KEY=<optional>
OTX_API_KEY=<optional>
```

Do not commit `.env`.

## 3. Start Backend

```bash
python3 -m venv backend/.venv
source backend/.venv/bin/activate
pip install --upgrade pip
pip install -e backend
python3 -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --app-dir backend
```

Check:

```bash
curl -s http://127.0.0.1:8000/health
```

## 4. Start Frontend

```bash
cd frontend
cp .env.example .env
printf 'VITE_API_BASE_URL=http://5.189.170.179:8000\n' > .env
npm install
npm run dev -- --host 0.0.0.0 --port 5174
```

Open:

```text
http://5.189.170.179:5174
```

Default MVP login:

```text
admin@aisocmvp.com / admin123
```

## 5. Validate API From Server

```bash
APP_TOKEN=$(curl -s -X POST 'http://127.0.0.1:8000/api/v1/auth/login' \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@aisocmvp.com","password":"admin123"}' \
  | python3 -c 'import sys,json; print(json.load(sys.stdin)["access_token"])')

curl -s -H "Authorization: Bearer $APP_TOKEN" \
  'http://127.0.0.1:8000/api/v1/connectors/wazuh/health' | python3 -m json.tool

curl -s -H "Authorization: Bearer $APP_TOKEN" \
  'http://127.0.0.1:8000/api/v1/connectors/opensearch/health' | python3 -m json.tool
```

## 6. Demo Flow

1. Login and show executive dashboard.
2. Open Connectors and show Wazuh/OpenSearch health.
3. Run Wazuh sync with triage enabled.
4. Open AI Triage and show verdict, confidence, evidence, suppression reason,
   investigation steps, containment steps, and raw event view.
5. Run threat-intel enrichment on an alert.
6. Raise a case and show lifecycle/SLA/owner fields.
7. Trigger n8n dry-run workflow.
8. Show audit/admin settings and RBAC.
9. Open the pitch deck and explain cost/privacy/compliance wedge.

## 7. Editable Pitch Deck

- PPTX: `docs/pitch/NetraShield_MVP_Judge_Deck.pptx`
- Contact sheet: `docs/pitch/NetraShield_MVP_Judge_Deck_contact_sheet.png`

## 8. Judge Talk Track

- Pain: SOC analysts waste time on duplicate and low-context alerts.
- Gap: AI SIEM products exist, but are often expensive and token-heavy.
- Wedge: Wazuh-first, self-hosted AI triage for cost-sensitive SOC teams.
- Differentiator: reduce calls before AI with grouping, local model fallback,
  compact prompts, cache, public IOC enrichment, and case workflow.
- India angle: privacy-aware operations for DPDP-era security monitoring and
  ISO 27001 logging/monitoring evidence.
- Business: low product price plus customer-owned infra and optional token usage.
- Future: SIEM-agnostic connectors, MSSP multi-tenancy, Postgres, HTTPS, SSO,
  closed-loop analyst feedback, and stronger local LLM tuning.

## 9. Last-Minute Troubleshooting

- n8n SSL error: open `http://5.189.170.179:5679`, not HTTPS.
- Frontend API failure: confirm `frontend/.env` has
  `VITE_API_BASE_URL=http://5.189.170.179:8000`.
- OpenSearch 403 on cluster health: use alert-index health or admin credentials.
- No alerts: confirm `wazuh-alerts-*` has data in OpenSearch, then run sync.
- Threat intel failures: keys may be rate-limited or invalid; local IOC
  enrichment still works.
