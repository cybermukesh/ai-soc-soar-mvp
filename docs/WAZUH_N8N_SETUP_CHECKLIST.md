# Wazuh + n8n Manual Setup Checklist

Use this checklist before switching from sample data to live pipeline mode.

## 1) Wazuh Manager

- [ ] Wazuh manager reachable from app host
- [ ] `WAZUH_API_URL` set (e.g., `https://<host>:55000`)
- [ ] `WAZUH_API_USER` set
- [ ] `WAZUH_API_PASSWORD` set

## 2) OpenSearch

- [ ] OpenSearch reachable from app host
- [ ] `OPENSEARCH_URL` set (e.g., `https://<host>:9200`)
- [ ] `OPENSEARCH_USER` set
- [ ] `OPENSEARCH_PASSWORD` set
- [ ] `OPENSEARCH_ALERT_INDEX` verified (default `wazuh-alerts-*`)

## 3) n8n

- [ ] n8n instance running
- [ ] Webhook workflow created for SOAR action intake
- [ ] `N8N_WEBHOOK_URL` set
- [ ] Test webhook receives payload and returns success

## 4) App Readiness Checks

- [ ] `GET /api/v1/readiness/env` returns `ready=true`
- [ ] `GET /api/v1/connectors/setup/summary` shows `ready=true` for enabled connectors
- [ ] `GET /api/v1/connectors/{name}/health` is `ok=true`

## 5) Functional Smoke

- [ ] Login works (`/api/v1/auth/login`)
- [ ] Triage sample works (`/triage/sample`)
- [ ] Incident create/update works (`/api/v1/incidents`)
- [ ] `scripts/smoke_local.sh` returns `SMOKE_OK`
