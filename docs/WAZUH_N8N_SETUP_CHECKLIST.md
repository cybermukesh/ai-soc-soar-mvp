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
- [ ] Port does not conflict with Wazuh/OpenSearch/app ports. Recommended: `5679`
- [ ] Docker installed on the Wazuh machine or another reachable automation host
- [ ] Webhook workflow created for SOAR action intake
- [ ] `N8N_WEBHOOK_URL` set
- [ ] Test webhook receives payload and returns success

### Quick n8n Docker Start

Run on the Wazuh machine or any reachable Linux host:

```bash
docker volume create n8n_data
docker run -d --name n8n --restart unless-stopped \
  -p 5679:5678 \
  -e N8N_HOST=0.0.0.0 \
  -e N8N_PORT=5678 \
  -e N8N_PROTOCOL=http \
  -v n8n_data:/home/node/.n8n \
  n8nio/n8n:latest
```

Open:

```text
http://<wazuh-or-automation-host-ip>:5679
```

Create one workflow:

- Trigger: Webhook
- Method: POST
- Path: `netrashield-soar-action`
- Response: JSON with `status`, `workflow_execution_id`, and optional `ticket_id`

The webhook URL will look like:

```text
http://<host>:5679/webhook/netrashield-soar-action
```

Share that URL with the app as `N8N_WEBHOOK_URL` for the first MVP demo.

## 4) App Readiness Checks

- [ ] `GET /api/v1/readiness/env` returns `ready=true`
- [ ] `GET /api/v1/connectors/setup/summary` shows `ready=true` for enabled connectors
- [ ] `GET /api/v1/connectors/{name}/health` is `ok=true`

## 5) Functional Smoke

- [ ] Login works (`/api/v1/auth/login`)
- [ ] Triage sample works (`/triage/sample`)
- [ ] Incident create/update works (`/api/v1/incidents`)
- [ ] `scripts/smoke_local.sh` returns `SMOKE_OK`
