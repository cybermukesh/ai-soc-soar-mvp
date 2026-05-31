# n8n Workflows

This folder will hold exportable n8n workflows for MVP SOAR actions.

Initial MVP workflows:

- Slack notification for high-risk incident.
- Analyst approval request.
- Wazuh active-response placeholder.
- TheHive/Jira case creation placeholder.

## First Local Workflow

Run n8n on port `5678` so it does not conflict with:

- Wazuh API: `55000`
- OpenSearch: `9200`
- Wazuh dashboard: usually `443` or `8443`
- AI SOC backend: `8000`
- AI SOC frontend: `5174`

Recommended quick start:

```bash
docker volume create n8n_data
docker run -d --name n8n --restart unless-stopped \
  -p 5678:5678 \
  -e N8N_HOST=0.0.0.0 \
  -e N8N_PORT=5678 \
  -e N8N_PROTOCOL=http \
  -v n8n_data:/home/node/.n8n \
  n8nio/n8n:latest
```

Create a webhook workflow:

Option A: import the ready workflow:

1. Open n8n: `http://<automation-host>:5678`
2. Create the owner account.
3. Go to `Workflows` -> `Import from File`.
4. Import `soar/n8n/ai-soc-soar-action.workflow.json`.
5. Activate the workflow.
6. Copy the production webhook URL:
   `http://<automation-host>:5678/webhook/ai-soc-soar-action`

Option B: create the workflow manually:

- Webhook node
  - Method: `POST`
  - Path: `ai-soc-soar-action`
  - Response mode: `Using Respond to Webhook node`
- Code node
  - Return `status`, `workflow_execution_id`, `ticket_id`, `action`, `incident_id`, and `alert_id`
- Respond to Webhook node
  - Respond with JSON

```json
{
  "status": "accepted",
  "workflow_execution_id": "{{$execution.id}}",
  "ticket_id": ""
}
```

## Connect It To The MVP

Add this to `.env` on the machine running the FastAPI backend:

```bash
N8N_WEBHOOK_URL=http://<automation-host>:5678/webhook/ai-soc-soar-action
```

Restart the backend after saving `.env`.

Smoke test from the AI SOC app host:

```bash
curl -s -X POST 'http://<automation-host>:5678/webhook/ai-soc-soar-action' \
  -H 'Content-Type: application/json' \
  -d '{"incident_id":"demo-case-1","alert_id":"demo-alert-1","dry_run":true,"payload":{"requested_workflow":"notify"}}' | python3 -m json.tool
```

Expected response:

```json
{
  "status": "accepted",
  "workflow_execution_id": "...",
  "ticket_id": "demo-case-1",
  "action": "notify"
}
```

Containment workflows in the MVP are intentionally held as `pending_approval`
until an admin approves them from the Automation page.
