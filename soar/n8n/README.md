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

- Method: `POST`
- Path: `ai-soc-soar-action`
- Response body:

```json
{
  "status": "accepted",
  "workflow_execution_id": "{{$execution.id}}",
  "ticket_id": ""
}
```
