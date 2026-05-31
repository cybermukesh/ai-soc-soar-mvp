---
name: soar-integration
description: Use when integrating n8n, Shuffle, Slack, TheHive, Jira, Wazuh active response, or SOAR workflow triggers for the NetraShield MVP.
---

# SOAR Integration

SOAR execution is a controlled dispatch layer. The MVP sends workflow requests to n8n or Shuffle and records the result.

## MVP Actions

- Slack notification.
- Create case placeholder.
- Block IP placeholder.
- Analyst approval request.

## Guardrails

- Use webhook calls for n8n/Shuffle.
- Include `incident_id`, `alert_id`, `risk_score`, `verdict`, `summary`, and `recommended_action`.
- Require explicit approval for containment actions.
- Log request payload, response status, actor, and timestamp.
