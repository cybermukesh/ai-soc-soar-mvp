# AI SOC SOAR MVP

Low-cost AI SOC automation layer for Wazuh-first deployments, designed to become SIEM-agnostic.

## MVP Goal

Convert noisy SIEM alerts into prioritized, explainable incidents and trigger analyst-approved SOAR workflows through open-source automation.

## Core Flow

1. Ingest Wazuh/OpenSearch alerts.
2. Normalize alerts into a SIEM-agnostic schema.
3. Enrich with asset, identity, threat intel, MITRE, and history context.
4. Use an LLM triage agent to classify and summarize.
5. Group related alerts into incidents.
6. Show analyst-ready context in the UI.
7. Trigger n8n/Shuffle workflows with approval and audit logging.

## Repository Layout

```text
backend/          FastAPI backend
frontend/         React dashboard
codex-skills/     Project-specific Codex skills
data/             Demo Wazuh alerts and fixtures
docs/             Architecture and build notes
site/             7-day MVP progress website
soar/             n8n and Shuffle workflow templates
```

## 7-Day Build Plan

- Day 1: Architecture, repository setup, sample alerts, normalized schema.
- Day 2: Wazuh/OpenSearch connector and demo ingestion.
- Day 3: LLM triage agent with structured JSON output.
- Day 4: Incident grouping, risk scoring, and analyst feedback.
- Day 5: n8n/Shuffle workflow triggers and Slack demo.
- Day 6: React SOC dashboard and incident detail workflow.
- Day 7: Security review, demo polish, GitHub Pages progress site.

## Development

Backend and frontend commands will be added as the implementation is built.
