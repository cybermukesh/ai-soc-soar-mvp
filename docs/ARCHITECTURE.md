# Architecture

## Product Positioning

The MVP is an AI alert-noise reduction and SOAR trigger layer. It starts with Wazuh because Wazuh is open source and demo-friendly, but all internal logic uses a normalized alert schema so future Splunk, Sentinel, Elastic, QRadar, and EDR connectors can be added without rewriting the agent.

## Logical Components

```mermaid
flowchart TD
    SIEM["SIEM Connectors"]
    Wazuh["Wazuh / OpenSearch"]
    API["FastAPI Backend"]
    Norm["Normalized Alert Schema"]
    Agent["LLM Triage Agent"]
    DB["SQLite/Postgres"]
    UI["React SOC UI"]
    SOAR["n8n / Shuffle"]
    Slack["Slack / Ticketing"]

    Wazuh --> SIEM
    SIEM --> API
    API --> Norm
    Norm --> Agent
    Agent --> DB
    DB --> UI
    API --> SOAR
    SOAR --> Slack
```

## MVP Modules

- `connectors`: SIEM/source-specific ingestion.
- `models`: normalized alert, triage decision, incident, SOAR action schemas.
- `agents`: LLM prompt construction and structured output validation.
- `services`: triage, incident grouping, SOAR dispatch, metrics.
- `api`: FastAPI route definitions.
- `db`: persistence and migrations.

## Design Guardrails

- Keep Wazuh-specific logic inside the Wazuh connector.
- Store raw alert separately from normalized fields.
- Never let raw log text directly control SOAR actions.
- Require analyst approval for response actions in MVP.
- Every AI decision should include evidence and confidence.
