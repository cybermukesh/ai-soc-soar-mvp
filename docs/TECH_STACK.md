# Technology Stack

| Layer | Choice | Reason |
| --- | --- | --- |
| Backend | FastAPI | Fast Python APIs, connector work, schema support. |
| Frontend | React + Vite | Fast dashboard build with low setup overhead. |
| Data model | Pydantic | Shared normalized alert and decision contracts. |
| MVP storage | SQLite | Lowest-friction local demo storage. |
| Production storage | Postgres | Clean path for multi-user deployments. |
| SIEM source | Wazuh + OpenSearch | Open-source, low-cost, strong demo fit. |
| SOAR | n8n and Shuffle | Open-source workflow engines with webhook triggers. |
| Notifications | Slack | Fast analyst-facing demo channel. |
| AI provider | OpenAI gpt-4o-mini | Cheap Cloud default for structured triage. |

## Cheap Cloud Policy

- Use the smallest useful model by default.
- Do not fine-tune in the MVP.
- Send only normalized alert fields and compact context.
- Require JSON-only model output.
- Cache duplicate alert triage.
- Escalate low-confidence alerts to analysts instead of repeating model calls.
