# Day 4-5 Engineering Backlog

This backlog converts judge feedback into implementation-grade work. The rule is simple: every visible control must have a backend path, persistent storage where needed, RBAC, audit evidence, and a verification command.

## Product Goal

Build a Wazuh-first AI SOC copilot that reduces alert noise, enriches important alerts, groups duplicates into analyst-ready incidents, and keeps a complete case-management trail for SOC operations.

## Secure Development Guardrails

- Keep this as a clean-room implementation. Do not copy source code, branding, secrets, users, credentials, or private identifiers from reference tools.
- Store secrets encrypted or masked. Never expose API keys, passwords, tokens, or connector passwords in API responses or frontend state.
- Enforce RBAC on every write path. Viewers can read operational state only.
- Add audit logs for config changes, connector checks, triage feedback, ticket/case mutations, and automation actions.
- Keep Wazuh as the first connector, but preserve the normalized alert schema for future SIEM sources.
- Use bounded pagination, limits, and filtering for flood conditions.
- Prefer batch operations and caching for alert floods; do not call LLMs per duplicate alert.

## Day 4 - AI Triage and Noise Reduction Core

### 4.1 Alert Flood Intake

- [x] Fetch Wazuh alerts from OpenSearch.
- [x] Normalize alerts into SIEM-agnostic objects.
- [x] Persist normalized alerts.
- [x] Record ingestion runs.
- [ ] Add time-range filters: 1H, 6H, 24H, 3D, 7D, 15D, 30D, 1Y.
- [ ] Add server-side pagination with `limit` and `offset`.
- [ ] Add filter fields: severity, rule id, agent, hostname, source IP, user, MITRE technique, text search.
- [ ] Add flood-safe sync controls: max batch size, skipped duplicate count, failed parse count, and duration.
- [ ] Add continuous ingestion mode with interval settings and last-run state.

Acceptance:

- A 500-alert sync returns within a bounded time, stores unique alerts, and records a run summary.
- UI can page through alerts without loading every record at once.
- Viewer role can inspect alerts, but cannot run ingestion.

### 4.2 Noise Reduction Engine

- [x] Produce verdict, confidence, risk score, signal score, noise score, queue, suppression decision, and suppression reason.
- [x] Correlate alerts using rule, asset, source IP, user, and source tool.
- [x] Return estimated analyst workload reduction.
- [x] Cache repeated triage signatures.
- [ ] Persist correlation groups as first-class objects.
- [ ] Track group counts, first seen, last seen, representative alert, and grouped alert ids.
- [ ] Promote repeated high-signal groups to incidents automatically when policy allows.
- [ ] Add feedback override so analyst verdicts influence future duplicate triage.
- [ ] Add explainability trail for every suppress/group/escalate decision.

Acceptance:

- For a noisy batch, UI shows raw alert count, suppressed count, grouped count, analyst items, and top reasons.
- Analysts can see why an alert was suppressed, grouped, or escalated.
- Re-running triage on the same duplicate set does not create unnecessary LLM calls.

### 4.3 Bring-Your-Own AI Configuration

- [x] Persist AI provider settings in DB.
- [x] Support OpenAI, Anthropic, Ollama, and disabled/offline heuristic mode.
- [x] Store provider API keys as encrypted secrets with masked display.
- [x] Add provider health/status check.
- [x] Add model limits: max input chars, max output tokens, min severity, cache enabled, stronger-model fallback.
- [x] Add UI settings page for AI model configuration.
- [ ] Make triage service read active settings from DB with env fallback.

Acceptance:

- Admin can save model settings without exposing secrets.
- Analyst can see active provider/model and whether cache is enabled.
- Viewer cannot modify settings.

## Day 5 - Enrichment, Cases, and Analyst Lifecycle

### 5.1 Threat Intelligence Enrichment

- [x] Persist threat intel provider settings.
- [x] Support VirusTotal, AbuseIPDB, OTX, MISP, and local IOC list.
- [x] Store API keys encrypted and masked.
- [x] Add provider health checks.
- [ ] Add IOC extraction from alert fields: IP, domain, hash, URL, username, host.
- [ ] Add enrichment cache with TTL to prevent API overuse.
- [ ] Show enrichment result in AI triage detail and case detail.

Acceptance:

- A triaged alert shows IOC reputation, matched source, confidence, and cache age.
- Missing API keys degrade gracefully without breaking triage.

### 5.2 Wazuh/Kibana-Style Analyst Views

- [ ] Add full alert table with column controls.
- [x] Add search and filter bar.
- [x] Add severity, verdict, queue, source, MITRE, and time filters.
- [ ] Add expandable raw JSON drawer.
- [ ] Add export for visible alert rows.
- [ ] Add saved views for common SOC filters.

Acceptance:

- L1 can quickly find high-priority alerts without opening raw OpenSearch.
- L2 can inspect normalized fields, raw event JSON, and triage evidence from one screen.

### 5.3 Case and Ticket Management

- [x] Create incident from triage.
- [x] Track owner, priority, SLA, escalation, phase, close reason, and resolution summary.
- [x] Add case events.
- [ ] Add comments, evidence links, and affected assets table.
- [ ] Add linked alerts and linked IOC records.
- [ ] Add SLA timers and breach state.
- [ ] Add workflow stages: New, Triage, Investigation, Containment, Eradication, Recovery, Closed.
- [x] Add ticket bridge payload for n8n webhook automation foundation.
- [ ] Add executive summary generation for closed cases.
- [ ] Add case analytics for 7 days, 15 days, 30 days, and 1 year.

Acceptance:

- Every case has a complete timeline from creation to closure.
- Every automated action and analyst note is auditable.
- Cases can be filtered by owner, status, severity, priority, SLA, and date range.

### 5.4 SOAR and Workflow Automation

- [ ] Prefer Shuffle for SOC-native workflow orchestration, keep n8n optional for broad integration use cases.
- [x] Add outbound webhook setting for n8n.
- [x] Add first workflow template: n8n test webhook with case/alert context.
- [ ] Add Shuffle connector settings.
- [ ] Add workflow templates: notify Slack, create ticket, disable account, block IP, isolate host, request approval.
- [ ] Add approval gate before destructive actions.
- [x] Add action log with request payload summary, response, actor, status, and timestamp.

Acceptance:

- Analysts can trigger a non-destructive test workflow from a case.
- Destructive workflows require explicit approval and are audit logged.

### 5.5 Deployment and Operations

- [ ] Add Dockerfile for backend.
- [ ] Add Dockerfile for frontend or static build.
- [ ] Add docker-compose for API, frontend, DB volume, and optional local Ollama.
- [ ] Add healthcheck endpoints for API, DB, connector readiness, and frontend.
- [ ] Add startup seed that is idempotent and does not erase persistent DB.
- [ ] Add CI checks for lint, tests, build, and Pages publish.

Acceptance:

- Restarting the app does not erase users, connectors, alerts, triage history, or cases.
- A new machine can run the MVP with documented commands.

## UI Rules

- Use a clean Wazuh/Kibana-style operational dashboard: dense, readable, low-noise.
- Avoid overlapping text, oversized marketing blocks, and decorative visuals.
- Every button must call a real function or be visibly disabled with a planned label.
- Mobile/tablet views must stack panels without horizontal overflow.
- Use icons for navigation and clear actions.

## Verification Matrix

- Backend health: `GET /health`
- Auth: login, `/me`, logout, register pending approval.
- RBAC: admin write allowed, analyst operational write allowed, viewer write blocked.
- Connectors: save, seed, health check, history.
- Ingestion: sync Wazuh/OpenSearch, persist alerts, run triage, record run.
- Triage: recent batch, noise reduction, feedback, cache.
- Cases: create, update, timeline, resolve.
- Settings: save AI provider, save threat intel provider, mask secrets, audit update.
- Frontend: no console crash, no layout overlap, successful API calls.
