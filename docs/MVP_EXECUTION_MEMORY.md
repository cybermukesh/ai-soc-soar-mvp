# MVP Execution Memory (Detailed)

This file is the working memory for implementation depth, sequencing, and done/pending subtasks.  
It is intentionally detailed and operational (not pitch-level).

## 1) Delivery Rules

- Build production-lean MVP behavior, not placeholder-only flows.
- Keep SIEM ingestion abstraction so Wazuh is first connector, not hard lock-in.
- Every major module must have:
  - API contract
  - RBAC guard
  - audit trace for write/ops actions
  - observable status in UI
- Token budget discipline:
  - compact context to LLM
  - JSON-only output
  - cache duplicate triage decisions
  - avoid retriage unless forced.

## 2) Day-by-Day Detailed Subtasks

## Day 2 (Completed) - Platform Foundation

### Auth and RBAC
- [x] user/role model
- [x] JWT login
- [x] session auth check endpoint (`/api/v1/auth/me`)
- [x] role guard helpers for `admin`, `analyst`, `viewer`
- [x] default admin seed

### Admin and Governance
- [x] create/list users
- [x] activate/deactivate users
- [x] audit log table
- [x] audit listing endpoint with filters

### Backend Baseline
- [x] persistent SQLite path and session management
- [x] startup migration-safe table evolution for key columns
- [x] `/health` and baseline app boot checks

### Frontend Baseline
- [x] login flow + token persistence
- [x] role-aware navigation shell
- [x] admin user management screen

## Day 3 (Completed) - Wazuh Connector Operations

### Connector Data Model + APIs
- [x] connector persistence (name/type/url/user/masked secret/enabled)
- [x] seed connector configs from env
- [x] connector setup summary endpoint
- [x] connector health history persistence

### Secure Connector Handling
- [x] encrypted password storage path
- [x] masked secret display
- [x] validation for enabled connectors (url/user/password rules)

### Live Connectivity Probes
- [x] Wazuh API probe:
  - [x] authenticate token endpoint
  - [x] manager status endpoint
- [x] OpenSearch probe:
  - [x] cluster health endpoint
- [x] connector health endpoint wired to live probe results

### Live Alert Ingestion Path
- [x] recent alerts fetch from OpenSearch index
- [x] normalize Wazuh hits into internal schema
- [x] persist normalized alerts
- [x] return dashboard-ready summary and alert list
- [x] hardened error behavior (`400` missing config / `502` upstream query failure)
- [x] live-source summary label fixed to `opensearch:wazuh-alerts`
- [x] auditable ingestion run table (`ingestion_runs`)
- [x] one-click Wazuh sync API (`POST /api/v1/ingestion/wazuh/sync`)
- [x] ingestion status API (`GET /api/v1/ingestion/status`)
- [x] sync path fetches, normalizes, persists, triages, and records run stats
- [x] verified live sync run: fetched 5, stored 5, triaged 5

### UI for Connectors
- [x] connector list and save form
- [x] health check action
- [x] health history display
- [x] improved connector status readability (status pills, latency/check detail)
- [x] dashboard Live Wazuh Ingestion panel
- [x] connector page ingestion control and run history
- [x] persistent alert count shown when row fetch is still loading

## Day 4 (In Progress) - Triage + Incident Depth

### AI Triage Engine
- [x] triage endpoints for single and sample batch
- [x] verdict/confidence/risk/recommendation structured output
- [x] duplicate triage cache hook
- [x] impacted entities field
- [x] L2 investigation steps field
- [x] containment steps field
- [x] resolution criteria field
- [x] analyst questions field
- [x] recommended actions shown in UI
- [x] raw event visibility in triage detail
- [x] analyst feedback/disposition save flow
- [ ] confidence threshold routing policy (strict escalation logic)
- [ ] prompt template versioning + deterministic fallback path

### Incident Lifecycle
- [x] incident schema and incident events schema
- [x] create/list/status update APIs
- [x] timeline retrieval endpoint
- [x] incident panel in dashboard
- [x] alert-to-case handoff from triage
- [x] owner field
- [x] ticket reference field
- [x] priority field
- [x] SLA due field
- [x] escalation flag
- [x] close reason field
- [x] resolution summary field
- [x] case board phase buckets: New, Triage, Investigation, Response, Closed
- [ ] richer timeline tagging (analysis/action/system)
- [ ] case comments with structured evidence attachments

### UI Improvements (Current Sprint)
- [x] overview KPI cards
- [x] clearer connector cards and status
- [x] Wazuh/Kibana-style responsive UI polish
- [x] compact mobile/tablet navigation
- [x] duplicate React key fix for repeated Wazuh alert IDs
- [x] case cards show priority, owner, SLA, escalation, and resolution
- [ ] incident table sorting/paging
- [ ] explicit severity/risk chips in incident rows
- [ ] timeline panel grouping by event_type

## Day 5 (Planned) - Grouping + Noise Reduction Metrics

### Incident Grouping Logic
- [ ] grouping key strategy (asset+rule+window+src)
- [ ] dedupe window and merge policy
- [ ] promotion rule from repeated suspicious alerts to incident

### Noise Reduction Metrics
- [ ] baseline raw alert count
- [ ] suppressed/merged/retriaged counters
- [ ] before/after dashboard section for judge evidence

### Analyst Feedback Loop
- [ ] false-positive feedback endpoint
- [ ] feedback to triage cache override
- [ ] explainability log for why grouped/suppressed

## Day 6 (Planned) - SOAR Execution Controls

### SOAR Integration
- [ ] workflow dispatch service (n8n/Shuffle selectable)
- [ ] outbound request signing/secret handling
- [ ] execution logs persisted

### Human-in-the-Loop Controls
- [ ] approval gate for high-impact actions
- [ ] per-severity auto/approval policy
- [ ] retry/backoff + dead-letter tracking

### UI
- [ ] runbook action panel in incident detail
- [ ] execution status timeline (queued/running/success/fail)

## Day 7 (Planned) - Demo Readiness + Security Hardening

### Demo Packaging
- [ ] scripted demo flow with fixed data checkpoints
- [ ] screenshots and short walkthrough notes
- [ ] judge-facing result board (alert reduction, MTTR proxy, automation counts)

### Security + Reliability
- [ ] dependency check + lock cleanup
- [ ] API input validation review
- [ ] auth policy sanity checks and least-privilege pass
- [ ] final RBAC walkthrough tests

## 3) MVP Validation Checklist (Operational)

- [x] backend boots with env and responds on `/health`
- [x] login with default admin works
- [x] Wazuh health probe returns reachable
- [x] OpenSearch health probe returns cluster state
- [x] recent alerts endpoint returns normalized records
- [x] connectors and incidents visible in UI
- [ ] full SOAR execution path tested with webhook targets
- [ ] Day 5 metrics visible in dashboard

## 4) Command Memory (Runbook)

Backend:
```bash
cd /Users/mukeshkumarrao/Documents/Codex/ai-soc-soar-mvp
set -a && source .env && set +a
python3 -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --app-dir backend
```

Frontend:
```bash
cd /Users/mukeshkumarrao/Documents/Codex/ai-soc-soar-mvp/frontend
npm install
npm run dev
```

Health smoke:
```bash
APP_TOKEN=$(curl -s -X POST 'http://localhost:8000/api/v1/auth/login' \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@aisocmvp.com","password":"admin123"}' | python3 -c 'import sys,json; print(json.load(sys.stdin)["access_token"])')

curl -s -H "Authorization: Bearer $APP_TOKEN" 'http://localhost:8000/api/v1/connectors/wazuh/health'
curl -s -H "Authorization: Bearer $APP_TOKEN" 'http://localhost:8000/api/v1/connectors/opensearch/health'
curl -s -H "Authorization: Bearer $APP_TOKEN" 'http://localhost:8000/alerts/wazuh/recent?limit=3'
curl -s -X POST -H "Authorization: Bearer $APP_TOKEN" 'http://localhost:8000/api/v1/ingestion/wazuh/sync?limit=5&triage=true'
curl -s -H "Authorization: Bearer $APP_TOKEN" 'http://localhost:8000/api/v1/ingestion/status'
```
