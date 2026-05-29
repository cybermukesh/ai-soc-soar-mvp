# Day 4 AI Triage and Case Lifecycle

## Status

In progress, with the core triage and case lifecycle now functional.

Day 4 is no longer just a simple triage output. It now includes deeper analyst evidence, L2 investigation guidance, containment and resolution guidance, analyst feedback, and case-management fields required for SOC operations.

## AI Triage Implemented

- Structured decision model:
  - verdict
  - confidence
  - risk score
  - attack summary
  - evidence
  - MITRE tactics and techniques
  - SOAR recommendation
- Expanded analyst fields:
  - impacted entities
  - L2 investigation steps
  - containment steps
  - resolution criteria
  - analyst questions
  - recommended actions
- Cache-aware triage:
  - duplicate alert signatures avoid repeated triage work
  - force-refresh remains available for analyst-controlled retriage
- Triage review:
  - analyst disposition
  - analyst note
  - updated history view

## Case Lifecycle Implemented

- Incident model and event model.
- Incident APIs:
  - create
  - list
  - update status
  - list timeline events
  - add timeline event
- Alert-to-case workflow from the AI Triage Workbench.
- Case board phases:
  - New
  - Triage
  - Investigation
  - Response
  - Closed
- Case fields:
  - title
  - severity
  - risk score
  - source tool
  - alert ID
  - ticket reference
  - owner
  - phase
  - priority
  - SLA due time
  - escalation flag
  - close reason
  - resolution summary

## Frontend Implemented

- AI Triage Workbench:
  - triage table
  - selected alert detail
  - raw event access
  - evidence
  - impacted entities
  - L2 steps
  - recommended actions
  - containment
  - resolution criteria
  - analyst questions
  - feedback save form
  - raise-ticket action
- Case Management Board:
  - Jira-style phase columns
  - case creation form
  - filters
  - timeline loading
  - add event form
  - investigate/resolve actions
  - priority/SLA/escalation/resolution display
- UI polish:
  - Wazuh/Kibana-style operational dashboard
  - compact responsive navigation
  - stable card spacing
  - long alert IDs and event content wrap safely
  - duplicate React key issue fixed for repeated Wazuh alert IDs

## Backend Endpoints

| Endpoint | Purpose |
| --- | --- |
| `GET /triage/alerts/recent` | Triage recent persisted alerts. |
| `POST /triage/alert` | Triage one normalized alert. |
| `GET /triage/history` | Review triage decisions and analyst feedback. |
| `POST /triage/feedback` | Save analyst disposition and notes. |
| `GET /api/v1/incidents` | List/filter cases. |
| `POST /api/v1/incidents` | Create case. |
| `PATCH /api/v1/incidents/{id}/status` | Update case status, phase, owner, priority, SLA, escalation, resolution. |
| `GET /api/v1/incidents/{id}/events` | Read case timeline. |
| `POST /api/v1/incidents/{id}/events` | Add case timeline event. |

## Still Pending

- Strict confidence threshold policy.
- Prompt/template versioning for future LLM provider integration.
- Incident correlation and deduplication engine.
- Evidence attachments and investigation notebook.
- SLA timers and escalation automation.
- n8n/Shuffle SOAR dispatch with approval gates.

## Day 5 Handoff

Use Day 3 ingestion records plus Day 4 triage/case records to build grouping and noise-reduction metrics:

- group repeated alerts by asset, rule, source IP, user, and time window
- suppress duplicates safely
- promote repeated suspicious activity to cases
- show before/after alert reduction metrics
- preserve analyst override and audit history
