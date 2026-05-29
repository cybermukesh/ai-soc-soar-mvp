# Day 3 Wazuh Pipeline

## Status

Completed for the current MVP sprint.

Day 3 now covers both connector operations and a real live-ingestion path. The tool can check Wazuh API health, check OpenSearch cluster health, fetch Wazuh alerts from OpenSearch, normalize them, persist them, run triage, and record an auditable ingestion run.

## What Was Built

### Connector Operations

- Connector persistence for Wazuh and OpenSearch.
- Connector fields: name, type, base URL, username, masked secret, enabled flag, last status, last error, latency, last checked time.
- Admin-only connector upsert endpoint with validation.
- Seed-from-env endpoint for quick local setup.
- Connector setup summary endpoint.
- Connector health history table.
- Connector audit trail for update, seed, and health-check actions.

### Live Connectivity

- Wazuh API probe:
  - token authentication
  - manager status check
- OpenSearch probe:
  - `_cluster/health`
  - cluster state returned in health detail

### Alert Ingestion

- OpenSearch query against the Wazuh alert index pattern.
- Wazuh hit normalization into the internal `NormalizedAlert` model.
- Persisted normalized alerts in the local runtime store.
- Live source summary now reports `opensearch:wazuh-alerts`.
- Error behavior:
  - `400` when credentials/config are missing
  - `502` when upstream OpenSearch query fails

### Auditable Sync Workflow

- `POST /api/v1/ingestion/wazuh/sync`
  - fetches OpenSearch Wazuh alerts
  - normalizes alert records
  - stores normalized alerts
  - runs triage when requested
  - records ingestion run statistics
- `GET /api/v1/ingestion/status`
  - stored alert count
  - triage record count
  - last run
  - run history
  - live source

## Verified Result

- Wazuh API health: manager status reachable.
- OpenSearch health: cluster green.
- Live sync run verified:
  - fetched 5 alerts
  - stored 5 alerts
  - triaged 5 alerts
  - recorded ingestion run `#1`

## Backend Endpoints

| Endpoint | Purpose |
| --- | --- |
| `GET /api/v1/connectors` | List configured connectors. |
| `PUT /api/v1/connectors/{name}` | Save connector configuration. |
| `GET /api/v1/connectors/wazuh/health` | Check Wazuh API token and manager status. |
| `GET /api/v1/connectors/opensearch/health` | Check OpenSearch cluster health. |
| `GET /api/v1/connectors/{name}/history` | Show connector health history. |
| `GET /alerts/wazuh/recent` | Fetch and persist recent Wazuh alerts from OpenSearch. |
| `POST /api/v1/ingestion/wazuh/sync` | Fetch, normalize, persist, triage, and audit a Wazuh sync run. |
| `GET /api/v1/ingestion/status` | Show ingestion status and run history. |

## Frontend Work

- Live Wazuh Ingestion panel on the executive dashboard.
- Sync button for admin/analyst users.
- Stored alert count, triage record count, last sync status, and live source visible.
- Connector page includes ingestion control and recent ingestion run history.
- Responsive dashboard layout polished for browser, tablet, and mobile.

## Day 4 Handoff

Day 4 consumes persisted normalized alerts and ingestion-triggered triage decisions. The next focus is stronger analyst triage, case creation, SLA/priority handling, and a richer investigation workflow.
