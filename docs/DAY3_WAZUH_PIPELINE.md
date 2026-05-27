# Day 3 Wazuh Pipeline

## Status

Complete for MVP demo mode. The product now has a working Wazuh alert pipeline using sample fixtures and a live-ready OpenSearch connector for real Wazuh deployments.

## What Was Built

- Four Wazuh sample alerts covering auth failure, malware, cloud root login, and network scan scenarios.
- Wazuh raw-alert normalizer that maps rule, asset, user, network, MITRE, severity, and raw event fields.
- FastAPI endpoints for normalized sample alerts and one-off raw alert normalization.
- OpenSearch connector for `wazuh-alerts-*` searches when credentials are available.
- React dashboard preview showing normalized alert rows, severity, asset, source IP, and MITRE technique.

## Backend Endpoints

| Endpoint | Purpose |
| --- | --- |
| `GET /alerts/sample` | Demo summary plus normalized Wazuh sample alerts. |
| `GET /alerts/normalized` | Normalized alert list for the dashboard. |
| `POST /alerts/normalize` | Convert one raw Wazuh alert payload to normalized schema. |
| `GET /alerts/wazuh/recent` | Fetch recent alerts from OpenSearch when credentials are configured. |

## Day 4 Handoff

Day 4 should consume only `NormalizedAlert` objects, use compact JSON prompts, cache duplicate alert verdicts, and return structured triage decisions with evidence, confidence, risk score, MITRE context, and safe recommended actions.
