# Build Sequence

## Day 1 - Complete

- Validate market pain and startup positioning.
- Narrow the idea to Wazuh-first AI alert-noise reduction.
- Create repo structure, progress site, and initial skeletons.

## Day 2 - Complete

- Define product plan and MVP boundaries.
- Document architecture and stack decisions.
- Create Codex skills for architecture, Wazuh, LLM triage, SOAR, and security.
- Confirm normalized schema direction.
- Add Day 2 status to public site and local dashboard skeleton.

## Day 3 - Wazuh Pipeline

1. Run or connect a Wazuh deployment.
2. Validate Wazuh API and OpenSearch credentials.
3. Fetch recent alerts from OpenSearch.
4. Normalize alert fields into NormalizedAlert.
5. Store or serve fetched alerts through the backend.
6. Display normalized alerts on the MVP dashboard.

## Day 4 - AI Triage

Add low-cost LLM adapter, compact prompts, strict JSON output, and audit records.

## Day 5 - Incidents And Feedback

Group related alerts and track duplicate suppression/noise metrics.

## Day 6 - SOAR And UI

Add approval-gated n8n and Shuffle webhook dispatch plus Slack notification.

## Day 7 - Demo Polish

Run security review, prepare metrics, screenshots, and final pitch story.
