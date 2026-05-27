# Day 2 Product Plan

## Goal

Convert the validated startup idea into a buildable MVP plan. Day 2 is complete when the repo clearly defines the product wedge, architecture, stack, skills, build sequence, and Day 3 Wazuh implementation inputs.

## Product Wedge

Build a Wazuh-first AI SOC/SOAR automation layer that reduces alert noise before analysts spend time on it. The first proof is not a generic chatbot. It is a workflow that ingests Wazuh alerts, normalizes them, triages them with a low-cost LLM, groups repeated alerts, and sends approval-gated SOAR actions.

## Target Users

- SMB security teams running Wazuh or a low-cost SIEM.
- MSSPs that need repeatable triage for multiple clients.
- SOC teams that cannot justify enterprise SOAR or AI-copilot pricing.

## MVP Boundaries

Included: Wazuh/OpenSearch connector, normalized alert schema, AI triage JSON, incident grouping, n8n/Shuffle webhook dispatch, Slack notification, and React dashboard.

Excluded: fine-tuning, autonomous destructive actions, full case-management replacement, SIEM building, workflow designer, billing, and multi-tenant admin.

## Day 3 Readiness Checklist

- Wazuh Manager URL and API credentials.
- OpenSearch URL, index pattern, and credentials.
- Sample alerts for auth failure, malware, cloud, and network events.
- Asset criticality mapping for demo hosts.
- Slack webhook or demo notification destination.
- n8n or Shuffle webhook endpoint for the first response workflow.
