---
name: ai-soc-architecture
description: Use when designing or modifying the NetraShield MVP architecture, including SIEM-agnostic connector boundaries, normalized alert schema, incident workflow, SOAR approvals, and product scope.
---

# NetraShield Architecture

Keep the product Wazuh-first but SIEM-agnostic. Wazuh-specific parsing belongs only in connectors. Core services should consume normalized alerts.

## Workflow

1. Confirm the change fits the MVP wedge: alert noise reduction, explainable triage, incident grouping, or SOAR trigger.
2. Preserve the normalized alert schema as the boundary between connectors and AI logic.
3. Require analyst approval for any response action during MVP.
4. Store raw events separately from normalized fields.
5. Include auditability: evidence, confidence, actor, timestamp, action status.

## Avoid

- Vendor-specific fields leaking into triage prompts.
- Autonomous destructive response actions.
- Building a SIEM, workflow editor, or full case-management suite inside the MVP.
