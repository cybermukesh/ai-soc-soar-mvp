---
name: wazuh-connector
description: Use when building or modifying Wazuh/OpenSearch ingestion, Wazuh alert normalization, sample Wazuh fixtures, or connector tests for the NetraShield MVP.
---

# Wazuh Connector

Wazuh is the first SIEM connector, not the core data model.

## Mapping Rules

- `rule.level` maps to `severity_score`.
- `rule.id`, `rule.description`, and `rule.groups` map to `rule`.
- `agent.id`, `agent.name`, and `agent.ip` map to `asset`.
- `data.srcip`, `data.src_ip`, `data.dstip`, and `data.dst_ip` map to `network`.
- `data.srcuser`, `data.dstuser`, or `data.user` map to `user`.
- `rule.mitre.id` and `rule.mitre.tactic` map to `mitre`.
- Preserve the full original event in `raw_event`.

## Validation

Add tests with at least one auth failure, malware, cloud, and network alert fixture before changing connector behavior.
