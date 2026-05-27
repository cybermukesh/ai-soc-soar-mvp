# Normalized Alert Schema

```json
{
  "alert_id": "string",
  "source_tool": "wazuh",
  "timestamp": "2026-05-27T00:00:00Z",
  "severity": "low | medium | high | critical",
  "severity_score": 0,
  "rule": {
    "id": "string",
    "name": "string",
    "description": "string",
    "groups": []
  },
  "asset": {
    "id": "string",
    "hostname": "string",
    "ip": "string",
    "criticality": "unknown | low | medium | high | critical"
  },
  "user": {
    "name": "string",
    "risk_level": "unknown | standard | elevated | privileged"
  },
  "network": {
    "src_ip": "string",
    "dst_ip": "string",
    "src_port": null,
    "dst_port": null
  },
  "mitre": {
    "tactics": [],
    "techniques": []
  },
  "raw_event": {}
}
```
