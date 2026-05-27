from app.models.alert import (
    AssetContext,
    MitreContext,
    NetworkContext,
    NormalizedAlert,
    RuleContext,
    UserContext,
)


def _as_list(value: object) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value]
    return [str(value)]


def severity_from_wazuh_level(level: int) -> tuple[str, int]:
    score = min(100, max(0, round((level / 15) * 100)))
    if score >= 75:
        return "critical", score
    if score >= 50:
        return "high", score
    if score >= 25:
        return "medium", score
    return "low", score


def normalize_wazuh_alert(raw: dict) -> NormalizedAlert:
    rule = raw.get("rule", {}) or {}
    agent = raw.get("agent", {}) or {}
    data = raw.get("data", {}) or {}
    mitre = rule.get("mitre", {}) or {}
    level = int(rule.get("level", 0) or 0)
    severity, score = severity_from_wazuh_level(level)

    return NormalizedAlert(
        alert_id=str(raw.get("id", "")),
        source_tool="wazuh",
        timestamp=str(raw.get("timestamp", "")),
        severity=severity,
        severity_score=score,
        rule=RuleContext(
            id=str(rule.get("id", "")),
            name=str(rule.get("description", "")),
            description=str(rule.get("description", "")),
            groups=_as_list(rule.get("groups")),
        ),
        asset=AssetContext(
            id=str(agent.get("id", "")),
            hostname=str(agent.get("name", "")),
            ip=str(agent.get("ip", "")),
        ),
        user=UserContext(name=str(data.get("srcuser") or data.get("user") or "")),
        network=NetworkContext(
            src_ip=str(data.get("srcip") or data.get("src_ip") or ""),
            dst_ip=str(data.get("dstip") or data.get("dst_ip") or ""),
            src_port=int(data["srcport"]) if str(data.get("srcport", "")).isdigit() else None,
            dst_port=int(data["dstport"]) if str(data.get("dstport", "")).isdigit() else None,
        ),
        mitre=MitreContext(
            tactics=_as_list(mitre.get("tactic")),
            techniques=_as_list(mitre.get("id")),
        ),
        raw_event=raw,
    )


def normalize_wazuh_hits(response: dict) -> list[NormalizedAlert]:
    alerts: list[NormalizedAlert] = []
    for hit in response.get("hits", {}).get("hits", []):
        source = hit.get("_source", hit)
        if isinstance(source, dict):
            alerts.append(normalize_wazuh_alert(source))
    return alerts
