from app.models.alert import (
    AssetContext,
    MitreContext,
    NetworkContext,
    NormalizedAlert,
    RuleContext,
    UserContext,
)


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
            description=str(rule.get("description", "")),
            groups=list(rule.get("groups", []) or []),
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
        ),
        mitre=MitreContext(
            tactics=list(mitre.get("tactic", []) or []),
            techniques=list(mitre.get("id", []) or []),
        ),
        raw_event=raw,
    )
