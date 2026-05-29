import hashlib
import json
import os
from typing import Iterable

from app.models.alert import NormalizedAlert
from app.models.triage import TriageDecision


_TRIAGE_CACHE: dict[str, TriageDecision] = {}


def triage_cache_size() -> int:
    return len(_TRIAGE_CACHE)


def _cache_enabled() -> bool:
    return os.getenv("LLM_CACHE_ENABLED", "true").lower() == "true"


def _cache_key(alert: NormalizedAlert) -> str:
    # Compact key to suppress repeated triage calls for equivalent alerts.
    key_payload = {
        "source_tool": alert.source_tool,
        "severity": alert.severity,
        "rule_id": alert.rule.id,
        "rule_desc": alert.rule.description,
        "asset": alert.asset.hostname,
        "src_ip": alert.network.src_ip,
        "dst_ip": alert.network.dst_ip,
        "user": alert.user.name,
    }
    return hashlib.sha256(json.dumps(key_payload, sort_keys=True).encode()).hexdigest()


def _contains_any(values: Iterable[str], keywords: Iterable[str]) -> bool:
    hay = " ".join(values).lower()
    return any(keyword in hay for keyword in keywords)


def _heuristic_triage(alert: NormalizedAlert) -> TriageDecision:
    groups = [group.lower() for group in alert.rule.groups]
    text_fields = [alert.rule.description, " ".join(groups), alert.user.name, alert.network.src_ip]
    risk_score = alert.severity_score
    verdict = "needs_review"
    confidence = 0.55
    recommended_actions = ["analyst review"]
    investigation_steps = [
        "review raw event and normalized fields",
        "confirm asset owner and business criticality",
        "check whether similar alerts exist in the same time window",
    ]
    containment_steps = ["hold containment until analyst validates impact"]
    resolution_criteria = ["analyst confirms benign activity or creates incident for response"]
    analyst_questions = ["Is the source IP expected for this asset?", "Has this user or host generated related alerts?"]
    summary = "Alert requires analyst review based on current evidence."

    if _contains_any(groups, ["malware"]):
        verdict = "true_positive"
        confidence = 0.9
        risk_score = max(risk_score, 88)
        recommended_actions = ["isolate endpoint", "collect host artifacts", "notify incident channel"]
        investigation_steps = [
            "collect process tree, hashes, and network connections from host",
            "check Wazuh file integrity and malware module details",
            "search for the same hash or process on other assets",
        ]
        containment_steps = ["isolate endpoint", "block known malicious indicators", "preserve evidence before cleanup"]
        resolution_criteria = ["malware removed", "persistence removed", "no new matching alerts after monitoring window"]
        analyst_questions = ["What process created the alert?", "Did the indicator appear on other endpoints?"]
        summary = "Potential malware behavior detected on endpoint."
    elif _contains_any(text_fields, ["root login", "credential", "authentication_failed", "brute"]):
        verdict = "suspicious"
        confidence = 0.78
        risk_score = max(risk_score, 72)
        recommended_actions = ["validate login context", "reset credentials if unauthorized"]
        investigation_steps = [
            "validate whether the username exists and should access the target asset",
            "check failed login count, source IP reputation, and geolocation",
            "review successful logins after the failed attempts",
        ]
        containment_steps = ["block source IP if malicious", "reset impacted credentials", "increase monitoring for target host"]
        resolution_criteria = ["source validated or blocked", "credential risk addressed", "no follow-on successful compromise observed"]
        analyst_questions = ["Was any login successful after the failures?", "Is the source IP part of approved admin access?"]
        summary = "Authentication activity looks suspicious and needs validation."
    elif _contains_any(groups, ["network_scan", "firewall"]):
        verdict = "low_priority"
        confidence = 0.71
        risk_score = max(risk_score, 45)
        recommended_actions = ["review source IP history", "tune firewall threshold"]
        investigation_steps = [
            "review target ports and scan breadth",
            "check whether source is vulnerability scanner or monitoring system",
            "look for exploitation attempts after scan behavior",
        ]
        containment_steps = ["block source if unauthorized", "rate-limit repeated scanner traffic"]
        resolution_criteria = ["source classified as authorized or blocked", "no exploitation activity linked to scan"]
        analyst_questions = ["Is this a scheduled scanner?", "Did the same source attempt authentication or exploitation?"]
        summary = "Network scanning pattern observed with moderate risk."
    elif alert.severity in {"critical", "high"}:
        verdict = "suspicious"
        confidence = 0.7
        risk_score = max(risk_score, 70)
        recommended_actions = ["correlate with related alerts", "escalate to SOC lead"]
        investigation_steps = [
            "correlate alert with asset, user, and network activity",
            "review preceding and following alerts for the same entity",
            "capture evidence required for escalation",
        ]
        containment_steps = ["prepare approval-gated response action", "notify SOC lead if impact is confirmed"]
        resolution_criteria = ["impact confirmed and remediated or documented false positive"]
        analyst_questions = ["What changed on the asset before this alert?", "Does the raw event prove malicious intent?"]
        summary = "High-severity alert requires immediate triage and correlation."
    elif alert.severity == "low":
        verdict = "false_positive"
        confidence = 0.66
        risk_score = min(risk_score, 25)
        recommended_actions = ["monitor only", "consider detection tuning"]
        investigation_steps = ["sample check raw event", "compare against known benign baselines"]
        containment_steps = ["no containment unless repeated or correlated with higher severity alerts"]
        resolution_criteria = ["benign pattern documented", "rule tuning proposed if noise repeats"]
        analyst_questions = ["Is this recurring noise?", "Can the rule be safely tuned?"]
        summary = "Low-severity pattern likely benign but should be monitored."

    evidence = [
        f"rule_id={alert.rule.id}",
        f"severity={alert.severity}",
        f"asset={alert.asset.hostname or 'unknown'}",
        f"src_ip={alert.network.src_ip or 'unknown'}",
        f"user={alert.user.name or 'unknown'}",
        f"mitre={','.join(alert.mitre.techniques) or 'none'}",
    ]

    soar = "notify_slack_only"
    if verdict in {"true_positive", "suspicious"}:
        soar = "request_approval_then_soar_containment"

    return TriageDecision(
        alert_id=alert.alert_id,
        verdict=verdict,  # type: ignore[arg-type]
        confidence=round(confidence, 2),
        risk_score=risk_score,
        attack_summary=summary,
        evidence=evidence,
        mitre={"tactics": alert.mitre.tactics, "techniques": alert.mitre.techniques},
        impacted_entities=[
            value
            for value in [
                alert.asset.hostname,
                alert.asset.ip,
                alert.user.name,
                alert.network.src_ip,
                alert.network.dst_ip,
            ]
            if value
        ],
        investigation_steps=investigation_steps,
        containment_steps=containment_steps,
        resolution_criteria=resolution_criteria,
        analyst_questions=analyst_questions,
        recommended_actions=recommended_actions,
        soar_recommendation=soar,
        model_used=os.getenv("LLM_MODEL", "gpt-4o-mini"),
    )


def triage_alert(alert: NormalizedAlert, force_refresh: bool = False) -> TriageDecision:
    key = _cache_key(alert)
    if _cache_enabled() and not force_refresh and key in _TRIAGE_CACHE:
        cached = _TRIAGE_CACHE[key].model_copy()
        cached.from_cache = True
        return cached

    decision = _heuristic_triage(alert)
    if _cache_enabled():
        _TRIAGE_CACHE[key] = decision
    return decision


def triage_alerts(alerts: list[NormalizedAlert], force_refresh: bool = False) -> list[TriageDecision]:
    return [triage_alert(alert, force_refresh=force_refresh) for alert in alerts]
