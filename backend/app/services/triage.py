import hashlib
import json
import os
from collections import Counter
from dataclasses import dataclass
from typing import Iterable

from app.models.alert import NormalizedAlert
from app.models.triage import TriageDecision


_TRIAGE_CACHE: dict[str, TriageDecision] = {}


@dataclass(frozen=True)
class BatchContext:
    correlation_counts: Counter[str]
    src_counts: Counter[str]
    asset_counts: Counter[str]
    user_counts: Counter[str]
    rule_counts: Counter[str]
    total_alerts: int


def triage_cache_size() -> int:
    return len(_TRIAGE_CACHE)


def _cache_enabled() -> bool:
    return os.getenv("LLM_CACHE_ENABLED", "true").lower() == "true"


def _cache_key(alert: NormalizedAlert) -> str:
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


def _correlation_key(alert: NormalizedAlert) -> str:
    parts = [
        alert.source_tool,
        alert.rule.id or alert.rule.name,
        alert.asset.hostname or alert.asset.id or "unknown-asset",
        alert.network.src_ip or "unknown-src",
        alert.user.name or "unknown-user",
    ]
    return "|".join(parts)


def _batch_context(alerts: list[NormalizedAlert]) -> BatchContext:
    return BatchContext(
        correlation_counts=Counter(_correlation_key(alert) for alert in alerts),
        src_counts=Counter(alert.network.src_ip for alert in alerts if alert.network.src_ip),
        asset_counts=Counter((alert.asset.hostname or alert.asset.id) for alert in alerts if alert.asset.hostname or alert.asset.id),
        user_counts=Counter(alert.user.name for alert in alerts if alert.user.name),
        rule_counts=Counter(alert.rule.id or alert.rule.name for alert in alerts if alert.rule.id or alert.rule.name),
        total_alerts=len(alerts),
    )


def _clamp(value: int) -> int:
    return max(0, min(100, value))


def _priority(risk_score: int, signal_score: int) -> str:
    if risk_score >= 90 or signal_score >= 88:
        return "P1"
    if risk_score >= 75 or signal_score >= 72:
        return "P2"
    if risk_score >= 45 or signal_score >= 45:
        return "P3"
    return "P4"


def _queue(verdict: str, priority: str, suppression_decision: str) -> str:
    if suppression_decision == "suppress":
        return "suppressed_noise"
    if suppression_decision == "escalate_group":
        return "grouped_incident"
    if verdict in {"true_positive", "suspicious"} and priority in {"P1", "P2"}:
        return "analyst_escalation"
    if verdict == "needs_review":
        return "l1_review"
    return "watchlist"


def _heuristic_triage(alert: NormalizedAlert, context: BatchContext | None = None) -> TriageDecision:
    groups = [group.lower() for group in alert.rule.groups]
    text_fields = [alert.rule.description, " ".join(groups), alert.user.name, alert.network.src_ip]
    rule_text = " ".join([alert.rule.id, alert.rule.name, alert.rule.description, " ".join(groups)]).lower()
    correlation_key = _correlation_key(alert)
    correlation_count = context.correlation_counts[correlation_key] if context else 1
    src_frequency = context.src_counts[alert.network.src_ip] if context and alert.network.src_ip else 0
    asset_frequency = context.asset_counts[alert.asset.hostname or alert.asset.id] if context and (alert.asset.hostname or alert.asset.id) else 0
    user_frequency = context.user_counts[alert.user.name] if context and alert.user.name else 0
    rule_frequency = context.rule_counts[alert.rule.id or alert.rule.name] if context and (alert.rule.id or alert.rule.name) else 0
    related_alert_count = max(correlation_count, src_frequency, asset_frequency, user_frequency, rule_frequency, 1)

    risk_score = alert.severity_score
    verdict = "needs_review"
    confidence = 0.55
    noise_score = 20
    signal_score = max(35, alert.severity_score)
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
    escalation_reason = ""
    tuning_recommendation = ""

    if _contains_any(groups, ["malware"]) or _contains_any(text_fields, ["trojan", "malware", "virus", "ransom"]):
        verdict = "true_positive"
        confidence = 0.91
        risk_score = max(risk_score, 90)
        signal_score = max(signal_score, 92)
        noise_score = min(noise_score, 8)
        recommended_actions = ["isolate endpoint", "collect host artifacts", "notify incident channel"]
        investigation_steps = [
            "collect process tree, hashes, and network connections from host",
            "check Wazuh file integrity and malware module details",
            "search for the same hash or process on other assets",
        ]
        containment_steps = ["isolate endpoint", "block known malicious indicators", "preserve evidence before cleanup"]
        resolution_criteria = ["malware removed", "persistence removed", "no new matching alerts after monitoring window"]
        analyst_questions = ["What process created the alert?", "Did the indicator appear on other endpoints?"]
        summary = "High-signal malware behavior detected; prioritize as a real incident candidate."
        escalation_reason = "malware indicator has high analyst value and low expected noise"
    elif _contains_any(text_fields, ["root login", "credential", "authentication_failed", "invalid_login", "brute", "password"]):
        verdict = "suspicious"
        confidence = 0.8
        risk_score = max(risk_score, 68)
        signal_score = max(signal_score, 62)
        noise_score = 35
        if src_frequency >= 5 or user_frequency >= 5 or correlation_count >= 3:
            risk_score = max(risk_score, 82)
            signal_score = max(signal_score, 78)
            noise_score = max(10, noise_score - 12)
            escalation_reason = "repeated authentication failures indicate burst behavior, not a single noisy alert"
        recommended_actions = ["validate login context", "reset credentials if unauthorized"]
        investigation_steps = [
            "validate whether the username exists and should access the target asset",
            "check failed login count, source IP reputation, and geolocation",
            "review successful logins after the failed attempts",
            "correlate this source IP against other users and assets in the current batch",
        ]
        containment_steps = ["block source IP if malicious", "reset impacted credentials", "increase monitoring for target host"]
        resolution_criteria = ["source validated or blocked", "credential risk addressed", "no follow-on successful compromise observed"]
        analyst_questions = ["Was any login successful after the failures?", "Is the source IP part of approved admin access?"]
        summary = "Authentication activity is suspicious; repeated entity frequency raises signal above ordinary login noise."
        tuning_recommendation = "Suppress isolated invalid-user SSH failures below threshold, but escalate repeated source/user bursts."
    elif _contains_any(groups, ["network_scan", "firewall"]) or "scan" in rule_text:
        verdict = "low_priority"
        confidence = 0.74
        risk_score = max(risk_score, 42)
        signal_score = max(signal_score, 43)
        noise_score = 58
        if src_frequency >= 8 or asset_frequency >= 12:
            verdict = "suspicious"
            risk_score = max(risk_score, 66)
            signal_score = max(signal_score, 65)
            noise_score = 34
            escalation_reason = "scan activity repeats across entities and may precede exploitation"
        recommended_actions = ["review source IP history", "tune firewall threshold"]
        investigation_steps = [
            "review target ports and scan breadth",
            "check whether source is vulnerability scanner or monitoring system",
            "look for exploitation attempts after scan behavior",
        ]
        containment_steps = ["block source if unauthorized", "rate-limit repeated scanner traffic"]
        resolution_criteria = ["source classified as authorized or blocked", "no exploitation activity linked to scan"]
        analyst_questions = ["Is this a scheduled scanner?", "Did the same source attempt authentication or exploitation?"]
        summary = "Network scan is usually noisy unless correlated with broad or repeated activity."
        tuning_recommendation = "Auto-suppress known scanner sources; escalate unknown repeated scanners."
    elif alert.severity in {"critical", "high"}:
        verdict = "suspicious"
        confidence = 0.72
        risk_score = max(risk_score, 72)
        signal_score = max(signal_score, 70)
        noise_score = 25
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
        escalation_reason = "high source severity"
    elif alert.severity == "low":
        verdict = "false_positive"
        confidence = 0.68
        risk_score = min(risk_score, 25)
        signal_score = min(signal_score, 25)
        noise_score = 80
        recommended_actions = ["monitor only", "consider detection tuning"]
        investigation_steps = ["sample check raw event", "compare against known benign baselines"]
        containment_steps = ["no containment unless repeated or correlated with higher severity alerts"]
        resolution_criteria = ["benign pattern documented", "rule tuning proposed if noise repeats"]
        analyst_questions = ["Is this recurring noise?", "Can the rule be safely tuned?"]
        summary = "Low-severity pattern likely benign and should be suppressed unless correlated."
        tuning_recommendation = "Candidate for default suppression after analyst validation."

    # Cross-alert correlation is the key differentiator: repeated entities can raise signal,
    # while repeated identical low-signal records can be collapsed to one analyst item.
    if correlation_count > 1:
        evidence_boost = min(14, correlation_count * 2)
        signal_score = _clamp(signal_score + evidence_boost)
        if verdict in {"low_priority", "false_positive"} and correlation_count >= 5:
            tuning_recommendation = "Collapse repeated identical alerts into one grouped work item."
    if src_frequency >= 10:
        risk_score = max(risk_score, 76)
        signal_score = max(signal_score, 76)
        noise_score = min(noise_score, 30)
        escalation_reason = escalation_reason or "single source IP is generating a high-volume burst"
    if rule_frequency >= 15 and signal_score < 60:
        noise_score = max(noise_score, 76)
        tuning_recommendation = tuning_recommendation or "High rule frequency with weak signal; candidate for threshold tuning."

    suppression_decision = "review"
    suppression_reason = "requires analyst review"
    if verdict in {"false_positive", "low_priority"} and noise_score >= 70 and signal_score < 45:
        suppression_decision = "suppress"
        suppression_reason = "low signal, high noise, no strong correlation"
    elif correlation_count >= 2 and verdict in {"low_priority", "false_positive"}:
        suppression_decision = "group"
        suppression_reason = f"{correlation_count} equivalent alerts can be grouped into one analyst item"
    elif verdict in {"suspicious", "true_positive"} and signal_score >= 70:
        suppression_decision = "escalate_group" if correlation_count > 1 else "escalate"
        suppression_reason = (
            f"{correlation_count} related high-signal alerts should become one grouped incident"
            if correlation_count > 1
            else escalation_reason or "high signal score"
        )

    priority = _priority(risk_score, signal_score)
    queue = _queue(verdict, priority, suppression_decision)

    evidence = [
        f"rule_id={alert.rule.id}",
        f"severity={alert.severity}",
        f"asset={alert.asset.hostname or 'unknown'}",
        f"src_ip={alert.network.src_ip or 'unknown'}",
        f"user={alert.user.name or 'unknown'}",
        f"mitre={','.join(alert.mitre.techniques) or 'none'}",
        f"correlation_count={correlation_count}",
        f"src_frequency={src_frequency}",
        f"asset_frequency={asset_frequency}",
        f"rule_frequency={rule_frequency}",
        f"noise_score={noise_score}",
        f"signal_score={signal_score}",
    ]

    soar = "notify_slack_only"
    if suppression_decision == "suppress":
        soar = "no_soar_suppress_noise"
    elif verdict in {"true_positive", "suspicious"}:
        soar = "request_approval_then_soar_containment"

    return TriageDecision(
        alert_id=alert.alert_id,
        verdict=verdict,  # type: ignore[arg-type]
        confidence=round(confidence, 2),
        risk_score=_clamp(risk_score),
        attack_summary=summary,
        evidence=evidence,
        mitre={"tactics": alert.mitre.tactics, "techniques": alert.mitre.techniques},
        analyst_priority=priority,
        queue=queue,
        noise_score=_clamp(noise_score),
        signal_score=_clamp(signal_score),
        suppression_decision=suppression_decision,
        suppression_reason=suppression_reason,
        correlation_key=correlation_key,
        correlation_count=correlation_count,
        related_alert_count=related_alert_count,
        entity_frequency={
            "src_ip": src_frequency,
            "asset": asset_frequency,
            "user": user_frequency,
            "rule": rule_frequency,
        },
        escalation_reason=escalation_reason,
        tuning_recommendation=tuning_recommendation,
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


def triage_alert(alert: NormalizedAlert, force_refresh: bool = False, context: BatchContext | None = None) -> TriageDecision:
    key = _cache_key(alert)
    # Batch-aware triage needs fresh correlation fields, so cache is used only for standalone calls.
    if context is None and _cache_enabled() and not force_refresh and key in _TRIAGE_CACHE:
        cached = _TRIAGE_CACHE[key].model_copy()
        cached.from_cache = True
        return cached

    decision = _heuristic_triage(alert, context=context)
    if context is None and _cache_enabled():
        _TRIAGE_CACHE[key] = decision
    return decision


def triage_alerts(alerts: list[NormalizedAlert], force_refresh: bool = False) -> list[TriageDecision]:
    context = _batch_context(alerts)
    return [triage_alert(alert, force_refresh=force_refresh, context=context) for alert in alerts]


def noise_reduction_summary(decisions: list[TriageDecision]) -> dict:
    total = len(decisions)
    suppressed = sum(1 for decision in decisions if decision.suppression_decision == "suppress")
    non_suppressed = [decision for decision in decisions if decision.suppression_decision != "suppress"]
    grouped_keys = {decision.correlation_key for decision in non_suppressed if decision.correlation_key}
    analyst_items = len(grouped_keys)
    grouped = max(len(non_suppressed) - analyst_items, 0)
    escalated = sum(1 for decision in decisions if decision.suppression_decision in {"escalate", "escalate_group"})
    review = sum(1 for decision in decisions if decision.queue in {"l1_review", "watchlist"})
    reduction = 0 if total == 0 else round(((total - analyst_items) / total) * 100, 1)
    return {
        "total_alerts": total,
        "suppressed_noise": suppressed,
        "grouped_duplicates": grouped,
        "escalated_signals": escalated,
        "review_items": review,
        "estimated_analyst_items": analyst_items,
        "estimated_noise_reduction_percent": reduction,
        "strategy": "batch-aware correlation, duplicate grouping, low-signal suppression, high-signal escalation",
    }
