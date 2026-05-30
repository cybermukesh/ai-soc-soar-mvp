import os

from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import text

from app.api.automation import ensure_automation_connectors, router as automation_router
from app.api.auth import current_user, require_role, router as auth_router
from app.api.connectors import router as connectors_router
from app.api.incidents import router as incidents_router
from app.api.settings import router as settings_router
from app.connectors.opensearch import fetch_recent_wazuh_alerts, opensearch_configured
from app.db.models import AiProviderSetting, Base, ThreatIntelProviderSetting
from app.db.sqlite_store import (
    count_alerts,
    add_local_ioc,
    enrich_alert_with_local_iocs,
    init_db,
    list_alerts,
    list_correlation_groups,
    list_ingestion_runs,
    list_triage_history,
    list_local_iocs,
    record_ingestion_run,
    update_triage_feedback,
    upsert_alert,
    upsert_correlation_groups,
    upsert_triage,
)
from app.db.session import engine, SessionLocal
from app.connectors.wazuh import normalize_wazuh_alert, normalize_wazuh_hits
from app.models.triage import TriageBatchResponse, TriageFeedbackRequest, TriageHistoryEntry, TriageRequest
from app.services.alert_store import load_normalized_sample_alerts, summarize_alerts
from app.services.auth import ensure_admin_seed
from app.services.crypto import encrypt_secret
from app.services.triage import noise_reduction_summary, triage_alert, triage_alerts, triage_cache_size

app = FastAPI(
    title="AI SOC SOAR MVP",
    description="Wazuh-first, SIEM-agnostic AI SOC automation backend",
    version="0.1.0",
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def startup() -> None:
    init_db()
    Base.metadata.create_all(bind=engine)
    with engine.connect() as conn:
        cols = conn.execute(text("PRAGMA table_info(connectors)")).fetchall()
        names = {row[1] for row in cols}
        if cols and "password_encrypted" not in names:
            conn.execute(text("ALTER TABLE connectors ADD COLUMN password_encrypted VARCHAR(1000) DEFAULT ''"))
            conn.commit()
        if cols and "last_latency_ms" not in names:
            conn.execute(text("ALTER TABLE connectors ADD COLUMN last_latency_ms INTEGER DEFAULT 0"))
            conn.commit()
        if cols and "last_checked_at" not in names:
            conn.execute(text("ALTER TABLE connectors ADD COLUMN last_checked_at DATETIME"))
            conn.commit()
        check_cols = conn.execute(text("PRAGMA table_info(connector_health_checks)")).fetchall()
        if not check_cols:
            conn.execute(
                text(
                    """
                    CREATE TABLE connector_health_checks (
                        id INTEGER PRIMARY KEY,
                        connector_id INTEGER NOT NULL,
                        ok BOOLEAN DEFAULT 0,
                        detail VARCHAR(300) DEFAULT '',
                        latency_ms INTEGER DEFAULT 0,
                        checked_by_user_id INTEGER NOT NULL,
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                    )
                    """
                )
            )
            conn.commit()
        incident_cols = conn.execute(text("PRAGMA table_info(incidents)")).fetchall()
        if not incident_cols:
            conn.execute(
                text(
                    """
                    CREATE TABLE incidents (
                        id INTEGER PRIMARY KEY,
                        title VARCHAR(200) NOT NULL,
                        severity VARCHAR(20) DEFAULT 'medium',
                        status VARCHAR(30) DEFAULT 'open',
                        risk_score INTEGER DEFAULT 50,
                        source_tool VARCHAR(40) DEFAULT 'wazuh',
                        alert_id VARCHAR(120) DEFAULT '',
                        ticket_ref VARCHAR(120) DEFAULT '',
                        owner_name VARCHAR(120) DEFAULT '',
                        phase VARCHAR(40) DEFAULT 'new',
                        summary VARCHAR(1000) DEFAULT '',
                        priority VARCHAR(20) DEFAULT 'P3',
                        sla_due_at VARCHAR(60) DEFAULT '',
                        escalated BOOLEAN DEFAULT 0,
                        close_reason VARCHAR(120) DEFAULT '',
                        resolution_summary VARCHAR(1000) DEFAULT '',
                        created_by_user_id INTEGER NOT NULL,
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                    )
                    """
                )
            )
            conn.commit()
        else:
            incident_names = {row[1] for row in incident_cols}
            if "alert_id" not in incident_names:
                conn.execute(text("ALTER TABLE incidents ADD COLUMN alert_id VARCHAR(120) DEFAULT ''"))
                conn.commit()
            if "ticket_ref" not in incident_names:
                conn.execute(text("ALTER TABLE incidents ADD COLUMN ticket_ref VARCHAR(120) DEFAULT ''"))
                conn.commit()
            if "owner_name" not in incident_names:
                conn.execute(text("ALTER TABLE incidents ADD COLUMN owner_name VARCHAR(120) DEFAULT ''"))
                conn.commit()
            if "phase" not in incident_names:
                conn.execute(text("ALTER TABLE incidents ADD COLUMN phase VARCHAR(40) DEFAULT 'new'"))
                conn.commit()
            if "summary" not in incident_names:
                conn.execute(text("ALTER TABLE incidents ADD COLUMN summary VARCHAR(1000) DEFAULT ''"))
                conn.commit()
            if "priority" not in incident_names:
                conn.execute(text("ALTER TABLE incidents ADD COLUMN priority VARCHAR(20) DEFAULT 'P3'"))
                conn.commit()
            if "sla_due_at" not in incident_names:
                conn.execute(text("ALTER TABLE incidents ADD COLUMN sla_due_at VARCHAR(60) DEFAULT ''"))
                conn.commit()
            if "escalated" not in incident_names:
                conn.execute(text("ALTER TABLE incidents ADD COLUMN escalated BOOLEAN DEFAULT 0"))
                conn.commit()
            if "close_reason" not in incident_names:
                conn.execute(text("ALTER TABLE incidents ADD COLUMN close_reason VARCHAR(120) DEFAULT ''"))
                conn.commit()
            if "resolution_summary" not in incident_names:
                conn.execute(text("ALTER TABLE incidents ADD COLUMN resolution_summary VARCHAR(1000) DEFAULT ''"))
                conn.commit()
        event_cols = conn.execute(text("PRAGMA table_info(incident_events)")).fetchall()
        if not event_cols:
            conn.execute(
                text(
                    """
                    CREATE TABLE incident_events (
                        id INTEGER PRIMARY KEY,
                        incident_id INTEGER NOT NULL,
                        event_type VARCHAR(50) NOT NULL,
                        detail VARCHAR(500) DEFAULT '',
                        actor_user_id INTEGER NOT NULL,
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                    )
                    """
                )
            )
            conn.commit()
        ai_cols = conn.execute(text("PRAGMA table_info(ai_provider_settings)")).fetchall()
        if not ai_cols:
            conn.execute(
                text(
                    """
                    CREATE TABLE ai_provider_settings (
                        id INTEGER PRIMARY KEY,
                        provider VARCHAR(40) NOT NULL UNIQUE,
                        model VARCHAR(120) DEFAULT '',
                        api_key_encrypted VARCHAR(1000) DEFAULT '',
                        api_key_masked VARCHAR(20) DEFAULT '',
                        base_url VARCHAR(255) DEFAULT '',
                        enabled BOOLEAN DEFAULT 0,
                        cache_enabled BOOLEAN DEFAULT 1,
                        max_input_chars INTEGER DEFAULT 6000,
                        max_output_tokens INTEGER DEFAULT 700,
                        min_severity VARCHAR(20) DEFAULT 'medium',
                        fallback_model VARCHAR(120) DEFAULT '',
                        last_status VARCHAR(40) DEFAULT 'unknown',
                        last_error VARCHAR(300) DEFAULT '',
                        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
                    )
                    """
                )
            )
            conn.commit()
        intel_cols = conn.execute(text("PRAGMA table_info(threat_intel_provider_settings)")).fetchall()
        if not intel_cols:
            conn.execute(
                text(
                    """
                    CREATE TABLE threat_intel_provider_settings (
                        id INTEGER PRIMARY KEY,
                        provider VARCHAR(40) NOT NULL UNIQUE,
                        api_key_encrypted VARCHAR(1000) DEFAULT '',
                        api_key_masked VARCHAR(20) DEFAULT '',
                        base_url VARCHAR(255) DEFAULT '',
                        enabled BOOLEAN DEFAULT 0,
                        daily_limit INTEGER DEFAULT 500,
                        cache_ttl_minutes INTEGER DEFAULT 1440,
                        last_status VARCHAR(40) DEFAULT 'unknown',
                        last_error VARCHAR(300) DEFAULT '',
                        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
                    )
                    """
                )
            )
            conn.commit()
    db: Session = SessionLocal()
    try:
        ensure_admin_seed(db)
        _seed_platform_settings(db)
        ensure_automation_connectors(db)
    finally:
        db.close()


app.include_router(auth_router)
app.include_router(connectors_router)
app.include_router(incidents_router)
app.include_router(settings_router)
app.include_router(automation_router)


def _mask_secret(value: str) -> str:
    if not value:
        return ""
    if len(value) <= 6:
        return "******"
    return f"{value[:3]}...{value[-3:]}"


def _seed_platform_settings(db: Session) -> None:
    ai_defaults = [
        {
            "provider": "openai",
            "model": os.getenv("LLM_MODEL", "gpt-4o-mini"),
            "api_key": os.getenv("OPENAI_API_KEY", ""),
            "enabled": os.getenv("LLM_PROVIDER", "openai") == "openai",
            "cache_enabled": os.getenv("LLM_CACHE_ENABLED", "true").lower() == "true",
            "max_input_chars": int(os.getenv("LLM_MAX_INPUT_CHARS", "6000")),
            "max_output_tokens": int(os.getenv("LLM_MAX_OUTPUT_TOKENS", "700")),
            "min_severity": os.getenv("LLM_TRIAGE_ONLY_MIN_SEVERITY", "medium"),
        },
        {
            "provider": "anthropic",
            "model": "claude-3-5-haiku-latest",
            "api_key": os.getenv("ANTHROPIC_API_KEY", ""),
            "enabled": os.getenv("LLM_PROVIDER", "") == "anthropic",
            "cache_enabled": True,
            "max_input_chars": 6000,
            "max_output_tokens": 700,
            "min_severity": "medium",
        },
        {
            "provider": "ollama",
            "model": os.getenv("OLLAMA_MODEL", "llama3.1:8b"),
            "api_key": "",
            "base_url": os.getenv("OLLAMA_BASE_URL", "http://localhost:11434"),
            "enabled": os.getenv("LLM_PROVIDER", "") == "ollama",
            "cache_enabled": True,
            "max_input_chars": 6000,
            "max_output_tokens": 700,
            "min_severity": "medium",
        },
        {
            "provider": "offline",
            "model": "heuristic-v1",
            "api_key": "",
            "enabled": os.getenv("LLM_PROVIDER", "") == "offline",
            "cache_enabled": True,
            "max_input_chars": 6000,
            "max_output_tokens": 700,
            "min_severity": "low",
        },
    ]
    for item in ai_defaults:
        if db.query(AiProviderSetting).filter(AiProviderSetting.provider == item["provider"]).first():
            continue
        row = AiProviderSetting(
            provider=item["provider"],
            model=item["model"],
            base_url=item.get("base_url", ""),
            enabled=item["enabled"],
            cache_enabled=item["cache_enabled"],
            max_input_chars=item["max_input_chars"],
            max_output_tokens=item["max_output_tokens"],
            min_severity=item["min_severity"],
            api_key_encrypted=encrypt_secret(item["api_key"]),
            api_key_masked=_mask_secret(item["api_key"]),
            last_status="seeded",
        )
        db.add(row)
    for provider in ("virustotal", "abuseipdb", "otx", "misp", "local_ioc"):
        if db.query(ThreatIntelProviderSetting).filter(ThreatIntelProviderSetting.provider == provider).first():
            continue
        db.add(
            ThreatIntelProviderSetting(
                provider=provider,
                enabled=provider == "local_ioc",
                last_status="seeded",
            )
        )
    db.commit()


async def _sync_wazuh_from_opensearch(limit: int = 100, triage: bool = True) -> dict:
    response = await fetch_recent_wazuh_alerts(limit=limit)
    alerts = normalize_wazuh_hits(response)
    decisions = triage_alerts(alerts) if triage else []
    for alert in alerts:
        upsert_alert(alert)
    for decision in decisions:
        upsert_triage(decision)
    run = record_ingestion_run(
        source="opensearch:wazuh-alerts",
        status="success",
        detail=f"synced {len(alerts)} alerts from OpenSearch",
        fetched_count=len(alerts),
        stored_count=len(alerts),
        triaged_count=len(decisions),
    )
    return {
        "run": run,
        "summary": summarize_alerts(alerts, source="opensearch:wazuh-alerts"),
        "noise_reduction": noise_reduction_summary(decisions),
        "alerts": [alert.model_dump() for alert in alerts],
        "decisions": [decision.model_dump() for decision in decisions],
    }


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.get("/api/v1/readiness/env")
def env_readiness(_: Session = Depends(require_role("admin", "analyst", "viewer"))) -> dict:
    required = {
        "WAZUH_API_URL": bool(__import__("os").getenv("WAZUH_API_URL")),
        "WAZUH_API_USER": bool(__import__("os").getenv("WAZUH_API_USER")),
        "WAZUH_API_PASSWORD": bool(__import__("os").getenv("WAZUH_API_PASSWORD")),
        "OPENSEARCH_URL": bool(__import__("os").getenv("OPENSEARCH_URL")),
        "OPENSEARCH_USER": bool(__import__("os").getenv("OPENSEARCH_USER")),
        "OPENSEARCH_PASSWORD": bool(__import__("os").getenv("OPENSEARCH_PASSWORD")),
        "N8N_WEBHOOK_URL": bool(__import__("os").getenv("N8N_WEBHOOK_URL")),
    }
    missing = [k for k, ok in required.items() if not ok]
    return {"ready": len(missing) == 0, "missing": missing, "checks": required}


@app.get("/")
def root() -> dict:
    return {
        "name": "AI SOC SOAR MVP",
        "status": "day-3-complete",
        "docs": "/docs",
    }


@app.get("/mvp/status")
def mvp_status() -> dict:
    return {
        "current_day": 3,
        "status": "complete",
        "next_day": "Day 5 - Incidents",
        "product_wedge": "Wazuh-first AI alert-noise reduction and SOAR automation layer",
        "wazuh_pipeline": {
            "sample_alerts": "/alerts/sample",
            "normalized_alerts": "/alerts/normalized",
            "opensearch_configured": opensearch_configured(),
            "live_endpoint": "/alerts/wazuh/recent",
        },
        "model_strategy": {
            "mode": "Cheap Cloud",
            "default_model": "gpt-4o-mini",
            "fine_tuning": "not in MVP",
            "controls": [
                "compact normalized alert prompts",
                "structured JSON-only triage output",
                "duplicate alert triage cache",
                "low-confidence analyst escalation",
            ],
        },
        "day_4_triage": {
            "single_alert_endpoint": "/triage/alert",
            "sample_batch_endpoint": "/triage/sample",
            "cache_enabled": True,
            "cache_size": triage_cache_size(),
        },
        "completed_deliverables": [
            "product plan",
            "high-level architecture",
            "technology stack",
            "Codex skill map",
            "build sequence",
            "Day 3 readiness checklist",
            "Wazuh sample fixtures",
            "Wazuh raw-to-normalized mapping",
            "normalized alert API",
            "dashboard alert preview",
            "structured triage JSON output",
            "low-token cache-aware triage workflow",
        ],
    }


@app.get("/alerts/sample")
def sample_alerts(_: Session = Depends(require_role("admin", "analyst", "viewer"))) -> dict:
    alerts = load_normalized_sample_alerts()
    return {
        "summary": summarize_alerts(alerts),
        "alerts": [alert.model_dump() for alert in alerts],
    }


@app.get("/alerts/normalized")
def normalized_alerts(
    limit: int = 200,
    offset: int = 0,
    severity: str = "",
    rule_id: str = "",
    hostname: str = "",
    src_ip: str = "",
    user_name: str = "",
    mitre: str = "",
    q: str = "",
    _: Session = Depends(require_role("admin", "analyst", "viewer")),
) -> dict:
    if limit < 1 or limit > 1000:
        raise HTTPException(status_code=400, detail="limit must be between 1 and 1000")
    filters = {
        "severity": severity,
        "rule_id": rule_id,
        "hostname": hostname,
        "src_ip": src_ip,
        "user": user_name,
        "mitre": mitre,
        "q": q,
    }
    alerts = list_alerts(limit=limit, offset=offset, filters=filters)
    if not alerts:
        alerts = load_normalized_sample_alerts()
        for alert in alerts:
            upsert_alert(alert)
    return {
        "total": count_alerts(filters=filters),
        "limit": limit,
        "offset": offset,
        "filters": filters,
        "alerts": [alert.model_dump() for alert in alerts],
    }


@app.get("/api/v1/alerts")
def alert_search(
    limit: int = 100,
    offset: int = 0,
    severity: str = "",
    rule_id: str = "",
    hostname: str = "",
    src_ip: str = "",
    user_name: str = "",
    mitre: str = "",
    q: str = "",
    _: Session = Depends(require_role("admin", "analyst", "viewer")),
) -> dict:
    if limit < 1 or limit > 1000:
        raise HTTPException(status_code=400, detail="limit must be between 1 and 1000")
    filters = {
        "severity": severity,
        "rule_id": rule_id,
        "hostname": hostname,
        "src_ip": src_ip,
        "user": user_name,
        "mitre": mitre,
        "q": q,
    }
    alerts = list_alerts(limit=limit, offset=offset, filters=filters)
    return {
        "total": count_alerts(filters=filters),
        "limit": limit,
        "offset": offset,
        "filters": filters,
        "alerts": [alert.model_dump() for alert in alerts],
    }


@app.get("/triage/alerts/recent")
def triage_recent_alerts(
    limit: int = 25,
    force_refresh: bool = False,
    _: Session = Depends(require_role("admin", "analyst", "viewer")),
) -> TriageBatchResponse:
    alerts = list_alerts(limit=limit)
    if not alerts:
        alerts = load_normalized_sample_alerts()
    decisions = triage_alerts(alerts, force_refresh=force_refresh)
    for alert, decision in zip(alerts, decisions):
        upsert_alert(alert)
        upsert_triage(decision)
    upsert_correlation_groups(alerts, decisions)
    return TriageBatchResponse(decisions=decisions)


@app.get("/triage/noise-reduction")
def triage_noise_reduction(
    limit: int = 100,
    force_refresh: bool = False,
    _: Session = Depends(require_role("admin", "analyst", "viewer")),
) -> dict:
    alerts = list_alerts(limit=limit)
    if not alerts:
        alerts = load_normalized_sample_alerts()
    decisions = triage_alerts(alerts, force_refresh=force_refresh)
    for alert, decision in zip(alerts, decisions):
        upsert_alert(alert)
        upsert_triage(decision)
    groups = upsert_correlation_groups(alerts, decisions)
    return {
        "summary": noise_reduction_summary(decisions),
        "correlation_groups": groups[:20],
        "top_signals": [
            decision.model_dump()
            for decision in sorted(decisions, key=lambda item: (item.signal_score, item.risk_score), reverse=True)[:10]
        ],
        "top_noise": [
            decision.model_dump()
            for decision in sorted(decisions, key=lambda item: item.noise_score, reverse=True)[:10]
        ],
    }


@app.get("/triage/history", response_model=list[TriageHistoryEntry])
def triage_history(
    limit: int = 100,
    _: Session = Depends(require_role("admin", "analyst", "viewer")),
) -> list[TriageHistoryEntry]:
    return list_triage_history(limit=limit)


@app.get("/triage/correlation-groups")
def triage_correlation_groups(
    limit: int = 50,
    min_count: int = 1,
    queue: str = "",
    _: Session = Depends(require_role("admin", "analyst", "viewer")),
) -> dict:
    groups = list_correlation_groups(limit=limit, min_count=min_count, queue=queue)
    return {"total": len(groups), "groups": groups}


@app.get("/api/v1/threat-intel/local-iocs")
def threat_intel_local_iocs(
    limit: int = 200,
    _: Session = Depends(require_role("admin", "analyst", "viewer")),
) -> dict:
    return {"items": list_local_iocs(limit=limit), "total": len(list_local_iocs(limit=limit))}


@app.post("/api/v1/threat-intel/local-iocs")
def threat_intel_add_local_ioc(
    payload: dict,
    _: Session = Depends(require_role("admin", "analyst")),
) -> dict:
    indicator = str(payload.get("indicator", "")).strip()
    if not indicator:
        raise HTTPException(status_code=400, detail="indicator is required")
    return add_local_ioc(
        indicator=indicator,
        indicator_type=str(payload.get("indicator_type", "ip")),
        severity=str(payload.get("severity", "medium")),
        description=str(payload.get("description", "")),
        source=str(payload.get("source", "local")),
        enabled=bool(payload.get("enabled", True)),
    )


@app.get("/api/v1/threat-intel/enrich-alert/{alert_id}")
def threat_intel_enrich_alert(
    alert_id: str,
    _: Session = Depends(require_role("admin", "analyst", "viewer")),
) -> dict:
    matches = [alert for alert in list_alerts(limit=1000) if alert.alert_id == alert_id]
    if not matches:
        raise HTTPException(status_code=404, detail="Alert not found")
    return enrich_alert_with_local_iocs(matches[0])


@app.post("/triage/feedback")
def triage_feedback(
    payload: TriageFeedbackRequest,
    _: Session = Depends(require_role("admin", "analyst")),
) -> dict:
    update_triage_feedback(payload.alert_id, payload.disposition, payload.note)
    return {"status": "ok"}


@app.post("/alerts/normalize")
def normalize_alert(
    raw_alert: dict, _: Session = Depends(require_role("admin", "analyst"))
) -> dict:
    normalized = normalize_wazuh_alert(raw_alert)
    upsert_alert(normalized)
    return normalized.model_dump()


@app.get("/alerts/wazuh/recent")
async def recent_wazuh_alerts(
    limit: int = 25, _: Session = Depends(require_role("admin", "analyst", "viewer"))
) -> dict:
    try:
        response = await fetch_recent_wazuh_alerts(limit=limit)
    except RuntimeError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"OpenSearch query failed: {exc}") from exc
    alerts = normalize_wazuh_hits(response)
    for alert in alerts:
        upsert_alert(alert)
    return {
        "summary": summarize_alerts(alerts, source="opensearch:wazuh-alerts"),
        "alerts": [alert.model_dump() for alert in alerts],
    }


@app.post("/api/v1/ingestion/wazuh/sync")
async def sync_wazuh_alerts(
    limit: int = 100,
    triage: bool = True,
    _: Session = Depends(require_role("admin", "analyst")),
) -> dict:
    if limit < 1 or limit > 500:
        raise HTTPException(status_code=400, detail="limit must be between 1 and 500")
    try:
        return await _sync_wazuh_from_opensearch(limit=limit, triage=triage)
    except RuntimeError as exc:
        run = record_ingestion_run("opensearch:wazuh-alerts", "error", str(exc))
        raise HTTPException(status_code=400, detail={"message": str(exc), "run": run}) from exc
    except Exception as exc:
        run = record_ingestion_run("opensearch:wazuh-alerts", "error", f"OpenSearch sync failed: {exc}")
        raise HTTPException(status_code=502, detail={"message": f"OpenSearch sync failed: {exc}", "run": run}) from exc


@app.get("/api/v1/ingestion/status")
def ingestion_status(
    limit: int = 20,
    _: Session = Depends(require_role("admin", "analyst", "viewer")),
) -> dict:
    runs = list_ingestion_runs(limit=limit)
    return {
        "stored_alerts": count_alerts(),
        "triage_history": len(list_triage_history(limit=1000)),
        "last_run": runs[0] if runs else None,
        "runs": runs,
        "live_source": "opensearch:wazuh-alerts" if opensearch_configured() else "not_configured",
    }


@app.post("/triage/alert")
def triage_single_alert(
    request: TriageRequest, _: Session = Depends(require_role("admin", "analyst"))
) -> dict:
    decision = triage_alert(request.alert, force_refresh=request.force_refresh)
    upsert_alert(request.alert)
    upsert_triage(decision)
    upsert_correlation_groups([request.alert], [decision])
    return decision.model_dump()


@app.get("/triage/sample")
def triage_sample_alerts(
    force_refresh: bool = False, _: Session = Depends(require_role("admin", "analyst", "viewer"))
) -> TriageBatchResponse:
    alerts = load_normalized_sample_alerts()
    decisions = triage_alerts(alerts, force_refresh=force_refresh)
    upsert_correlation_groups(alerts, decisions)
    return TriageBatchResponse(decisions=decisions)
