from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import text

from app.api.auth import current_user, require_role, router as auth_router
from app.api.connectors import router as connectors_router
from app.api.incidents import router as incidents_router
from app.connectors.opensearch import fetch_recent_wazuh_alerts, opensearch_configured
from app.db.models import Base
from app.db.sqlite_store import (
    count_alerts,
    init_db,
    list_alerts,
    list_ingestion_runs,
    list_triage_history,
    record_ingestion_run,
    update_triage_feedback,
    upsert_alert,
    upsert_triage,
)
from app.db.session import engine, SessionLocal
from app.connectors.wazuh import normalize_wazuh_alert, normalize_wazuh_hits
from app.models.triage import TriageBatchResponse, TriageFeedbackRequest, TriageHistoryEntry, TriageRequest
from app.services.alert_store import load_normalized_sample_alerts, summarize_alerts
from app.services.auth import ensure_admin_seed
from app.services.triage import triage_alert, triage_alerts, triage_cache_size

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
    db: Session = SessionLocal()
    try:
        ensure_admin_seed(db)
    finally:
        db.close()


app.include_router(auth_router)
app.include_router(connectors_router)
app.include_router(incidents_router)


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
def normalized_alerts(_: Session = Depends(require_role("admin", "analyst", "viewer"))) -> list[dict]:
    alerts = list_alerts(limit=200)
    if not alerts:
        alerts = load_normalized_sample_alerts()
        for alert in alerts:
            upsert_alert(alert)
    return [alert.model_dump() for alert in alerts]


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
    return TriageBatchResponse(decisions=decisions)


@app.get("/triage/history", response_model=list[TriageHistoryEntry])
def triage_history(
    limit: int = 100,
    _: Session = Depends(require_role("admin", "analyst", "viewer")),
) -> list[TriageHistoryEntry]:
    return list_triage_history(limit=limit)


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
    return decision.model_dump()


@app.get("/triage/sample")
def triage_sample_alerts(
    force_refresh: bool = False, _: Session = Depends(require_role("admin", "analyst", "viewer"))
) -> TriageBatchResponse:
    alerts = load_normalized_sample_alerts()
    decisions = triage_alerts(alerts, force_refresh=force_refresh)
    return TriageBatchResponse(decisions=decisions)
