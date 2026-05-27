from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.connectors.opensearch import fetch_recent_wazuh_alerts, opensearch_configured
from app.db.sqlite_store import init_db, list_alerts, upsert_alert, upsert_triage
from app.connectors.wazuh import normalize_wazuh_alert, normalize_wazuh_hits
from app.models.triage import TriageBatchResponse, TriageRequest
from app.services.alert_store import load_normalized_sample_alerts, summarize_alerts
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


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


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
def sample_alerts() -> dict:
    alerts = load_normalized_sample_alerts()
    return {
        "summary": summarize_alerts(alerts),
        "alerts": [alert.model_dump() for alert in alerts],
    }


@app.get("/alerts/normalized")
def normalized_alerts() -> list[dict]:
    alerts = list_alerts(limit=200)
    if not alerts:
        alerts = load_normalized_sample_alerts()
        for alert in alerts:
            upsert_alert(alert)
    return [alert.model_dump() for alert in alerts]


@app.post("/alerts/normalize")
def normalize_alert(raw_alert: dict) -> dict:
    normalized = normalize_wazuh_alert(raw_alert)
    upsert_alert(normalized)
    return normalized.model_dump()


@app.get("/alerts/wazuh/recent")
async def recent_wazuh_alerts(limit: int = 25) -> dict:
    response = await fetch_recent_wazuh_alerts(limit=limit)
    alerts = normalize_wazuh_hits(response)
    for alert in alerts:
        upsert_alert(alert)
    return {
        "summary": summarize_alerts(alerts),
        "alerts": [alert.model_dump() for alert in alerts],
    }


@app.post("/triage/alert")
def triage_single_alert(request: TriageRequest) -> dict:
    decision = triage_alert(request.alert, force_refresh=request.force_refresh)
    upsert_alert(request.alert)
    upsert_triage(decision)
    return decision.model_dump()


@app.get("/triage/sample")
def triage_sample_alerts(force_refresh: bool = False) -> TriageBatchResponse:
    alerts = load_normalized_sample_alerts()
    decisions = triage_alerts(alerts, force_refresh=force_refresh)
    return TriageBatchResponse(decisions=decisions)
