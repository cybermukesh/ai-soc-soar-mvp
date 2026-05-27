from fastapi import FastAPI

from app.connectors.opensearch import fetch_recent_wazuh_alerts, opensearch_configured
from app.connectors.wazuh import normalize_wazuh_alert, normalize_wazuh_hits
from app.services.alert_store import load_normalized_sample_alerts, summarize_alerts

app = FastAPI(
    title="AI SOC SOAR MVP",
    description="Wazuh-first, SIEM-agnostic AI SOC automation backend",
    version="0.1.0",
)


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.get("/")
def root() -> dict:
    return {"name": "AI SOC SOAR MVP", "status": "day-3-complete", "docs": "/docs"}


@app.get("/mvp/status")
def mvp_status() -> dict:
    return {
        "current_day": 3,
        "status": "complete",
        "next_day": "Day 4 - AI Triage",
        "product_wedge": "Wazuh-first AI alert-noise reduction and SOAR automation layer",
        "wazuh_pipeline": {
            "sample_alerts": "/alerts/sample",
            "normalized_alerts": "/alerts/normalized",
            "opensearch_configured": opensearch_configured(),
            "live_endpoint": "/alerts/wazuh/recent",
        },
    }


@app.get("/alerts/sample")
def sample_alerts() -> dict:
    alerts = load_normalized_sample_alerts()
    return {"summary": summarize_alerts(alerts), "alerts": [alert.model_dump() for alert in alerts]}


@app.get("/alerts/normalized")
def normalized_alerts() -> list[dict]:
    return [alert.model_dump() for alert in load_normalized_sample_alerts()]


@app.post("/alerts/normalize")
def normalize_alert(raw_alert: dict) -> dict:
    return normalize_wazuh_alert(raw_alert).model_dump()


@app.get("/alerts/wazuh/recent")
async def recent_wazuh_alerts(limit: int = 25) -> dict:
    response = await fetch_recent_wazuh_alerts(limit=limit)
    alerts = normalize_wazuh_hits(response)
    return {"summary": summarize_alerts(alerts), "alerts": [alert.model_dump() for alert in alerts]}
