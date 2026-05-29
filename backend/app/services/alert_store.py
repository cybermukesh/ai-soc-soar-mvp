import json
from pathlib import Path
from typing import Any

from app.connectors.wazuh import normalize_wazuh_alert
from app.models.alert import NormalizedAlert

ROOT_DIR = Path(__file__).resolve().parents[3]
SAMPLE_ALERT_DIR = ROOT_DIR / "data" / "sample-alerts"


def load_sample_wazuh_alerts() -> list[dict[str, Any]]:
    return [json.loads(path.read_text()) for path in sorted(SAMPLE_ALERT_DIR.glob("*.json"))]


def load_normalized_sample_alerts() -> list[NormalizedAlert]:
    return [normalize_wazuh_alert(alert) for alert in load_sample_wazuh_alerts()]


def summarize_alerts(alerts: list[NormalizedAlert], source: str = "sample-wazuh-fixtures") -> dict[str, Any]:
    severity_counts = {"low": 0, "medium": 0, "high": 0, "critical": 0}
    for alert in alerts:
        severity_counts[alert.severity] += 1
    return {
        "total_alerts": len(alerts),
        "source": source,
        "severity_counts": severity_counts,
        "unique_assets": len({alert.asset.hostname for alert in alerts if alert.asset.hostname}),
        "ready_for_dashboard": True,
    }
