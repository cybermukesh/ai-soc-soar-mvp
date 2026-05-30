import json
import sqlite3
from pathlib import Path

from app.models.alert import NormalizedAlert
from app.models.triage import TriageDecision, TriageHistoryEntry

ROOT_DIR = Path(__file__).resolve().parents[3]
DB_DIR = ROOT_DIR / "data" / "runtime"
DB_PATH = DB_DIR / "mvp.db"


def get_conn() -> sqlite3.Connection:
    DB_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS alerts (
          alert_id TEXT PRIMARY KEY,
          payload TEXT NOT NULL,
          created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS triage_decisions (
          alert_id TEXT PRIMARY KEY,
          payload TEXT NOT NULL,
          disposition TEXT DEFAULT '',
          note TEXT DEFAULT '',
          updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS ingestion_runs (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          source TEXT NOT NULL,
          status TEXT NOT NULL,
          detail TEXT DEFAULT '',
          fetched_count INTEGER DEFAULT 0,
          stored_count INTEGER DEFAULT 0,
          triaged_count INTEGER DEFAULT 0,
          created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS correlation_groups (
          correlation_key TEXT PRIMARY KEY,
          representative_alert_id TEXT DEFAULT '',
          verdict TEXT DEFAULT '',
          queue TEXT DEFAULT '',
          suppression_decision TEXT DEFAULT '',
          suppression_reason TEXT DEFAULT '',
          alert_count INTEGER DEFAULT 0,
          max_risk_score INTEGER DEFAULT 0,
          max_signal_score INTEGER DEFAULT 0,
          avg_noise_score REAL DEFAULT 0,
          alert_ids TEXT DEFAULT '[]',
          first_seen TEXT DEFAULT '',
          last_seen TEXT DEFAULT '',
          updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS local_iocs (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          indicator TEXT NOT NULL UNIQUE,
          indicator_type TEXT DEFAULT 'ip',
          severity TEXT DEFAULT 'medium',
          description TEXT DEFAULT '',
          source TEXT DEFAULT 'local',
          enabled BOOLEAN DEFAULT 1,
          created_at TEXT DEFAULT CURRENT_TIMESTAMP,
          updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    cols = {row["name"] for row in cur.execute("PRAGMA table_info(triage_decisions)").fetchall()}
    if "disposition" not in cols:
        cur.execute("ALTER TABLE triage_decisions ADD COLUMN disposition TEXT DEFAULT ''")
    if "note" not in cols:
        cur.execute("ALTER TABLE triage_decisions ADD COLUMN note TEXT DEFAULT ''")
    conn.commit()
    conn.close()


def upsert_alert(alert: NormalizedAlert) -> None:
    conn = get_conn()
    conn.execute(
        """
        INSERT INTO alerts(alert_id, payload, created_at)
        VALUES (?, ?, CURRENT_TIMESTAMP)
        ON CONFLICT(alert_id) DO UPDATE SET payload=excluded.payload, created_at=CURRENT_TIMESTAMP
        """,
        (alert.alert_id, json.dumps(alert.model_dump())),
    )
    conn.commit()
    conn.close()


def _alert_matches(alert: NormalizedAlert, filters: dict[str, str]) -> bool:
    severity = filters.get("severity", "").lower()
    if severity and alert.severity.lower() != severity:
        return False
    rule_id = filters.get("rule_id", "").lower()
    if rule_id and rule_id not in alert.rule.id.lower():
        return False
    hostname = filters.get("hostname", "").lower()
    if hostname and hostname not in alert.asset.hostname.lower():
        return False
    src_ip = filters.get("src_ip", "").lower()
    if src_ip and src_ip not in alert.network.src_ip.lower():
        return False
    username = filters.get("user", "").lower()
    if username and username not in alert.user.name.lower():
        return False
    mitre = filters.get("mitre", "").lower()
    if mitre:
        values = " ".join(alert.mitre.tactics + alert.mitre.techniques).lower()
        if mitre not in values:
            return False
    query = filters.get("q", "").lower()
    if query:
        searchable = " ".join(
            [
                alert.alert_id,
                alert.severity,
                alert.source_tool,
                alert.rule.id,
                alert.rule.name,
                alert.rule.description,
                alert.asset.hostname,
                alert.asset.ip,
                alert.user.name,
                alert.network.src_ip,
                alert.network.dst_ip,
            ]
        ).lower()
        if query not in searchable:
            return False
    return True


def list_alerts(limit: int = 100, offset: int = 0, filters: dict[str, str] | None = None) -> list[NormalizedAlert]:
    safe_limit = max(1, min(limit, 1000))
    safe_offset = max(0, offset)
    conn = get_conn()
    # Pull extra rows when filters are active so analysts can page through flood data
    # without loading the full table into the frontend.
    fetch_limit = safe_limit if not filters else 10000
    rows = conn.execute("SELECT payload FROM alerts ORDER BY created_at DESC LIMIT ?", (fetch_limit,)).fetchall()
    conn.close()
    alerts = [NormalizedAlert(**json.loads(row["payload"])) for row in rows]
    if filters:
        active_filters = {key: value for key, value in filters.items() if value}
        alerts = [alert for alert in alerts if _alert_matches(alert, active_filters)]
    return alerts[safe_offset : safe_offset + safe_limit]


def count_alerts(filters: dict[str, str] | None = None) -> int:
    conn = get_conn()
    if not filters:
        row = conn.execute("SELECT COUNT(*) AS total FROM alerts").fetchone()
        conn.close()
        return int(row["total"] if row else 0)
    rows = conn.execute("SELECT payload FROM alerts ORDER BY created_at DESC LIMIT 10000").fetchall()
    conn.close()
    active_filters = {key: value for key, value in filters.items() if value}
    return sum(1 for row in rows if _alert_matches(NormalizedAlert(**json.loads(row["payload"])), active_filters))


def upsert_triage(decision: TriageDecision) -> None:
    conn = get_conn()
    conn.execute(
        """
        INSERT INTO triage_decisions(alert_id, payload, updated_at)
        VALUES (?, ?, CURRENT_TIMESTAMP)
        ON CONFLICT(alert_id) DO UPDATE SET payload=excluded.payload, updated_at=CURRENT_TIMESTAMP
        """,
        (decision.alert_id, json.dumps(decision.model_dump())),
    )
    conn.commit()
    conn.close()


def update_triage_feedback(alert_id: str, disposition: str, note: str) -> None:
    conn = get_conn()
    conn.execute(
        """
        UPDATE triage_decisions
        SET disposition = ?, note = ?, updated_at = CURRENT_TIMESTAMP
        WHERE alert_id = ?
        """,
        (disposition, note, alert_id),
    )
    conn.commit()
    conn.close()


def list_triage_history(limit: int = 100) -> list[TriageHistoryEntry]:
    conn = get_conn()
    rows = conn.execute(
        """
        SELECT alert_id, payload, disposition, note, updated_at
        FROM triage_decisions
        ORDER BY updated_at DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()
    conn.close()
    entries: list[TriageHistoryEntry] = []
    for row in rows:
        payload = json.loads(row["payload"]) if row["payload"] else None
        entries.append(
            TriageHistoryEntry(
                alert_id=row["alert_id"],
                decision=TriageDecision(**payload) if payload else None,
                disposition=row["disposition"] or "",
                note=row["note"] or "",
                updated_at=row["updated_at"] or "",
            )
        )
    return entries


def record_ingestion_run(
    source: str,
    status: str,
    detail: str = "",
    fetched_count: int = 0,
    stored_count: int = 0,
    triaged_count: int = 0,
) -> dict:
    conn = get_conn()
    cur = conn.execute(
        """
        INSERT INTO ingestion_runs(source, status, detail, fetched_count, stored_count, triaged_count, created_at)
        VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        """,
        (source, status, detail[:500], fetched_count, stored_count, triaged_count),
    )
    conn.commit()
    row = conn.execute(
        """
        SELECT id, source, status, detail, fetched_count, stored_count, triaged_count, created_at
        FROM ingestion_runs WHERE id = ?
        """,
        (cur.lastrowid,),
    ).fetchone()
    conn.close()
    return dict(row) if row else {}


def list_ingestion_runs(limit: int = 20) -> list[dict]:
    conn = get_conn()
    rows = conn.execute(
        """
        SELECT id, source, status, detail, fetched_count, stored_count, triaged_count, created_at
        FROM ingestion_runs
        ORDER BY id DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()
    conn.close()
    return [dict(row) for row in rows]


def upsert_correlation_groups(alerts: list[NormalizedAlert], decisions: list[TriageDecision]) -> list[dict]:
    grouped: dict[str, dict] = {}
    alert_lookup = {alert.alert_id: alert for alert in alerts}
    for decision in decisions:
        key = decision.correlation_key or decision.alert_id
        alert = alert_lookup.get(decision.alert_id)
        item = grouped.setdefault(
            key,
            {
                "correlation_key": key,
                "representative_alert_id": decision.alert_id,
                "verdict": decision.verdict,
                "queue": decision.queue,
                "suppression_decision": decision.suppression_decision,
                "suppression_reason": decision.suppression_reason,
                "alert_ids": [],
                "first_seen": alert.timestamp if alert else "",
                "last_seen": alert.timestamp if alert else "",
                "max_risk_score": 0,
                "max_signal_score": 0,
                "noise_scores": [],
            },
        )
        item["alert_ids"].append(decision.alert_id)
        item["max_risk_score"] = max(item["max_risk_score"], decision.risk_score)
        item["max_signal_score"] = max(item["max_signal_score"], decision.signal_score)
        item["noise_scores"].append(decision.noise_score)
        if decision.risk_score >= item["max_risk_score"]:
            item["representative_alert_id"] = decision.alert_id
            item["verdict"] = decision.verdict
            item["queue"] = decision.queue
            item["suppression_decision"] = decision.suppression_decision
            item["suppression_reason"] = decision.suppression_reason
        if alert and alert.timestamp:
            timestamps = [value for value in [item["first_seen"], item["last_seen"], alert.timestamp] if value]
            item["first_seen"] = min(timestamps)
            item["last_seen"] = max(timestamps)

    rows: list[dict] = []
    conn = get_conn()
    for item in grouped.values():
        alert_ids = sorted(set(item["alert_ids"]))
        avg_noise = round(sum(item["noise_scores"]) / max(len(item["noise_scores"]), 1), 2)
        conn.execute(
            """
            INSERT INTO correlation_groups(
              correlation_key, representative_alert_id, verdict, queue, suppression_decision,
              suppression_reason, alert_count, max_risk_score, max_signal_score, avg_noise_score,
              alert_ids, first_seen, last_seen, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(correlation_key) DO UPDATE SET
              representative_alert_id=excluded.representative_alert_id,
              verdict=excluded.verdict,
              queue=excluded.queue,
              suppression_decision=excluded.suppression_decision,
              suppression_reason=excluded.suppression_reason,
              alert_count=excluded.alert_count,
              max_risk_score=excluded.max_risk_score,
              max_signal_score=excluded.max_signal_score,
              avg_noise_score=excluded.avg_noise_score,
              alert_ids=excluded.alert_ids,
              first_seen=excluded.first_seen,
              last_seen=excluded.last_seen,
              updated_at=CURRENT_TIMESTAMP
            """,
            (
                item["correlation_key"],
                item["representative_alert_id"],
                item["verdict"],
                item["queue"],
                item["suppression_decision"],
                item["suppression_reason"],
                len(alert_ids),
                item["max_risk_score"],
                item["max_signal_score"],
                avg_noise,
                json.dumps(alert_ids),
                item["first_seen"],
                item["last_seen"],
            ),
        )
        rows.append(
            {
                "correlation_key": item["correlation_key"],
                "representative_alert_id": item["representative_alert_id"],
                "verdict": item["verdict"],
                "queue": item["queue"],
                "suppression_decision": item["suppression_decision"],
                "suppression_reason": item["suppression_reason"],
                "alert_count": len(alert_ids),
                "max_risk_score": item["max_risk_score"],
                "max_signal_score": item["max_signal_score"],
                "avg_noise_score": avg_noise,
                "alert_ids": alert_ids,
                "first_seen": item["first_seen"],
                "last_seen": item["last_seen"],
            }
        )
    conn.commit()
    conn.close()
    return sorted(rows, key=lambda row: (row["max_signal_score"], row["alert_count"]), reverse=True)


def list_correlation_groups(limit: int = 50, min_count: int = 1, queue: str = "") -> list[dict]:
    conn = get_conn()
    rows = conn.execute(
        """
        SELECT correlation_key, representative_alert_id, verdict, queue, suppression_decision,
               suppression_reason, alert_count, max_risk_score, max_signal_score, avg_noise_score,
               alert_ids, first_seen, last_seen, updated_at
        FROM correlation_groups
        WHERE alert_count >= ? AND (? = '' OR queue = ?)
        ORDER BY max_signal_score DESC, alert_count DESC, updated_at DESC
        LIMIT ?
        """,
        (max(1, min_count), queue, queue, max(1, min(limit, 200))),
    ).fetchall()
    conn.close()
    results = []
    for row in rows:
        item = dict(row)
        item["alert_ids"] = json.loads(item["alert_ids"] or "[]")
        results.append(item)
    return results


def add_local_ioc(
    indicator: str,
    indicator_type: str = "ip",
    severity: str = "medium",
    description: str = "",
    source: str = "local",
    enabled: bool = True,
) -> dict:
    normalized = indicator.strip().lower()
    conn = get_conn()
    conn.execute(
        """
        INSERT INTO local_iocs(indicator, indicator_type, severity, description, source, enabled, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
        ON CONFLICT(indicator) DO UPDATE SET
          indicator_type=excluded.indicator_type,
          severity=excluded.severity,
          description=excluded.description,
          source=excluded.source,
          enabled=excluded.enabled,
          updated_at=CURRENT_TIMESTAMP
        """,
        (normalized, indicator_type, severity, description[:500], source[:120], 1 if enabled else 0),
    )
    conn.commit()
    row = conn.execute(
        """
        SELECT id, indicator, indicator_type, severity, description, source, enabled, created_at, updated_at
        FROM local_iocs WHERE indicator = ?
        """,
        (normalized,),
    ).fetchone()
    conn.close()
    return dict(row) if row else {}


def list_local_iocs(limit: int = 200, enabled_only: bool = False) -> list[dict]:
    conn = get_conn()
    rows = conn.execute(
        """
        SELECT id, indicator, indicator_type, severity, description, source, enabled, created_at, updated_at
        FROM local_iocs
        WHERE (? = 0 OR enabled = 1)
        ORDER BY updated_at DESC
        LIMIT ?
        """,
        (1 if enabled_only else 0, max(1, min(limit, 1000))),
    ).fetchall()
    conn.close()
    return [dict(row) for row in rows]


def enrich_alert_with_local_iocs(alert: NormalizedAlert) -> dict:
    candidates = {
        value.strip().lower()
        for value in [
            alert.network.src_ip,
            alert.network.dst_ip,
            alert.asset.ip,
            alert.asset.hostname,
            alert.user.name,
        ]
        if value
    }
    raw_text = json.dumps(alert.raw_event).lower()
    matches = []
    for ioc in list_local_iocs(limit=1000, enabled_only=True):
        indicator = ioc["indicator"].lower()
        if indicator in candidates or (indicator and indicator in raw_text):
            matches.append(ioc)
    max_severity = "none"
    severity_rank = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    for match in matches:
        if severity_rank.get(match["severity"], 0) > severity_rank.get(max_severity, 0):
            max_severity = match["severity"]
    return {
        "alert_id": alert.alert_id,
        "checked_candidates": sorted(candidates),
        "match_count": len(matches),
        "max_severity": max_severity,
        "matches": matches,
        "provider": "local_ioc",
        "cache_source": "local_db",
    }
