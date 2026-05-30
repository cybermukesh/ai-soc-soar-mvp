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
