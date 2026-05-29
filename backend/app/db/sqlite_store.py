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


def list_alerts(limit: int = 100) -> list[NormalizedAlert]:
    conn = get_conn()
    rows = conn.execute(
        "SELECT payload FROM alerts ORDER BY created_at DESC LIMIT ?", (limit,)
    ).fetchall()
    conn.close()
    return [NormalizedAlert(**json.loads(row["payload"])) for row in rows]


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
