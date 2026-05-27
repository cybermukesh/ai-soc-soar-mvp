import os
import time
from datetime import datetime, timezone
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.auth import require_role
from app.db.models import AuditLog, Connector, ConnectorHealthCheck, User
from app.db.session import get_db
from app.models.connectors import (
    ConnectorHealthCheckOut,
    ConnectorHealthResponse,
    ConnectorOut,
    ConnectorUpsertRequest,
)
from app.services.crypto import decrypt_secret, encrypt_secret

router = APIRouter(prefix="/api/v1/connectors", tags=["connectors"])


def _is_valid_url(value: str) -> bool:
    try:
        parsed = urlparse(value)
        return parsed.scheme in {"http", "https"} and bool(parsed.netloc)
    except Exception:
        return False


def _missing_required(row: Connector) -> list[str]:
    missing: list[str] = []
    if not row.base_url:
        missing.append("base_url")
    if not row.username:
        missing.append("username")
    if not row.password_encrypted:
        missing.append("password")
    return missing


def _to_out(c: Connector) -> ConnectorOut:
    return ConnectorOut(
        id=c.id,
        name=c.name,
        connector_type=c.connector_type,
        base_url=c.base_url,
        username=c.username,
        password_masked=c.password_masked,
        enabled=c.enabled,
        last_status=c.last_status,
        last_error=c.last_error,
        last_latency_ms=c.last_latency_ms,
        last_checked_at=c.last_checked_at.isoformat() if c.last_checked_at else "",
    )


def _audit(db: Session, actor: User, action: str, target_id: str, detail: str = "") -> None:
    db.add(
        AuditLog(
            actor_user_id=actor.id,
            action=action,
            target_type="connector",
            target_id=target_id,
            detail=detail[:500],
        )
    )
    db.commit()


@router.get("", response_model=list[ConnectorOut])
def list_connectors(
    db: Session = Depends(get_db), _: User = Depends(require_role("admin", "analyst", "viewer"))
):
    rows = db.query(Connector).order_by(Connector.id.asc()).all()
    return [_to_out(r) for r in rows]


@router.put("/{name}", response_model=ConnectorOut)
def upsert_connector(
    name: str,
    payload: ConnectorUpsertRequest,
    db: Session = Depends(get_db),
    admin: User = Depends(require_role("admin")),
):
    row = db.query(Connector).filter(Connector.name == name).first()
    if not row:
        row = Connector(name=name, connector_type=name)
        db.add(row)
    base_url = payload.base_url.strip()
    username = payload.username.strip()
    if payload.enabled:
        if not _is_valid_url(base_url):
            raise HTTPException(status_code=400, detail="Invalid base_url. Use http(s)://host[:port]")
        if not username:
            raise HTTPException(status_code=400, detail="Username is required when connector is enabled")
        if not payload.password and not row.password_encrypted:
            raise HTTPException(status_code=400, detail="Password is required for first-time connector enable")
    row.base_url = base_url
    row.username = username
    if payload.password:
        row.password_encrypted = encrypt_secret(payload.password)
    row.password_masked = "********" if payload.password else row.password_masked
    row.enabled = payload.enabled
    row.last_status = "configured"
    row.last_error = ""
    db.commit()
    db.refresh(row)
    _audit(db, admin, "upsert_connector", str(row.id), f"name={name}")
    return _to_out(row)


@router.get("/{name}/health", response_model=ConnectorHealthResponse)
def connector_health(
    name: str,
    db: Session = Depends(get_db),
    user: User = Depends(require_role("admin", "analyst", "viewer")),
):
    row = db.query(Connector).filter(Connector.name == name).first()
    if not row:
        raise HTTPException(status_code=404, detail="Connector not found")

    started = time.perf_counter()
    if not row.enabled:
        row.last_status = "disabled"
        row.last_error = "connector disabled"
        row.last_checked_at = datetime.now(timezone.utc)
        row.last_latency_ms = int((time.perf_counter() - started) * 1000)
        db.add(
            ConnectorHealthCheck(
                connector_id=row.id,
                ok=False,
                detail="disabled",
                latency_ms=row.last_latency_ms,
                checked_by_user_id=user.id,
            )
        )
        db.commit()
        return ConnectorHealthResponse(name=name, ok=False, detail="disabled")

    has_secret = bool(decrypt_secret(row.password_encrypted))
    ok = bool(row.base_url and row.username and has_secret)
    detail = "configured" if ok else "missing base_url/username/password"
    row.last_status = "ok" if ok else "error"
    row.last_error = "" if ok else detail
    row.last_checked_at = datetime.now(timezone.utc)
    row.last_latency_ms = int((time.perf_counter() - started) * 1000)
    db.add(
        ConnectorHealthCheck(
            connector_id=row.id,
            ok=ok,
            detail=detail,
            latency_ms=row.last_latency_ms,
            checked_by_user_id=user.id,
        )
    )
    db.commit()
    _audit(db, user, "check_connector_health", str(row.id), detail)
    return ConnectorHealthResponse(name=name, ok=ok, detail=detail)


@router.post("/seed-defaults")
def seed_defaults(
    db: Session = Depends(get_db),
    admin: User = Depends(require_role("admin")),
):
    defaults = [
        ("wazuh", os.getenv("WAZUH_API_URL", ""), os.getenv("WAZUH_API_USER", "")),
        ("opensearch", os.getenv("OPENSEARCH_URL", ""), os.getenv("OPENSEARCH_USER", "")),
    ]
    for name, base_url, username in defaults:
        row = db.query(Connector).filter(Connector.name == name).first()
        if not row:
            row = Connector(name=name, connector_type=name)
            db.add(row)
        row.base_url = base_url
        row.username = username
        row.password_encrypted = encrypt_secret("env-placeholder") if base_url and username else ""
        row.password_masked = "********" if base_url and username else ""
        row.enabled = bool(base_url and username)
        row.last_latency_ms = 0
    db.commit()
    _audit(db, admin, "seed_default_connectors", "all", "from env")
    return {"status": "ok"}


@router.get("/{name}/history", response_model=list[ConnectorHealthCheckOut])
def connector_history(
    name: str,
    db: Session = Depends(get_db),
    _: User = Depends(require_role("admin", "analyst", "viewer")),
):
    row = db.query(Connector).filter(Connector.name == name).first()
    if not row:
        raise HTTPException(status_code=404, detail="Connector not found")
    checks = (
        db.query(ConnectorHealthCheck)
        .filter(ConnectorHealthCheck.connector_id == row.id)
        .order_by(ConnectorHealthCheck.id.desc())
        .limit(100)
        .all()
    )
    return [
        ConnectorHealthCheckOut(
            id=c.id,
            connector_id=c.connector_id,
            ok=c.ok,
            detail=c.detail,
            latency_ms=c.latency_ms,
            checked_by_user_id=c.checked_by_user_id,
            created_at=c.created_at.isoformat() if c.created_at else "",
        )
        for c in checks
    ]


@router.get("/setup/summary")
def connector_setup_summary(
    db: Session = Depends(get_db),
    _: User = Depends(require_role("admin", "analyst", "viewer")),
):
    rows = db.query(Connector).order_by(Connector.id.asc()).all()
    data = []
    for row in rows:
        missing = _missing_required(row) if row.enabled else []
        data.append(
            {
                "name": row.name,
                "enabled": row.enabled,
                "last_status": row.last_status,
                "missing_required_fields": missing,
                "ready": row.enabled and len(missing) == 0,
            }
        )
    return {"connectors": data}
