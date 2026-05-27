from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.auth import require_role
from app.db.models import AuditLog, Incident, IncidentEvent, User
from app.db.session import get_db
from app.models.incidents import IncidentCreateRequest, IncidentOut, IncidentStatusUpdateRequest

router = APIRouter(prefix="/api/v1/incidents", tags=["incidents"])


def _out(i: Incident) -> IncidentOut:
    return IncidentOut(
        id=i.id,
        title=i.title,
        severity=i.severity,
        status=i.status,
        risk_score=i.risk_score,
        source_tool=i.source_tool,
        created_by_user_id=i.created_by_user_id,
        created_at=i.created_at.isoformat() if i.created_at else "",
    )


def _audit(db: Session, user: User, action: str, target_id: str, detail: str = "") -> None:
    db.add(AuditLog(actor_user_id=user.id, action=action, target_type="incident", target_id=target_id, detail=detail[:500]))


@router.get("", response_model=list[IncidentOut])
def list_incidents(db: Session = Depends(get_db), _: User = Depends(require_role("admin", "analyst", "viewer"))):
    rows = db.query(Incident).order_by(Incident.id.desc()).limit(200).all()
    return [_out(r) for r in rows]


@router.post("", response_model=IncidentOut)
def create_incident(
    payload: IncidentCreateRequest,
    db: Session = Depends(get_db),
    user: User = Depends(require_role("admin", "analyst")),
):
    row = Incident(
        title=payload.title,
        severity=payload.severity,
        risk_score=payload.risk_score,
        source_tool=payload.source_tool,
        status="open",
        created_by_user_id=user.id,
    )
    db.add(row)
    db.flush()
    db.add(IncidentEvent(incident_id=row.id, event_type="created", detail="incident created", actor_user_id=user.id))
    _audit(db, user, "create_incident", str(row.id), row.title)
    db.commit()
    db.refresh(row)
    return _out(row)


@router.patch("/{incident_id}/status", response_model=IncidentOut)
def update_incident_status(
    incident_id: int,
    payload: IncidentStatusUpdateRequest,
    db: Session = Depends(get_db),
    user: User = Depends(require_role("admin", "analyst")),
):
    row = db.query(Incident).filter(Incident.id == incident_id).first()
    if not row:
        raise HTTPException(status_code=404, detail="Incident not found")
    row.status = payload.status
    db.add(IncidentEvent(incident_id=row.id, event_type="status_change", detail=payload.note or payload.status, actor_user_id=user.id))
    _audit(db, user, "update_incident_status", str(row.id), payload.status)
    db.commit()
    db.refresh(row)
    return _out(row)
