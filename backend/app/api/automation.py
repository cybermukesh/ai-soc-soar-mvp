from datetime import datetime, timezone
from urllib.parse import urlparse

import httpx
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.auth import require_role
from app.core.settings import settings
from app.db.models import AuditLog, AutomationConnector, AutomationWorkflowRun, User
from app.db.session import get_db
from app.models.automation import (
    AutomationConnectorOut,
    TriggerWorkflowRequest,
    WorkflowApprovalRequest,
    WorkflowRunOut,
    WorkflowTemplateOut,
)

router = APIRouter(prefix="/api/v1/automation", tags=["automation"])

WORKFLOW_TEMPLATES = [
    {
        "id": "n8n-test-webhook",
        "name": "n8n Test Webhook",
        "description": "Send a bounded test payload to the configured n8n webhook.",
        "connector_name": "n8n",
        "action": "webhook_post",
    }
]


def _mask_url(value: str) -> str:
    if not value:
        return ""
    parsed = urlparse(value)
    if not parsed.netloc:
        return "configured"
    return f"{parsed.scheme}://{parsed.netloc}/..."


def _template_by_id(template_id: str) -> dict:
    for template in WORKFLOW_TEMPLATES:
        if template["id"] == template_id:
            return template
    raise HTTPException(status_code=404, detail="Workflow template not found")


def _connector_out(row: AutomationConnector) -> AutomationConnectorOut:
    return AutomationConnectorOut(
        id=row.id,
        name=row.name,
        connector_type=row.connector_type,
        enabled=row.enabled,
        webhook_url_masked=row.webhook_url_masked,
        last_status=row.last_status,
        last_error=row.last_error,
        updated_at=row.updated_at.isoformat() if row.updated_at else "",
    )


def _run_out(row: AutomationWorkflowRun) -> WorkflowRunOut:
    return WorkflowRunOut(
        id=row.id,
        template_id=row.template_id,
        template_name=row.template_name,
        connector_name=row.connector_name,
        status=row.status,
        incident_id=row.incident_id,
        alert_id=row.alert_id,
        request_summary=row.request_summary,
        response_detail=row.response_detail,
        triggered_by_user_id=row.triggered_by_user_id,
        created_at=row.created_at.isoformat() if row.created_at else "",
        completed_at=row.completed_at.isoformat() if row.completed_at else "",
    )


def _audit(db: Session, actor: User, action: str, target_id: str, detail: str = "") -> None:
    db.add(
        AuditLog(
            actor_user_id=actor.id,
            action=action,
            target_type="automation",
            target_id=target_id,
            detail=detail[:500],
        )
    )


def ensure_automation_connectors(db: Session) -> None:
    n8n = db.query(AutomationConnector).filter(AutomationConnector.name == "n8n").first()
    webhook_url = settings.n8n_webhook_url.strip()
    if not n8n:
        n8n = AutomationConnector(name="n8n", connector_type="webhook")
        db.add(n8n)
    n8n.enabled = bool(webhook_url)
    n8n.webhook_url_masked = _mask_url(webhook_url)
    if not webhook_url:
        n8n.last_status = "not_configured"
        n8n.last_error = "N8N_WEBHOOK_URL is not configured"
    db.commit()


@router.get("/connectors", response_model=list[AutomationConnectorOut])
def list_automation_connectors(
    db: Session = Depends(get_db),
    _: User = Depends(require_role("admin", "analyst", "viewer")),
):
    ensure_automation_connectors(db)
    rows = db.query(AutomationConnector).order_by(AutomationConnector.id.asc()).all()
    return [_connector_out(row) for row in rows]


@router.get("/workflow-templates", response_model=list[WorkflowTemplateOut])
def list_workflow_templates(
    db: Session = Depends(get_db),
    _: User = Depends(require_role("admin", "analyst", "viewer")),
):
    ensure_automation_connectors(db)
    connectors = {row.name: row for row in db.query(AutomationConnector).all()}
    results = []
    for template in WORKFLOW_TEMPLATES:
        connector = connectors.get(template["connector_name"])
        results.append(
            WorkflowTemplateOut(**template, enabled=bool(connector and connector.enabled))
        )
    return results


@router.get("/workflow-runs", response_model=list[WorkflowRunOut])
def list_workflow_runs(
    status: str | None = None,
    template_id: str | None = None,
    db: Session = Depends(get_db),
    _: User = Depends(require_role("admin", "analyst", "viewer")),
):
    query = db.query(AutomationWorkflowRun)
    if status:
        query = query.filter(AutomationWorkflowRun.status == status)
    if template_id:
        query = query.filter(AutomationWorkflowRun.template_id == template_id)
    rows = query.order_by(AutomationWorkflowRun.id.desc()).limit(200).all()
    return [_run_out(row) for row in rows]


@router.post("/workflow-templates/{template_id}/trigger", response_model=WorkflowRunOut)
async def trigger_workflow_template(
    template_id: str,
    payload: TriggerWorkflowRequest,
    db: Session = Depends(get_db),
    user: User = Depends(require_role("admin", "analyst")),
):
    template = _template_by_id(template_id)
    ensure_automation_connectors(db)
    connector = (
        db.query(AutomationConnector)
        .filter(AutomationConnector.name == template["connector_name"])
        .first()
    )
    webhook_url = settings.n8n_webhook_url.strip()
    requested_workflow = str(payload.payload.get("requested_workflow", ""))
    requires_admin_approval = requested_workflow == "containment_approval"
    if (not connector or not connector.enabled or not webhook_url) and not requires_admin_approval:
        raise HTTPException(status_code=400, detail="n8n webhook is not configured")
    run = AutomationWorkflowRun(
        template_id=template["id"],
        template_name=template["name"],
        connector_name=template["connector_name"],
        status="pending_approval" if requires_admin_approval else "pending",
        incident_id=payload.incident_id,
        alert_id=payload.alert_id,
        request_summary=(
            f"workflow={requested_workflow or 'unspecified'}; dry_run={payload.dry_run}; keys={','.join(sorted(payload.payload.keys()))[:360]}"
        ),
        triggered_by_user_id=user.id,
    )
    db.add(run)
    db.flush()
    _audit(db, user, "trigger_workflow", str(run.id), template["id"])

    if run.status == "pending_approval":
        run.response_detail = "High-impact containment workflow is waiting for admin approval"
        run.completed_at = datetime.now(timezone.utc)
        connector.last_status = "pending_approval"
        connector.last_error = ""
        db.commit()
        db.refresh(run)
        return _run_out(run)

    outbound = {
        "template_id": template["id"],
        "template_name": template["name"],
        "incident_id": payload.incident_id,
        "alert_id": payload.alert_id,
        "dry_run": payload.dry_run,
        "payload": payload.payload,
        "triggered_by_user_id": user.id,
    }
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.post(webhook_url, json=outbound)
        run.status = "success" if response.status_code < 400 else "error"
        run.response_detail = f"HTTP {response.status_code}: {response.text[:450]}"
    except httpx.HTTPError as exc:
        run.status = "error"
        run.response_detail = str(exc)[:500]

    run.completed_at = datetime.now(timezone.utc)
    connector.last_status = run.status
    connector.last_error = "" if run.status == "success" else run.response_detail[:300]
    db.commit()
    db.refresh(run)
    return _run_out(run)


@router.post("/workflow-runs/{run_id}/approval", response_model=WorkflowRunOut)
async def approve_workflow_run(
    run_id: int,
    payload: WorkflowApprovalRequest,
    db: Session = Depends(get_db),
    user: User = Depends(require_role("admin")),
):
    run = db.query(AutomationWorkflowRun).filter(AutomationWorkflowRun.id == run_id).first()
    if not run:
        raise HTTPException(status_code=404, detail="Workflow run not found")
    if run.status != "pending_approval":
        raise HTTPException(status_code=400, detail="Workflow run is not pending approval")

    decision = payload.decision.lower().strip()
    if decision not in {"approve", "reject"}:
        raise HTTPException(status_code=400, detail="decision must be approve or reject")

    ensure_automation_connectors(db)
    connector = db.query(AutomationConnector).filter(AutomationConnector.name == run.connector_name).first()
    webhook_url = settings.n8n_webhook_url.strip()
    if decision == "reject":
        run.status = "rejected"
        run.response_detail = f"Rejected by admin {user.email}: {payload.note}"[:500]
        run.completed_at = datetime.now(timezone.utc)
        if connector:
            connector.last_status = "rejected"
            connector.last_error = ""
        _audit(db, user, "reject_workflow", str(run.id), payload.note)
        db.commit()
        db.refresh(run)
        return _run_out(run)

    if not connector or not connector.enabled or not webhook_url:
        raise HTTPException(status_code=400, detail="n8n webhook is not configured")

    outbound = {
        "template_id": run.template_id,
        "template_name": run.template_name,
        "workflow_run_id": run.id,
        "incident_id": run.incident_id,
        "alert_id": run.alert_id,
        "request_summary": run.request_summary,
        "approval": {
            "decision": decision,
            "note": payload.note,
            "approved_by_user_id": user.id,
            "approved_by_email": user.email,
        },
    }
    _audit(db, user, "approve_workflow", str(run.id), payload.note)
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.post(webhook_url, json=outbound)
        run.status = "success" if response.status_code < 400 else "error"
        run.response_detail = f"APPROVED HTTP {response.status_code}: {response.text[:420]}"
    except httpx.HTTPError as exc:
        run.status = "error"
        run.response_detail = str(exc)[:500]

    run.completed_at = datetime.now(timezone.utc)
    connector.last_status = run.status
    connector.last_error = "" if run.status == "success" else run.response_detail[:300]
    db.commit()
    db.refresh(run)
    return _run_out(run)
