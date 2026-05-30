from pydantic import BaseModel, Field


class AutomationConnectorOut(BaseModel):
    id: int
    name: str
    connector_type: str
    enabled: bool
    webhook_url_masked: str
    last_status: str
    last_error: str
    updated_at: str


class WorkflowTemplateOut(BaseModel):
    id: str
    name: str
    description: str
    connector_name: str
    action: str
    enabled: bool


class TriggerWorkflowRequest(BaseModel):
    incident_id: str = ""
    alert_id: str = ""
    dry_run: bool = False
    payload: dict = Field(default_factory=dict)


class WorkflowApprovalRequest(BaseModel):
    decision: str = "approve"
    note: str = ""


class WorkflowRunOut(BaseModel):
    id: int
    template_id: str
    template_name: str
    connector_name: str
    status: str
    incident_id: str
    alert_id: str
    request_summary: str
    response_detail: str
    triggered_by_user_id: int
    created_at: str
    completed_at: str
