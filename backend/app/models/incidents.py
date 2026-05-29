from pydantic import BaseModel


class IncidentCreateRequest(BaseModel):
    title: str
    severity: str = "medium"
    risk_score: int = 50
    source_tool: str = "wazuh"
    alert_id: str = ""
    ticket_ref: str = ""
    owner_name: str = ""
    phase: str = "new"
    summary: str = ""


class IncidentOut(BaseModel):
    id: int
    title: str
    severity: str
    status: str
    risk_score: int
    source_tool: str
    alert_id: str
    ticket_ref: str
    owner_name: str
    phase: str
    summary: str
    created_by_user_id: int
    created_at: str


class IncidentStatusUpdateRequest(BaseModel):
    status: str
    note: str = ""
    owner_name: str = ""
    ticket_ref: str = ""
    phase: str = ""


class IncidentEventCreateRequest(BaseModel):
    event_type: str
    detail: str


class IncidentEventOut(BaseModel):
    id: int
    incident_id: int
    event_type: str
    detail: str
    actor_user_id: int
    created_at: str
