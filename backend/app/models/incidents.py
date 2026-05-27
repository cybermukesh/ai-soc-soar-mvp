from pydantic import BaseModel


class IncidentCreateRequest(BaseModel):
    title: str
    severity: str = "medium"
    risk_score: int = 50
    source_tool: str = "wazuh"


class IncidentOut(BaseModel):
    id: int
    title: str
    severity: str
    status: str
    risk_score: int
    source_tool: str
    created_by_user_id: int
    created_at: str


class IncidentStatusUpdateRequest(BaseModel):
    status: str
    note: str = ""


class IncidentEventOut(BaseModel):
    id: int
    incident_id: int
    event_type: str
    detail: str
    actor_user_id: int
    created_at: str
