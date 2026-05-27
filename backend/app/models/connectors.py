from pydantic import BaseModel


class ConnectorOut(BaseModel):
    id: int
    name: str
    connector_type: str
    base_url: str
    username: str
    password_masked: str
    enabled: bool
    last_status: str
    last_error: str
    last_latency_ms: int
    last_checked_at: str


class ConnectorUpsertRequest(BaseModel):
    base_url: str
    username: str
    password: str
    enabled: bool = True


class ConnectorHealthResponse(BaseModel):
    name: str
    ok: bool
    detail: str
