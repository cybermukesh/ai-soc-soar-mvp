from typing import Any, Literal

from pydantic import BaseModel, Field


Severity = Literal["low", "medium", "high", "critical"]


class RuleContext(BaseModel):
    id: str = ""
    name: str = ""
    description: str = ""
    groups: list[str] = Field(default_factory=list)


class AssetContext(BaseModel):
    id: str = ""
    hostname: str = ""
    ip: str = ""
    criticality: str = "unknown"


class UserContext(BaseModel):
    name: str = ""
    risk_level: str = "unknown"


class NetworkContext(BaseModel):
    src_ip: str = ""
    dst_ip: str = ""
    src_port: int | None = None
    dst_port: int | None = None


class MitreContext(BaseModel):
    tactics: list[str] = Field(default_factory=list)
    techniques: list[str] = Field(default_factory=list)


class NormalizedAlert(BaseModel):
    alert_id: str
    source_tool: str
    timestamp: str
    severity: Severity
    severity_score: int = Field(ge=0, le=100)
    rule: RuleContext = Field(default_factory=RuleContext)
    asset: AssetContext = Field(default_factory=AssetContext)
    user: UserContext = Field(default_factory=UserContext)
    network: NetworkContext = Field(default_factory=NetworkContext)
    mitre: MitreContext = Field(default_factory=MitreContext)
    raw_event: dict[str, Any] = Field(default_factory=dict)
