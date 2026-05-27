from typing import Literal

from pydantic import BaseModel, Field

from app.models.alert import NormalizedAlert


TriageVerdict = Literal[
    "false_positive",
    "low_priority",
    "suspicious",
    "true_positive",
    "needs_review",
]


class TriageDecision(BaseModel):
    alert_id: str
    verdict: TriageVerdict
    confidence: float = Field(ge=0, le=1)
    risk_score: int = Field(ge=0, le=100)
    attack_summary: str
    evidence: list[str] = Field(default_factory=list)
    mitre: dict[str, list[str]] = Field(default_factory=dict)
    recommended_actions: list[str] = Field(default_factory=list)
    soar_recommendation: str = ""
    model_used: str = "gpt-4o-mini"
    from_cache: bool = False


class TriageRequest(BaseModel):
    alert: NormalizedAlert
    force_refresh: bool = False


class TriageBatchResponse(BaseModel):
    decisions: list[TriageDecision]
