from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.auth import require_role
from app.db.models import AiProviderSetting, AuditLog, ThreatIntelProviderSetting, User
from app.db.session import get_db
from app.models.settings import (
    AiProviderOut,
    AiProviderUpsertRequest,
    ProviderHealthResponse,
    ThreatIntelProviderOut,
    ThreatIntelProviderUpsertRequest,
)
from app.services.crypto import encrypt_secret

router = APIRouter(prefix="/api/v1/settings", tags=["settings"])

AI_PROVIDERS = {"openai", "anthropic", "ollama", "offline"}
THREAT_INTEL_PROVIDERS = {"virustotal", "abuseipdb", "otx", "misp", "local_ioc"}
SEVERITIES = {"low", "medium", "high", "critical"}


def _mask_secret(secret: str, existing: str = "") -> str:
    if not secret:
        return existing
    if len(secret) <= 6:
        return "******"
    return f"{secret[:3]}...{secret[-3:]}"


def _audit(db: Session, actor: User, action: str, target_type: str, target_id: str, detail: str = "") -> None:
    db.add(
        AuditLog(
            actor_user_id=actor.id,
            action=action,
            target_type=target_type,
            target_id=target_id,
            detail=detail[:500],
        )
    )
    db.commit()


def _ai_out(row: AiProviderSetting) -> AiProviderOut:
    return AiProviderOut(
        id=row.id,
        provider=row.provider,
        model=row.model,
        api_key_masked=row.api_key_masked,
        base_url=row.base_url,
        enabled=row.enabled,
        cache_enabled=row.cache_enabled,
        max_input_chars=row.max_input_chars,
        max_output_tokens=row.max_output_tokens,
        min_severity=row.min_severity,
        fallback_model=row.fallback_model,
        last_status=row.last_status,
        last_error=row.last_error,
        updated_at=row.updated_at.isoformat() if row.updated_at else "",
    )


def _intel_out(row: ThreatIntelProviderSetting) -> ThreatIntelProviderOut:
    return ThreatIntelProviderOut(
        id=row.id,
        provider=row.provider,
        api_key_masked=row.api_key_masked,
        base_url=row.base_url,
        enabled=row.enabled,
        daily_limit=row.daily_limit,
        cache_ttl_minutes=row.cache_ttl_minutes,
        last_status=row.last_status,
        last_error=row.last_error,
        updated_at=row.updated_at.isoformat() if row.updated_at else "",
    )


@router.get("/ai-providers", response_model=list[AiProviderOut])
def list_ai_providers(
    db: Session = Depends(get_db),
    _: User = Depends(require_role("admin", "analyst", "viewer")),
):
    rows = db.query(AiProviderSetting).order_by(AiProviderSetting.provider.asc()).all()
    return [_ai_out(row) for row in rows]


@router.put("/ai-providers/{provider}", response_model=AiProviderOut)
def upsert_ai_provider(
    provider: str,
    payload: AiProviderUpsertRequest,
    db: Session = Depends(get_db),
    admin: User = Depends(require_role("admin")),
):
    provider = provider.lower().strip()
    if provider != payload.provider.lower().strip():
        raise HTTPException(status_code=400, detail="Provider path and payload mismatch")
    if provider not in AI_PROVIDERS:
        raise HTTPException(status_code=400, detail=f"Unsupported AI provider: {provider}")
    if payload.min_severity not in SEVERITIES:
        raise HTTPException(status_code=400, detail="min_severity must be low, medium, high, or critical")
    if payload.enabled and provider != "offline" and not payload.api_key and not payload.base_url:
        existing = db.query(AiProviderSetting).filter(AiProviderSetting.provider == provider).first()
        if not existing or not existing.api_key_encrypted:
            raise HTTPException(status_code=400, detail="Enabled cloud/local provider requires api_key or base_url")

    row = db.query(AiProviderSetting).filter(AiProviderSetting.provider == provider).first()
    if not row:
        row = AiProviderSetting(provider=provider)
        db.add(row)
    row.model = payload.model.strip()
    row.base_url = payload.base_url.strip()
    row.enabled = payload.enabled
    row.cache_enabled = payload.cache_enabled
    row.max_input_chars = payload.max_input_chars
    row.max_output_tokens = payload.max_output_tokens
    row.min_severity = payload.min_severity
    row.fallback_model = payload.fallback_model.strip()
    if payload.api_key:
        row.api_key_encrypted = encrypt_secret(payload.api_key)
        row.api_key_masked = _mask_secret(payload.api_key, row.api_key_masked)
    row.last_status = "configured"
    row.last_error = ""
    db.commit()
    db.refresh(row)
    _audit(db, admin, "upsert_ai_provider", "ai_provider", provider, f"enabled={row.enabled};model={row.model}")
    return _ai_out(row)


@router.post("/ai-providers/{provider}/health", response_model=ProviderHealthResponse)
def ai_provider_health(
    provider: str,
    db: Session = Depends(get_db),
    user: User = Depends(require_role("admin", "analyst", "viewer")),
):
    provider = provider.lower().strip()
    row = db.query(AiProviderSetting).filter(AiProviderSetting.provider == provider).first()
    if not row:
        raise HTTPException(status_code=404, detail="AI provider not found")
    if not row.enabled:
        ok, detail = False, "disabled"
    elif provider == "offline":
        ok, detail = True, "offline heuristic triage enabled"
    elif provider == "ollama":
        ok, detail = bool(row.base_url), "ollama base_url configured" if row.base_url else "missing ollama base_url"
    else:
        ok = bool(row.api_key_encrypted)
        detail = "api key configured" if ok else "missing api key"
    row.last_status = "ok" if ok else "error"
    row.last_error = "" if ok else detail
    db.commit()
    _audit(db, user, "check_ai_provider_health", "ai_provider", provider, detail)
    return ProviderHealthResponse(provider=provider, ok=ok, detail=detail)


@router.get("/threat-intel", response_model=list[ThreatIntelProviderOut])
def list_threat_intel_providers(
    db: Session = Depends(get_db),
    _: User = Depends(require_role("admin", "analyst", "viewer")),
):
    rows = db.query(ThreatIntelProviderSetting).order_by(ThreatIntelProviderSetting.provider.asc()).all()
    return [_intel_out(row) for row in rows]


@router.put("/threat-intel/{provider}", response_model=ThreatIntelProviderOut)
def upsert_threat_intel_provider(
    provider: str,
    payload: ThreatIntelProviderUpsertRequest,
    db: Session = Depends(get_db),
    admin: User = Depends(require_role("admin")),
):
    provider = provider.lower().strip()
    if provider != payload.provider.lower().strip():
        raise HTTPException(status_code=400, detail="Provider path and payload mismatch")
    if provider not in THREAT_INTEL_PROVIDERS:
        raise HTTPException(status_code=400, detail=f"Unsupported threat intel provider: {provider}")
    row = db.query(ThreatIntelProviderSetting).filter(ThreatIntelProviderSetting.provider == provider).first()
    if not row:
        row = ThreatIntelProviderSetting(provider=provider)
        db.add(row)
    if payload.enabled and provider != "local_ioc" and not payload.api_key and not row.api_key_encrypted:
        raise HTTPException(status_code=400, detail="Enabled provider requires an API key")
    row.base_url = payload.base_url.strip()
    row.enabled = payload.enabled
    row.daily_limit = payload.daily_limit
    row.cache_ttl_minutes = payload.cache_ttl_minutes
    if payload.api_key:
        row.api_key_encrypted = encrypt_secret(payload.api_key)
        row.api_key_masked = _mask_secret(payload.api_key, row.api_key_masked)
    row.last_status = "configured"
    row.last_error = ""
    db.commit()
    db.refresh(row)
    _audit(db, admin, "upsert_threat_intel_provider", "threat_intel", provider, f"enabled={row.enabled}")
    return _intel_out(row)


@router.post("/threat-intel/{provider}/health", response_model=ProviderHealthResponse)
def threat_intel_health(
    provider: str,
    db: Session = Depends(get_db),
    user: User = Depends(require_role("admin", "analyst", "viewer")),
):
    provider = provider.lower().strip()
    row = db.query(ThreatIntelProviderSetting).filter(ThreatIntelProviderSetting.provider == provider).first()
    if not row:
        raise HTTPException(status_code=404, detail="Threat intel provider not found")
    if not row.enabled:
        ok, detail = False, "disabled"
    elif provider == "local_ioc":
        ok, detail = True, "local IOC matching enabled"
    else:
        ok = bool(row.api_key_encrypted)
        detail = "api key configured" if ok else "missing api key"
    row.last_status = "ok" if ok else "error"
    row.last_error = "" if ok else detail
    db.commit()
    _audit(db, user, "check_threat_intel_health", "threat_intel", provider, detail)
    return ProviderHealthResponse(provider=provider, ok=ok, detail=detail)
