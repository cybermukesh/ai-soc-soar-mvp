from pydantic import BaseModel, Field


class AiProviderOut(BaseModel):
    id: int
    provider: str
    model: str
    api_key_masked: str
    base_url: str
    enabled: bool
    cache_enabled: bool
    max_input_chars: int
    max_output_tokens: int
    min_severity: str
    fallback_model: str
    last_status: str
    last_error: str
    updated_at: str


class AiProviderUpsertRequest(BaseModel):
    provider: str = Field(min_length=2, max_length=40)
    model: str = Field(default="", max_length=120)
    api_key: str = ""
    base_url: str = Field(default="", max_length=255)
    enabled: bool = False
    cache_enabled: bool = True
    max_input_chars: int = Field(default=6000, ge=500, le=50000)
    max_output_tokens: int = Field(default=700, ge=100, le=4000)
    min_severity: str = "medium"
    fallback_model: str = Field(default="", max_length=120)


class ThreatIntelProviderOut(BaseModel):
    id: int
    provider: str
    api_key_masked: str
    base_url: str
    enabled: bool
    daily_limit: int
    cache_ttl_minutes: int
    last_status: str
    last_error: str
    updated_at: str


class ThreatIntelProviderUpsertRequest(BaseModel):
    provider: str = Field(min_length=2, max_length=40)
    api_key: str = ""
    base_url: str = Field(default="", max_length=255)
    enabled: bool = False
    daily_limit: int = Field(default=500, ge=1, le=100000)
    cache_ttl_minutes: int = Field(default=1440, ge=5, le=43200)


class ProviderHealthResponse(BaseModel):
    provider: str
    ok: bool
    detail: str
