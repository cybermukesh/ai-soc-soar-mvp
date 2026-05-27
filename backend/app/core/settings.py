from pydantic_settings import BaseSettings, SettingsConfigDict
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[3]
DEFAULT_DB = ROOT_DIR / "data" / "runtime" / "mvp_auth.db"
ENV_FILE = ROOT_DIR / ".env"


class Settings(BaseSettings):
    app_env: str = "development"
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    jwt_secret: str = "replace-with-strong-secret"
    jwt_algorithm: str = "HS256"
    jwt_exp_minutes: int = 60 * 8
    db_url: str = f"sqlite:///{DEFAULT_DB}"

    model_config = SettingsConfigDict(env_file=str(ENV_FILE), extra="ignore")


settings = Settings()
