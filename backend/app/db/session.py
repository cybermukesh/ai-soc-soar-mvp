from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker
from pathlib import Path

from app.core.settings import settings


class Base(DeclarativeBase):
    pass


connect_args = {"check_same_thread": False} if settings.db_url.startswith("sqlite") else {}
if settings.db_url.startswith("sqlite:///"):
    db_file = settings.db_url.replace("sqlite:///", "")
    Path(db_file).parent.mkdir(parents=True, exist_ok=True)
engine = create_engine(settings.db_url, future=True, connect_args=connect_args)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
