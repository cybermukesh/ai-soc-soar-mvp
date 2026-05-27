from datetime import datetime, timedelta, timezone

from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.orm import Session

from app.core.settings import settings
from app.db.models import Role, User

pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    return pwd_context.verify(password, password_hash)


def create_access_token(user: User) -> str:
    exp = datetime.now(timezone.utc) + timedelta(minutes=settings.jwt_exp_minutes)
    payload = {"sub": str(user.id), "role": user.role.name, "exp": exp}
    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)


def decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, settings.jwt_secret, algorithms=[settings.jwt_algorithm])
    except JWTError as exc:
        raise ValueError("Invalid token") from exc


def get_or_create_default_roles(db: Session) -> None:
    for role_name in ("admin", "analyst", "viewer"):
        if not db.query(Role).filter(Role.name == role_name).first():
            db.add(Role(name=role_name))
    db.commit()


def ensure_admin_seed(db: Session) -> None:
    get_or_create_default_roles(db)
    if db.query(User).filter(User.email == "admin@aisocmvp.com").first():
        return
    admin_role = db.query(Role).filter(Role.name == "admin").first()
    db.add(
        User(
            email="admin@aisocmvp.com",
            full_name="Platform Admin",
            password_hash=hash_password("admin123"),
            role_id=admin_role.id,  # type: ignore[union-attr]
            is_active=True,
        )
    )
    db.commit()
