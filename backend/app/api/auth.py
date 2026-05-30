from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.db.models import AuditLog, Role, User
from app.db.session import get_db
from app.models.auth import (
    AuditLogOut,
    CreateUserRequest,
    LoginRequest,
    MessageResponse,
    RegisterUserRequest,
    ToggleUserActiveRequest,
    TokenResponse,
    UpdateUserRoleRequest,
    UserOut,
)
from app.services.auth import create_access_token, decode_token, hash_password, verify_password

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])
bearer = HTTPBearer(auto_error=False)


def _user_out(user: User) -> UserOut:
    return UserOut(
        id=user.id,
        email=user.email,
        full_name=user.full_name,
        role=user.role.name,
        is_active=user.is_active,
    )


def _write_audit(
    db: Session, actor_user_id: int, action: str, target_type: str, target_id: str, detail: str = ""
) -> None:
    db.add(
        AuditLog(
            actor_user_id=actor_user_id,
            action=action,
            target_type=target_type,
            target_id=target_id,
            detail=detail[:500],
        )
    )
    db.commit()


def current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer), db: Session = Depends(get_db)
) -> User:
    if not credentials:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing token")
    payload = decode_token(credentials.credentials)
    user = db.query(User).filter(User.id == int(payload["sub"])).first()
    if not user or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid user")
    return user


def require_role(*roles: str):
    def checker(user: User = Depends(current_user)) -> User:
        if user.role.name not in roles:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient role")
        return user

    return checker


@router.post("/login", response_model=TokenResponse)
def login(payload: LoginRequest, db: Session = Depends(get_db)) -> TokenResponse:
    user = db.query(User).filter(User.email == payload.email).first()
    if not user or not verify_password(payload.password, user.password_hash):
        if user:
            _write_audit(db, actor_user_id=user.id, action="login_failed", target_type="auth", target_id=str(user.id), detail=payload.email)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account pending approval or inactive")
    _write_audit(db, actor_user_id=user.id, action="login_success", target_type="auth", target_id=str(user.id), detail=payload.email)
    return TokenResponse(access_token=create_access_token(user))


@router.post("/register", response_model=MessageResponse, status_code=status.HTTP_201_CREATED)
def register(payload: RegisterUserRequest, db: Session = Depends(get_db)) -> MessageResponse:
    if db.query(User).filter(User.email == payload.email).first():
        raise HTTPException(status_code=400, detail="Email already exists")
    viewer_role = db.query(Role).filter(Role.name == "viewer").first()
    if not viewer_role:
        raise HTTPException(status_code=500, detail="Default viewer role missing")
    user = User(
        email=payload.email,
        full_name=payload.full_name,
        password_hash=hash_password(payload.password),
        role_id=viewer_role.id,
        is_active=False,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    _write_audit(
        db,
        actor_user_id=user.id,
        action="register_user",
        target_type="user",
        target_id=str(user.id),
        detail="self-registration pending admin approval",
    )
    return MessageResponse(message="Registration submitted. Await admin approval.")


@router.get("/me", response_model=UserOut)
def me(user: User = Depends(current_user)) -> UserOut:
    return _user_out(user)


@router.post("/logout", response_model=MessageResponse)
def logout(user: User = Depends(current_user), db: Session = Depends(get_db)) -> MessageResponse:
    _write_audit(db, actor_user_id=user.id, action="logout", target_type="auth", target_id=str(user.id), detail=user.email)
    return MessageResponse(message="Logged out")


@router.post("/users", response_model=UserOut)
def create_user(
    payload: CreateUserRequest,
    db: Session = Depends(get_db),
    _: User = Depends(require_role("admin")),
) -> UserOut:
    if db.query(User).filter(User.email == payload.email).first():
        raise HTTPException(status_code=400, detail="Email already exists")
    role = db.query(Role).filter(Role.name == payload.role).first()
    if not role:
        raise HTTPException(status_code=400, detail="Unknown role")
    user = User(
        email=payload.email,
        full_name=payload.full_name,
        password_hash=hash_password(payload.password),
        role_id=role.id,
        is_active=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    _write_audit(db, actor_user_id=_.id, action="create_user", target_type="user", target_id=str(user.id), detail=user.email)
    return _user_out(user)


@router.get("/users", response_model=list[UserOut])
def list_users(db: Session = Depends(get_db), _: User = Depends(require_role("admin"))):
    users = db.query(User).order_by(User.id.asc()).all()
    return [_user_out(u) for u in users]


@router.patch("/users/{user_id}/active", response_model=UserOut)
def toggle_user_active(
    user_id: int,
    payload: ToggleUserActiveRequest,
    db: Session = Depends(get_db),
    admin: User = Depends(require_role("admin")),
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    user.is_active = payload.is_active
    db.commit()
    db.refresh(user)
    _write_audit(
        db,
        actor_user_id=admin.id,
        action="toggle_user_active",
        target_type="user",
        target_id=str(user.id),
        detail=f"is_active={user.is_active}",
    )
    return _user_out(user)


@router.patch("/users/{user_id}/role", response_model=UserOut)
def update_user_role(
    user_id: int,
    payload: UpdateUserRoleRequest,
    db: Session = Depends(get_db),
    admin: User = Depends(require_role("admin")),
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    role = db.query(Role).filter(Role.name == payload.role).first()
    if not role:
        raise HTTPException(status_code=400, detail="Unknown role")
    if user.id == admin.id and payload.role != "admin":
        raise HTTPException(status_code=400, detail="Admin cannot revoke their own admin role")
    previous_role = user.role.name
    user.role_id = role.id
    db.commit()
    db.refresh(user)
    _write_audit(
        db,
        actor_user_id=admin.id,
        action="update_user_role",
        target_type="user",
        target_id=str(user.id),
        detail=f"{previous_role}->{payload.role}",
    )
    return _user_out(user)


@router.get("/audit-logs", response_model=list[AuditLogOut])
def list_audit_logs(
    action: str | None = None,
    actor_user_id: int | None = None,
    target_type: str | None = None,
    db: Session = Depends(get_db),
    _: User = Depends(require_role("admin")),
):
    q = db.query(AuditLog)
    if action:
        q = q.filter(AuditLog.action == action)
    if actor_user_id is not None:
        q = q.filter(AuditLog.actor_user_id == actor_user_id)
    if target_type:
        q = q.filter(AuditLog.target_type == target_type)
    logs = q.order_by(AuditLog.id.desc()).limit(200).all()
    return [
        AuditLogOut(
            id=log.id,
            actor_user_id=log.actor_user_id,
            action=log.action,
            target_type=log.target_type,
            target_id=log.target_id,
            detail=log.detail,
            created_at=log.created_at.isoformat() if log.created_at else "",
        )
        for log in logs
    ]
