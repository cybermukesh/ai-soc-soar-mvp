from typing import Literal

from pydantic import BaseModel, EmailStr


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class MessageResponse(BaseModel):
    message: str


class UserOut(BaseModel):
    id: int
    email: EmailStr
    full_name: str
    role: str
    is_active: bool


class CreateUserRequest(BaseModel):
    email: EmailStr
    full_name: str
    password: str
    role: str


class RegisterUserRequest(BaseModel):
    email: EmailStr
    full_name: str
    password: str


class ToggleUserActiveRequest(BaseModel):
    is_active: bool


class UpdateUserRoleRequest(BaseModel):
    role: Literal["admin", "analyst", "viewer"]


class AuditLogOut(BaseModel):
    id: int
    actor_user_id: int
    action: str
    target_type: str
    target_id: str
    detail: str
    created_at: str
