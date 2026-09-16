"""Pydantic request/response schemas for the auth API."""

from __future__ import annotations

from pydantic import BaseModel


class LoginRequest(BaseModel):
    """POST /auth/login request body."""

    email: str
    password: str
    tenant_id: str


class TokenResponse(BaseModel):
    """Successful token issuance response."""

    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


class RefreshRequest(BaseModel):
    """POST /auth/refresh request body."""

    refresh_token: str


class LogoutResponse(BaseModel):
    """POST /auth/logout response."""

    detail: str = "Logged out."


class ConfirmationRequest(BaseModel):
    """POST /confirmations request body."""

    case_id: str
    tool_name: str
    request_fingerprint: str
    target_ids: list[str] = []


class ConfirmationResponse(BaseModel):
    """Successful grant issuance response."""

    grant_id: str


__all__ = [
    "ConfirmationRequest",
    "ConfirmationResponse",
    "LoginRequest",
    "LogoutResponse",
    "RefreshRequest",
    "TokenResponse",
]
