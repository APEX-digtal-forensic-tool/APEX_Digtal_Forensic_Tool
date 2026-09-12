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


__all__ = ["LoginRequest", "RefreshRequest", "TokenResponse"]
