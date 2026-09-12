"""FastAPI router for /auth endpoints and JWKS."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from apex_backend.auth.schemas import LoginRequest, RefreshRequest, TokenResponse
from apex_backend.auth.service import AuthError, AuthService

router = APIRouter()


def _get_auth_service() -> AuthService:
    """Dependency: resolved by the app factory via dependency_overrides."""
    raise NotImplementedError("auth_service dependency not wired.")


def _get_db() -> AsyncSession:
    """Dependency: resolved by the app factory via dependency_overrides."""
    raise NotImplementedError("db dependency not wired.")


@router.post("/auth/login", response_model=TokenResponse)
async def login(
    body: LoginRequest,
    service: AuthService = Depends(_get_auth_service),  # noqa: B008
    db: AsyncSession = Depends(_get_db),  # noqa: B008
) -> TokenResponse:
    """Authenticate with email + password and receive JWT token pair."""
    try:
        access, refresh = await service.login(
            db,
            email=body.email,
            password=body.password,
            tenant_id=body.tenant_id,
        )
    except AuthError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc)) from exc

    from apex_backend.auth.jwt_utils import ACCESS_TOKEN_TTL_SECONDS

    return TokenResponse(
        access_token=access,
        refresh_token=refresh,
        expires_in=ACCESS_TOKEN_TTL_SECONDS,
    )


@router.post("/auth/refresh", response_model=TokenResponse)
async def refresh(
    body: RefreshRequest,
    service: AuthService = Depends(_get_auth_service),  # noqa: B008
    db: AsyncSession = Depends(_get_db),  # noqa: B008
) -> TokenResponse:
    """Exchange a valid refresh token for a new token pair."""
    try:
        access, new_refresh = await service.refresh(db, refresh_token=body.refresh_token)
    except AuthError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc)) from exc

    from apex_backend.auth.jwt_utils import ACCESS_TOKEN_TTL_SECONDS

    return TokenResponse(
        access_token=access,
        refresh_token=new_refresh,
        expires_in=ACCESS_TOKEN_TTL_SECONDS,
    )


__all__ = ["router"]
