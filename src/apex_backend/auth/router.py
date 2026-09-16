"""FastAPI router for /auth endpoints and JWKS."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession

from apex_backend.auth.jwt_verifier import JwtTokenVerifier
from apex_backend.auth.schemas import LoginRequest, LogoutResponse, RefreshRequest, TokenResponse
from apex_backend.auth.service import AuthError, AuthService

router = APIRouter()

_bearer = HTTPBearer()


def _get_auth_service() -> AuthService:
    """Dependency: resolved by the app factory via dependency_overrides."""
    raise NotImplementedError("auth_service dependency not wired.")


def _get_db() -> AsyncSession:
    """Dependency: resolved by the app factory via dependency_overrides."""
    raise NotImplementedError("db dependency not wired.")


def _get_jwt_verifier() -> JwtTokenVerifier:
    """Dependency: resolved by the app factory via dependency_overrides."""
    raise NotImplementedError("jwt_verifier dependency not wired.")


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


@router.post(
    "/auth/logout",
    response_model=LogoutResponse,
    status_code=status.HTTP_200_OK,
    tags=["auth"],
)
async def logout(
    credentials: HTTPAuthorizationCredentials = Depends(_bearer),  # noqa: B008
    service: AuthService = Depends(_get_auth_service),  # noqa: B008
    verifier: JwtTokenVerifier = Depends(_get_jwt_verifier),  # noqa: B008
    db: AsyncSession = Depends(_get_db),  # noqa: B008
) -> LogoutResponse:
    """Revoke the current session. Subsequent refresh attempts will be rejected."""
    access_token = await verifier.verify_token(credentials.credentials)
    if access_token is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired access token.",
        )

    claims = access_token.claims or {}
    session_id = str(claims.get("session_id", "")).strip()
    if not session_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token missing session_id claim.",
        )

    await service.logout(db, session_id=session_id)
    return LogoutResponse()


__all__ = ["router"]
