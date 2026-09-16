"""FastAPI router for POST /confirmations — confirmation grant issuance."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from apex_backend.auth.jwt_verifier import JwtTokenVerifier
from apex_backend.auth.schemas import ConfirmationRequest, ConfirmationResponse
from apex_backend.models import ConfirmationGrantRow, UserSession

router = APIRouter()

_GRANT_TTL_SECONDS = 300  # 5 minutes
_bearer = HTTPBearer()


def _get_jwt_verifier() -> JwtTokenVerifier:
    """Dependency: resolved by the app factory via dependency_overrides."""
    raise NotImplementedError("jwt_verifier dependency not wired.")


def _get_db() -> AsyncSession:
    """Dependency: resolved by the app factory via dependency_overrides."""
    raise NotImplementedError("db dependency not wired.")


@router.post(
    "/confirmations",
    response_model=ConfirmationResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["confirmations"],
)
async def issue_confirmation(
    body: ConfirmationRequest,
    credentials: HTTPAuthorizationCredentials = Depends(_bearer),  # noqa: B008
    verifier: JwtTokenVerifier = Depends(_get_jwt_verifier),  # noqa: B008
    db: AsyncSession = Depends(_get_db),  # noqa: B008
) -> ConfirmationResponse:
    """Issue a one-time confirmation grant after a human approval action.

    The actor_id and session_id are extracted from the verified JWT — the
    client cannot supply them.  case_id must be within the token's
    allowed_case_ids.
    """
    access_token = await verifier.verify_token(credentials.credentials)
    if access_token is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired access token.",
        )

    claims = access_token.claims or {}
    actor_id = str(claims.get("sub") or access_token.subject or "").strip()
    session_id = str(claims.get("session_id", "")).strip()

    if not actor_id or not session_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token missing required claims.",
        )

    # Verify the session is still active in DB (catches post-logout access tokens).
    db_session = (
        await db.execute(select(UserSession).where(UserSession.session_id == session_id))
    ).scalar_one_or_none()
    if db_session is None or not db_session.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session revoked or not found.",
        )

    allowed_case_ids: list[str] = claims.get("allowed_case_ids") or []
    if body.case_id not in allowed_case_ids:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="case_id not in token's allowed_case_ids.",
        )

    grant = ConfirmationGrantRow(
        grant_id=str(uuid.uuid4()),
        actor_id=actor_id,
        session_id=session_id,
        case_id=body.case_id,
        tool_name=body.tool_name,
        request_fingerprint=body.request_fingerprint,
        target_ids=body.target_ids,
        expires_at=datetime.now(UTC) + timedelta(seconds=_GRANT_TTL_SECONDS),
        max_uses=1,
        uses_count=0,
    )
    db.add(grant)
    await db.commit()

    return ConfirmationResponse(grant_id=grant.grant_id)


__all__ = ["router"]
