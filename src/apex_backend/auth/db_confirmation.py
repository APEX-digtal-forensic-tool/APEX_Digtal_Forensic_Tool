"""DB-backed frontend security provider for production deployments."""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from apex_backend.models import ConfirmationGrantRow
from apex_mcp.confirmation import ConfirmationRequest
from apex_mcp.frontend_security import FrontendSession, PersistentFrontendSecurityProvider


class DbFrontendSecurityProvider(PersistentFrontendSecurityProvider):
    """PersistentFrontendSecurityProvider with synchronous DB-backed confirmation.

    Requires a *sync* session factory (psycopg2 for PostgreSQL, sqlite for tests).
    ``call_tool`` is synchronous, so confirmation queries must be sync.
    """

    def __init__(self, sync_session_factory: sessionmaker[Session]) -> None:
        super().__init__()
        self._sync_factory = sync_session_factory

    def confirmation_for(
        self,
        session: FrontendSession,
        *,
        case_id: str,
        tool_name: str,
        request_fingerprint: str,
        target_ids: tuple[str, ...],
    ) -> ConfirmationRequest | None:
        now = datetime.now(UTC)
        with self._sync_factory() as db:
            rows = db.execute(
                select(ConfirmationGrantRow).where(
                    ConfirmationGrantRow.actor_id == session.actor_id,
                    ConfirmationGrantRow.session_id == session.session_id,
                    ConfirmationGrantRow.case_id == case_id,
                    ConfirmationGrantRow.tool_name == tool_name,
                    ConfirmationGrantRow.request_fingerprint == request_fingerprint,
                    ConfirmationGrantRow.expires_at > now,
                )
            ).scalars().all()

        for row in rows:
            if row.uses_count < row.max_uses and tuple(row.target_ids) == target_ids:
                return ConfirmationRequest(
                    grant_id=row.grant_id,
                    actor_id=session.actor_id,
                    session_id=session.session_id,
                    case_id=case_id,
                    tool_name=tool_name,
                    request_fingerprint=request_fingerprint,
                    target_ids=target_ids,
                )
        return None

    def authorize(self, request: ConfirmationRequest) -> bool:
        now = datetime.now(UTC)
        with self._sync_factory() as db:
            row = db.get(ConfirmationGrantRow, request.grant_id)
            if row is None:
                return False

            expires_at = row.expires_at
            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=UTC)
            if expires_at <= now:
                return False
            if row.uses_count >= row.max_uses:
                return False
            if (
                row.actor_id != request.actor_id
                or row.session_id != request.session_id
                or row.case_id != request.case_id
                or row.tool_name != request.tool_name
                or row.request_fingerprint != request.request_fingerprint
                or tuple(row.target_ids) != request.target_ids
            ):
                return False

            row.uses_count += 1
            db.commit()
            return True


__all__ = ["DbFrontendSecurityProvider"]
