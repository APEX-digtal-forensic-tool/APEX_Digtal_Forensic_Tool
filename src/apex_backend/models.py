"""ORM models: users, case_tenancy, user_sessions, confirmation_grants."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    String,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from apex_backend.database import Base

# ---------------------------------------------------------------------------
# users
# ---------------------------------------------------------------------------


class User(Base):
    """Login account. actor_id in FrontendSession maps to users.id."""

    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    username: Mapped[str] = mapped_column(String(255), nullable=False)
    email: Mapped[str] = mapped_column(String(255), nullable=False)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    case_tenancies: Mapped[list[CaseTenancy]] = relationship(
        "CaseTenancy", back_populates="user", cascade="all, delete-orphan"
    )
    sessions: Mapped[list[UserSession]] = relationship(
        "UserSession", back_populates="user", cascade="all, delete-orphan"
    )

    __table_args__ = (
        UniqueConstraint("email", "tenant_id", name="uq_users_email_tenant"),
    )


# ---------------------------------------------------------------------------
# case_tenancy
# ---------------------------------------------------------------------------


class CaseTenancy(Base):
    """user ↔ case_id ↔ role mapping.

    One user can have different roles across different cases.
    Session issuance aggregates all tenancies for a user into
    FrontendSession.allowed_case_ids and FrontendSession.roles.
    """

    __tablename__ = "case_tenancy"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    actor_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    case_id: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(50), nullable=False)
    granted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    user: Mapped[User] = relationship("User", back_populates="case_tenancies")

    __table_args__ = (
        UniqueConstraint("actor_id", "case_id", name="uq_case_tenancy_actor_case"),
    )


# ---------------------------------------------------------------------------
# user_sessions  (named UserSession to avoid clashing with sqlalchemy.orm.Session)
# ---------------------------------------------------------------------------


class UserSession(Base):
    """Authenticated login session. Revoked via revoked_at timestamp."""

    __tablename__ = "user_sessions"

    session_id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    actor_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, default=None
    )
    current_refresh_jti: Mapped[str | None] = mapped_column(
        String(36), nullable=True, default=None
    )

    user: Mapped[User] = relationship("User", back_populates="sessions")

    @property
    def is_active(self) -> bool:
        """True if not revoked."""
        return self.revoked_at is None


# ---------------------------------------------------------------------------
# confirmation_grants
# ---------------------------------------------------------------------------


class ConfirmationGrantRow(Base):
    """Persistent store for ConfirmationGrant domain objects.

    Mirrors apex_mcp.confirmation.ConfirmationGrant field-for-field.
    target_ids stored as JSON array (TEXT in SQLite, JSON in PostgreSQL).
    uses_count tracks consumed uses against max_uses.
    """

    __tablename__ = "confirmation_grants"

    grant_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    actor_id: Mapped[str] = mapped_column(String(36), nullable=False)
    session_id: Mapped[str] = mapped_column(String(36), nullable=False)
    case_id: Mapped[str] = mapped_column(String(255), nullable=False)
    tool_name: Mapped[str] = mapped_column(String(255), nullable=False)
    request_fingerprint: Mapped[str] = mapped_column(String(255), nullable=False)
    target_ids: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    max_uses: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    uses_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)


__all__ = [
    "CaseTenancy",
    "ConfirmationGrantRow",
    "User",
    "UserSession",
]
