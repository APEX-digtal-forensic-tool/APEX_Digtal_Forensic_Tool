"""CRUD tests for apex_backend ORM models against SQLite in-memory DB."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
import pytest_asyncio
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from apex_backend.models import CaseTenancy, ConfirmationGrantRow, User, UserSession

pytestmark = pytest.mark.asyncio


def _now() -> datetime:
    return datetime.now(UTC)


def _make_user(tenant_id: str = "tenant-1") -> User:
    return User(
        id=str(uuid.uuid4()),
        username="alice",
        email="alice@example.com",
        hashed_password="hashed",
        tenant_id=tenant_id,
        created_at=_now(),
        is_active=True,
    )


# ---------------------------------------------------------------------------
# User
# ---------------------------------------------------------------------------


async def test_user_create_and_fetch(session: AsyncSession) -> None:
    user = _make_user()
    session.add(user)
    await session.commit()

    result = await session.get(User, user.id)
    assert result is not None
    assert result.username == "alice"
    assert result.is_active is True


async def test_user_deactivate(session: AsyncSession) -> None:
    user = _make_user()
    session.add(user)
    await session.commit()

    user.is_active = False
    await session.commit()

    result = await session.get(User, user.id)
    assert result is not None
    assert result.is_active is False


# ---------------------------------------------------------------------------
# CaseTenancy
# ---------------------------------------------------------------------------


async def test_case_tenancy_create_and_query(session: AsyncSession) -> None:
    user = _make_user()
    session.add(user)
    await session.flush()

    tenancy = CaseTenancy(
        id=str(uuid.uuid4()),
        actor_id=user.id,
        case_id="case-001",
        role="ANALYST",
        granted_at=_now(),
    )
    session.add(tenancy)
    await session.commit()

    rows = (
        await session.execute(
            select(CaseTenancy).where(CaseTenancy.actor_id == user.id)
        )
    ).scalars().all()
    assert len(rows) == 1
    assert rows[0].role == "ANALYST"


async def test_case_tenancy_multiple_cases(session: AsyncSession) -> None:
    user = _make_user()
    session.add(user)
    await session.flush()

    for case_id, role in [("case-A", "VIEWER"), ("case-B", "APPROVER")]:
        session.add(
            CaseTenancy(
                id=str(uuid.uuid4()),
                actor_id=user.id,
                case_id=case_id,
                role=role,
                granted_at=_now(),
            )
        )
    await session.commit()

    rows = (
        await session.execute(
            select(CaseTenancy).where(CaseTenancy.actor_id == user.id)
        )
    ).scalars().all()
    assert len(rows) == 2
    case_ids = {r.case_id for r in rows}
    assert case_ids == {"case-A", "case-B"}


# ---------------------------------------------------------------------------
# UserSession
# ---------------------------------------------------------------------------


async def test_user_session_create_and_active(session: AsyncSession) -> None:
    user = _make_user()
    session.add(user)
    await session.flush()

    sess = UserSession(
        session_id=str(uuid.uuid4()),
        actor_id=user.id,
        tenant_id="tenant-1",
        created_at=_now(),
        expires_at=_now() + timedelta(hours=1),
    )
    session.add(sess)
    await session.commit()

    result = await session.get(UserSession, sess.session_id)
    assert result is not None
    assert result.is_active is True
    assert result.revoked_at is None


async def test_user_session_revoke(session: AsyncSession) -> None:
    user = _make_user()
    session.add(user)
    await session.flush()

    sess = UserSession(
        session_id=str(uuid.uuid4()),
        actor_id=user.id,
        tenant_id="tenant-1",
        created_at=_now(),
        expires_at=_now() + timedelta(hours=1),
    )
    session.add(sess)
    await session.flush()

    sess.revoked_at = _now()
    await session.commit()

    result = await session.get(UserSession, sess.session_id)
    assert result is not None
    assert result.is_active is False


# ---------------------------------------------------------------------------
# ConfirmationGrantRow
# ---------------------------------------------------------------------------


async def test_confirmation_grant_create_and_fetch(session: AsyncSession) -> None:
    grant = ConfirmationGrantRow(
        grant_id=str(uuid.uuid4()),
        actor_id="user-123",
        session_id="sess-456",
        case_id="case-001",
        tool_name="report.approve",
        request_fingerprint="fp-abc",
        target_ids=["report-1", "report-2"],
        expires_at=_now() + timedelta(minutes=10),
        max_uses=1,
        uses_count=0,
    )
    session.add(grant)
    await session.commit()

    result = await session.get(ConfirmationGrantRow, grant.grant_id)
    assert result is not None
    assert result.target_ids == ["report-1", "report-2"]
    assert result.uses_count == 0


async def test_confirmation_grant_consume(session: AsyncSession) -> None:
    grant = ConfirmationGrantRow(
        grant_id=str(uuid.uuid4()),
        actor_id="user-123",
        session_id="sess-456",
        case_id="case-001",
        tool_name="report.approve",
        request_fingerprint="fp-abc",
        target_ids=["report-1"],
        expires_at=_now() + timedelta(minutes=10),
        max_uses=1,
        uses_count=0,
    )
    session.add(grant)
    await session.flush()

    grant.uses_count += 1
    await session.commit()

    result = await session.get(ConfirmationGrantRow, grant.grant_id)
    assert result is not None
    assert result.uses_count == 1
    assert result.uses_count >= result.max_uses  # exhausted


async def test_confirmation_grant_multi_use(session: AsyncSession) -> None:
    grant = ConfirmationGrantRow(
        grant_id=str(uuid.uuid4()),
        actor_id="user-123",
        session_id="sess-456",
        case_id="case-001",
        tool_name="report.approve",
        request_fingerprint="fp-abc",
        target_ids=[],
        expires_at=_now() + timedelta(minutes=10),
        max_uses=3,
        uses_count=0,
    )
    session.add(grant)
    await session.flush()

    for _ in range(3):
        grant.uses_count += 1
    await session.commit()

    result = await session.get(ConfirmationGrantRow, grant.grant_id)
    assert result is not None
    assert result.uses_count == 3
