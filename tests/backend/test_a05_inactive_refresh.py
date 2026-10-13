"""Tests for A05: deactivated / deleted accounts must not receive new tokens via refresh."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
import pytest_asyncio
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from apex_backend.auth.keys import load_private_key
from apex_backend.auth.service import AuthError, AuthService, hash_password
from apex_backend.database import Base
from apex_backend.models import CaseTenancy, User, UserSession

SQLITE_ASYNC = "sqlite+aiosqlite:///:memory:"


@pytest.fixture(scope="module")
def keypair():
    return load_private_key()


@pytest_asyncio.fixture
async def engine():
    eng = create_async_engine(SQLITE_ASYNC, echo=False)
    async with eng.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield eng
    async with eng.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await eng.dispose()


@pytest_asyncio.fixture
async def session(engine):
    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with factory() as sess:
        yield sess


async def _setup_user_with_session(db, *, service: AuthService, tenant_id: str = "t1"):
    """Create an active user and return (user, access, refresh)."""
    uid = str(uuid.uuid4())
    db.add(
        User(
            id=uid,
            username="tester",
            email=f"{uid}@test.local",
            hashed_password=hash_password("pw"),
            tenant_id=tenant_id,
            created_at=datetime.now(UTC),
            is_active=True,
        )
    )
    db.add(CaseTenancy(
        id=str(uuid.uuid4()),
        actor_id=uid,
        case_id="case-001",
        role="ANALYST",
        granted_at=datetime.now(UTC),
    ))
    await db.commit()

    access, refresh = await service.login(
        db,
        email=f"{uid}@test.local",
        password="pw",
        tenant_id=tenant_id,
    )
    user = (await db.execute(select(User).where(User.id == uid))).scalar_one()
    return user, access, refresh


# ---------------------------------------------------------------------------
# A05: deactivated account cannot refresh
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_refresh_blocked_for_inactive_user(session, keypair):
    private_key, kid = keypair
    service = AuthService(private_key, kid)

    user, _access, refresh = await _setup_user_with_session(session, service=service)

    # Deactivate the user.
    user.is_active = False
    await session.commit()

    with pytest.raises(AuthError, match="inactive|deleted"):
        await service.refresh(session, refresh_token=refresh)


@pytest.mark.asyncio
async def test_refresh_blocked_after_deactivate_user_helper(session, keypair):
    """deactivate_user() revokes sessions; subsequent refresh must fail."""
    private_key, kid = keypair
    service = AuthService(private_key, kid)

    user, _access, refresh = await _setup_user_with_session(session, service=service)

    await service.deactivate_user(session, actor_id=user.id)

    with pytest.raises(AuthError):
        await service.refresh(session, refresh_token=refresh)


@pytest.mark.asyncio
async def test_refresh_still_works_for_active_user(session, keypair):
    """Rotation still works when account is active (regression guard)."""
    private_key, kid = keypair
    service = AuthService(private_key, kid)

    _user, _access, refresh = await _setup_user_with_session(session, service=service)

    new_access, new_refresh = await service.refresh(session, refresh_token=refresh)
    assert new_access
    assert new_refresh
    assert new_refresh != refresh  # rotated


@pytest.mark.asyncio
async def test_refresh_reuse_still_revokes_session(session, keypair):
    """Token reuse detection still works after A05 fix."""
    private_key, kid = keypair
    service = AuthService(private_key, kid)

    _user, _access, refresh = await _setup_user_with_session(session, service=service)

    # First rotation succeeds.
    _a2, _r2 = await service.refresh(session, refresh_token=refresh)

    # Reusing the old refresh token must revoke the session.
    with pytest.raises(AuthError, match="reuse|revoked"):
        await service.refresh(session, refresh_token=refresh)
