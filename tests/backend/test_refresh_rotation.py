"""Tests for Phase 12: refresh token rotation, reuse detection, logout."""

from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime, timedelta

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from apex_backend.app import create_app
from apex_backend.auth.jwt_utils import issue_refresh_token
from apex_backend.auth.keys import load_private_key
from apex_backend.auth.service import AuthError, AuthService, hash_password
from apex_backend.database import Base
from apex_backend.models import CaseTenancy, User, UserSession

SQLITE_ASYNC = "sqlite+aiosqlite:///:memory:"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def keypair():
    private_key, kid = load_private_key()
    return private_key, kid


@pytest.fixture(scope="module")
def auth_service(keypair):
    private_key, kid = keypair
    return AuthService(private_key=private_key, kid=kid)


@pytest_asyncio.fixture
async def engine_and_factory():
    """Fresh in-memory SQLite engine with tables created."""
    eng = create_async_engine(SQLITE_ASYNC, echo=False)
    async with eng.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(eng, expire_on_commit=False)
    yield eng, factory
    async with eng.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await eng.dispose()


@pytest_asyncio.fixture
async def db(engine_and_factory):
    _, factory = engine_and_factory
    async with factory() as sess:
        yield sess


@pytest_asyncio.fixture
async def seeded_user(engine_and_factory):
    """Seed one user + one case tenancy; return (user, factory)."""
    _, factory = engine_and_factory
    async with factory() as sess:
        user = User(
            id=str(uuid.uuid4()),
            username="alice",
            email="alice@example.com",
            hashed_password=hash_password("pass1"),
            tenant_id="t1",
            created_at=datetime.now(UTC),
            is_active=True,
        )
        sess.add(user)
        await sess.flush()
        sess.add(CaseTenancy(
            id=str(uuid.uuid4()),
            actor_id=user.id,
            case_id="case-1",
            role="ANALYST",
            granted_at=datetime.now(UTC),
        ))
        await sess.commit()
    return user


# ---------------------------------------------------------------------------
# 1. login stores jti in session
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_login_stores_current_refresh_jti(
    auth_service, db, seeded_user
) -> None:
    user = seeded_user
    access, refresh = await auth_service.login(
        db, email=user.email, password="pass1", tenant_id=user.tenant_id
    )
    assert access and refresh

    sess = (
        await db.execute(
            select(UserSession).where(UserSession.actor_id == user.id)
        )
    ).scalar_one()
    assert sess.current_refresh_jti is not None
    assert len(sess.current_refresh_jti) == 36  # UUID4


# ---------------------------------------------------------------------------
# 2. Basic rotation: new tokens issued, old refresh rejected
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_refresh_rotation_basic(auth_service, db, seeded_user) -> None:
    user = seeded_user
    _access, refresh_v1 = await auth_service.login(
        db, email=user.email, password="pass1", tenant_id=user.tenant_id
    )

    access_v2, refresh_v2 = await auth_service.refresh(db, refresh_token=refresh_v1)
    assert access_v2 and refresh_v2
    assert refresh_v2 != refresh_v1

    # Old refresh token rejected after rotation.
    with pytest.raises(AuthError, match=r"reuse detected|revoked|not found"):
        await auth_service.refresh(db, refresh_token=refresh_v1)


# ---------------------------------------------------------------------------
# 3. Reuse detection revokes entire session
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_refresh_reuse_revokes_session(
    auth_service, engine_and_factory, seeded_user
) -> None:
    _, factory = engine_and_factory
    user = seeded_user

    async with factory() as db1:
        _access, refresh_v1 = await auth_service.login(
            db1, email=user.email, password="pass1", tenant_id=user.tenant_id
        )
        session_row = (
            await db1.execute(
                select(UserSession).where(UserSession.actor_id == user.id)
            )
        ).scalar_one()
        session_id = session_row.session_id

    async with factory() as db2:
        # First use of refresh_v1 — should succeed and rotate.
        await auth_service.refresh(db2, refresh_token=refresh_v1)

    async with factory() as db3:
        # Second use of the same old refresh_v1 — reuse detected, session revoked.
        with pytest.raises(AuthError, match="reuse detected"):
            await auth_service.refresh(db3, refresh_token=refresh_v1)

    # Session must now be revoked.
    async with factory() as db4:
        revoked = (
            await db4.execute(
                select(UserSession).where(UserSession.session_id == session_id)
            )
        ).scalar_one()
        assert not revoked.is_active


# ---------------------------------------------------------------------------
# 4. Concurrent refresh: first wins, second triggers reuse detection
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_concurrent_refresh_first_wins(
    auth_service, engine_and_factory, seeded_user
) -> None:
    """Two concurrent refreshes with the same token: one succeeds, one triggers reuse.

    The second coroutine finds rowcount == 0 and a non-matching jti, meaning
    the first already rotated — reuse detected → session revoked.
    """
    _, factory = engine_and_factory
    user = seeded_user

    async with factory() as db0:
        _access, refresh_v1 = await auth_service.login(
            db0, email=user.email, password="pass1", tenant_id=user.tenant_id
        )

    results: list[str | BaseException] = []

    async def do_refresh() -> None:
        try:
            async with factory() as db:
                _a, _r = await auth_service.refresh(db, refresh_token=refresh_v1)
            results.append("ok")
        except AuthError as e:
            results.append(e)

    await asyncio.gather(do_refresh(), do_refresh())

    ok_count = sum(1 for r in results if r == "ok")
    err_count = sum(1 for r in results if isinstance(r, AuthError))
    assert ok_count == 1, f"Expected exactly 1 success, got: {results}"
    assert err_count == 1


# ---------------------------------------------------------------------------
# 5. POST /auth/logout (service-layer)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_logout_revokes_session(
    auth_service, engine_and_factory, seeded_user
) -> None:
    _, factory = engine_and_factory
    user = seeded_user

    async with factory() as db1:
        _access, refresh = await auth_service.login(
            db1, email=user.email, password="pass1", tenant_id=user.tenant_id
        )
        session_row = (
            await db1.execute(
                select(UserSession).where(UserSession.actor_id == user.id)
            )
        ).scalar_one()
        session_id = session_row.session_id

    async with factory() as db2:
        await auth_service.logout(db2, session_id=session_id)

    async with factory() as db3:
        with pytest.raises(AuthError, match=r"revoked|not found"):
            await auth_service.refresh(db3, refresh_token=refresh)


# ---------------------------------------------------------------------------
# 6. NULL current_refresh_jti (legacy session) — 401, session NOT revoked
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_null_jti_legacy_session_rejected_without_revoke(
    auth_service, engine_and_factory, seeded_user, keypair
) -> None:
    """Sessions created before rotation was deployed (jti=None) get re-login error.

    The session must NOT be revoked — only a genuine reuse triggers revocation.
    """
    _, factory = engine_and_factory
    private_key, kid = keypair
    user = seeded_user

    # Manually insert a session with current_refresh_jti=None.
    session_id = str(uuid.uuid4())
    async with factory() as db0:
        db0.add(UserSession(
            session_id=session_id,
            actor_id=user.id,
            tenant_id=user.tenant_id,
            created_at=datetime.now(UTC),
            expires_at=datetime.now(UTC) + timedelta(hours=1),
            current_refresh_jti=None,
        ))
        await db0.commit()

    # Issue a refresh token for that session (any jti in token; DB has None).
    legacy_refresh = issue_refresh_token(
        private_key=private_key,
        kid=kid,
        actor_id=user.id,
        session_id=session_id,
    )

    async with factory() as db1:
        with pytest.raises(AuthError, match="re-login"):
            await auth_service.refresh(db1, refresh_token=legacy_refresh)

    # Session must still be active (not revoked on legacy path).
    async with factory() as db2:
        sess = (
            await db2.execute(
                select(UserSession).where(UserSession.session_id == session_id)
            )
        ).scalar_one()
        assert sess.is_active, "Legacy session must not be revoked by null-jti rejection."


# ---------------------------------------------------------------------------
# 7. POST /auth/logout HTTP endpoint
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def http_app_client(tmp_path):
    """HTTP test client backed by a file-based SQLite for cross-engine seeding.

    Uses a temp-file DB so that the seed engine and the app engine share state.
    create_app pre-populates the jwt_verifier cache with its own key — no
    extra patching needed.
    """
    db_path = tmp_path / "test_phase12.db"
    db_url = f"sqlite+aiosqlite:///{db_path}"

    # Seed the DB with a user before the app boots.
    seed_engine = create_async_engine(db_url)
    async with seed_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    seed_factory = async_sessionmaker(seed_engine, expire_on_commit=False)
    async with seed_factory() as sess:
        user = User(
            id=str(uuid.uuid4()),
            username="bob",
            email="bob@logout.test",
            hashed_password=hash_password("secretpass"),
            tenant_id="t-logout",
            created_at=datetime.now(UTC),
            is_active=True,
        )
        sess.add(user)
        await sess.flush()
        sess.add(CaseTenancy(
            id=str(uuid.uuid4()),
            actor_id=user.id,
            case_id="case-lgt",
            role="ANALYST",
            granted_at=datetime.now(UTC),
        ))
        await sess.commit()
    await seed_engine.dispose()

    app = create_app(db_url)

    async with app.router.lifespan_context(app), AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        yield client


@pytest.mark.asyncio
async def test_logout_endpoint_rejects_subsequent_refresh(http_app_client) -> None:
    client = http_app_client

    # Login.
    resp = await client.post(
        "/auth/login",
        json={"email": "bob@logout.test", "password": "secretpass", "tenant_id": "t-logout"},
    )
    assert resp.status_code == 200, resp.text
    tokens = resp.json()
    access = tokens["access_token"]
    refresh = tokens["refresh_token"]

    # Logout with access token.
    resp = await client.post(
        "/auth/logout",
        headers={"Authorization": f"Bearer {access}"},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["detail"] == "Logged out."

    # Refresh after logout must fail.
    resp = await client.post("/auth/refresh", json={"refresh_token": refresh})
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_logout_endpoint_no_token(http_app_client) -> None:
    client = http_app_client
    resp = await client.post("/auth/logout")
    assert resp.status_code in (401, 403)  # HTTPBearer rejects missing credentials


# ---------------------------------------------------------------------------
# 8. Revoked session access token rejected at POST /confirmations
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_confirmation_rejects_revoked_session(http_app_client) -> None:
    """After logout, access token is still valid JWT but session is revoked in DB.

    POST /confirmations must check DB and return 401.
    """
    client = http_app_client

    resp = await client.post(
        "/auth/login",
        json={"email": "bob@logout.test", "password": "secretpass", "tenant_id": "t-logout"},
    )
    assert resp.status_code == 200, resp.text
    tokens = resp.json()
    access = tokens["access_token"]

    # Logout.
    resp = await client.post(
        "/auth/logout",
        headers={"Authorization": f"Bearer {access}"},
    )
    assert resp.status_code == 200, resp.text

    # Access token is still cryptographically valid, but session is DB-revoked.
    resp = await client.post(
        "/confirmations",
        json={
            "case_id": "case-lgt",
            "tool_name": "tool.run",
            "request_fingerprint": "fp-xyz",
            "target_ids": [],
        },
        headers={"Authorization": f"Bearer {access}"},
    )
    assert resp.status_code == 401
