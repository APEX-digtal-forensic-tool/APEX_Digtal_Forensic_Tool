"""Tests for A11: session row absence/expiry/revocation blocks grant issuance."""

from __future__ import annotations

import time
import uuid
from datetime import UTC, datetime, timedelta

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from apex_backend.app import create_app
from apex_backend.auth.confirmation_router import _get_jwt_verifier
from apex_backend.auth.jwt_utils import issue_access_token
from apex_backend.auth.jwt_verifier import _jwk_to_pem
from apex_backend.auth.keys import load_private_key, public_key_to_jwk
from apex_backend.auth.scopes import scopes_for_roles
from apex_backend.database import Base
from apex_backend.models import User, UserSession

SQLITE_ASYNC = "sqlite+aiosqlite:///:memory:"
_ACTOR_ID = "actor-a11"
_SESSION_ID = "sess-a11"
_TENANT = "tenant-a11"


@pytest.fixture(scope="module")
def keypair():
    return load_private_key()


def _make_token(private_key, kid, session_id: str = _SESSION_ID) -> str:
    roles = ["ANALYST"]
    return issue_access_token(
        private_key=private_key,
        kid=kid,
        actor_id=_ACTOR_ID,
        session_id=session_id,
        tenant_id=_TENANT,
        allowed_case_ids=["case-001"],
        roles=roles,
        scopes=sorted(scopes_for_roles(frozenset(roles))),
        case_roles={"case-001": "ANALYST"},
    )


def _confirmation_payload():
    return {
        "case_id": "case-001",
        "tool_name": "report.approve",
        "request_fingerprint": "fp",
        "target_ids": [],
    }


@pytest_asyncio.fixture
async def app_with_engine(keypair):
    """App + async engine pair so we can manipulate DB rows."""
    from collections.abc import AsyncGenerator

    private_key, kid = keypair
    engine = create_async_engine(SQLITE_ASYNC, echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)

    app = create_app(SQLITE_ASYNC)
    verifier = app.dependency_overrides[_get_jwt_verifier]()
    jwk = public_key_to_jwk(private_key.public_key(), kid)
    verifier._keys = {kid: _jwk_to_pem(jwk)}
    verifier._fetched_at = time.monotonic()

    # Override the confirmation router's DB dependency to use the shared engine
    # so seeded rows are visible to the endpoint.
    from apex_backend.auth.confirmation_router import _get_db as _conf_get_db
    from sqlalchemy.ext.asyncio import AsyncSession

    async def _shared_db() -> AsyncGenerator[AsyncSession, None]:
        async with factory() as sess:
            yield sess

    app.dependency_overrides[_conf_get_db] = _shared_db

    async with app.router.lifespan_context(app), AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        yield private_key, kid, client, factory

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await engine.dispose()


async def _seed_user_and_session(
    factory,
    *,
    actor_id: str = _ACTOR_ID,
    session_id: str = _SESSION_ID,
    tenant_id: str = _TENANT,
    revoked: bool = False,
    expired: bool = False,
) -> None:
    async with factory() as db:
        db.add(
            User(
                id=actor_id,
                username="tester",
                email=f"{actor_id}@test.local",
                hashed_password="x",
                tenant_id=tenant_id,
                created_at=datetime.now(UTC),
                is_active=True,
            )
        )
        expires_at = (
            datetime.now(UTC) - timedelta(hours=1) if expired
            else datetime.now(UTC) + timedelta(hours=1)
        )
        db.add(
            UserSession(
                session_id=session_id,
                actor_id=actor_id,
                tenant_id=tenant_id,
                created_at=datetime.now(UTC),
                expires_at=expires_at,
                revoked_at=datetime.now(UTC) if revoked else None,
            )
        )
        await db.commit()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_normal_session_yields_201(app_with_engine):
    private_key, kid, client, factory = app_with_engine
    await _seed_user_and_session(factory)
    token = _make_token(private_key, kid)

    resp = await client.post(
        "/confirmations",
        json=_confirmation_payload(),
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 201, resp.text


@pytest.mark.asyncio
async def test_missing_session_row_yields_401(app_with_engine):
    """A11 core: no DB row for session_id → must be 401, not 201."""
    private_key, kid, client, factory = app_with_engine
    # No user/session seeded for this session_id.
    token = _make_token(private_key, kid, session_id="ghost-session-" + str(uuid.uuid4()))

    resp = await client.post(
        "/confirmations",
        json=_confirmation_payload(),
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_revoked_session_yields_401(app_with_engine):
    private_key, kid, client, factory = app_with_engine
    sid = "revoked-" + str(uuid.uuid4())
    aid = "actor-rev-" + str(uuid.uuid4())
    await _seed_user_and_session(factory, actor_id=aid, session_id=sid, revoked=True)
    token = _make_token(private_key, kid, session_id=sid)

    resp = await client.post(
        "/confirmations",
        json={**_confirmation_payload(), "case_id": "case-001"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_expired_session_yields_401(app_with_engine):
    private_key, kid, client, factory = app_with_engine
    sid = "expired-" + str(uuid.uuid4())
    aid = "actor-exp-" + str(uuid.uuid4())
    await _seed_user_and_session(factory, actor_id=aid, session_id=sid, expired=True)
    token = _make_token(private_key, kid, session_id=sid)

    resp = await client.post(
        "/confirmations",
        json=_confirmation_payload(),
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 401
