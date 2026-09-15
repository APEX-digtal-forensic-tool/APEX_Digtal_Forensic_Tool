"""Tests for Phase 5: confirmation grant issuance and DB-backed consume."""

from __future__ import annotations

import threading
import uuid
from datetime import UTC, datetime, timedelta

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from apex_backend.app import create_app
from apex_backend.auth.confirmation_router import _get_jwt_verifier
from apex_backend.auth.db_confirmation import DbFrontendSecurityProvider
from apex_backend.auth.jwt_utils import issue_access_token
from apex_backend.auth.jwt_verifier import _jwk_to_pem
from apex_backend.auth.keys import load_private_key, public_key_to_jwk
from apex_backend.auth.scopes import scopes_for_roles
from apex_backend.database import Base
from apex_backend.models import ConfirmationGrantRow
from apex_mcp.confirmation import ConfirmationRequest
from apex_mcp.frontend_security import FrontendSession

SQLITE_ASYNC = "sqlite+aiosqlite:///:memory:"
SQLITE_SYNC = "sqlite:///:memory:"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def keypair():
    private_key, kid = load_private_key()
    return private_key, kid


def _make_access_token(
    private_key,
    kid,
    actor_id: str = "user-abc",
    session_id: str = "sess-xyz",
    tenant_id: str = "tenant-1",
    allowed_case_ids: list[str] | None = None,
    roles: list[str] | None = None,
) -> str:
    roles = roles or ["ANALYST"]
    return issue_access_token(
        private_key=private_key,
        kid=kid,
        actor_id=actor_id,
        session_id=session_id,
        tenant_id=tenant_id,
        allowed_case_ids=allowed_case_ids or ["case-001"],
        roles=roles,
        scopes=sorted(scopes_for_roles(frozenset(roles))),
    )


@pytest_asyncio.fixture
async def app_client(keypair):
    import time

    private_key, kid = keypair
    app = create_app(SQLITE_ASYNC)
    # Override verifier with test keypair so tokens issued by this fixture verify.
    verifier = app.dependency_overrides[_get_jwt_verifier]()
    jwk = public_key_to_jwk(private_key.public_key(), kid)
    verifier._keys = {kid: _jwk_to_pem(jwk)}
    verifier._fetched_at = time.monotonic()

    async with app.router.lifespan_context(app), AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        yield private_key, kid, client


@pytest.fixture
def sync_db():
    """Sync SQLite session factory with tables created."""
    engine = create_engine(SQLITE_SYNC)
    Base.metadata.create_all(engine)
    factory = sessionmaker(engine, expire_on_commit=False)
    yield factory
    Base.metadata.drop_all(engine)
    engine.dispose()


@pytest.fixture
def sync_db_threadsafe(tmp_path):
    """File-based SQLite session factory safe for multi-threaded tests.

    Uses a real file so each thread gets its own connection with proper
    SQLite write-lock serialization (unlike shared in-memory StaticPool).
    """
    db_url = f"sqlite:///{tmp_path / 'concurrent_test.db'}"
    engine = create_engine(db_url, connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    factory = sessionmaker(engine, expire_on_commit=False)
    yield factory
    engine.dispose()


# ---------------------------------------------------------------------------
# POST /confirmations endpoint
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_issue_confirmation_success(app_client):
    private_key, kid, client = app_client
    token = _make_access_token(private_key, kid, allowed_case_ids=["case-001"])

    resp = await client.post(
        "/confirmations",
        json={
            "case_id": "case-001",
            "tool_name": "report.approve",
            "request_fingerprint": "fp-abc",
            "target_ids": ["report-1"],
        },
        headers={"Authorization": f"Bearer {token}"},
    )

    assert resp.status_code == 201
    body = resp.json()
    assert "grant_id" in body
    assert body["grant_id"]


@pytest.mark.asyncio
async def test_issue_confirmation_no_token(app_client):
    _private_key, _kid, client = app_client

    resp = await client.post(
        "/confirmations",
        json={
            "case_id": "case-001",
            "tool_name": "report.approve",
            "request_fingerprint": "fp",
            "target_ids": [],
        },
    )

    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_issue_confirmation_wrong_case(app_client):
    private_key, kid, client = app_client
    token = _make_access_token(private_key, kid, allowed_case_ids=["case-001"])

    resp = await client.post(
        "/confirmations",
        json={
            "case_id": "case-999",  # not in token's allowed_case_ids
            "tool_name": "report.approve",
            "request_fingerprint": "fp",
            "target_ids": [],
        },
        headers={"Authorization": f"Bearer {token}"},
    )

    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# DbFrontendSecurityProvider — confirmation_for
# ---------------------------------------------------------------------------


def _seed_grant(
    factory: sessionmaker,
    *,
    actor_id: str = "user-abc",
    session_id: str = "sess-xyz",
    case_id: str = "case-001",
    tool_name: str = "report.approve",
    fingerprint: str = "fp-abc",
    target_ids: list[str] | None = None,
    expires_delta: timedelta = timedelta(minutes=5),
    max_uses: int = 1,
    uses_count: int = 0,
) -> str:
    grant_id = str(uuid.uuid4())
    with factory() as db:
        db.add(ConfirmationGrantRow(
            grant_id=grant_id,
            actor_id=actor_id,
            session_id=session_id,
            case_id=case_id,
            tool_name=tool_name,
            request_fingerprint=fingerprint,
            target_ids=target_ids or ["report-1"],
            expires_at=datetime.now(UTC) + expires_delta,
            max_uses=max_uses,
            uses_count=uses_count,
        ))
        db.commit()
    return grant_id


def _make_session(
    actor_id: str = "user-abc",
    session_id: str = "sess-xyz",
    tenant_id: str = "tenant-1",
    allowed_case_ids: frozenset[str] | None = None,
    roles: frozenset[str] | None = None,
) -> FrontendSession:
    return FrontendSession(
        actor_id=actor_id,
        session_id=session_id,
        tenant_id=tenant_id,
        allowed_case_ids=allowed_case_ids or frozenset({"case-001"}),
        roles=roles or frozenset({"ANALYST"}),
    )


def test_confirmation_for_finds_active_grant(sync_db):
    _seed_grant(sync_db)
    provider = DbFrontendSecurityProvider(sync_db)
    session = _make_session()

    result = provider.confirmation_for(
        session,
        case_id="case-001",
        tool_name="report.approve",
        request_fingerprint="fp-abc",
        target_ids=("report-1",),
    )

    assert result is not None
    assert result.tool_name == "report.approve"
    assert result.actor_id == "user-abc"


def test_confirmation_for_returns_none_when_no_grant(sync_db):
    provider = DbFrontendSecurityProvider(sync_db)
    session = _make_session()

    result = provider.confirmation_for(
        session,
        case_id="case-001",
        tool_name="report.approve",
        request_fingerprint="fp-not-exist",
        target_ids=("report-1",),
    )

    assert result is None


def test_confirmation_for_returns_none_for_expired(sync_db):
    _seed_grant(sync_db, expires_delta=timedelta(seconds=-1))
    provider = DbFrontendSecurityProvider(sync_db)
    session = _make_session()

    result = provider.confirmation_for(
        session,
        case_id="case-001",
        tool_name="report.approve",
        request_fingerprint="fp-abc",
        target_ids=("report-1",),
    )

    assert result is None


def test_confirmation_for_returns_none_for_exhausted(sync_db):
    _seed_grant(sync_db, max_uses=1, uses_count=1)
    provider = DbFrontendSecurityProvider(sync_db)
    session = _make_session()

    result = provider.confirmation_for(
        session,
        case_id="case-001",
        tool_name="report.approve",
        request_fingerprint="fp-abc",
        target_ids=("report-1",),
    )

    assert result is None


# ---------------------------------------------------------------------------
# DbFrontendSecurityProvider — authorize (consume)
# ---------------------------------------------------------------------------


def test_authorize_consumes_grant(sync_db):
    grant_id = _seed_grant(sync_db)
    provider = DbFrontendSecurityProvider(sync_db)
    request = ConfirmationRequest(
        grant_id=grant_id,
        actor_id="user-abc",
        session_id="sess-xyz",
        case_id="case-001",
        tool_name="report.approve",
        request_fingerprint="fp-abc",
        target_ids=("report-1",),
    )

    assert provider.authorize(request) is True


def test_authorize_rejects_second_use(sync_db):
    grant_id = _seed_grant(sync_db, max_uses=1)
    provider = DbFrontendSecurityProvider(sync_db)
    request = ConfirmationRequest(
        grant_id=grant_id,
        actor_id="user-abc",
        session_id="sess-xyz",
        case_id="case-001",
        tool_name="report.approve",
        request_fingerprint="fp-abc",
        target_ids=("report-1",),
    )

    assert provider.authorize(request) is True
    assert provider.authorize(request) is False  # already consumed


def test_authorize_rejects_expired(sync_db):
    grant_id = _seed_grant(sync_db, expires_delta=timedelta(seconds=-1))
    provider = DbFrontendSecurityProvider(sync_db)
    request = ConfirmationRequest(
        grant_id=grant_id,
        actor_id="user-abc",
        session_id="sess-xyz",
        case_id="case-001",
        tool_name="report.approve",
        request_fingerprint="fp-abc",
        target_ids=("report-1",),
    )

    assert provider.authorize(request) is False


def test_authorize_rejects_mismatched_actor(sync_db):
    grant_id = _seed_grant(sync_db)
    provider = DbFrontendSecurityProvider(sync_db)
    request = ConfirmationRequest(
        grant_id=grant_id,
        actor_id="wrong-actor",  # mismatch
        session_id="sess-xyz",
        case_id="case-001",
        tool_name="report.approve",
        request_fingerprint="fp-abc",
        target_ids=("report-1",),
    )

    assert provider.authorize(request) is False


def test_authorize_rejects_unknown_grant(sync_db):
    provider = DbFrontendSecurityProvider(sync_db)
    request = ConfirmationRequest(
        grant_id=str(uuid.uuid4()),  # doesn't exist
        actor_id="user-abc",
        session_id="sess-xyz",
        case_id="case-001",
        tool_name="report.approve",
        request_fingerprint="fp-abc",
        target_ids=("report-1",),
    )

    assert provider.authorize(request) is False


def test_authorize_multi_use_grant(sync_db):
    grant_id = _seed_grant(sync_db, max_uses=3)
    provider = DbFrontendSecurityProvider(sync_db)
    request = ConfirmationRequest(
        grant_id=grant_id,
        actor_id="user-abc",
        session_id="sess-xyz",
        case_id="case-001",
        tool_name="report.approve",
        request_fingerprint="fp-abc",
        target_ids=("report-1",),
    )

    assert provider.authorize(request) is True
    assert provider.authorize(request) is True
    assert provider.authorize(request) is True
    assert provider.authorize(request) is False  # exhausted


# ---------------------------------------------------------------------------
# Phase 11: atomic UPDATE — race condition regression test
# ---------------------------------------------------------------------------


def test_authorize_concurrent_race_max_uses_1(sync_db_threadsafe):
    """Two threads racing on max_uses=1 grant: exactly one True (atomic UPDATE)."""
    grant_id = _seed_grant(sync_db_threadsafe, max_uses=1)
    provider = DbFrontendSecurityProvider(sync_db_threadsafe)
    request = ConfirmationRequest(
        grant_id=grant_id,
        actor_id="user-abc",
        session_id="sess-xyz",
        case_id="case-001",
        tool_name="report.approve",
        request_fingerprint="fp-abc",
        target_ids=("report-1",),
    )

    results: list[bool] = []
    barrier = threading.Barrier(2)

    def call() -> None:
        barrier.wait()
        results.append(provider.authorize(request))

    threads = [threading.Thread(target=call) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(results) == 2
    assert results.count(True) == 1, f"Expected exactly 1 True, got: {results}"
    assert results.count(False) == 1
