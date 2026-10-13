"""Tests for A04: per-case role enforcement via case_roles JWT claim."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
import pytest_asyncio
from mcp.server.auth.provider import AccessToken
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from apex_backend.auth import jwt_utils
from apex_backend.auth.jwt_utils import AUDIENCE, ISSUER, issue_access_token
from apex_backend.auth.keys import load_private_key
from apex_backend.auth.scopes import scopes_for_roles
from apex_backend.auth.service import AuthService, hash_password
from apex_backend.database import Base
from apex_backend.models import CaseTenancy, User
from apex_mcp.errors import McpAuthorizationDeniedError, McpTenantScopeViolationError
from apex_mcp.frontend_security import (
    FrontendAuthorizationGate,
    FrontendSession,
    PersistentFrontendSecurityProvider,
)

SQLITE_ASYNC = "sqlite+aiosqlite:///:memory:"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def keypair():
    return load_private_key()


def _all_scopes() -> list[str]:
    return sorted(scopes_for_roles(frozenset({"ADMIN"})))


def _make_access_token(
    private_key,
    kid,
    case_roles: dict[str, str],
    *,
    actor_id: str = "user-a",
    session_id: str = "sess-1",
    tenant_id: str = "tenant-1",
) -> AccessToken:
    """Issue a real signed JWT and wrap it in an AccessToken."""
    allowed = list(case_roles.keys())
    roles = list({r.upper() for r in case_roles.values()})
    scopes = sorted(scopes_for_roles(frozenset(roles)))
    token_str = issue_access_token(
        private_key=private_key,
        kid=kid,
        actor_id=actor_id,
        session_id=session_id,
        tenant_id=tenant_id,
        allowed_case_ids=allowed,
        roles=roles,
        scopes=scopes,
        case_roles=case_roles,
    )
    # Decode to get claims; build AccessToken manually to avoid network calls.
    from apex_backend.auth.jwt_utils import ALGORITHM
    from cryptography.hazmat.primitives import serialization
    from jose import jwt as jose_jwt

    pub_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    claims = jose_jwt.decode(
        token_str, pub_pem, algorithms=[ALGORITHM],
        audience=AUDIENCE, issuer=ISSUER,
    )
    return AccessToken(
        token=token_str,
        client_id=ISSUER,
        scopes=scopes,
        subject=actor_id,
        resource=AUDIENCE,
        claims=claims,
    )


def _session_from_token(token: AccessToken) -> FrontendSession:
    return PersistentFrontendSecurityProvider().resolve_session(token)


def _descriptor(*, mutates: bool = False, approval: bool = False) -> dict:
    return {
        "mutates_state": mutates,
        "requires_confirmation": approval,
    }


# ---------------------------------------------------------------------------
# resolve_session: legacy token (no case_roles) is denied
# ---------------------------------------------------------------------------


def test_legacy_token_without_case_roles_is_denied() -> None:
    provider = PersistentFrontendSecurityProvider()
    claims = {
        "sub": "u",
        "iss": ISSUER,
        "aud": AUDIENCE,
        "session_id": "s",
        "tenant_id": "t",
        "allowed_case_ids": ["c"],
        "roles": ["ANALYST"],
        "token_type": "access",
        # no "case_roles" key
    }
    token = AccessToken(
        token="t", client_id=ISSUER, scopes=["apex:mcp"], subject="u",
        resource=AUDIENCE, claims=claims,
    )
    with pytest.raises(McpAuthorizationDeniedError):
        provider.resolve_session(token)


# ---------------------------------------------------------------------------
# resolve_session: valid token with case_roles populates session correctly
# ---------------------------------------------------------------------------


def test_resolve_session_with_case_roles(keypair) -> None:
    private_key, kid = keypair
    token = _make_access_token(
        private_key, kid,
        case_roles={"case-A": "ADMIN", "case-B": "VIEWER"},
    )
    session = _session_from_token(token)
    assert session.allowed_case_ids == frozenset({"case-A", "case-B"})
    assert "ADMIN" in session.roles
    assert "VIEWER" in session.roles


# ---------------------------------------------------------------------------
# Gate: VIEWER on case B cannot approve/mutate in case B
# ---------------------------------------------------------------------------


def test_viewer_cannot_approve_in_their_case(keypair) -> None:
    """A=ADMIN, B=VIEWER: gate must deny approval in case B."""
    private_key, kid = keypair
    # A has ADMIN in case-A and VIEWER in case-B.
    # The token therefore has apex:approve scope (from ADMIN union) — but the
    # per-case role check must still reject approval for case-B.
    token = _make_access_token(
        private_key, kid,
        case_roles={"case-A": "ADMIN", "case-B": "VIEWER"},
    )
    session = _session_from_token(token)
    gate = FrontendAuthorizationGate()

    with pytest.raises(McpAuthorizationDeniedError):
        gate.require(
            session, token, _descriptor(mutates=True, approval=True),
            tool_name="report.approve",
            target_case_ids=frozenset({"case-B"}),
        )


def test_viewer_cannot_mutate_in_their_case(keypair) -> None:
    private_key, kid = keypair
    token = _make_access_token(
        private_key, kid,
        case_roles={"case-A": "ADMIN", "case-B": "VIEWER"},
    )
    session = _session_from_token(token)
    gate = FrontendAuthorizationGate()

    with pytest.raises(McpAuthorizationDeniedError):
        gate.require(
            session, token, _descriptor(mutates=True),
            tool_name="evidence.update",
            target_case_ids=frozenset({"case-B"}),
        )


def test_viewer_can_read_in_their_case(keypair) -> None:
    """VIEWER role is sufficient for read-only tools (no role requirement)."""
    private_key, kid = keypair
    token = _make_access_token(
        private_key, kid,
        case_roles={"case-A": "ADMIN", "case-B": "VIEWER"},
    )
    session = _session_from_token(token)
    gate = FrontendAuthorizationGate()

    # Should not raise: read-only tool, no role required.
    gate.require(
        session, token, _descriptor(),
        tool_name="apex.view.get",
        target_case_ids=frozenset({"case-B"}),
    )


def test_viewer_cannot_raw_read_in_their_case(keypair) -> None:
    """apex.view.raw_read requires apex:raw scope; VIEWER role lacks it (union with ADMIN)."""
    private_key, kid = keypair
    # VIEWER alone: scopes won't include apex:raw.
    viewer_scopes = sorted(scopes_for_roles(frozenset({"VIEWER"})))
    token_str = issue_access_token(
        private_key=private_key,
        kid=kid,
        actor_id="user-viewer",
        session_id="sess-v",
        tenant_id="t1",
        allowed_case_ids=["case-B"],
        roles=["VIEWER"],
        scopes=viewer_scopes,
        case_roles={"case-B": "VIEWER"},
    )
    from cryptography.hazmat.primitives import serialization
    from jose import jwt as jose_jwt

    pub_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    claims = jose_jwt.decode(
        token_str, pub_pem, algorithms=["RS256"],
        audience=AUDIENCE, issuer=ISSUER,
    )
    token = AccessToken(
        token=token_str, client_id=ISSUER, scopes=viewer_scopes,
        subject="user-viewer", resource=AUDIENCE, claims=claims,
    )
    session = _session_from_token(token)
    gate = FrontendAuthorizationGate()

    with pytest.raises(McpAuthorizationDeniedError):
        gate.require(
            session, token, _descriptor(),
            tool_name="apex.view.raw_read",
            target_case_ids=frozenset({"case-B"}),
        )


def test_admin_can_approve_in_their_case(keypair) -> None:
    """ADMIN role in case A can approve in case A."""
    private_key, kid = keypair
    token = _make_access_token(
        private_key, kid,
        case_roles={"case-A": "ADMIN", "case-B": "VIEWER"},
    )
    session = _session_from_token(token)
    gate = FrontendAuthorizationGate()

    # Should not raise: ADMIN in case-A.
    gate.require(
        session, token, _descriptor(mutates=True, approval=True),
        tool_name="report.approve",
        target_case_ids=frozenset({"case-A"}),
    )


# ---------------------------------------------------------------------------
# login() and refresh() produce tokens with case_roles
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def db_engine():
    eng = create_async_engine(SQLITE_ASYNC, echo=False)
    async with eng.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield eng
    async with eng.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await eng.dispose()


@pytest_asyncio.fixture
async def db_session(db_engine):
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as sess:
        yield sess


@pytest.mark.asyncio
async def test_login_token_contains_case_roles(keypair, db_session) -> None:
    private_key, kid = keypair
    service = AuthService(private_key, kid)

    uid = str(uuid.uuid4())
    db_session.add(User(
        id=uid, username="u", email=f"{uid}@t.local",
        hashed_password=hash_password("pw"), tenant_id="t1",
        created_at=datetime.now(UTC), is_active=True,
    ))
    db_session.add(CaseTenancy(
        id=str(uuid.uuid4()), actor_id=uid,
        case_id="case-login-01", role="ANALYST",
        granted_at=datetime.now(UTC),
    ))
    await db_session.commit()

    access, _refresh = await service.login(
        db_session, email=f"{uid}@t.local", password="pw", tenant_id="t1"
    )

    from cryptography.hazmat.primitives import serialization
    from jose import jwt as jose_jwt

    pub_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    claims = jose_jwt.decode(
        access, pub_pem, algorithms=["RS256"],
        audience=AUDIENCE, issuer=ISSUER,
    )
    assert "case_roles" in claims
    assert claims["case_roles"] == {"case-login-01": "ANALYST"}


@pytest.mark.asyncio
async def test_refresh_token_contains_case_roles(keypair, db_session) -> None:
    private_key, kid = keypair
    service = AuthService(private_key, kid)

    uid = str(uuid.uuid4())
    db_session.add(User(
        id=uid, username="u2", email=f"{uid}@t.local",
        hashed_password=hash_password("pw"), tenant_id="t1",
        created_at=datetime.now(UTC), is_active=True,
    ))
    db_session.add(CaseTenancy(
        id=str(uuid.uuid4()), actor_id=uid,
        case_id="case-refresh-01", role="ADMIN",
        granted_at=datetime.now(UTC),
    ))
    await db_session.commit()

    _access, refresh = await service.login(
        db_session, email=f"{uid}@t.local", password="pw", tenant_id="t1"
    )
    new_access, _new_refresh = await service.refresh(db_session, refresh_token=refresh)

    from cryptography.hazmat.primitives import serialization
    from jose import jwt as jose_jwt

    pub_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    claims = jose_jwt.decode(
        new_access, pub_pem, algorithms=["RS256"],
        audience=AUDIENCE, issuer=ISSUER,
    )
    assert "case_roles" in claims
    assert claims["case_roles"]["case-refresh-01"] == "ADMIN"
