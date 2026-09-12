"""Tests for Phase 4: PersistentFrontendSecurityProvider."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from mcp.server.auth.provider import AccessToken

from apex_backend.auth.jwt_utils import AUDIENCE, ISSUER
from apex_mcp.confirmation import ConfirmationRequest, InMemoryConfirmationProvider
from apex_mcp.errors import McpAuthorizationDeniedError, McpTenantScopeViolationError
from apex_mcp.frontend_security import FrontendAuthorizationGate, PersistentFrontendSecurityProvider

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_token(
    actor_id: str = "user-abc",
    session_id: str = "sess-xyz",
    tenant_id: str = "tenant-1",
    allowed_case_ids: list[str] | None = None,
    roles: list[str] | None = None,
    scopes: list[str] | None = None,
) -> AccessToken:
    claims = {
        "sub": actor_id,
        "iss": ISSUER,
        "aud": AUDIENCE,
        "session_id": session_id,
        "tenant_id": tenant_id,
        "allowed_case_ids": allowed_case_ids if allowed_case_ids is not None else ["case-001"],
        "roles": roles if roles is not None else ["ANALYST"],
        "token_type": "access",
    }
    return AccessToken(
        token="raw-token-value",
        client_id=ISSUER,
        scopes=scopes if scopes is not None else ["apex:mcp", "apex:read", "apex:write"],
        subject=actor_id,
        resource=AUDIENCE,
        claims=claims,
    )


# ---------------------------------------------------------------------------
# resolve_session — happy path
# ---------------------------------------------------------------------------


def test_resolve_session_extracts_all_claims() -> None:
    provider = PersistentFrontendSecurityProvider()
    token = _make_token(allowed_case_ids=["case-001", "case-002"], roles=["ANALYST", "VIEWER"])

    session = provider.resolve_session(token)

    assert session.actor_id == "user-abc"
    assert session.session_id == "sess-xyz"
    assert session.tenant_id == "tenant-1"
    assert session.allowed_case_ids == frozenset({"case-001", "case-002"})
    assert session.roles == frozenset({"ANALYST", "VIEWER"})


def test_resolve_session_normalizes_roles_to_upper() -> None:
    provider = PersistentFrontendSecurityProvider()
    token = _make_token(roles=["analyst"])

    session = provider.resolve_session(token)

    assert "ANALYST" in session.roles


def test_resolve_session_uses_subject_fallback() -> None:
    """AccessToken.subject used when claims dict lacks 'sub'."""
    provider = PersistentFrontendSecurityProvider()
    claims = {
        "iss": ISSUER,
        "session_id": "sess-1",
        "tenant_id": "tenant-1",
        "allowed_case_ids": ["case-A"],
        "roles": ["VIEWER"],
        "token_type": "access",
    }
    token = AccessToken(
        token="t",
        client_id=ISSUER,
        scopes=["apex:mcp"],
        subject="user-fallback",
        resource=AUDIENCE,
        claims=claims,
    )

    session = provider.resolve_session(token)

    assert session.actor_id == "user-fallback"


# ---------------------------------------------------------------------------
# resolve_session — rejection cases
# ---------------------------------------------------------------------------


def test_resolve_session_rejects_missing_actor() -> None:
    provider = PersistentFrontendSecurityProvider()
    token = _make_token(actor_id="")
    token = AccessToken(
        token="t",
        client_id=ISSUER,
        scopes=["apex:mcp"],
        subject=None,
        resource=AUDIENCE,
        claims={
            "session_id": "sess-1",
            "tenant_id": "tenant-1",
            "allowed_case_ids": ["case-A"],
            "roles": ["VIEWER"],
        },
    )

    with pytest.raises(McpAuthorizationDeniedError):
        provider.resolve_session(token)


def test_resolve_session_rejects_missing_session_id() -> None:
    provider = PersistentFrontendSecurityProvider()
    claims = {
        "sub": "user-1",
        "tenant_id": "tenant-1",
        "allowed_case_ids": ["case-A"],
        "roles": ["VIEWER"],
    }
    token = AccessToken(
        token="t", client_id=ISSUER, scopes=["apex:mcp"], subject="user-1",
        resource=AUDIENCE, claims=claims,
    )

    with pytest.raises(McpAuthorizationDeniedError):
        provider.resolve_session(token)


def test_resolve_session_rejects_missing_tenant() -> None:
    provider = PersistentFrontendSecurityProvider()
    claims = {
        "sub": "user-1",
        "session_id": "sess-1",
        "allowed_case_ids": ["case-A"],
        "roles": ["VIEWER"],
    }
    token = AccessToken(
        token="t", client_id=ISSUER, scopes=["apex:mcp"], subject="user-1",
        resource=AUDIENCE, claims=claims,
    )

    with pytest.raises(McpAuthorizationDeniedError):
        provider.resolve_session(token)


# ---------------------------------------------------------------------------
# Tenancy and role enforcement via FrontendAuthorizationGate
# ---------------------------------------------------------------------------


def _make_descriptor(
    *,
    mutates_state: bool = False,
    requires_confirmation: bool = False,
) -> dict[str, object]:
    return {
        "mutates_state": mutates_state,
        "requires_confirmation": requires_confirmation,
    }


def test_gate_raises_on_out_of_scope_case() -> None:
    provider = PersistentFrontendSecurityProvider()
    gate = FrontendAuthorizationGate()
    token = _make_token(
        allowed_case_ids=["case-001"],
        scopes=["apex:mcp", "apex:read"],
    )
    session = provider.resolve_session(token)

    with pytest.raises(McpTenantScopeViolationError):
        gate.require(
            session, token, _make_descriptor(),
            tool_name="some.tool",
            target_case_ids=frozenset({"case-999"}),  # not in allowed_case_ids
        )


def test_gate_passes_for_allowed_case() -> None:
    provider = PersistentFrontendSecurityProvider()
    gate = FrontendAuthorizationGate()
    token = _make_token(
        allowed_case_ids=["case-001"],
        scopes=["apex:mcp", "apex:read"],
    )
    session = provider.resolve_session(token)

    gate.require(
        session, token, _make_descriptor(),
        tool_name="some.tool",
        target_case_ids=frozenset({"case-001"}),
    )


def test_gate_raises_missing_write_scope() -> None:
    provider = PersistentFrontendSecurityProvider()
    gate = FrontendAuthorizationGate()
    token = _make_token(
        allowed_case_ids=["case-001"],
        scopes=["apex:mcp", "apex:read"],  # no apex:write
    )
    session = provider.resolve_session(token)

    from apex_mcp.errors import McpAuthorizationDeniedError

    with pytest.raises(McpAuthorizationDeniedError):
        gate.require(
            session, token, _make_descriptor(mutates_state=True),
            tool_name="some.write.tool",
            target_case_ids=frozenset({"case-001"}),
        )


# ---------------------------------------------------------------------------
# confirmation_for and authorize
# ---------------------------------------------------------------------------


def test_confirmation_for_returns_none_by_default() -> None:
    provider = PersistentFrontendSecurityProvider()
    token = _make_token()
    session = provider.resolve_session(token)

    result = provider.confirmation_for(
        session,
        case_id="case-001",
        tool_name="report.approve",
        request_fingerprint="fp-abc",
        target_ids=("report-1",),
    )

    assert result is None


def test_authorize_denies_by_default() -> None:
    provider = PersistentFrontendSecurityProvider()
    request = ConfirmationRequest(
        grant_id="g-1",
        actor_id="user-abc",
        session_id="sess-xyz",
        case_id="case-001",
        tool_name="report.approve",
        request_fingerprint="fp-abc",
        target_ids=("report-1",),
    )

    assert provider.authorize(request) is False


def test_authorize_delegates_to_injected_provider() -> None:
    mock_provider = MagicMock(spec=InMemoryConfirmationProvider)
    mock_provider.authorize.return_value = True

    provider = PersistentFrontendSecurityProvider(confirmation_provider=mock_provider)
    request = ConfirmationRequest(
        grant_id="g-1",
        actor_id="user-abc",
        session_id="sess-xyz",
        case_id="case-001",
        tool_name="report.approve",
        request_fingerprint="fp-abc",
        target_ids=("report-1",),
    )

    assert provider.authorize(request) is True
    mock_provider.authorize.assert_called_once_with(request)
