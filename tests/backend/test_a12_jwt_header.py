"""Tests for A12: malformed JWT header returns None / HTTP 401, not 500."""

from __future__ import annotations

import time
from unittest.mock import patch

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from jose import jwt as jose_jwt

from apex_backend.app import create_app
from apex_backend.auth.jwt_utils import ALGORITHM, AUDIENCE, ISSUER, issue_access_token
from apex_backend.auth.jwt_verifier import JwtTokenVerifier, _jwk_to_pem
from apex_backend.auth.keys import load_private_key, public_key_to_jwk
from apex_backend.auth.scopes import scopes_for_roles

SQLITE_ASYNC = "sqlite+aiosqlite:///:memory:"


@pytest.fixture(scope="module")
def keypair():
    private_key, kid = load_private_key()
    jwk = public_key_to_jwk(private_key.public_key(), kid)
    jwks_body = {"keys": [jwk]}
    return private_key, kid, jwks_body


def _make_verifier(keypair):
    private_key, kid, jwks_body = keypair
    verifier = JwtTokenVerifier("http://test/.well-known/jwks.json", cache_ttl_seconds=300)
    verifier._keys = {jwk["kid"]: _jwk_to_pem(jwk) for jwk in jwks_body["keys"]}
    verifier._fetched_at = time.monotonic()
    return verifier


def _good_token(keypair):
    private_key, kid, _ = keypair
    roles = ["ANALYST"]
    return issue_access_token(
        private_key=private_key,
        kid=kid,
        actor_id="user-1",
        session_id="sess-1",
        tenant_id="tenant-1",
        allowed_case_ids=["case-001"],
        roles=roles,
        scopes=sorted(scopes_for_roles(frozenset(roles))),
        case_roles={"case-001": "ANALYST"},
    )


def _forge_token_with_header(keypair, header_override: dict) -> str:
    """Create a token-shaped string with a tampered header (unsigned)."""
    import base64
    import json

    private_key, kid, _ = keypair
    good = _good_token(keypair)
    # Use the real payload/signature from a valid token, swap only the header.
    parts = good.split(".")
    bad_header = base64.urlsafe_b64encode(
        json.dumps(header_override).encode()
    ).rstrip(b"=").decode()
    return f"{bad_header}.{parts[1]}.{parts[2]}"


# ---------------------------------------------------------------------------
# verify_token — malformed headers must return None, never raise
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_kid_as_list_returns_none(keypair) -> None:
    verifier = _make_verifier(keypair)
    token = _forge_token_with_header(keypair, {"alg": "RS256", "typ": "JWT", "kid": []})
    result = await verifier.verify_token(token)
    assert result is None


@pytest.mark.asyncio
async def test_kid_as_dict_returns_none(keypair) -> None:
    verifier = _make_verifier(keypair)
    token = _forge_token_with_header(keypair, {"alg": "RS256", "typ": "JWT", "kid": {}})
    result = await verifier.verify_token(token)
    assert result is None


@pytest.mark.asyncio
async def test_kid_as_number_returns_none(keypair) -> None:
    verifier = _make_verifier(keypair)
    token = _forge_token_with_header(keypair, {"alg": "RS256", "typ": "JWT", "kid": 42})
    result = await verifier.verify_token(token)
    assert result is None


@pytest.mark.asyncio
async def test_kid_too_long_returns_none(keypair) -> None:
    verifier = _make_verifier(keypair)
    long_kid = "x" * 129
    token = _forge_token_with_header(keypair, {"alg": "RS256", "typ": "JWT", "kid": long_kid})
    result = await verifier.verify_token(token)
    assert result is None


@pytest.mark.asyncio
async def test_kid_none_falls_through_to_first_key(keypair) -> None:
    """kid=null/absent is allowed — falls back to first cached key."""
    verifier = _make_verifier(keypair)
    good = _good_token(keypair)
    # A normal valid token should still pass (kid is a valid str in good tokens).
    result = await verifier.verify_token(good)
    assert result is not None


@pytest.mark.asyncio
async def test_wrong_alg_returns_none(keypair) -> None:
    verifier = _make_verifier(keypair)
    token = _forge_token_with_header(keypair, {"alg": "HS256", "typ": "JWT", "kid": "key-1"})
    result = await verifier.verify_token(token)
    assert result is None


@pytest.mark.asyncio
async def test_corrupted_token_returns_none(keypair) -> None:
    verifier = _make_verifier(keypair)
    result = await verifier.verify_token("not.a.jwt.at.all")
    assert result is None


@pytest.mark.asyncio
async def test_valid_token_still_passes(keypair) -> None:
    verifier = _make_verifier(keypair)
    good = _good_token(keypair)
    result = await verifier.verify_token(good)
    assert result is not None
    assert result.subject == "user-1"


# ---------------------------------------------------------------------------
# /confirmations endpoint: malformed tokens → 401 not 500
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def app_client(keypair):
    private_key, kid, jwks_body = keypair
    app = create_app(SQLITE_ASYNC)
    from apex_backend.auth.confirmation_router import _get_jwt_verifier

    verifier = app.dependency_overrides[_get_jwt_verifier]()
    verifier._keys = {jwk["kid"]: _jwk_to_pem(jwk) for jwk in jwks_body["keys"]}
    verifier._fetched_at = time.monotonic()

    async with app.router.lifespan_context(app), AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        yield client


@pytest.mark.asyncio
async def test_kid_array_returns_401_not_500(app_client, keypair) -> None:
    token = _forge_token_with_header(keypair, {"alg": "RS256", "typ": "JWT", "kid": []})
    resp = await app_client.post(
        "/confirmations",
        json={"case_id": "c", "tool_name": "t", "request_fingerprint": "f", "target_ids": []},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_corrupted_token_returns_401_not_500(app_client) -> None:
    resp = await app_client.post(
        "/confirmations",
        json={"case_id": "c", "tool_name": "t", "request_fingerprint": "f", "target_ids": []},
        headers={"Authorization": "Bearer totally.bogus.token"},
    )
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# JWKS cooldown: unknown kid does not cause rapid re-fetches
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_unknown_kid_cooldown(keypair) -> None:
    """Two consecutive calls with an unknown kid only trigger one JWKS fetch."""
    private_key, kid, jwks_body = keypair
    verifier = JwtTokenVerifier("http://test/.well-known/jwks.json", cache_ttl_seconds=300)
    verifier._keys = {jwk["kid"]: _jwk_to_pem(jwk) for jwk in jwks_body["keys"]}
    verifier._fetched_at = time.monotonic()
    # Point to future so cooldown not elapsed yet after first fetch.
    verifier._unknown_kid_fetched_at = time.monotonic()

    fetch_count = 0

    async def count_fetch(self):
        nonlocal fetch_count
        fetch_count += 1

    unknown_token = _forge_token_with_header(
        keypair, {"alg": "RS256", "typ": "JWT", "kid": "unknown-key-id"}
    )

    with patch.object(JwtTokenVerifier, "_fetch_jwks", count_fetch):
        await verifier.verify_token(unknown_token)
        await verifier.verify_token(unknown_token)

    # Cooldown should prevent second re-fetch.
    assert fetch_count <= 1
