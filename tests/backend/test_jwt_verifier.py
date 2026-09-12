"""Tests for Phase 3: JwtTokenVerifier — JWKS-backed RS256 verification."""

from __future__ import annotations

import time
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from cryptography.hazmat.primitives import serialization

from apex_backend.auth.jwt_utils import (
    AUDIENCE,
    ISSUER,
    issue_access_token,
    issue_refresh_token,
)
from apex_backend.auth.jwt_verifier import JwtTokenVerifier, _jwk_to_pem
from apex_backend.auth.keys import load_private_key, public_key_to_jwk

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def keypair():
    private_key, kid = load_private_key()
    pub_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    jwk = public_key_to_jwk(private_key.public_key(), kid)
    jwks_body = {"keys": [jwk]}
    return private_key, kid, pub_pem, jwks_body


def _make_verifier(jwks_body: dict[str, Any]) -> JwtTokenVerifier:
    """Return a verifier whose JWKS fetch is mocked."""
    verifier = JwtTokenVerifier(
        jwks_uri="http://test/.well-known/jwks.json",
        cache_ttl_seconds=300,
    )
    keys = {}
    for jwk in jwks_body.get("keys", []):
        keys[jwk["kid"]] = _jwk_to_pem(jwk)
    verifier._keys = keys
    verifier._fetched_at = time.monotonic()
    return verifier


def _make_access_token(private_key: Any, kid: str, **overrides: Any) -> str:
    kwargs: dict[str, Any] = {
        "private_key": private_key,
        "kid": kid,
        "actor_id": "user-123",
        "session_id": "sess-456",
        "tenant_id": "tenant-1",
        "allowed_case_ids": ["case-001"],
        "roles": ["ANALYST"],
        "scopes": ["apex:mcp", "apex:read", "apex:write"],
    }
    kwargs.update(overrides)
    return issue_access_token(**kwargs)


# ---------------------------------------------------------------------------
# _jwk_to_pem helper
# ---------------------------------------------------------------------------


def test_jwk_to_pem_roundtrip(keypair: Any) -> None:
    _private_key, _kid, pub_pem, jwks_body = keypair
    jwk = jwks_body["keys"][0]
    pem = _jwk_to_pem(jwk)
    assert pem.startswith("-----BEGIN PUBLIC KEY-----")
    assert pem.strip() == pub_pem.strip()


# ---------------------------------------------------------------------------
# verify_token — happy path
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_verify_valid_access_token(keypair: Any) -> None:
    private_key, kid, _pub_pem, jwks_body = keypair
    verifier = _make_verifier(jwks_body)
    token = _make_access_token(private_key, kid)

    result = await verifier.verify_token(token)

    assert result is not None
    assert result.client_id == ISSUER
    assert result.subject == "user-123"
    assert "apex:mcp" in result.scopes
    assert "apex:write" in result.scopes
    assert result.expires_at is not None and result.expires_at > int(time.time())
    assert result.resource == AUDIENCE
    assert result.token == token


@pytest.mark.asyncio
async def test_verify_returns_all_claims(keypair: Any) -> None:
    private_key, kid, _pub_pem, jwks_body = keypair
    verifier = _make_verifier(jwks_body)
    token = _make_access_token(private_key, kid)

    result = await verifier.verify_token(token)

    assert result is not None
    assert result.claims is not None
    assert result.claims["session_id"] == "sess-456"
    assert result.claims["tenant_id"] == "tenant-1"
    assert result.claims["allowed_case_ids"] == ["case-001"]
    assert "ANALYST" in result.claims["roles"]


# ---------------------------------------------------------------------------
# verify_token — rejection cases
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_reject_refresh_token(keypair: Any) -> None:
    private_key, kid, _pub_pem, jwks_body = keypair
    verifier = _make_verifier(jwks_body)
    refresh = issue_refresh_token(private_key=private_key, kid=kid, actor_id="u", session_id="s")

    result = await verifier.verify_token(refresh)

    assert result is None


@pytest.mark.asyncio
async def test_reject_garbage_token(keypair: Any) -> None:
    _private_key, _kid, _pub_pem, jwks_body = keypair
    verifier = _make_verifier(jwks_body)

    result = await verifier.verify_token("not.a.jwt")

    assert result is None


@pytest.mark.asyncio
async def test_reject_wrong_issuer(keypair: Any) -> None:
    private_key, kid, _pub_pem, jwks_body = keypair
    verifier = JwtTokenVerifier(
        jwks_uri="http://test/.well-known/jwks.json",
        issuer="https://wrong.issuer",
        cache_ttl_seconds=300,
    )
    verifier._keys = {jwk["kid"]: _jwk_to_pem(jwk) for jwk in jwks_body["keys"]}
    verifier._fetched_at = time.monotonic()

    token = _make_access_token(private_key, kid)
    result = await verifier.verify_token(token)

    assert result is None


@pytest.mark.asyncio
async def test_reject_unknown_kid(keypair: Any) -> None:
    private_key, kid, _pub_pem, jwks_body = keypair
    verifier = _make_verifier(jwks_body)
    verifier._keys = {}
    verifier._fetched_at = time.monotonic()

    token = _make_access_token(private_key, kid)
    result = await verifier.verify_token(token)

    assert result is None


# ---------------------------------------------------------------------------
# JWKS cache refresh
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_cache_populated_on_first_call(keypair: Any) -> None:
    private_key, kid, _pub_pem, jwks_body = keypair

    verifier = JwtTokenVerifier(
        jwks_uri="http://test/.well-known/jwks.json",
        cache_ttl_seconds=300,
    )

    mock_response = MagicMock()
    mock_response.raise_for_status = MagicMock()
    mock_response.json = MagicMock(return_value=jwks_body)

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)
    mock_client.get = AsyncMock(return_value=mock_response)

    token = _make_access_token(private_key, kid)

    with patch("apex_backend.auth.jwt_verifier.httpx.AsyncClient", return_value=mock_client):
        result = await verifier.verify_token(token)

    assert result is not None
    assert kid in verifier._keys


@pytest.mark.asyncio
async def test_cache_not_refetched_within_ttl(keypair: Any) -> None:
    private_key, kid, _pub_pem, jwks_body = keypair
    verifier = _make_verifier(jwks_body)

    fetch_count = 0

    async def fake_fetch(self: Any) -> None:
        nonlocal fetch_count
        fetch_count += 1

    token = _make_access_token(private_key, kid)

    with patch.object(JwtTokenVerifier, "_fetch_jwks", fake_fetch):
        await verifier.verify_token(token)
        await verifier.verify_token(token)

    assert fetch_count == 0


@pytest.mark.asyncio
async def test_cache_refetched_after_ttl(keypair: Any) -> None:
    private_key, kid, _pub_pem, jwks_body = keypair
    verifier = _make_verifier(jwks_body)
    verifier._fetched_at = time.monotonic() - 400

    fetch_called = False

    async def fake_fetch(self: Any) -> None:
        nonlocal fetch_called
        fetch_called = True
        self._keys = {jwk["kid"]: _jwk_to_pem(jwk) for jwk in jwks_body["keys"]}
        self._fetched_at = time.monotonic()

    token = _make_access_token(private_key, kid)

    with patch.object(JwtTokenVerifier, "_fetch_jwks", fake_fetch):
        result = await verifier.verify_token(token)

    assert fetch_called
    assert result is not None


@pytest.mark.asyncio
async def test_network_error_returns_none(keypair: Any) -> None:
    _private_key, _kid, _pub_pem, _jwks_body = keypair

    verifier = JwtTokenVerifier(
        jwks_uri="http://test/.well-known/jwks.json",
        cache_ttl_seconds=300,
    )

    async def fail_fetch(self: Any) -> None:
        pass

    token = "not.a.valid.jwt"

    with patch.object(JwtTokenVerifier, "_fetch_jwks", fail_fetch):
        result = await verifier.verify_token(token)

    assert result is None
