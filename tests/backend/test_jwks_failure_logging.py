"""Tests for Phase 15: JwtTokenVerifier JWKS failure logging."""

from __future__ import annotations

import logging
import time
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from apex_backend.auth.jwt_verifier import JwtTokenVerifier, _jwk_to_pem
from apex_backend.auth.keys import load_private_key, public_key_to_jwk

_JWKS_URI = "http://test/.well-known/jwks.json"


@pytest.fixture
def verifier_empty() -> JwtTokenVerifier:
    """Verifier with empty key cache (first-time fetch scenario)."""
    return JwtTokenVerifier(jwks_uri=_JWKS_URI, cache_ttl_seconds=300)


@pytest.fixture
def verifier_with_cache() -> JwtTokenVerifier:
    """Verifier with pre-populated key cache (stale-cache scenario)."""
    private_key, kid = load_private_key()
    jwk = public_key_to_jwk(private_key.public_key(), kid)
    v = JwtTokenVerifier(jwks_uri=_JWKS_URI, cache_ttl_seconds=300)
    v._keys = {kid: _jwk_to_pem(jwk)}
    v._fetched_at = time.monotonic()
    return v


def _mock_http_error() -> Any:
    """Patch httpx.AsyncClient to raise a connection error."""
    mock_client = MagicMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.get = AsyncMock(side_effect=Exception("connection refused"))
    return patch("httpx.AsyncClient", return_value=mock_client)


def _mock_http_response(body: dict[str, Any]) -> Any:
    """Patch httpx.AsyncClient to return *body* as JSON."""
    mock_resp = MagicMock()
    mock_resp.raise_for_status.return_value = None
    mock_resp.json.return_value = body

    mock_client = MagicMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.get = AsyncMock(return_value=mock_resp)
    return patch("httpx.AsyncClient", return_value=mock_client)


# ---------------------------------------------------------------------------
# Fetch failure logging
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_fetch_failure_empty_cache_logs_warning(
    verifier_empty: JwtTokenVerifier, caplog: pytest.LogCaptureFixture
) -> None:
    with (
        caplog.at_level(logging.WARNING, logger="apex_backend.auth.jwt_verifier"),
        _mock_http_error(),
    ):
        await verifier_empty._fetch_jwks()

    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert warnings, "Expected at least one WARNING log when fetch fails with empty cache"
    assert any("no cached keys" in r.message for r in warnings)


@pytest.mark.asyncio
async def test_fetch_failure_stale_cache_logs_warning(
    verifier_with_cache: JwtTokenVerifier, caplog: pytest.LogCaptureFixture
) -> None:
    with (
        caplog.at_level(logging.WARNING, logger="apex_backend.auth.jwt_verifier"),
        _mock_http_error(),
    ):
        await verifier_with_cache._fetch_jwks()

    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert warnings, "Expected at least one WARNING log when fetch fails with stale cache"
    assert any("cached key" in r.message for r in warnings)


@pytest.mark.asyncio
async def test_fetch_failure_includes_exc_info(
    verifier_empty: JwtTokenVerifier, caplog: pytest.LogCaptureFixture
) -> None:
    with (
        caplog.at_level(logging.WARNING, logger="apex_backend.auth.jwt_verifier"),
        _mock_http_error(),
    ):
        await verifier_empty._fetch_jwks()

    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert warnings
    # exc_info=True means exc_info tuple is attached to the record
    assert warnings[0].exc_info is not None


# ---------------------------------------------------------------------------
# JWK parse failure logging
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_bad_jwk_logs_warning(
    verifier_empty: JwtTokenVerifier, caplog: pytest.LogCaptureFixture
) -> None:
    malformed_jwks = {"keys": [{"kid": "bad-key", "kty": "RSA", "n": "!!!invalid!!!"}]}

    with (
        caplog.at_level(logging.WARNING, logger="apex_backend.auth.jwt_verifier"),
        _mock_http_response(malformed_jwks),
    ):
        await verifier_empty._fetch_jwks()

    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert warnings, "Expected WARNING when JWK parse fails"
    assert any("bad-key" in r.message for r in warnings)


@pytest.mark.asyncio
async def test_bad_jwk_does_not_affect_valid_keys(
    verifier_empty: JwtTokenVerifier, caplog: pytest.LogCaptureFixture
) -> None:
    private_key, kid = load_private_key()
    jwk_valid = public_key_to_jwk(private_key.public_key(), kid)
    mixed_jwks = {
        "keys": [
            {"kid": "bad-key", "kty": "RSA", "n": "!!!invalid!!!"},
            jwk_valid,
        ]
    }

    with (
        caplog.at_level(logging.WARNING, logger="apex_backend.auth.jwt_verifier"),
        _mock_http_response(mixed_jwks),
    ):
        await verifier_empty._fetch_jwks()

    assert kid in verifier_empty._keys, "Valid key must be cached despite bad-key failure"
    assert "bad-key" not in verifier_empty._keys


# ---------------------------------------------------------------------------
# Existing behavior unchanged
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_fetch_failure_empty_cache_fail_closed(
    verifier_empty: JwtTokenVerifier,
) -> None:
    with _mock_http_error():
        await verifier_empty._fetch_jwks()

    assert verifier_empty._keys == {}


@pytest.mark.asyncio
async def test_fetch_failure_stale_cache_fail_open(
    verifier_with_cache: JwtTokenVerifier,
) -> None:
    cached_keys = dict(verifier_with_cache._keys)
    with _mock_http_error():
        await verifier_with_cache._fetch_jwks()

    assert verifier_with_cache._keys == cached_keys, "Stale cache must survive fetch failure"
