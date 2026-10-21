"""Signed but malformed issuer output must fail authentication, not crash consumers."""

import time

import pytest
from jose import JWTError, jwt

from apex_backend.auth.jwt_utils import (
    _private_key_pem,
    _public_key_pem,
    decode_refresh_token,
    issue_access_token,
    issue_refresh_token,
)
from apex_backend.auth.jwt_verifier import JwtTokenVerifier
from apex_backend.auth.keys import load_private_key


@pytest.fixture(scope="module")
def keypair():
    return load_private_key()


def malformed(keypair, token_type, field, value):
    key, kid = keypair
    options = {"private_key": key, "kid": kid, "actor_id": "user", "session_id": "session"}
    token = (
        issue_refresh_token(**options)
        if token_type == "refresh"
        else issue_access_token(
            **options,
            tenant_id="tenant",
            allowed_case_ids=["case"],
            roles=["ANALYST"],
            scopes=["apex:read"],
            case_roles={"case": "ANALYST"},
        )
    )
    claims = jwt.get_unverified_claims(token)
    if value == "MISSING":
        claims.pop(field)
    else:
        claims[field] = value
    return jwt.encode(claims, _private_key_pem(key), algorithm="RS256", headers={"kid": kid})


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "field,value",
    [
        ("exp", "MISSING"),
        ("exp", None),
        ("exp", []),
        ("sub", "MISSING"),
        ("session_id", "MISSING"),
        ("tenant_id", []),
        ("scopes", [1]),
        ("scopes", "apex:read"),
        ("allowed_case_ids", 7),
        ("roles", [None]),
        ("case_roles", []),
        ("case_roles", {"case": ["ADMIN"]}),
    ],
)
async def test_access_rejects_invalid_claims_without_raising(keypair, field, value):
    key, kid = keypair
    verifier = JwtTokenVerifier("https://never-request.invalid/jwks")
    verifier._keys = {kid: _public_key_pem(key)}
    verifier._fetched_at = time.monotonic()
    assert await verifier.verify_token(malformed(keypair, "access", field, value)) is None


@pytest.mark.parametrize(
    "field,value",
    [
        ("exp", "MISSING"),
        ("exp", None),
        ("exp", []),
        ("iat", None),
        ("sub", "MISSING"),
        ("session_id", "MISSING"),
        ("session_id", []),
        ("jti", "MISSING"),
        ("jti", ""),
    ],
)
def test_refresh_rejects_missing_or_invalid_claims_as_jwt_error(keypair, field, value):
    key, _ = keypair
    with pytest.raises(JWTError):
        decode_refresh_token(malformed(keypair, "refresh", field, value), _public_key_pem(key))


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "token_type,field,value",
    [
        ("access", "exp", None),
        ("access", "scopes", [1]),
        ("refresh", "session_id", "MISSING"),
        ("refresh", "exp", None),
    ],
)
async def test_http_auth_returns_401_for_invalid_signed_claims(
    keypair, monkeypatch, token_type, field, value
):
    from httpx import ASGITransport, AsyncClient

    from apex_backend import app as backend

    monkeypatch.setattr(backend, "load_private_key", lambda: keypair)
    app = backend.create_app("sqlite+aiosqlite:///:memory:")
    token = malformed(keypair, token_type, field, value)
    async with (
        app.router.lifespan_context(app),
        AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test", trust_env=False
        ) as client,
    ):
        response = (
            await client.post("/auth/refresh", json={"refresh_token": token})
            if token_type == "refresh"
            else await client.post("/auth/logout", headers={"Authorization": f"Bearer {token}"})
        )
    assert response.status_code == 401
