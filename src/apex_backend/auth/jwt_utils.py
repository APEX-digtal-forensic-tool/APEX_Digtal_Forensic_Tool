"""JWT encode/decode helpers using python-jose with RS256."""

from __future__ import annotations

import os
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from jose import JWTError, jwt

ISSUER = os.environ.get("APEX_ISSUER", "https://apex.local")
AUDIENCE = os.environ.get("APEX_MCP_RESOURCE", "https://apex.local/mcp")

ACCESS_TOKEN_TTL_SECONDS = int(os.environ.get("APEX_ACCESS_TOKEN_TTL", "3600"))
REFRESH_TOKEN_TTL_SECONDS = int(os.environ.get("APEX_REFRESH_TOKEN_TTL", "86400"))

ALGORITHM = "RS256"


def _private_key_pem(private_key: RSAPrivateKey) -> str:
    from cryptography.hazmat.primitives import serialization

    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()


def _public_key_pem(private_key: RSAPrivateKey) -> str:
    from cryptography.hazmat.primitives import serialization

    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()


def issue_access_token(
    *,
    private_key: RSAPrivateKey,
    kid: str,
    actor_id: str,
    session_id: str,
    tenant_id: str,
    allowed_case_ids: list[str],
    roles: list[str],
    scopes: list[str],
) -> str:
    """Issue a signed RS256 access JWT."""
    now = datetime.now(UTC)
    payload: dict[str, Any] = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": actor_id,
        "jti": str(uuid.uuid4()),
        "iat": now,
        "exp": now + timedelta(seconds=ACCESS_TOKEN_TTL_SECONDS),
        "session_id": session_id,
        "tenant_id": tenant_id,
        "allowed_case_ids": allowed_case_ids,
        "roles": roles,
        "scopes": scopes,
        "token_type": "access",
    }
    encoded = jwt.encode(
        payload, _private_key_pem(private_key), algorithm=ALGORITHM, headers={"kid": kid}
    )
    return str(encoded)


def issue_refresh_token(
    *,
    private_key: RSAPrivateKey,
    kid: str,
    actor_id: str,
    session_id: str,
) -> str:
    """Issue a signed RS256 refresh JWT tied to *session_id*."""
    now = datetime.now(UTC)
    payload: dict[str, Any] = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": actor_id,
        "jti": str(uuid.uuid4()),
        "iat": now,
        "exp": now + timedelta(seconds=REFRESH_TOKEN_TTL_SECONDS),
        "session_id": session_id,
        "token_type": "refresh",
    }
    encoded = jwt.encode(
        payload, _private_key_pem(private_key), algorithm=ALGORITHM, headers={"kid": kid}
    )
    return str(encoded)


def decode_refresh_token(token: str, public_key_pem: str) -> dict[str, Any]:
    """Decode and validate a refresh token. Raises JWTError on failure."""
    claims: dict[str, Any] = jwt.decode(
        token,
        public_key_pem,
        algorithms=[ALGORITHM],
        audience=AUDIENCE,
        issuer=ISSUER,
        options={"require_aud": True},
    )
    if claims.get("token_type") != "refresh":
        raise JWTError("Not a refresh token.")
    return claims


__all__ = [
    "ALGORITHM",
    "AUDIENCE",
    "ISSUER",
    "decode_refresh_token",
    "issue_access_token",
    "issue_refresh_token",
]
