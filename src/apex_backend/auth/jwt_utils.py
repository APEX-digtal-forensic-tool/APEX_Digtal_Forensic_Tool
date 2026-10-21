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
    case_roles: dict[str, str] | None = None,
) -> str:
    """Issue a signed RS256 access JWT.

    *case_roles* maps each case_id to the actor's role in that case.
    When provided, recipients can enforce per-case role boundaries (A04).
    Tokens without case_roles are legacy tokens; FrontendAuthorizationGate
    rejects them for any role-gated tool as a secure default.
    """
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
    if case_roles is not None:
        payload["case_roles"] = case_roles
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
    jti: str | None = None,
) -> str:
    """Issue a signed RS256 refresh JWT tied to *session_id*.

    *jti* allows the caller to supply the UUID that is already stored in DB,
    so the token and DB row stay in sync for rotation tracking.
    """
    now = datetime.now(UTC)
    payload: dict[str, Any] = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": actor_id,
        "jti": jti if jti is not None else str(uuid.uuid4()),
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
    try:
        claims: dict[str, Any] = jwt.decode(
            token,
            public_key_pem,
            algorithms=[ALGORITHM],
            audience=AUDIENCE,
            issuer=ISSUER,
            options={"require_aud": True, "require_exp": True},
        )
        validate_token_claims(claims, token_type="refresh")
    except (TypeError, ValueError, OverflowError) as exc:
        # python-jose may leak conversion errors for null/compound NumericDates.
        raise JWTError("Invalid refresh token claims.") from exc
    return claims


def validate_token_claims(claims: dict[str, Any], *, token_type: str) -> None:
    """Validate issuer contract before auth/MCP consumers use typed claims.

    Signature, issuer, audience and time validity are checked by jwt.decode.
    This also requires expiry and session identity; python-jose otherwise accepts
    missing claims and does not type-check our custom authorization fields.
    """
    if claims.get("token_type") != token_type:
        raise JWTError("Unexpected token type.")
    for field in ("sub", "session_id", "jti"):
        value = claims.get(field)
        if not isinstance(value, str) or not value.strip():
            raise JWTError(f"Invalid {field} claim.")
    for field in ("iat", "exp"):
        if type(claims.get(field)) is not int:
            raise JWTError(f"Invalid {field} claim.")
    if token_type != "access":
        return
    tenant = claims.get("tenant_id")
    if not isinstance(tenant, str) or not tenant.strip():
        raise JWTError("Invalid tenant_id claim.")
    for field in ("scopes", "roles", "allowed_case_ids"):
        values = claims.get(field)
        if not isinstance(values, list) or any(
            not isinstance(value, str) or not value.strip() for value in values
        ):
            raise JWTError(f"Invalid {field} claim.")
    # Legacy tokens may omit case_roles; the authorization gate denies role-gated
    # tools for those tokens. Malformed maps must never reach that gate.
    if "case_roles" in claims:
        roles = claims["case_roles"]
        if not isinstance(roles, dict) or any(
            not isinstance(case, str) or not case.strip()
            or not isinstance(role, str) or not role.strip()
            for case, role in roles.items()
        ):
            raise JWTError("Invalid case_roles claim.")


__all__ = [
    "ALGORITHM",
    "AUDIENCE",
    "ISSUER",
    "decode_refresh_token",
    "issue_access_token",
    "issue_refresh_token",
]
