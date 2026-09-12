"""JwtTokenVerifier: JWKS-backed RS256 token verifier for MCP server."""

from __future__ import annotations

import asyncio
import base64
import time
from typing import Any

import httpx
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from jose import JWTError
from jose import jwt as jose_jwt
from mcp.server.auth.provider import AccessToken

from apex_backend.auth.jwt_utils import ALGORITHM, AUDIENCE, ISSUER


class JwtTokenVerifier:
    """Verify RS256 JWTs against a JWKS endpoint.

    Caches public keys for *cache_ttl_seconds* before re-fetching.
    Returns None on any verification failure — never raises.
    """

    def __init__(
        self,
        jwks_uri: str,
        issuer: str = ISSUER,
        audience: str = AUDIENCE,
        *,
        cache_ttl_seconds: int = 300,
    ) -> None:
        self._jwks_uri = jwks_uri
        self._issuer = issuer
        self._audience = audience
        self._cache_ttl = cache_ttl_seconds
        self._keys: dict[str, str] = {}  # kid → PEM public key
        self._fetched_at: float = 0.0
        self._lock = asyncio.Lock()

    async def verify_token(self, token: str) -> AccessToken | None:
        """Return AccessToken if valid RS256 JWT, else None."""
        try:
            header = jose_jwt.get_unverified_header(token)
        except JWTError:
            return None

        kid: str | None = header.get("kid")
        public_key_pem = await self._resolve_key(kid)
        if public_key_pem is None:
            return None

        try:
            claims: dict[str, Any] = jose_jwt.decode(
                token,
                public_key_pem,
                algorithms=[ALGORITHM],
                audience=self._audience,
                issuer=self._issuer,
            )
        except JWTError:
            return None

        if claims.get("token_type") != "access":
            return None

        scopes_raw = claims.get("scopes", [])
        scopes: list[str] = scopes_raw if isinstance(scopes_raw, list) else []

        return AccessToken(
            token=token,
            client_id=str(claims.get("iss", "")),
            scopes=scopes,
            expires_at=int(claims["exp"]) if "exp" in claims else None,
            resource=str(claims["aud"]) if isinstance(claims.get("aud"), str) else None,
            subject=claims.get("sub"),
            claims=claims,
        )

    async def _resolve_key(self, kid: str | None) -> str | None:
        """Return PEM for *kid*, fetching JWKS if stale or key absent."""
        async with self._lock:
            now = time.monotonic()
            stale = (now - self._fetched_at) > self._cache_ttl
            if stale or (kid is not None and kid not in self._keys):
                await self._fetch_jwks()
            if kid is not None:
                return self._keys.get(kid)
            if self._keys:
                return next(iter(self._keys.values()))
            return None

    async def _fetch_jwks(self) -> None:
        """Fetch JWKS and populate *_keys* cache. Silently no-ops on error."""
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(self._jwks_uri)
                resp.raise_for_status()
                body = resp.json()
        except Exception:
            return

        new_keys: dict[str, str] = {}
        for jwk in body.get("keys", []):
            try:
                pem = _jwk_to_pem(jwk)
                new_keys[jwk["kid"]] = pem
            except Exception:
                continue

        self._keys = new_keys
        self._fetched_at = time.monotonic()


def _b64url_to_int(value: str) -> int:
    padded = value + "=" * (-len(value) % 4)
    return int.from_bytes(base64.urlsafe_b64decode(padded), "big")


def _jwk_to_pem(jwk: dict[str, Any]) -> str:
    from cryptography.hazmat.primitives import serialization

    n = _b64url_to_int(jwk["n"])
    e = _b64url_to_int(jwk["e"])
    pub: RSAPublicKey = rsa.RSAPublicNumbers(e, n).public_key()
    return pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()


__all__ = ["JwtTokenVerifier"]
