"""JwtTokenVerifier: JWKS-backed RS256 token verifier for MCP server."""

from __future__ import annotations

import asyncio
import base64
import logging
import time
from typing import Any

import httpx
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from jose import JWTError
from jose import jwt as jose_jwt
from mcp.server.auth.provider import AccessToken

from apex_backend.auth.jwt_utils import ALGORITHM, AUDIENCE, ISSUER

_logger = logging.getLogger(__name__)


_KID_MAX_LEN = 128
# Minimum seconds between JWKS re-fetches triggered by an unknown kid.
# Prevents an attacker from hammering the JWKS endpoint with crafted tokens.
_UNKNOWN_KID_COOLDOWN = 10.0


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
        self._unknown_kid_fetched_at: float = 0.0
        self._lock = asyncio.Lock()

    async def verify_token(self, token: str) -> AccessToken | None:
        """Return AccessToken if valid RS256 JWT, else None.

        Any malformed header (non-dict, wrong alg, non-string kid, oversized kid)
        is treated as a verification failure and returns None without raising.
        """
        try:
            header = jose_jwt.get_unverified_header(token)
        except JWTError:
            return None

        # Validate header shape before touching any field.
        if not isinstance(header, dict):
            return None
        if header.get("alg") != ALGORITHM:
            return None
        kid = header.get("kid")
        if kid is not None and (not isinstance(kid, str) or len(kid) > _KID_MAX_LEN):
            return None

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
        """Return PEM for *kid*, fetching JWKS if stale or key absent.

        For unknown-kid triggered re-fetches a cooldown of _UNKNOWN_KID_COOLDOWN
        seconds is enforced so that crafted tokens cannot hammer the JWKS endpoint.
        Normal key-rotation re-fetches (stale cache) are unaffected by the cooldown.
        """
        async with self._lock:
            now = time.monotonic()
            stale = (now - self._fetched_at) > self._cache_ttl
            unknown_kid = kid is not None and kid not in self._keys
            cooldown_elapsed = (now - self._unknown_kid_fetched_at) > _UNKNOWN_KID_COOLDOWN
            if stale or (unknown_kid and cooldown_elapsed):
                await self._fetch_jwks()
                if unknown_kid:
                    self._unknown_kid_fetched_at = now
            if kid is not None:
                return self._keys.get(kid)
            if self._keys:
                return next(iter(self._keys.values()))
            return None

    async def _fetch_jwks(self) -> None:
        """Fetch JWKS and populate *_keys* cache. Logs on error, no-ops otherwise."""
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(self._jwks_uri)
                resp.raise_for_status()
                body = resp.json()
        except Exception:
            if self._keys:
                _logger.warning(
                    "JWKS fetch failed for %s; continuing with %d cached key(s)",
                    self._jwks_uri,
                    len(self._keys),
                    exc_info=True,
                )
            else:
                _logger.warning(
                    "JWKS fetch failed for %s; no cached keys — all tokens will be rejected",
                    self._jwks_uri,
                    exc_info=True,
                )
            return

        new_keys: dict[str, str] = {}
        for jwk in body.get("keys", []):
            try:
                pem = _jwk_to_pem(jwk)
                new_keys[jwk["kid"]] = pem
            except Exception:
                _logger.warning(
                    "Failed to parse JWK kid=%r from %s; skipping",
                    jwk.get("kid"),
                    self._jwks_uri,
                    exc_info=True,
                )
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
