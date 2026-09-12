"""RSA key management for RS256 JWT signing.

Keys are loaded from environment variables or generated on first use.
Set APEX_RS256_PRIVATE_KEY_PEM to a PEM-encoded RSA private key for
production deployments. In development, a key is auto-generated in memory.
"""

from __future__ import annotations

import base64
import os
import uuid

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey


def _generate_rsa_key() -> RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def load_private_key() -> tuple[RSAPrivateKey, str]:
    """Return (private_key, kid).

    Reads APEX_RS256_PRIVATE_KEY_PEM + APEX_RS256_KID from env.
    Falls back to auto-generated key with a random kid.
    """
    pem = os.environ.get("APEX_RS256_PRIVATE_KEY_PEM", "").strip()
    kid = os.environ.get("APEX_RS256_KID", "").strip()

    if pem:
        private_key = serialization.load_pem_private_key(pem.encode(), password=None)
        if not isinstance(private_key, RSAPrivateKey):
            raise ValueError("APEX_RS256_PRIVATE_KEY_PEM must be an RSA private key.")
        return private_key, kid or str(uuid.uuid4())

    private_key = _generate_rsa_key()
    return private_key, kid or str(uuid.uuid4())


def _int_to_base64url(n: int) -> str:
    length = (n.bit_length() + 7) // 8
    return base64.urlsafe_b64encode(n.to_bytes(length, "big")).rstrip(b"=").decode()


def public_key_to_jwk(public_key: RSAPublicKey, kid: str) -> dict[str, str]:
    """Serialize RSA public key as a JWK dict (RFC 7517)."""
    pub_numbers = public_key.public_numbers()
    return {
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": kid,
        "n": _int_to_base64url(pub_numbers.n),
        "e": _int_to_base64url(pub_numbers.e),
    }


__all__ = ["load_private_key", "public_key_to_jwk"]
