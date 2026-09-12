"""AuthService: login, token issuance, and refresh logic."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from jose import JWTError
from passlib.context import CryptContext
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from apex_backend.auth import jwt_utils
from apex_backend.auth.scopes import scopes_for_roles
from apex_backend.models import CaseTenancy, User, UserSession

_pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(plain: str) -> str:
    """Return bcrypt hash of *plain*."""
    return str(_pwd_context.hash(plain))


def verify_password(plain: str, hashed: str) -> bool:
    """Return True if *plain* matches *hashed*."""
    return bool(_pwd_context.verify(plain, hashed))


class AuthError(Exception):
    """Raised for invalid credentials or revoked sessions."""


class AuthService:
    """Stateless service; receives session and key material per call."""

    def __init__(self, private_key: RSAPrivateKey, kid: str) -> None:
        self._private_key = private_key
        self._kid = kid
        self._public_key_pem = self._extract_public_key_pem()

    def _extract_public_key_pem(self) -> str:
        from cryptography.hazmat.primitives import serialization

        return self._private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()

    async def login(
        self, db: AsyncSession, *, email: str, password: str, tenant_id: str
    ) -> tuple[str, str]:
        """Authenticate user and return (access_token, refresh_token).

        Raises AuthError on bad credentials.
        """
        user = await self._fetch_user(db, email=email, tenant_id=tenant_id)
        if user is None or not verify_password(password, user.hashed_password):
            raise AuthError("Invalid credentials.")
        if not user.is_active:
            raise AuthError("Account inactive.")

        tenancies = (
            await db.execute(
                select(CaseTenancy).where(CaseTenancy.actor_id == user.id)
            )
        ).scalars().all()

        allowed_case_ids = [t.case_id for t in tenancies]
        roles = list({t.role for t in tenancies})
        scopes = sorted(scopes_for_roles(frozenset(roles)))

        session = UserSession(
            session_id=str(uuid.uuid4()),
            actor_id=user.id,
            tenant_id=tenant_id,
            created_at=datetime.now(UTC),
            expires_at=datetime.now(UTC) + timedelta(seconds=jwt_utils.REFRESH_TOKEN_TTL_SECONDS),
        )
        db.add(session)
        await db.commit()

        access = jwt_utils.issue_access_token(
            private_key=self._private_key,
            kid=self._kid,
            actor_id=user.id,
            session_id=session.session_id,
            tenant_id=tenant_id,
            allowed_case_ids=allowed_case_ids,
            roles=roles,
            scopes=scopes,
        )
        refresh = jwt_utils.issue_refresh_token(
            private_key=self._private_key,
            kid=self._kid,
            actor_id=user.id,
            session_id=session.session_id,
        )
        return access, refresh

    async def refresh(self, db: AsyncSession, *, refresh_token: str) -> tuple[str, str]:
        """Validate refresh token, check session liveness, return new token pair.

        Raises AuthError on failure.
        """
        try:
            claims = jwt_utils.decode_refresh_token(refresh_token, self._public_key_pem)
        except JWTError as exc:
            raise AuthError(f"Invalid refresh token: {exc}") from exc

        session_id: str = claims["session_id"]
        actor_id: str = claims["sub"]

        session = await db.get(UserSession, session_id)
        if session is None or not session.is_active:
            raise AuthError("Session revoked or not found.")
        now = datetime.now(UTC)
        expires_at = session.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=UTC)
        if expires_at <= now:
            raise AuthError("Session expired.")

        tenancies = (
            await db.execute(
                select(CaseTenancy).where(CaseTenancy.actor_id == actor_id)
            )
        ).scalars().all()

        allowed_case_ids = [t.case_id for t in tenancies]
        roles = list({t.role for t in tenancies})
        scopes = sorted(scopes_for_roles(frozenset(roles)))

        access = jwt_utils.issue_access_token(
            private_key=self._private_key,
            kid=self._kid,
            actor_id=actor_id,
            session_id=session_id,
            tenant_id=session.tenant_id,
            allowed_case_ids=allowed_case_ids,
            roles=roles,
            scopes=scopes,
        )
        new_refresh = jwt_utils.issue_refresh_token(
            private_key=self._private_key,
            kid=self._kid,
            actor_id=actor_id,
            session_id=session_id,
        )
        return access, new_refresh

    @staticmethod
    async def _fetch_user(
        db: AsyncSession, *, email: str, tenant_id: str
    ) -> User | None:
        result = await db.execute(
            select(User).where(User.email == email, User.tenant_id == tenant_id)
        )
        return result.scalar_one_or_none()


__all__ = ["AuthError", "AuthService", "hash_password", "verify_password"]
