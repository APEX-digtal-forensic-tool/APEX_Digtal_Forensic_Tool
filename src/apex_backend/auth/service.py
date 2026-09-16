"""AuthService: login, token issuance, refresh, and logout logic."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from jose import JWTError
from passlib.context import CryptContext
from sqlalchemy import select, update
from sqlalchemy.engine import CursorResult
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

        refresh_jti = str(uuid.uuid4())
        session = UserSession(
            session_id=str(uuid.uuid4()),
            actor_id=user.id,
            tenant_id=tenant_id,
            created_at=datetime.now(UTC),
            expires_at=datetime.now(UTC) + timedelta(seconds=jwt_utils.REFRESH_TOKEN_TTL_SECONDS),
            current_refresh_jti=refresh_jti,
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
            jti=refresh_jti,
        )
        return access, refresh

    async def refresh(self, db: AsyncSession, *, refresh_token: str) -> tuple[str, str]:
        """Validate refresh token, rotate jti, return new token pair.

        Raises AuthError on any failure. Reuse of an already-rotated token
        triggers session-wide forced logout (revoked_at set).
        """
        try:
            claims = jwt_utils.decode_refresh_token(refresh_token, self._public_key_pem)
        except JWTError as exc:
            raise AuthError(f"Invalid refresh token: {exc}") from exc

        session_id: str = claims["session_id"]
        actor_id: str = claims["sub"]
        incoming_jti: str = claims["jti"]
        new_jti = str(uuid.uuid4())

        # Atomic rotation: only update if the stored jti still matches.
        result: CursorResult[tuple[()]] = await db.execute(  # type: ignore[assignment]
            update(UserSession)
            .where(
                UserSession.session_id == session_id,
                UserSession.current_refresh_jti == incoming_jti,
                UserSession.revoked_at.is_(None),
            )
            .values(current_refresh_jti=new_jti)
        )
        await db.commit()

        if result.rowcount == 0:
            # Fresh select to avoid SQLAlchemy identity-map cache.
            session = (
                await db.execute(select(UserSession).where(UserSession.session_id == session_id))
            ).scalar_one_or_none()

            if session is None or not session.is_active:
                raise AuthError("Session revoked or not found.")

            # NULL jti means session was created before rotation was deployed.
            if session.current_refresh_jti is None:
                raise AuthError("Session requires re-login after server upgrade.")

            # Non-null jti mismatch — token reuse detected, revoke entire session.
            session.revoked_at = datetime.now(UTC)
            await db.commit()
            raise AuthError("Refresh token reuse detected. Session revoked.")

        # Rotation succeeded — fetch session for metadata.
        session = (
            await db.execute(select(UserSession).where(UserSession.session_id == session_id))
        ).scalar_one_or_none()
        if session is None:
            raise AuthError("Session not found after rotation.")

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
            jti=new_jti,
        )
        return access, new_refresh

    async def logout(self, db: AsyncSession, *, session_id: str) -> None:
        """Revoke the session identified by *session_id*.

        Idempotent: silently succeeds if already revoked or not found.
        """
        session = (
            await db.execute(select(UserSession).where(UserSession.session_id == session_id))
        ).scalar_one_or_none()
        if session is not None and session.is_active:
            session.revoked_at = datetime.now(UTC)
            await db.commit()

    @staticmethod
    async def _fetch_user(
        db: AsyncSession, *, email: str, tenant_id: str
    ) -> User | None:
        result = await db.execute(
            select(User).where(User.email == email, User.tenant_id == tenant_id)
        )
        user: User | None = result.scalar_one_or_none()
        return user


__all__ = ["AuthError", "AuthService", "hash_password", "verify_password"]
