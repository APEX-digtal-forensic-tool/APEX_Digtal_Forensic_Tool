"""FastAPI application factory for apex_backend."""

from __future__ import annotations

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from apex_backend.auth.confirmation_router import _get_db as _conf_get_db
from apex_backend.auth.confirmation_router import _get_jwt_verifier as _conf_get_jwt_verifier
from apex_backend.auth.confirmation_router import router as confirmation_router
from apex_backend.auth.jwt_utils import AUDIENCE, ISSUER
from apex_backend.auth.jwt_verifier import JwtTokenVerifier
from apex_backend.auth.keys import load_private_key, public_key_to_jwk
from apex_backend.auth.router import _get_auth_service, _get_db, _get_jwt_verifier
from apex_backend.auth.router import router as auth_router
from apex_backend.auth.service import AuthService
from apex_backend.database import Base


def create_app(database_url: str) -> FastAPI:
    """Create and configure the FastAPI application.

    Args:
        database_url: Async SQLAlchemy URL
            e.g. ``postgresql+asyncpg://user:pass@host/db``
    """
    engine = create_async_engine(database_url)
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    private_key, kid = load_private_key()
    auth_service = AuthService(private_key=private_key, kid=kid)
    jwks_data: dict[str, Any] = {
        "keys": [public_key_to_jwk(private_key.public_key(), kid)]
    }
    jwks_uri = f"{ISSUER}/.well-known/jwks.json"
    jwt_verifier = JwtTokenVerifier(jwks_uri=jwks_uri, issuer=ISSUER, audience=AUDIENCE)
    # Pre-populate verifier cache with the local key (avoids network call in tests).
    from apex_backend.auth.jwt_verifier import _jwk_to_pem
    jwt_verifier._keys = {kid: _jwk_to_pem(jwks_data["keys"][0])}
    import time as _time
    jwt_verifier._fetched_at = _time.monotonic()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        yield
        await engine.dispose()

    app = FastAPI(title="APEX Backend", lifespan=lifespan)

    async def _db_dep() -> AsyncGenerator[AsyncSession, None]:
        async with session_factory() as session:
            yield session

    app.dependency_overrides[_get_db] = _db_dep
    app.dependency_overrides[_conf_get_db] = _db_dep
    app.dependency_overrides[_get_auth_service] = lambda: auth_service
    app.dependency_overrides[_get_jwt_verifier] = lambda: jwt_verifier
    app.dependency_overrides[_conf_get_jwt_verifier] = lambda: jwt_verifier

    app.include_router(auth_router)
    app.include_router(confirmation_router)

    @app.get("/.well-known/jwks.json", tags=["auth"])
    async def jwks() -> dict[str, Any]:
        """Return RSA public key in JWKS format for token verification."""
        return jwks_data

    return app


__all__ = ["create_app"]
