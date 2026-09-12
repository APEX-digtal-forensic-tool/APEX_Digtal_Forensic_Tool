"""FastAPI application factory for apex_backend."""

from __future__ import annotations

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from apex_backend.auth.keys import load_private_key, public_key_to_jwk
from apex_backend.auth.router import _get_auth_service, _get_db
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
    app.dependency_overrides[_get_auth_service] = lambda: auth_service

    app.include_router(auth_router)

    @app.get("/.well-known/jwks.json", tags=["auth"])
    async def jwks() -> dict[str, Any]:
        """Return RSA public key in JWKS format for token verification."""
        return jwks_data

    return app


__all__ = ["create_app"]
