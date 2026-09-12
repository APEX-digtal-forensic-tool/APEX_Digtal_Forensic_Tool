"""Async SQLAlchemy engine and session factory."""

from __future__ import annotations

from collections.abc import AsyncGenerator
from typing import Any

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    """Shared declarative base for all ORM models."""


def build_engine(database_url: str, **kwargs: Any) -> AsyncEngine:
    """Create an async engine from *database_url*.

    Pass ``echo=True`` during development to log SQL statements.
    """
    return create_async_engine(database_url, **kwargs)


def build_session_factory(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    """Return a session factory bound to *engine*."""
    return async_sessionmaker(engine, expire_on_commit=False)


async def get_session(
    session_factory: async_sessionmaker[AsyncSession],
) -> AsyncGenerator[AsyncSession, None]:
    """Yield a single :class:`AsyncSession` and close it when done."""
    async with session_factory() as session:
        yield session


__all__ = [
    "Base",
    "build_engine",
    "build_session_factory",
    "get_session",
]
