"""Async and sync SQLAlchemy engine and session factories."""

from __future__ import annotations

from collections.abc import AsyncGenerator
from typing import Any

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker


class Base(DeclarativeBase):
    """Shared declarative base for all ORM models."""


def build_engine(database_url: str, **kwargs: Any) -> AsyncEngine:
    """Create an async engine from *database_url*."""
    return create_async_engine(database_url, **kwargs)


def build_session_factory(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    """Return an async session factory bound to *engine*."""
    return async_sessionmaker(engine, expire_on_commit=False)


async def get_session(
    session_factory: async_sessionmaker[AsyncSession],
) -> AsyncGenerator[AsyncSession, None]:
    """Yield a single :class:`AsyncSession` and close it when done."""
    async with session_factory() as session:
        yield session


def build_sync_engine(database_url: str, **kwargs: Any) -> Engine:
    """Create a sync engine from *database_url*.

    Strip async driver prefixes so the URL works with a sync driver:
    ``postgresql+asyncpg://`` → ``postgresql+psycopg2://``
    ``sqlite+aiosqlite://`` → ``sqlite://``
    """
    sync_url = (
        database_url.replace("postgresql+asyncpg://", "postgresql+psycopg2://")
        .replace("sqlite+aiosqlite://", "sqlite://")
    )
    return create_engine(sync_url, **kwargs)


def build_sync_session_factory(engine: Engine) -> sessionmaker[Session]:
    """Return a sync session factory bound to *engine*."""
    return sessionmaker(engine, expire_on_commit=False)


__all__ = [
    "Base",
    "build_engine",
    "build_session_factory",
    "build_sync_engine",
    "build_sync_session_factory",
    "get_session",
]
