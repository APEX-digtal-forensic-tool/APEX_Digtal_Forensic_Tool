"""Identifier generator port."""

from __future__ import annotations

from typing import Protocol


class IdGenerator(Protocol):
    """Generates stable external identifiers."""

    def new_id(self) -> str:
        """Return a new UUID string."""
        ...
