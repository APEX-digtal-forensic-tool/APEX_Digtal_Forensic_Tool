"""Chain of custody domain models."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(slots=True)
class CustodyEvent:
    """Append-only custody event stored as a schema-compatible document."""

    data: dict[str, Any]

    @property
    def event_id(self) -> str:
        return str(self.data["event_id"])

    @property
    def evidence_id(self) -> str:
        return str(self.data["evidence_id"])

    @property
    def immutable_revision(self) -> int:
        return int(self.data["immutable_revision"])

    @property
    def event_hash(self) -> str:
        return str(self.data["event_hash"])

    def to_schema_dict(self) -> dict[str, Any]:
        """Return the stored custody event DTO."""

        return dict(self.data)


@dataclass(slots=True)
class HashVerification:
    """Hash verification history record."""

    data: dict[str, Any]

    def to_schema_dict(self) -> dict[str, Any]:
        """Return a JSON Schema-compatible hash verification DTO."""

        return dict(self.data)
