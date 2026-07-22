"""Case domain model."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from apex_forensic._time import to_json_timestamp
from apex_forensic.constants import ENGINE_VERSION, SCHEMA_VERSION
from apex_forensic.domain.enums import CaseStatus


@dataclass(slots=True)
class Case:
    """A forensic case aggregate."""

    case_id: str
    name: str
    description: str | None
    investigator: str | None
    locale: str
    timezone: str
    status: CaseStatus
    created_at: datetime
    updated_at: datetime
    schema_version: str = SCHEMA_VERSION
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_schema_dict(self) -> dict[str, Any]:
        """Return a JSON Schema-compatible Case DTO."""

        metadata = dict(self.metadata)
        if self.investigator is not None:
            metadata.setdefault("investigator", self.investigator)
        metadata.setdefault("updated_at", to_json_timestamp(self.updated_at))
        metadata.setdefault("domain_case_id", self.case_id)
        return {
            "id": self.case_id,
            "name": self.name,
            "description": self.description,
            "status": self.status.value,
            "locale": self.locale,
            "timezone": self.timezone,
            "created_at": to_json_timestamp(self.created_at),
            "created_by": self.investigator,
            "closed_at": None,
            "engine_version": ENGINE_VERSION,
            "metadata": metadata,
            "timezone_decision_id": None,
        }
