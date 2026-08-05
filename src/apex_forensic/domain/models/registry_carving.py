"""Registry binary deleted-cell carving DTOs."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True, slots=True)
class RegistryDeletedCellCandidate:
    """One candidate carved from a free cell or HBIN slack region."""

    candidate_type: str
    source_region: str
    absolute_offset: int
    length: int
    hbin_offset: int
    confidence: str
    reasons: tuple[str, ...]
    name: str | None = None
    value_type: str | None = None
    value_data: Any = None
    data_reference_offset: int | None = None
    parent_cell_offset: int | None = None
    partial: bool = True
    overwritten: bool = False
    raw_name_hex: str | None = None

    def to_schema_dict(self) -> dict[str, Any]:
        return {
            "candidate_type": self.candidate_type,
            "source_region": self.source_region,
            "absolute_offset": self.absolute_offset,
            "length": self.length,
            "hbin_offset": self.hbin_offset,
            "confidence": self.confidence,
            "reasons": list(self.reasons),
            "name": self.name,
            "value_type": self.value_type,
            "value_data": self.value_data,
            "data_reference_offset": self.data_reference_offset,
            "parent_cell_offset": self.parent_cell_offset,
            "partial": self.partial,
            "overwritten": self.overwritten,
            "raw_name_hex": self.raw_name_hex,
        }


@dataclass(frozen=True, slots=True)
class RegistryCarvingReport:
    """Result metadata for one hive carving pass."""

    provider_id: str
    provider_version: str
    status: str
    candidates: tuple[RegistryDeletedCellCandidate, ...] = ()
    warnings: tuple[dict[str, Any], ...] = ()
    coverage: dict[str, Any] = field(default_factory=dict)

    def to_schema_dict(self) -> dict[str, Any]:
        return {
            "provider_id": self.provider_id,
            "provider_version": self.provider_version,
            "status": self.status,
            "candidates": [item.to_schema_dict() for item in self.candidates],
            "warnings": list(self.warnings),
            "coverage": self.coverage,
        }
