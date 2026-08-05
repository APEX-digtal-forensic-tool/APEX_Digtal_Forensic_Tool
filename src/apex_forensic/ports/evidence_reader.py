"""Evidence reader port for disk image and raw stream access."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from types import TracebackType
from typing import Any, Protocol, Self

from apex_forensic.domain.enums import EvidenceFormat
from apex_forensic.domain.models import EvidenceVolume

MAX_EVIDENCE_READ_SIZE = 16 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class EvidenceReaderCapabilityStatement:
    """One structured capability claim for a reader implementation."""

    capability: str
    status: str
    reason: str | None = None
    details: dict[str, Any] = field(default_factory=dict)

    def to_schema_dict(self) -> dict[str, Any]:
        return {
            "capability": self.capability,
            "status": self.status,
            "reason": self.reason,
            "details": self.details,
        }


@dataclass(frozen=True, slots=True)
class EvidenceProbeResult:
    """Read-only probe result for selecting an evidence reader."""

    reader_id: str
    reader_version: str
    evidence_format: EvidenceFormat
    supported: bool
    sector_size: int | None
    capabilities: tuple[EvidenceReaderCapabilityStatement, ...]
    warnings: tuple[dict[str, Any], ...] = ()
    unavailable_reason: str | None = None

    def to_schema_dict(self) -> dict[str, Any]:
        return {
            "reader": {"id": self.reader_id, "version": self.reader_version},
            "format": self.evidence_format.value,
            "supported": self.supported,
            "sector_size": self.sector_size,
            "capabilities": [item.to_schema_dict() for item in self.capabilities],
            "warnings": list(self.warnings),
            "unavailable_reason": self.unavailable_reason,
        }


class EvidenceReader(Protocol):
    """Read-only random access reader contract for evidence byte streams."""

    reader_id: str
    reader_version: str

    @classmethod
    def probe(cls, path: Path) -> EvidenceProbeResult:
        """Return support and capability information without mutating evidence."""
        ...

    def open_readonly(self) -> Self:
        """Open the underlying stream in read-only mode."""
        ...

    @property
    def size(self) -> int:
        """Logical stream size in bytes."""
        ...

    @property
    def sector_size(self) -> int:
        """Logical sector size in bytes."""
        ...

    @property
    def source_fingerprint(self) -> dict[str, Any]:
        """Stable fingerprint of the source stream."""
        ...

    def capabilities(self) -> tuple[EvidenceReaderCapabilityStatement, ...]:
        """Return structured capability claims."""
        ...

    def volumes(self, *, case_id: str, evidence_id: str) -> list[EvidenceVolume]:
        """Enumerate partitions or superfloppy ranges when supported."""
        ...

    def read_at(self, offset: int, length: int) -> bytes:
        """Return a bounded byte range using EOF-short-read policy."""
        ...

    def close(self) -> None:
        """Close the reader. Multiple calls must be safe."""
        ...

    def __enter__(self) -> Self:
        """Open and return this reader."""
        ...

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """Close the reader."""
        ...
