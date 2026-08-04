"""Evidence and hash domain models."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from apex_forensic._time import to_json_timestamp
from apex_forensic.constants import SCHEMA_VERSION
from apex_forensic.domain.enums import EvidenceFormat, EvidenceStatus, HashAlgorithm


@dataclass(slots=True)
class EvidenceFingerprint:
    """A stable file-stream fingerprint used by later analysis phases."""

    algorithm: HashAlgorithm
    value: str
    size_bytes: int
    reader_id: str
    reader_version: str
    created_at: datetime

    def to_schema_dict(self) -> dict[str, Any]:
        """Return a JSON Schema-compatible fingerprint DTO."""

        return {
            "algorithm": self.algorithm.value,
            "value": self.value,
            "size_bytes": self.size_bytes,
            "reader_id": self.reader_id,
            "reader_version": self.reader_version,
            "created_at": to_json_timestamp(self.created_at),
        }


@dataclass(slots=True)
class HashRecord:
    """A persisted hash calculation result."""

    hash_id: str
    evidence_id: str
    algorithm: HashAlgorithm
    digest: str
    calculated_at: datetime
    file_size: int
    chunk_size: int
    verified: bool
    verification_status: str
    bytes_hashed: int
    started_at: datetime
    completed_at: datetime
    job_id: str | None = None

    def to_schema_dict(self) -> dict[str, Any]:
        """Return the EvidenceHash schema projection."""

        verification_status = self.verification_status
        if verification_status == "ERROR":
            verification_status = "MISMATCH"
        return {
            "algorithm": self.algorithm.value,
            "digest_hex": self.digest,
            "scope": "FULL_SOURCE",
            "bytes_hashed": self.bytes_hashed,
            "completed_at": to_json_timestamp(self.completed_at),
            "verification_status": verification_status,
        }


@dataclass(slots=True)
class Evidence:
    """Registered evidence metadata."""

    evidence_id: str
    case_id: str
    display_name: str
    source_path: Path
    evidence_type: EvidenceFormat
    size_bytes: int
    status: EvidenceStatus
    read_only: bool
    fingerprint: EvidenceFingerprint | None
    created_at: datetime
    updated_at: datetime
    schema_version: str = SCHEMA_VERSION
    hashes: list[HashRecord] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_schema_dict(self) -> dict[str, Any]:
        """Return a JSON Schema-compatible Evidence DTO."""

        metadata = dict(self.metadata)
        metadata.setdefault("source_path", str(self.source_path))
        metadata.setdefault("updated_at", to_json_timestamp(self.updated_at))
        return {
            "id": self.evidence_id,
            "case_id": self.case_id,
            "display_name": self.display_name,
            "format": self.evidence_type.value,
            "status": self.status.value,
            "size_bytes": self.size_bytes,
            "sector_size": metadata.get("sector_size"),
            "read_only": self.read_only,
            "acquired_at": None,
            "registered_at": to_json_timestamp(self.created_at),
            "reader": {
                "id": metadata.get("reader_id", "apex.logical_file_reader"),
                "version": metadata.get("reader_version", "0.1.0"),
            },
            "capabilities": metadata.get("capabilities", ["READ_STREAM"]),
            "hashes": [item.to_schema_dict() for item in self.hashes],
            "metadata": metadata,
            "fingerprint": None if self.fingerprint is None else self.fingerprint.to_schema_dict(),
        }


@dataclass(slots=True)
class EvidenceVolume:
    """A bounded addressable volume or unallocated disk-image range."""

    volume_id: str
    case_id: str
    evidence_id: str
    volume_index: int
    scheme: str
    partition_type: str
    start_lba: int
    end_lba: int
    byte_offset: int
    byte_length: int
    sector_size: int
    is_allocated: bool
    raw_locator: dict[str, Any]
    reader_id: str
    reader_version: str
    created_at: datetime
    name: str | None = None
    guid: str | None = None
    warnings: list[dict[str, Any]] = field(default_factory=list)

    def to_schema_dict(self) -> dict[str, Any]:
        """Return a JSON-compatible volume DTO."""

        return {
            "id": self.volume_id,
            "case_id": self.case_id,
            "evidence_id": self.evidence_id,
            "volume_index": self.volume_index,
            "scheme": self.scheme,
            "partition_type": self.partition_type,
            "start_lba": self.start_lba,
            "end_lba": self.end_lba,
            "byte_offset": self.byte_offset,
            "byte_length": self.byte_length,
            "sector_size": self.sector_size,
            "allocated": self.is_allocated,
            "allocation_status": "ALLOCATED" if self.is_allocated else "UNALLOCATED",
            "name": self.name,
            "guid": self.guid,
            "raw_locator": self.raw_locator,
            "reader": {
                "id": self.reader_id,
                "version": self.reader_version,
            },
            "warnings": self.warnings,
            "created_at": to_json_timestamp(self.created_at),
        }
