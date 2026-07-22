"""File system indexing domain models."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from apex_forensic._time import to_json_timestamp
from apex_forensic.domain.enums import (
    AnalysisProfileType,
    FileSystemNodeType,
    IndexCoverageStatus,
)


def _json_timestamp_map(values: dict[str, datetime | None]) -> dict[str, str | None]:
    return {
        key: None if value is None else to_json_timestamp(value) for key, value in values.items()
    }


@dataclass(slots=True)
class FileSystemNode:
    """A provider-neutral metadata node in an evidence file tree."""

    node_id: str
    case_id: str
    evidence_id: str
    provider_id: str
    provider_version: str
    parent_node_id: str | None
    original_name: str
    original_relative_path: str
    display_path: str
    comparison_path: str
    node_type: FileSystemNodeType
    file_size: int | None
    extension: str | None
    mime_candidate: str | None
    mime_confidence: str
    fs_metadata: dict[str, Any]
    platform: str
    timestamp_meanings: dict[str, str]
    raw_timestamps: dict[str, Any]
    utc_timestamps: dict[str, datetime | None]
    timestamp_sources: dict[str, str]
    is_deleted: bool
    is_readable: bool
    is_link: bool
    is_traversed: bool
    raw_locator: dict[str, Any]
    provider_metadata: dict[str, Any]
    is_partial: bool
    index_revision: int
    created_at: datetime
    updated_at: datetime

    @property
    def is_directory_like(self) -> bool:
        """Return whether this node can have children in Phase 2."""

        return self.node_type in {FileSystemNodeType.ROOT, FileSystemNodeType.DIRECTORY}

    def to_schema_dict(self) -> dict[str, Any]:
        """Return the Phase 2 File System Node DTO."""

        return {
            "id": self.node_id,
            "case_id": self.case_id,
            "evidence_id": self.evidence_id,
            "filesystem_provider": {
                "id": self.provider_id,
                "version": self.provider_version,
            },
            "parent_node_id": self.parent_node_id,
            "original_name": self.original_name,
            "original_relative_path": self.original_relative_path,
            "display_path": self.display_path,
            "comparison_path": self.comparison_path,
            "node_type": self.node_type.value,
            "file_size": self.file_size,
            "extension": self.extension,
            "mime_candidate": self.mime_candidate,
            "mime_confidence": self.mime_confidence,
            "fs_metadata": self.fs_metadata,
            "platform": self.platform,
            "timestamp_meanings": self.timestamp_meanings,
            "raw_timestamps": self.raw_timestamps,
            "utc_timestamps": _json_timestamp_map(self.utc_timestamps),
            "timestamp_sources": self.timestamp_sources,
            "is_deleted": self.is_deleted,
            "is_readable": self.is_readable,
            "is_link": self.is_link,
            "is_traversed": self.is_traversed,
            "raw_locator": self.raw_locator,
            "provider_metadata": self.provider_metadata,
            "is_partial": self.is_partial,
            "index_revision": self.index_revision,
            "created_at": to_json_timestamp(self.created_at),
            "updated_at": to_json_timestamp(self.updated_at),
        }


@dataclass(slots=True)
class IndexCoverage:
    """Progress and coverage counters for one filesystem index revision."""

    case_id: str
    evidence_id: str
    provider_id: str
    provider_version: str
    profile_type: AnalysisProfileType
    option_fingerprint: str
    status: IndexCoverageStatus
    discovered_items: int = 0
    processed_items: int = 0
    skipped_items: int = 0
    warning_count: int = 0
    error_count: int = 0
    current_path: str | None = None
    elapsed_seconds: float = 0.0
    throughput_items_per_second: float | None = None
    estimated_remaining_seconds: float | None = None
    eta_confidence: str = "UNKNOWN"
    index_revision: int = 1
    job_id: str | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None

    def to_schema_dict(self) -> dict[str, Any]:
        """Return a JSON-compatible coverage DTO."""

        return {
            "case_id": self.case_id,
            "evidence_id": self.evidence_id,
            "filesystem_provider": {
                "id": self.provider_id,
                "version": self.provider_version,
            },
            "profile_type": self.profile_type.value,
            "option_fingerprint": self.option_fingerprint,
            "status": self.status.value,
            "discovered_items": self.discovered_items,
            "processed_items": self.processed_items,
            "skipped_items": self.skipped_items,
            "warning_count": self.warning_count,
            "error_count": self.error_count,
            "current_path": self.current_path,
            "elapsed_seconds": self.elapsed_seconds,
            "throughput_items_per_second": self.throughput_items_per_second,
            "estimated_remaining_seconds": self.estimated_remaining_seconds,
            "eta_confidence": self.eta_confidence,
            "index_revision": self.index_revision,
            "job_id": self.job_id,
            "created_at": None if self.created_at is None else to_json_timestamp(self.created_at),
            "updated_at": None if self.updated_at is None else to_json_timestamp(self.updated_at),
        }


@dataclass(frozen=True, slots=True)
class CursorPage:
    """Stable cursor pagination metadata."""

    next_cursor: str | None
    has_more: bool
    returned: int

    def to_schema_dict(self) -> dict[str, Any]:
        return {
            "next_cursor": self.next_cursor,
            "has_more": self.has_more,
            "returned": self.returned,
        }


@dataclass(slots=True)
class FileTreePage:
    """A page of filesystem nodes plus coverage metadata."""

    items: list[FileSystemNode] = field(default_factory=list)
    page: CursorPage = field(default_factory=lambda: CursorPage(None, False, 0))
    coverage: IndexCoverage | None = None

    def to_schema_dict(self) -> dict[str, Any]:
        return {
            "items": [item.to_schema_dict() for item in self.items],
            "page": self.page.to_schema_dict(),
            "coverage": None if self.coverage is None else self.coverage.to_schema_dict(),
        }
