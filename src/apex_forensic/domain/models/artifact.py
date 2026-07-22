"""Windows artifact domain models."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from apex_forensic._time import to_json_timestamp
from apex_forensic.constants import SCHEMA_VERSION
from apex_forensic.domain.enums import (
    AnalysisProfileType,
    ArtifactCoverageStatus,
    ArtifactParseStatus,
    ArtifactSourceKind,
    ArtifactType,
)


def _nullable_timestamp(value: datetime | None) -> str | None:
    return None if value is None else to_json_timestamp(value)


@dataclass(frozen=True, slots=True)
class ArtifactCapability:
    """Provider-neutral capability statement for one artifact analyzer."""

    analyzer_id: str
    analyzer_version: str
    parser_backend: str
    parser_backend_version: str
    supported_source_kinds: tuple[ArtifactSourceKind, ...]
    supported_artifact_types: tuple[ArtifactType, ...]
    capabilities: tuple[str, ...] = ()
    unavailable_capabilities: tuple[str, ...] = ()
    warnings: tuple[dict[str, Any], ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def is_available(self) -> bool:
        return not self.unavailable_capabilities

    def to_schema_dict(self) -> dict[str, Any]:
        return {
            "analyzer_id": self.analyzer_id,
            "analyzer_version": self.analyzer_version,
            "parser_backend": self.parser_backend,
            "parser_backend_version": self.parser_backend_version,
            "supported_source_kinds": [item.value for item in self.supported_source_kinds],
            "supported_artifact_types": [item.value for item in self.supported_artifact_types],
            "capabilities": list(self.capabilities),
            "unavailable_capabilities": list(self.unavailable_capabilities),
            "warnings": list(self.warnings),
            "metadata": self.metadata,
            "is_available": self.is_available,
        }


@dataclass(slots=True)
class ArtifactIssue:
    """Warning or parse error emitted by an analyzer."""

    severity: str
    code: str
    message_key: str
    developer_message: str
    source_file_node_id: str | None = None
    artifact_id: str | None = None
    source_path: str | None = None
    details: dict[str, Any] = field(default_factory=dict)

    def to_schema_dict(self) -> dict[str, Any]:
        return {
            "severity": self.severity,
            "code": self.code,
            "message_key": self.message_key,
            "developer_message": self.developer_message,
            "source_file_node_id": self.source_file_node_id,
            "artifact_id": self.artifact_id,
            "source_path": self.source_path,
            "details": self.details,
        }

    def to_warning_dict(self) -> dict[str, Any]:
        return self.to_schema_dict()

    def to_error_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "message_key": self.message_key,
            "developer_message": self.developer_message,
            "target": self.source_path or self.source_file_node_id,
            "retryable": False,
            "details": self.details,
        }


@dataclass(slots=True)
class ArtifactRecord:
    """An immutable observed fact extracted from a Windows artifact source."""

    artifact_id: str
    case_id: str
    evidence_id: str
    source_file_node_id: str
    artifact_type: ArtifactType
    artifact_subtype: str
    analyzer_id: str
    analyzer_version: str
    parser_backend: str
    parser_backend_version: str
    source_path: str
    source_kind: ArtifactSourceKind
    observed_at_raw: str | None
    observed_at_utc: datetime | None
    timezone_source: str | None
    timezone_confidence: str
    title: str
    summary: str
    fields: dict[str, Any]
    raw_locator: dict[str, Any]
    citations: list[dict[str, Any]]
    warnings: list[dict[str, Any]]
    parse_status: ArtifactParseStatus
    confidence: float
    is_partial: bool
    index_revision: int
    created_at: datetime
    updated_at: datetime
    dedup_key: str
    schema_version: str = SCHEMA_VERSION

    def to_schema_dict(self) -> dict[str, Any]:
        """Return a JSON Schema-compatible artifact DTO."""

        display_name_key = f"artifact.{self.artifact_type.value.casefold()}.display_name"
        description_key = f"artifact.{self.artifact_type.value.casefold()}.description"
        return {
            "id": self.artifact_id,
            "artifact_id": self.artifact_id,
            "case_id": self.case_id,
            "evidence_id": self.evidence_id,
            "source_file_node_id": self.source_file_node_id,
            "source_object_id": self.source_file_node_id,
            "artifact_type": self.artifact_type.value,
            "artifact_subtype": self.artifact_subtype,
            "schema_version": self.schema_version,
            "display_name_key": display_name_key,
            "description_key": description_key,
            "analyzer_id": self.analyzer_id,
            "analyzer_version": self.analyzer_version,
            "parser_backend": self.parser_backend,
            "parser_backend_version": self.parser_backend_version,
            "source_path": self.source_path,
            "source_kind": self.source_kind.value,
            "observed_at_raw": self.observed_at_raw,
            "observed_at_utc": _nullable_timestamp(self.observed_at_utc),
            "timezone_source": self.timezone_source,
            "timezone_confidence": self.timezone_confidence,
            "title": self.title,
            "summary": self.summary,
            "fields": self.fields,
            "payload": self.fields,
            "raw_locator": self.raw_locator,
            "citations": self.citations,
            "warnings": self.warnings,
            "parse_status": self.parse_status.value,
            "confidence": self.confidence,
            "is_partial": self.is_partial,
            "index_revision": self.index_revision,
            "created_at": to_json_timestamp(self.created_at),
            "updated_at": to_json_timestamp(self.updated_at),
            "dedup_key": self.dedup_key,
            "timestamp_interpretations": [],
            "provenance": {
                "evidence_id": self.evidence_id,
                "source_object_id": self.source_file_node_id,
                "source_path": self.source_path,
                "source_offset": self.raw_locator.get("offset"),
                "source_length": self.raw_locator.get("length"),
                "analyzer_run_id": self.dedup_key,
                "analyzer_id": self.analyzer_id,
                "analyzer_version": self.analyzer_version,
                "raw_locator": self.raw_locator,
            },
        }


@dataclass(slots=True)
class ArtifactSource:
    """A filesystem node selected as a candidate for artifact analysis."""

    source_id: str
    job_id: str | None
    case_id: str
    evidence_id: str
    source_file_node_id: str
    source_path: str
    source_kind: ArtifactSourceKind
    comparison_key: str
    analyzer_id: str
    analyzer_version: str
    parser_backend: str
    parser_backend_version: str
    option_fingerprint: str
    status: str
    priority: int
    source_order: int
    is_partial: bool
    warning_count: int
    error_count: int
    artifact_count: int
    parse_status: ArtifactParseStatus | None
    last_error: dict[str, Any] | None
    discovered_at: datetime
    analyzed_at: datetime | None
    updated_at: datetime

    def to_schema_dict(self) -> dict[str, Any]:
        return {
            "source_id": self.source_id,
            "job_id": self.job_id,
            "case_id": self.case_id,
            "evidence_id": self.evidence_id,
            "source_file_node_id": self.source_file_node_id,
            "source_path": self.source_path,
            "source_kind": self.source_kind.value,
            "comparison_key": self.comparison_key,
            "analyzer_id": self.analyzer_id,
            "analyzer_version": self.analyzer_version,
            "parser_backend": self.parser_backend,
            "parser_backend_version": self.parser_backend_version,
            "option_fingerprint": self.option_fingerprint,
            "status": self.status,
            "priority": self.priority,
            "source_order": self.source_order,
            "is_partial": self.is_partial,
            "warning_count": self.warning_count,
            "error_count": self.error_count,
            "artifact_count": self.artifact_count,
            "parse_status": None if self.parse_status is None else self.parse_status.value,
            "last_error": self.last_error,
            "discovered_at": to_json_timestamp(self.discovered_at),
            "analyzed_at": _nullable_timestamp(self.analyzed_at),
            "updated_at": to_json_timestamp(self.updated_at),
        }


@dataclass(slots=True)
class ArtifactCoverage:
    """Coverage and progress counters for one artifact analysis job."""

    job_id: str
    case_id: str
    evidence_id: str
    profile_type: AnalysisProfileType
    option_fingerprint: str
    status: ArtifactCoverageStatus
    source_count: int = 0
    processed_sources: int = 0
    skipped_sources: int = 0
    artifact_count: int = 0
    warning_count: int = 0
    error_count: int = 0
    current_analyzer: str | None = None
    current_source_path: str | None = None
    elapsed_seconds: float = 0.0
    throughput_items_per_second: float | None = None
    estimated_remaining_seconds: float | None = None
    eta_confidence: str = "UNKNOWN"
    is_partial: bool = False
    index_revision: int = 1
    created_at: datetime | None = None
    updated_at: datetime | None = None

    def to_schema_dict(self) -> dict[str, Any]:
        return {
            "job_id": self.job_id,
            "case_id": self.case_id,
            "evidence_id": self.evidence_id,
            "profile_type": self.profile_type.value,
            "option_fingerprint": self.option_fingerprint,
            "status": self.status.value,
            "source_count": self.source_count,
            "processed_sources": self.processed_sources,
            "skipped_sources": self.skipped_sources,
            "artifact_count": self.artifact_count,
            "warning_count": self.warning_count,
            "error_count": self.error_count,
            "current_analyzer": self.current_analyzer,
            "current_source_path": self.current_source_path,
            "elapsed_seconds": self.elapsed_seconds,
            "throughput_items_per_second": self.throughput_items_per_second,
            "estimated_remaining_seconds": self.estimated_remaining_seconds,
            "eta_confidence": self.eta_confidence,
            "is_partial": self.is_partial,
            "index_revision": self.index_revision,
            "created_at": None if self.created_at is None else to_json_timestamp(self.created_at),
            "updated_at": None if self.updated_at is None else to_json_timestamp(self.updated_at),
        }


@dataclass(frozen=True, slots=True)
class ArtifactQuery:
    """Stable artifact query filters."""

    case_id: str
    evidence_id: str | None = None
    source_file_node_id: str | None = None
    artifact_type: ArtifactType | None = None
    artifact_subtype: str | None = None
    analyzer_id: str | None = None
    event_id: int | None = None
    registry_path: str | None = None
    executable_name: str | None = None
    observed_from: datetime | None = None
    observed_to: datetime | None = None
    parse_status: ArtifactParseStatus | None = None
    has_warnings: bool | None = None
    limit: int = 100
    cursor: str | None = None


@dataclass(slots=True)
class ArtifactPage:
    """A page of artifact records plus cursor metadata."""

    items: list[ArtifactRecord]
    next_cursor: str | None
    has_more: bool
    returned: int
    coverage: ArtifactCoverage | None = None

    def to_schema_dict(self) -> dict[str, Any]:
        return {
            "items": [item.to_schema_dict() for item in self.items],
            "page": {
                "next_cursor": self.next_cursor,
                "has_more": self.has_more,
                "returned": self.returned,
            },
            "coverage": None if self.coverage is None else self.coverage.to_schema_dict(),
        }


@dataclass(frozen=True, slots=True)
class ArtifactAnalysisResult:
    """Analyzer output for one source file."""

    artifacts: tuple[ArtifactRecord, ...] = ()
    warnings: tuple[ArtifactIssue, ...] = ()
    errors: tuple[ArtifactIssue, ...] = ()
    coverage: dict[str, Any] = field(default_factory=dict)
    parse_status: ArtifactParseStatus = ArtifactParseStatus.SUCCESS

    def is_partial(self) -> bool:
        return self.parse_status in {
            ArtifactParseStatus.PARTIAL,
            ArtifactParseStatus.CORRUPT,
            ArtifactParseStatus.FAILED,
            ArtifactParseStatus.UNSUPPORTED,
        }
