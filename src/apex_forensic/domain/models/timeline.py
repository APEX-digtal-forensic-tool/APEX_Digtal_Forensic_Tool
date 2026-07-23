"""Timeline domain models and timestamp normalization DTOs."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from apex_forensic._time import to_json_timestamp
from apex_forensic.domain.enums import (
    TimelineEventType,
    TimelineSourceType,
    TimestampPrecision,
    TimezoneConfidence,
    TimezoneSource,
)
from apex_forensic.domain.models.filesystem import CursorPage


def _nullable_timestamp(value: datetime | None) -> str | None:
    return None if value is None else to_json_timestamp(value)


@dataclass(slots=True)
class TimestampNormalization:
    """Raw, UTC, and case-timezone timestamp representation."""

    raw_timestamp: str | None
    raw_timezone: str | None
    timestamp_semantics: str
    normalized_utc: datetime | None
    case_timezone: str
    displayed_case_time: str | None
    timezone_source: TimezoneSource
    timezone_confidence: TimezoneConfidence
    precision: TimestampPrecision
    warnings: list[dict[str, Any]] = field(default_factory=list)

    def to_schema_dict(self) -> dict[str, Any]:
        return {
            "raw_timestamp": self.raw_timestamp,
            "raw_timezone": self.raw_timezone,
            "timestamp_semantics": self.timestamp_semantics,
            "normalized_utc": _nullable_timestamp(self.normalized_utc),
            "case_timezone": self.case_timezone,
            "displayed_case_time": self.displayed_case_time,
            "timezone_source": self.timezone_source.value,
            "timezone_confidence": self.timezone_confidence.value,
            "precision": self.precision.value,
            "warnings": self.warnings,
        }


@dataclass(slots=True)
class TimezoneCandidate:
    """A non-authoritative timezone candidate discovered from artifacts."""

    candidate_id: str
    case_id: str
    evidence_id: str | None
    timezone: str
    source: TimezoneSource
    confidence: TimezoneConfidence
    raw_value: str | None
    citations: list[dict[str, Any]]
    created_at: datetime

    def to_schema_dict(self) -> dict[str, Any]:
        return {
            "candidate_id": self.candidate_id,
            "case_id": self.case_id,
            "evidence_id": self.evidence_id,
            "timezone": self.timezone,
            "source": self.source.value,
            "confidence": self.confidence.value,
            "raw_value": self.raw_value,
            "citations": self.citations,
            "created_at": to_json_timestamp(self.created_at),
        }


@dataclass(slots=True)
class TimelineEvent:
    """Unified timeline projection from filesystem and artifact sources."""

    timeline_event_id: str
    case_id: str
    evidence_id: str
    source_type: TimelineSourceType
    source_id: str
    source_revision: int
    event_type: TimelineEventType
    event_subtype: str
    title: str
    description: str
    raw_timestamp: str | None
    raw_timezone: str | None
    timestamp_semantics: str
    normalized_utc: datetime | None
    case_timezone: str
    displayed_case_time: str | None
    timezone_source: TimezoneSource
    timezone_confidence: TimezoneConfidence
    precision: TimestampPrecision
    analyzer_id: str | None
    analyzer_version: str | None
    raw_locator: dict[str, Any]
    citations: list[dict[str, Any]]
    fields: dict[str, Any]
    is_partial: bool
    timeline_revision: int
    created_at: datetime
    dedup_key: str

    def to_schema_dict(self) -> dict[str, Any]:
        return {
            "timeline_event_id": self.timeline_event_id,
            "case_id": self.case_id,
            "evidence_id": self.evidence_id,
            "source_type": self.source_type.value,
            "source_id": self.source_id,
            "source_revision": self.source_revision,
            "event_type": self.event_type.value,
            "event_subtype": self.event_subtype,
            "title": self.title,
            "description": self.description,
            "raw_timestamp": self.raw_timestamp,
            "raw_timezone": self.raw_timezone,
            "timestamp_semantics": self.timestamp_semantics,
            "normalized_utc": _nullable_timestamp(self.normalized_utc),
            "case_timezone": self.case_timezone,
            "displayed_case_time": self.displayed_case_time,
            "timezone_source": self.timezone_source.value,
            "timezone_confidence": self.timezone_confidence.value,
            "precision": self.precision.value,
            "analyzer_id": self.analyzer_id,
            "analyzer_version": self.analyzer_version,
            "raw_locator": self.raw_locator,
            "citations": self.citations,
            "fields": self.fields,
            "is_partial": self.is_partial,
            "timeline_revision": self.timeline_revision,
            "created_at": to_json_timestamp(self.created_at),
            "dedup_key": self.dedup_key,
        }


@dataclass(frozen=True, slots=True)
class TimelineQuery:
    """Stable-cursor timeline query options."""

    case_id: str
    evidence_id: str | None = None
    source_types: tuple[TimelineSourceType, ...] = ()
    event_types: tuple[TimelineEventType, ...] = ()
    analyzer_id: str | None = None
    keyword: str | None = None
    path: str | None = None
    artifact_type: str | None = None
    is_partial: bool | None = None
    confidence: TimezoneConfidence | None = None
    time_from: datetime | None = None
    time_to: datetime | None = None
    timezone: str | None = None
    cursor: str | None = None
    limit: int = 100
    order: str = "ASC"


@dataclass(slots=True)
class TimelineBuildCoverage:
    """Progress and coverage counters for timeline generation."""

    job_id: str
    case_id: str
    evidence_id: str | None
    status: str
    discovered_items: int = 0
    processed_items: int = 0
    skipped_items: int = 0
    event_count: int = 0
    warning_count: int = 0
    error_count: int = 0
    current_source: str | None = None
    is_partial: bool = False
    timeline_revision: int = 1
    created_at: datetime | None = None
    updated_at: datetime | None = None

    def to_schema_dict(self) -> dict[str, Any]:
        return {
            "job_id": self.job_id,
            "case_id": self.case_id,
            "evidence_id": self.evidence_id,
            "status": self.status,
            "discovered_items": self.discovered_items,
            "processed_items": self.processed_items,
            "skipped_items": self.skipped_items,
            "event_count": self.event_count,
            "warning_count": self.warning_count,
            "error_count": self.error_count,
            "current_source": self.current_source,
            "is_partial": self.is_partial,
            "timeline_revision": self.timeline_revision,
            "created_at": None if self.created_at is None else to_json_timestamp(self.created_at),
            "updated_at": None if self.updated_at is None else to_json_timestamp(self.updated_at),
        }


@dataclass(slots=True)
class TimelinePage:
    """A page of timeline events."""

    items: list[TimelineEvent]
    page: CursorPage
    timezone: str
    warnings: list[dict[str, Any]] = field(default_factory=list)

    def to_schema_dict(self) -> dict[str, Any]:
        return {
            "items": [item.to_schema_dict() for item in self.items],
            "page": self.page.to_schema_dict(),
            "timezone": self.timezone,
            "warnings": self.warnings,
        }
