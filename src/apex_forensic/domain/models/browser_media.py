"""Phase 5 browser, media, thumbnail, and machine extraction domain models."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from apex_forensic._time import to_json_timestamp


def _nullable_timestamp(value: datetime | None) -> str | None:
    return None if value is None else to_json_timestamp(value)


@dataclass(frozen=True, slots=True)
class BrowserProfile:
    """A browser profile candidate discovered from indexed filesystem metadata."""

    profile_id: str
    case_id: str
    evidence_id: str
    browser_family: str
    browser_name: str
    profile_name: str
    profile_path: str
    source_node_id: str
    operating_system: str
    user_candidate: str | None
    discovery_method: str
    source_revision: int
    raw_locator: dict[str, Any]
    citations: list[dict[str, Any]] = field(default_factory=list)
    warnings: list[dict[str, Any]] = field(default_factory=list)
    is_partial: bool = False
    discovered_at: datetime | None = None

    def to_schema_dict(self) -> dict[str, Any]:
        return {
            "profile_id": self.profile_id,
            "case_id": self.case_id,
            "evidence_id": self.evidence_id,
            "browser_family": self.browser_family,
            "browser_name": self.browser_name,
            "profile_name": self.profile_name,
            "profile_path": self.profile_path,
            "source_node_id": self.source_node_id,
            "operating_system": self.operating_system,
            "user_candidate": self.user_candidate,
            "discovery_method": self.discovery_method,
            "source_revision": self.source_revision,
            "raw_locator": self.raw_locator,
            "citations": self.citations,
            "warnings": self.warnings,
            "is_partial": self.is_partial,
            "discovered_at": _nullable_timestamp(self.discovered_at),
        }


@dataclass(frozen=True, slots=True)
class BrowserArtifact:
    """A browser history/search/download artifact with logical SQLite provenance."""

    artifact_id: str
    case_id: str
    evidence_id: str
    profile_id: str
    browser_family: str
    browser_name: str
    artifact_type: str
    artifact_subtype: str
    title: str
    url: str | None
    domain: str | None
    search_term: str | None
    download_url: str | None
    download_path: str | None
    referrer_url: str | None
    visit_count: int | None
    typed_count: int | None
    transition: str | None
    raw_timestamp: str | None
    timestamp_semantics: str
    normalized_utc: datetime | None
    case_timezone: str
    displayed_case_time: str | None
    fields: dict[str, Any]
    source_path: str
    source_node_id: str
    source_revision: int
    analyzer_id: str
    analyzer_version: str
    raw_locator: dict[str, Any]
    citations: list[dict[str, Any]] = field(default_factory=list)
    is_partial: bool = False
    created_at: datetime | None = None

    def to_schema_dict(self) -> dict[str, Any]:
        return {
            "artifact_id": self.artifact_id,
            "case_id": self.case_id,
            "evidence_id": self.evidence_id,
            "profile_id": self.profile_id,
            "browser_family": self.browser_family,
            "browser_name": self.browser_name,
            "artifact_type": self.artifact_type,
            "artifact_subtype": self.artifact_subtype,
            "title": self.title,
            "url": self.url,
            "domain": self.domain,
            "search_term": self.search_term,
            "download_url": self.download_url,
            "download_path": self.download_path,
            "referrer_url": self.referrer_url,
            "visit_count": self.visit_count,
            "typed_count": self.typed_count,
            "transition": self.transition,
            "raw_timestamp": self.raw_timestamp,
            "timestamp_semantics": self.timestamp_semantics,
            "normalized_utc": _nullable_timestamp(self.normalized_utc),
            "case_timezone": self.case_timezone,
            "displayed_case_time": self.displayed_case_time,
            "fields": self.fields,
            "source_path": self.source_path,
            "source_node_id": self.source_node_id,
            "source_revision": self.source_revision,
            "analyzer_id": self.analyzer_id,
            "analyzer_version": self.analyzer_version,
            "raw_locator": self.raw_locator,
            "citations": self.citations,
            "is_partial": self.is_partial,
            "created_at": _nullable_timestamp(self.created_at),
        }


@dataclass(frozen=True, slots=True)
class MediaArtifact:
    """A media metadata artifact with candidate EXIF/GPS/codec fields."""

    media_artifact_id: str
    case_id: str
    evidence_id: str
    source_node_id: str
    source_path: str
    media_type: str
    format: str | None
    mime_candidate: str | None
    size_bytes: int | None
    width: int | None
    height: int | None
    duration_ms: int | None
    frame_rate: str | None
    video_codec: str | None
    audio_codec: str | None
    sample_rate: int | None
    channels: int | None
    bit_rate: int | None
    creation_time_raw: str | None
    creation_time_utc: datetime | None
    modified_time_raw: str | None
    gps_latitude: float | None
    gps_longitude: float | None
    gps_altitude: float | None
    camera_make: str | None
    camera_model: str | None
    software: str | None
    orientation: str | None
    metadata: dict[str, Any]
    thumbnail_status: str
    analyzer_id: str
    analyzer_version: str
    backend_id: str
    backend_version: str
    source_revision: int
    raw_locator: dict[str, Any]
    citations: list[dict[str, Any]] = field(default_factory=list)
    is_partial: bool = False
    created_at: datetime | None = None

    def to_schema_dict(self) -> dict[str, Any]:
        return {
            "media_artifact_id": self.media_artifact_id,
            "case_id": self.case_id,
            "evidence_id": self.evidence_id,
            "source_node_id": self.source_node_id,
            "source_path": self.source_path,
            "media_type": self.media_type,
            "format": self.format,
            "mime_candidate": self.mime_candidate,
            "size_bytes": self.size_bytes,
            "width": self.width,
            "height": self.height,
            "duration_ms": self.duration_ms,
            "frame_rate": self.frame_rate,
            "video_codec": self.video_codec,
            "audio_codec": self.audio_codec,
            "sample_rate": self.sample_rate,
            "channels": self.channels,
            "bit_rate": self.bit_rate,
            "creation_time_raw": self.creation_time_raw,
            "creation_time_utc": _nullable_timestamp(self.creation_time_utc),
            "modified_time_raw": self.modified_time_raw,
            "gps_latitude": self.gps_latitude,
            "gps_longitude": self.gps_longitude,
            "gps_altitude": self.gps_altitude,
            "camera_make": self.camera_make,
            "camera_model": self.camera_model,
            "software": self.software,
            "orientation": self.orientation,
            "metadata": self.metadata,
            "thumbnail_status": self.thumbnail_status,
            "analyzer_id": self.analyzer_id,
            "analyzer_version": self.analyzer_version,
            "backend_id": self.backend_id,
            "backend_version": self.backend_version,
            "source_revision": self.source_revision,
            "raw_locator": self.raw_locator,
            "citations": self.citations,
            "is_partial": self.is_partial,
            "created_at": _nullable_timestamp(self.created_at),
        }


@dataclass(frozen=True, slots=True)
class ThumbnailRecord:
    """Hash-verifiable metadata for a derived thumbnail object."""

    thumbnail_id: str
    case_id: str
    evidence_id: str
    source_node_id: str
    source_artifact_id: str | None
    source_fingerprint: str
    cache_key: str
    relative_path: str
    output_format: str
    width: int | None
    height: int | None
    size_bytes: int
    content_sha256: str
    status: str
    analyzer_id: str
    analyzer_version: str
    created_at: datetime | None = None

    def to_schema_dict(self) -> dict[str, Any]:
        return {
            "thumbnail_id": self.thumbnail_id,
            "case_id": self.case_id,
            "evidence_id": self.evidence_id,
            "source_node_id": self.source_node_id,
            "source_artifact_id": self.source_artifact_id,
            "source_fingerprint": self.source_fingerprint,
            "cache_key": self.cache_key,
            "relative_path": self.relative_path,
            "output_format": self.output_format,
            "width": self.width,
            "height": self.height,
            "size_bytes": self.size_bytes,
            "content_sha256": self.content_sha256,
            "status": self.status,
            "analyzer_id": self.analyzer_id,
            "analyzer_version": self.analyzer_version,
            "created_at": _nullable_timestamp(self.created_at),
        }


@dataclass(frozen=True, slots=True)
class MachineExtractedCandidate:
    """OCR/STT/subtitle candidate text that is not an observed fact."""

    candidate_id: str
    case_id: str
    evidence_id: str
    source_node_id: str
    source_type: str
    extraction_type: str
    text: str
    language: str | None
    confidence: float
    provider_id: str
    provider_version: str
    model_id: str | None
    region: dict[str, Any] | None
    frame_number: int | None
    media_timestamp_ms: int | None
    audio_start_ms: int | None
    audio_end_ms: int | None
    raw_locator: dict[str, Any]
    citations: list[dict[str, Any]]
    review_status: str
    reviewed_by: str | None
    reviewed_at: datetime | None
    correction_text: str | None
    source_revision: int
    is_partial: bool
    created_at: datetime | None = None

    def to_schema_dict(self) -> dict[str, Any]:
        return {
            "candidate_id": self.candidate_id,
            "case_id": self.case_id,
            "evidence_id": self.evidence_id,
            "source_node_id": self.source_node_id,
            "source_type": self.source_type,
            "extraction_type": self.extraction_type,
            "text": self.text,
            "language": self.language,
            "confidence": self.confidence,
            "provider_id": self.provider_id,
            "provider_version": self.provider_version,
            "model_id": self.model_id,
            "region": self.region,
            "frame_number": self.frame_number,
            "media_timestamp_ms": self.media_timestamp_ms,
            "audio_start_ms": self.audio_start_ms,
            "audio_end_ms": self.audio_end_ms,
            "raw_locator": self.raw_locator,
            "citations": self.citations,
            "review_status": self.review_status,
            "reviewed_by": self.reviewed_by,
            "reviewed_at": _nullable_timestamp(self.reviewed_at),
            "correction_text": self.correction_text,
            "source_revision": self.source_revision,
            "is_partial": self.is_partial,
            "created_at": _nullable_timestamp(self.created_at),
            "candidate_semantics": "MACHINE_EXTRACTED_CANDIDATE_NOT_OBSERVED_FACT",
        }


@dataclass(frozen=True, slots=True)
class CandidateReviewEvent:
    """Append-only review event for a machine-extracted candidate."""

    review_event_id: str
    candidate_id: str
    case_id: str
    review_status: str
    reviewed_by: str
    reviewed_at: datetime
    correction_text: str | None = None
    previous_review_status: str | None = None
    reason: str | None = None

    def to_schema_dict(self) -> dict[str, Any]:
        return {
            "review_event_id": self.review_event_id,
            "candidate_id": self.candidate_id,
            "case_id": self.case_id,
            "review_status": self.review_status,
            "reviewed_by": self.reviewed_by,
            "reviewed_at": to_json_timestamp(self.reviewed_at),
            "correction_text": self.correction_text,
            "previous_review_status": self.previous_review_status,
            "reason": self.reason,
        }


@dataclass(frozen=True, slots=True)
class ProviderCapability:
    """Provider-neutral capability statement for optional Phase 5 backends."""

    provider_id: str
    provider_version: str
    capability_type: str
    is_available: bool
    supported_inputs: list[str]
    supported_outputs: list[str]
    unavailable_reason: str | None
    warnings: list[dict[str, Any]] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    updated_at: datetime | None = None

    def to_schema_dict(self) -> dict[str, Any]:
        return {
            "provider_id": self.provider_id,
            "provider_version": self.provider_version,
            "capability_type": self.capability_type,
            "is_available": self.is_available,
            "supported_inputs": self.supported_inputs,
            "supported_outputs": self.supported_outputs,
            "unavailable_reason": self.unavailable_reason,
            "warnings": self.warnings,
            "metadata": self.metadata,
            "updated_at": _nullable_timestamp(self.updated_at),
        }


@dataclass(frozen=True, slots=True)
class Phase5Checkpoint:
    """Checkpoint shell for browser/media coordinators backed by the artifact job tables."""

    job_id: str
    case_id: str
    evidence_id: str
    current_profile_id: str | None
    current_source_node_id: str | None
    current_path: str | None
    processed_items: int
    pending_items: int
    updated_at: datetime | None = None

    def to_schema_dict(self) -> dict[str, Any]:
        return {
            "job_id": self.job_id,
            "case_id": self.case_id,
            "evidence_id": self.evidence_id,
            "current_profile_id": self.current_profile_id,
            "current_source_node_id": self.current_source_node_id,
            "current_path": self.current_path,
            "processed_items": self.processed_items,
            "pending_items": self.pending_items,
            "updated_at": _nullable_timestamp(self.updated_at),
        }
