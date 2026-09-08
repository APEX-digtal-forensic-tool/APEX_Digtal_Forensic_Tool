"""SQLite repository adapter for Phase 1."""

from __future__ import annotations

import base64
import json
import re
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse
from uuid import uuid4
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from apex_forensic._time import parse_timestamp, to_json_timestamp, utc_now
from apex_forensic.constants import SCHEMA_VERSION
from apex_forensic.domain.enums import (
    AnalysisContextPurpose,
    AnalysisProfileType,
    AnalysisScopeType,
    ArtifactCoverageStatus,
    ArtifactParseStatus,
    ArtifactSourceKind,
    ArtifactType,
    CaseStatus,
    EvidenceFormat,
    EvidenceStatus,
    FileSystemNodeType,
    GuiRoute,
    HashAlgorithm,
    IndexCoverageStatus,
    JobStatus,
    JobType,
    KeywordMatchMode,
    KeywordSetStatus,
    KeywordType,
    ProgressUnit,
    ResourceType,
    RevisionStatus,
    SearchDocumentType,
    SearchQueryMode,
    SearchSourceType,
    TimelineEventType,
    TimelineSourceType,
    TimestampPrecision,
    TimezoneConfidence,
    TimezoneSource,
    ViewMode,
)
from apex_forensic.domain.errors import PersistenceError, StateConflictError, ValidationError
from apex_forensic.domain.models import (
    AiAssistanceRequest,
    AiKeywordPromotion,
    AiKeywordRecommendation,
    AiKeywordRecommendationBatch,
    AiProviderCapability,
    AiScopeSummaryRecord,
    AiVerificationEvent,
    AnalysisContextSnapshot,
    AnalysisScopeContext,
    ArtifactCapability,
    ArtifactCoverage,
    ArtifactQuery,
    ArtifactRecord,
    ArtifactSource,
    BrowserArtifact,
    BrowserProfile,
    CandidateReviewEvent,
    Case,
    CustodyEvent,
    CustodySnapshotRecord,
    DecryptionAttempt,
    DecryptionResult,
    EngineInterfaceVersion,
    EngineToolDescriptor,
    Evidence,
    EvidenceFingerprint,
    EvidenceVolume,
    FileSystemNode,
    GuiSessionContext,
    HashRecord,
    HashVerification,
    IndexCoverage,
    Job,
    JobProgress,
    Keyword,
    KeywordSet,
    MachineExtractedCandidate,
    MediaArtifact,
    ProviderCapability,
    RenderedReportArtifact,
    ReportApprovalRecord,
    ReportExportAuditEvent,
    ReportExportManifest,
    ReportRecord,
    ReportRendererCapability,
    ReportRenderPackage,
    ReportReviewEvent,
    ReportVersion,
    RevisionState,
    SearchCacheEntry,
    SearchDocument,
    SearchExecution,
    SearchIndexCapability,
    SearchQuery,
    SearchResult,
    SecretProviderCapability,
    ThumbnailRecord,
    TimelineBuildCoverage,
    TimelineEvent,
    TimelineQuery,
    ViewProjection,
)
from apex_forensic.domain.models.ai_governance import (
    AiEgressAuditRecord,
    CaseAiPolicy,
)
from apex_forensic.domain.services.canonical import canonical_sha256

_FS_METADATA_ALLOWLIST = {
    "mode",
    "inode",
    "device",
    "uid",
    "gid",
    "nlink",
}


class _ApexSQLiteConnection(sqlite3.Connection):
    """Translate SQLite failures at the adapter boundary without exposing SQL or paths."""

    def execute(
        self,
        sql: str,
        parameters: Any = (),
    ) -> sqlite3.Cursor:
        try:
            return super().execute(sql, parameters)
        except sqlite3.Error as error:
            raise _translate_sqlite_error(error) from error

    def executemany(
        self,
        sql: str,
        parameters: Any,
    ) -> sqlite3.Cursor:
        try:
            return super().executemany(sql, parameters)
        except sqlite3.Error as error:
            raise _translate_sqlite_error(error) from error

    def executescript(self, sql_script: str) -> sqlite3.Cursor:
        try:
            return super().executescript(sql_script)
        except sqlite3.Error as error:
            raise _translate_sqlite_error(error) from error

    def commit(self) -> None:
        try:
            super().commit()
        except sqlite3.Error as error:
            raise _translate_sqlite_error(error) from error

    def rollback(self) -> None:
        try:
            super().rollback()
        except sqlite3.Error as error:
            raise _translate_sqlite_error(error) from error


def _translate_sqlite_error(error: sqlite3.Error) -> sqlite3.Error | PersistenceError:
    if isinstance(error, sqlite3.IntegrityError):
        return error
    error_code = getattr(error, "sqlite_errorcode", None)
    error_name = getattr(error, "sqlite_errorname", None)
    primary_code = error_code & 0xFF if isinstance(error_code, int) else None
    details = {"sqlite_error_name": error_name} if isinstance(error_name, str) else {}
    if primary_code in {sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED}:
        return PersistenceError(
            "DATABASE_LOCKED",
            "The case database is busy with another writer.",
            retryable=True,
            details=details,
        )
    if primary_code in {sqlite3.SQLITE_CORRUPT, sqlite3.SQLITE_NOTADB}:
        return PersistenceError(
            "DATABASE_CORRUPT",
            "The case database is corrupt or is not a SQLite database.",
            retryable=False,
            details=details,
        )
    if primary_code in {sqlite3.SQLITE_FULL, sqlite3.SQLITE_IOERR, sqlite3.SQLITE_READONLY}:
        return PersistenceError(
            "DATABASE_WRITE_FAILED",
            "The case database write could not be completed.",
            retryable=primary_code == sqlite3.SQLITE_IOERR,
            details=details,
        )
    return PersistenceError(
        "DATABASE_ERROR",
        "The case database operation failed.",
        retryable=False,
        details=details,
    )


_PROVIDER_METADATA_ALLOWLIST = {
    "entry_sort_key",
    "file_attributes",
    "source_kind",
    "reads_file_body",
}
_ARTIFACT_FIELD_ALLOWLIST = {
    "registry_path",
    "value_name",
    "value_type",
    "value_data",
    "decoded_value",
    "raw_command",
    "executable_candidate",
    "arguments_candidate",
    "TimeZoneKeyName",
    "iana_candidate",
    "vendor_candidate",
    "product_candidate",
    "device_instance",
    "decoded_value_name",
    "provider_name",
    "provider_guid",
    "channel",
    "event_id",
    "event_data",
    "user_data",
    "executable_name",
    "prefetch_hash",
    "referenced_path_candidates",
    "source_path",
    "media_kind",
    "media_type",
    "classification",
    "format",
    "mime",
    "mime_candidate",
    "width",
    "height",
    "codec",
    "video_codec",
    "audio_codec",
    "frame_rate",
    "sample_rate",
    "channels",
    "bit_rate",
    "codec_candidates",
    "duration_seconds",
    "gps_normalized",
    "camera_make",
    "camera_model",
    "software",
    "orientation",
    "gps_raw",
    "thumbnail_cache",
    "browser",
    "browser_family",
    "browser_name",
    "domain",
    "browser_profile",
    "browser_profile_name",
    "database_path",
    "table",
    "row_id",
    "url",
    "cache_url",
    "title",
    "visit_count",
    "search_term",
    "download_path",
    "download_url",
    "referrer_url",
    "cookie_domain",
    "credential_origin_domain",
    "cache_key_sha256",
    "body_sha256",
    "communication_app",
    "communication_platform",
    "profile_id",
    "account_id",
    "conversation_id",
    "message_id",
    "sender",
    "recipients",
    "message_body",
    "attachment_name",
    "attachment_reference",
    "mime_type",
    "state_label",
}
_TIMELINE_FIELD_ALLOWLIST = {
    "path",
    "source_path",
    "registry_path",
    "artifact_type",
    "event_id",
    "executable_name",
    "executable_candidate",
    "timestamp_key",
    "node_type",
}


def _query_terms(value: str) -> list[str]:
    return [item for item in re.findall(r"[^\s\"]+", value, flags=re.UNICODE) if item]


def _quote_fts(value: str) -> str:
    return '"' + value.replace('"', '""') + '"'


def _prefix_fts_token(value: str) -> str:
    cleaned = re.sub(r"[^\w\u0080-\uffff]+", "", value, flags=re.UNICODE)
    return f"{cleaned}*" if cleaned else _quote_fts(value)


def _matched_fields(
    terms: list[str],
    title: str,
    path: str,
    searchable: str,
    structured: dict[str, Any],
) -> list[str]:
    fields: list[str] = []
    lowered_terms = [term.casefold() for term in terms]
    if any(term in title.casefold() for term in lowered_terms):
        fields.append("title")
    if any(term in path.casefold() for term in lowered_terms):
        fields.append("path")
    if any(term in searchable.casefold() for term in lowered_terms):
        fields.append("searchable_text")
    structured_text = " ".join(str(value) for value in structured.values()).casefold()
    if any(term in structured_text for term in lowered_terms):
        fields.append("structured_fields")
    return fields or ["searchable_text"]


def _safe_field_map(data: dict[str, Any], allowlist: set[str]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key in allowlist:
        if key not in data:
            continue
        value = _safe_field_value(data[key])
        if value is not None:
            result[key] = value
    return result


def _safe_field_value(value: Any) -> str | int | float | bool | list[str] | None:
    if value is None:
        return None
    if isinstance(value, bool | int | float):
        return value
    if isinstance(value, str):
        stripped = value.strip()
        return stripped[:1000] if stripped else None
    if isinstance(value, list):
        safe_items = []
        for item in value[:20]:
            safe = _safe_field_value(item)
            if safe is not None:
                safe_items.append(str(safe)[:300])
        return safe_items
    if isinstance(value, dict):
        safe_items = []
        for item_key in sorted(value)[:30]:
            safe = _safe_field_value(value[item_key])
            if safe is not None:
                safe_items.append(f"{item_key}={safe}"[:300])
        return safe_items
    return str(value)[:500]


def _join_search_text(values: Any) -> str:
    parts: list[str] = []
    for value in values:
        if value is None:
            continue
        if isinstance(value, list):
            parts.extend(str(item) for item in value)
        else:
            parts.append(str(value))
    return " ".join(parts)


def _fs_document_type(node_type: str) -> SearchDocumentType:
    if node_type in {FileSystemNodeType.ROOT.value, FileSystemNodeType.DIRECTORY.value}:
        return SearchDocumentType.DIRECTORY
    if node_type == FileSystemNodeType.FILE.value:
        return SearchDocumentType.FILE
    return SearchDocumentType.OTHER


def _artifact_document_type(artifact_type: str) -> SearchDocumentType:
    if artifact_type in {
        ArtifactType.REGISTRY_KEY.value,
        ArtifactType.REGISTRY_VALUE.value,
        ArtifactType.REGISTRY_AUTORUN.value,
        ArtifactType.REGISTRY_USB_DEVICE.value,
        ArtifactType.REGISTRY_TIMEZONE.value,
        ArtifactType.REGISTRY_USERASSIST.value,
    }:
        return SearchDocumentType.REGISTRY
    if artifact_type == ArtifactType.EVENT_LOG_RECORD.value:
        return SearchDocumentType.EVENT_LOG
    if artifact_type == ArtifactType.PREFETCH_EXECUTION.value:
        return SearchDocumentType.PREFETCH
    if artifact_type in {
        ArtifactType.MEDIA_IMAGE.value,
        ArtifactType.MEDIA_VIDEO.value,
        ArtifactType.MEDIA_AUDIO.value,
    }:
        return SearchDocumentType.MEDIA
    if artifact_type in {
        ArtifactType.BROWSER_PROFILE.value,
        ArtifactType.BROWSER_VISIT.value,
        ArtifactType.BROWSER_SEARCH.value,
        ArtifactType.BROWSER_DOWNLOAD.value,
        ArtifactType.BROWSER_COOKIE.value,
        ArtifactType.BROWSER_CREDENTIAL.value,
        ArtifactType.BROWSER_CACHE_ENTRY.value,
        ArtifactType.BROWSER_DELETED_SQLITE_ROW.value,
        ArtifactType.BROWSER_PRIVATE_MODE_CANDIDATE.value,
    }:
        return SearchDocumentType.BROWSER
    if artifact_type in {
        ArtifactType.COMMUNICATION_PROFILE.value,
        ArtifactType.COMMUNICATION_ACCOUNT.value,
        ArtifactType.COMMUNICATION_CONVERSATION.value,
        ArtifactType.COMMUNICATION_MESSAGE.value,
        ArtifactType.COMMUNICATION_ATTACHMENT.value,
        ArtifactType.COMMUNICATION_UNSUPPORTED_STORE.value,
    }:
        return SearchDocumentType.COMMUNICATION
    return SearchDocumentType.OTHER


def _dict_value(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _list_value(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _str_or_none(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value)
    return text if text else None


def _int_or_none(value: Any) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _float_or_none(value: Any) -> float | None:
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _duration_ms(value: Any) -> int | None:
    parsed = _float_or_none(value)
    if parsed is None:
        return None
    if parsed > 10_000_000:
        return int(parsed)
    return int(parsed * 1000)


def _phase5_id(*parts: str) -> str:
    return canonical_sha256(list(parts))


def _domain_from_url(value: str | None) -> str | None:
    if value is None:
        return None
    parsed = urlparse(value)
    return parsed.hostname


def _phase5_browser_artifact_type(artifact_type: ArtifactType) -> str:
    if artifact_type is ArtifactType.BROWSER_VISIT:
        return "HISTORY_VISIT"
    if artifact_type is ArtifactType.BROWSER_SEARCH:
        return "SEARCH_TERM"
    if artifact_type is ArtifactType.BROWSER_DOWNLOAD:
        return "DOWNLOAD"
    if artifact_type is ArtifactType.BROWSER_COOKIE:
        return "COOKIE"
    if artifact_type is ArtifactType.BROWSER_CREDENTIAL:
        return "CREDENTIAL"
    if artifact_type is ArtifactType.BROWSER_CACHE_ENTRY:
        return "CACHE_ENTRY"
    if artifact_type is ArtifactType.BROWSER_DELETED_SQLITE_ROW:
        return "DELETED_SQLITE_ROW_CANDIDATE"
    if artifact_type is ArtifactType.BROWSER_PRIVATE_MODE_CANDIDATE:
        return "PRIVATE_MODE_CANDIDATE"
    return "UNKNOWN"


def _browser_source_fingerprint(artifact: ArtifactRecord) -> str:
    database = _dict_value(artifact.fields.get("database"))
    snapshot = _dict_value(artifact.fields.get("snapshot"))
    return str(
        snapshot.get("source_fingerprint")
        or database.get("content_sha256")
        or artifact.raw_locator.get("content_sha256")
        or artifact.dedup_key
    )


def _displayed_case_time(
    value: datetime | None,
    case_timezone: str,
) -> tuple[str | None, str, dict[str, Any] | None]:
    if value is None:
        return None, case_timezone, None
    normalized = value if value.tzinfo is not None else value.replace(tzinfo=UTC)
    try:
        zone = ZoneInfo(case_timezone)
    except ZoneInfoNotFoundError:
        return (
            to_json_timestamp(normalized.astimezone(UTC)),
            "UTC",
            {
                "code": "INVALID_CASE_TIMEZONE_FALLBACK",
                "message_key": "warning.browser.invalid_case_timezone_fallback",
                "developer_message": (
                    "Case timezone was invalid while projecting browser case time; UTC was used."
                ),
                "details": {"case_timezone": case_timezone, "fallback_timezone": "UTC"},
            },
        )
    return normalized.astimezone(zone).isoformat(timespec="microseconds"), case_timezone, None


def _media_source_fingerprint(artifact: ArtifactRecord) -> str:
    thumbnail = _dict_value(artifact.fields.get("thumbnail_cache"))
    return str(
        thumbnail.get("source_content_sha256")
        or artifact.raw_locator.get("content_sha256")
        or artifact.dedup_key
    )


def _thumbnail_status(fields: dict[str, Any]) -> str:
    thumbnail = _dict_value(fields.get("thumbnail_cache"))
    if thumbnail.get("status") is not None:
        return str(thumbnail["status"])
    if thumbnail.get("cache_key") is not None:
        return "GENERATED"
    return "NOT_REQUESTED"


def _first_timestamp_candidate(candidates: list[Any]) -> tuple[str | None, Any]:
    for candidate in candidates:
        if not isinstance(candidate, dict):
            continue
        raw = candidate.get("raw_value")
        normalized = candidate.get("normalized_utc")
        if isinstance(normalized, str):
            try:
                return (None if raw is None else str(raw), parse_timestamp(normalized))
            except ValueError:
                return (None if raw is None else str(raw), None)
        if raw is not None:
            return (str(raw), None)
    return (None, None)


def _first_file_timestamp_candidate(candidates: list[Any], source_name: str) -> str | None:
    for candidate in candidates:
        if isinstance(candidate, dict) and candidate.get("source") == source_name:
            raw = candidate.get("raw_value")
            return None if raw is None else str(raw)
    return None


def _timeline_source_artifact_types(source_type: str) -> list[str]:
    if source_type == TimelineSourceType.EVENT_LOG_ARTIFACT.value:
        return [ArtifactType.EVENT_LOG_RECORD.value]
    if source_type == TimelineSourceType.PREFETCH_ARTIFACT.value:
        return [ArtifactType.PREFETCH_EXECUTION.value]
    if source_type == TimelineSourceType.MEDIA_ARTIFACT.value:
        return [
            ArtifactType.MEDIA_IMAGE.value,
            ArtifactType.MEDIA_VIDEO.value,
            ArtifactType.MEDIA_AUDIO.value,
        ]
    if source_type == TimelineSourceType.BROWSER_ARTIFACT.value:
        return [
            ArtifactType.BROWSER_PROFILE.value,
            ArtifactType.BROWSER_VISIT.value,
            ArtifactType.BROWSER_SEARCH.value,
            ArtifactType.BROWSER_DOWNLOAD.value,
            ArtifactType.BROWSER_COOKIE.value,
            ArtifactType.BROWSER_CREDENTIAL.value,
            ArtifactType.BROWSER_CACHE_ENTRY.value,
            ArtifactType.BROWSER_DELETED_SQLITE_ROW.value,
            ArtifactType.BROWSER_PRIVATE_MODE_CANDIDATE.value,
        ]
    if source_type == TimelineSourceType.COMMUNICATION_ARTIFACT.value:
        return [
            ArtifactType.COMMUNICATION_PROFILE.value,
            ArtifactType.COMMUNICATION_ACCOUNT.value,
            ArtifactType.COMMUNICATION_CONVERSATION.value,
            ArtifactType.COMMUNICATION_MESSAGE.value,
            ArtifactType.COMMUNICATION_ATTACHMENT.value,
            ArtifactType.COMMUNICATION_UNSUPPORTED_STORE.value,
        ]
    return [
        ArtifactType.REGISTRY_KEY.value,
        ArtifactType.REGISTRY_VALUE.value,
        ArtifactType.REGISTRY_AUTORUN.value,
        ArtifactType.REGISTRY_USB_DEVICE.value,
        ArtifactType.REGISTRY_TIMEZONE.value,
        ArtifactType.REGISTRY_USERASSIST.value,
    ]


class SQLiteRepository:
    """SQLite-backed repository for Phase 1 application services."""

    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(str(db_path), factory=_ApexSQLiteConnection)
        self.connection.row_factory = sqlite3.Row
        self._configure_connection()

    def close(self) -> None:
        """Close the underlying SQLite connection."""

        self.connection.close()

    def initialize(self) -> None:
        """Create the Phase 1 schema if it does not exist."""

        with self.connection:
            self.connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS schema_migrations (
                    version TEXT PRIMARY KEY,
                    applied_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS cases (
                    case_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    description TEXT,
                    investigator TEXT,
                    locale TEXT NOT NULL,
                    timezone TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    schema_version TEXT NOT NULL,
                    metadata_json TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS evidence (
                    evidence_id TEXT PRIMARY KEY,
                    case_id TEXT NOT NULL REFERENCES cases(case_id),
                    display_name TEXT NOT NULL,
                    source_path TEXT NOT NULL,
                    evidence_type TEXT NOT NULL,
                    size_bytes INTEGER NOT NULL CHECK (size_bytes >= 0),
                    status TEXT NOT NULL,
                    read_only INTEGER NOT NULL CHECK (read_only = 1),
                    fingerprint_json TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    schema_version TEXT NOT NULL,
                    metadata_json TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_evidence_case_status
                    ON evidence(case_id, status);

                CREATE TABLE IF NOT EXISTS evidence_volumes (
                    volume_id TEXT PRIMARY KEY,
                    case_id TEXT NOT NULL REFERENCES cases(case_id),
                    evidence_id TEXT NOT NULL REFERENCES evidence(evidence_id),
                    reader_id TEXT NOT NULL,
                    reader_version TEXT NOT NULL,
                    volume_index INTEGER NOT NULL,
                    scheme TEXT NOT NULL,
                    partition_type TEXT NOT NULL,
                    start_lba INTEGER NOT NULL,
                    end_lba INTEGER NOT NULL,
                    byte_offset INTEGER NOT NULL,
                    byte_length INTEGER NOT NULL,
                    sector_size INTEGER NOT NULL,
                    name TEXT,
                    guid TEXT,
                    is_allocated INTEGER NOT NULL,
                    raw_locator_json TEXT NOT NULL,
                    warnings_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    volume_json TEXT NOT NULL,
                    UNIQUE(evidence_id, reader_id, reader_version, scheme, byte_offset, byte_length)
                );
                CREATE INDEX IF NOT EXISTS idx_evidence_volumes_evidence
                    ON evidence_volumes(evidence_id, volume_index, byte_offset);

                CREATE TABLE IF NOT EXISTS evidence_hashes (
                    hash_id TEXT PRIMARY KEY,
                    evidence_id TEXT NOT NULL REFERENCES evidence(evidence_id),
                    algorithm TEXT NOT NULL,
                    digest TEXT NOT NULL,
                    calculated_at TEXT NOT NULL,
                    file_size INTEGER NOT NULL,
                    chunk_size INTEGER NOT NULL,
                    verified INTEGER NOT NULL,
                    verification_status TEXT NOT NULL,
                    bytes_hashed INTEGER NOT NULL,
                    started_at TEXT NOT NULL,
                    completed_at TEXT NOT NULL,
                    job_id TEXT REFERENCES jobs(job_id)
                );
                CREATE INDEX IF NOT EXISTS idx_evidence_hashes_lookup
                    ON evidence_hashes(evidence_id, algorithm, calculated_at);

                CREATE TABLE IF NOT EXISTS hash_verifications (
                    verification_id TEXT PRIMARY KEY,
                    case_id TEXT NOT NULL REFERENCES cases(case_id),
                    evidence_id TEXT NOT NULL REFERENCES evidence(evidence_id),
                    algorithm TEXT NOT NULL,
                    expected_digest TEXT NOT NULL,
                    observed_digest TEXT,
                    status TEXT NOT NULL,
                    verified_at TEXT NOT NULL,
                    tool_version TEXT NOT NULL,
                    job_id TEXT REFERENCES jobs(job_id),
                    custody_event_id TEXT,
                    error_json TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_hash_verifications_evidence
                    ON hash_verifications(evidence_id, verified_at);

                CREATE TABLE IF NOT EXISTS jobs (
                    job_id TEXT PRIMARY KEY,
                    case_id TEXT NOT NULL REFERENCES cases(case_id),
                    evidence_id TEXT REFERENCES evidence(evidence_id),
                    job_type TEXT NOT NULL,
                    status TEXT NOT NULL,
                    progress_json TEXT NOT NULL,
                    queued_at TEXT NOT NULL,
                    started_at TEXT,
                    finished_at TEXT,
                    cancel_requested_at TEXT,
                    warnings_json TEXT NOT NULL,
                    errors_json TEXT NOT NULL,
                    profile_id TEXT,
                    priority INTEGER NOT NULL,
                    checkpoint_available INTEGER NOT NULL,
                    job_revision INTEGER NOT NULL DEFAULT 1,
                    index_revision INTEGER
                );
                CREATE INDEX IF NOT EXISTS idx_jobs_case_status
                    ON jobs(case_id, status, queued_at);

                CREATE TABLE IF NOT EXISTS custody_events (
                    event_id TEXT PRIMARY KEY,
                    case_id TEXT NOT NULL REFERENCES cases(case_id),
                    evidence_id TEXT NOT NULL REFERENCES evidence(evidence_id),
                    event_type TEXT NOT NULL,
                    immutable_revision INTEGER NOT NULL,
                    previous_event_hash TEXT,
                    event_hash TEXT NOT NULL,
                    occurred_at_utc TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    event_json TEXT NOT NULL,
                    UNIQUE(evidence_id, immutable_revision)
                );
                CREATE INDEX IF NOT EXISTS idx_custody_events_evidence_revision
                    ON custody_events(evidence_id, immutable_revision);


                CREATE TABLE IF NOT EXISTS fs_providers (
                    provider_id TEXT NOT NULL,
                    provider_version TEXT NOT NULL,
                    capabilities_json TEXT NOT NULL,
                    metadata_json TEXT NOT NULL,
                    registered_at TEXT NOT NULL,
                    PRIMARY KEY (provider_id, provider_version)
                );

                CREATE TABLE IF NOT EXISTS fs_nodes (
                    node_id TEXT PRIMARY KEY,
                    case_id TEXT NOT NULL REFERENCES cases(case_id),
                    evidence_id TEXT NOT NULL REFERENCES evidence(evidence_id),
                    provider_id TEXT NOT NULL,
                    provider_version TEXT NOT NULL,
                    parent_node_id TEXT REFERENCES fs_nodes(node_id),
                    original_name TEXT NOT NULL,
                    original_relative_path TEXT NOT NULL,
                    display_path TEXT NOT NULL,
                    comparison_path TEXT NOT NULL,
                    node_type TEXT NOT NULL,
                    file_size INTEGER,
                    extension TEXT,
                    mime_candidate TEXT,
                    mime_confidence TEXT NOT NULL,
                    fs_metadata_json TEXT NOT NULL,
                    platform TEXT NOT NULL,
                    timestamp_meanings_json TEXT NOT NULL,
                    raw_timestamps_json TEXT NOT NULL,
                    utc_timestamps_json TEXT NOT NULL,
                    timestamp_sources_json TEXT NOT NULL,
                    is_deleted INTEGER NOT NULL,
                    is_readable INTEGER NOT NULL,
                    is_link INTEGER NOT NULL,
                    is_traversed INTEGER NOT NULL,
                    raw_locator_json TEXT NOT NULL,
                    provider_metadata_json TEXT NOT NULL,
                    is_partial INTEGER NOT NULL,
                    index_revision INTEGER NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    UNIQUE(
                        case_id, evidence_id, provider_id, provider_version,
                        original_relative_path
                    )
                );
                CREATE INDEX IF NOT EXISTS idx_fs_nodes_parent
                    ON fs_nodes(evidence_id, parent_node_id, comparison_path, node_id);
                CREATE INDEX IF NOT EXISTS idx_fs_nodes_evidence_path
                    ON fs_nodes(evidence_id, comparison_path, node_id);
                CREATE INDEX IF NOT EXISTS idx_fs_nodes_extension
                    ON fs_nodes(evidence_id, extension, comparison_path, node_id);

                CREATE TABLE IF NOT EXISTS fs_index_jobs (
                    job_id TEXT PRIMARY KEY REFERENCES jobs(job_id),
                    case_id TEXT NOT NULL REFERENCES cases(case_id),
                    evidence_id TEXT NOT NULL REFERENCES evidence(evidence_id),
                    provider_id TEXT NOT NULL,
                    provider_version TEXT NOT NULL,
                    profile_type TEXT NOT NULL,
                    options_json TEXT NOT NULL,
                    option_fingerprint TEXT NOT NULL,
                    index_revision INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    pause_requested INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_fs_index_jobs_evidence
                    ON fs_index_jobs(evidence_id, status, created_at);

                CREATE TABLE IF NOT EXISTS fs_index_queue (
                    queue_id TEXT PRIMARY KEY,
                    job_id TEXT NOT NULL REFERENCES jobs(job_id),
                    node_id TEXT NOT NULL REFERENCES fs_nodes(node_id),
                    priority INTEGER NOT NULL,
                    depth INTEGER NOT NULL,
                    cursor_key TEXT,
                    status TEXT NOT NULL,
                    sequence INTEGER NOT NULL,
                    reason TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    UNIQUE(job_id, node_id, reason)
                );
                CREATE INDEX IF NOT EXISTS idx_fs_index_queue_pick
                    ON fs_index_queue(job_id, status, priority, sequence);

                CREATE TABLE IF NOT EXISTS fs_index_checkpoints (
                    job_id TEXT PRIMARY KEY REFERENCES jobs(job_id),
                    current_node_id TEXT REFERENCES fs_nodes(node_id),
                    current_path TEXT,
                    pending_queue_count INTEGER NOT NULL,
                    processed_items INTEGER NOT NULL,
                    discovered_items INTEGER NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS fs_index_coverage (
                    case_id TEXT NOT NULL REFERENCES cases(case_id),
                    evidence_id TEXT NOT NULL REFERENCES evidence(evidence_id),
                    provider_id TEXT NOT NULL,
                    provider_version TEXT NOT NULL,
                    profile_type TEXT NOT NULL,
                    option_fingerprint TEXT NOT NULL,
                    status TEXT NOT NULL,
                    discovered_items INTEGER NOT NULL,
                    processed_items INTEGER NOT NULL,
                    skipped_items INTEGER NOT NULL,
                    warning_count INTEGER NOT NULL,
                    error_count INTEGER NOT NULL,
                    current_path TEXT,
                    elapsed_seconds REAL NOT NULL,
                    throughput_items_per_second REAL,
                    estimated_remaining_seconds REAL,
                    eta_confidence TEXT NOT NULL,
                    index_revision INTEGER NOT NULL,
                    job_id TEXT REFERENCES jobs(job_id),
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY (
                        case_id, evidence_id, provider_id, provider_version,
                        profile_type, option_fingerprint
                    )
                );

                CREATE TABLE IF NOT EXISTS fs_scan_events (
                    event_id TEXT PRIMARY KEY,
                    job_id TEXT REFERENCES jobs(job_id),
                    case_id TEXT NOT NULL REFERENCES cases(case_id),
                    evidence_id TEXT NOT NULL REFERENCES evidence(evidence_id),
                    node_id TEXT REFERENCES fs_nodes(node_id),
                    severity TEXT NOT NULL,
                    code TEXT NOT NULL,
                    message_key TEXT NOT NULL,
                    developer_message TEXT NOT NULL,
                    path TEXT,
                    details_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_fs_scan_events_job
                    ON fs_scan_events(job_id, created_at);

                CREATE TABLE IF NOT EXISTS artifact_analyzers (
                    analyzer_id TEXT NOT NULL,
                    analyzer_version TEXT NOT NULL,
                    parser_backend TEXT NOT NULL,
                    parser_backend_version TEXT NOT NULL,
                    capabilities_json TEXT NOT NULL,
                    metadata_json TEXT NOT NULL,
                    registered_at TEXT NOT NULL,
                    PRIMARY KEY (analyzer_id, analyzer_version)
                );

                CREATE TABLE IF NOT EXISTS analyzer_option_fingerprints (
                    option_fingerprint TEXT NOT NULL,
                    analyzer_id TEXT NOT NULL,
                    analyzer_version TEXT NOT NULL,
                    options_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    PRIMARY KEY (option_fingerprint, analyzer_id, analyzer_version)
                );

                CREATE TABLE IF NOT EXISTS artifact_analysis_jobs (
                    job_id TEXT PRIMARY KEY REFERENCES jobs(job_id),
                    case_id TEXT NOT NULL REFERENCES cases(case_id),
                    evidence_id TEXT NOT NULL REFERENCES evidence(evidence_id),
                    profile_type TEXT NOT NULL,
                    options_json TEXT NOT NULL,
                    option_fingerprint TEXT NOT NULL,
                    index_revision INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    pause_requested INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_artifact_analysis_jobs_evidence
                    ON artifact_analysis_jobs(evidence_id, status, created_at);

                CREATE TABLE IF NOT EXISTS artifact_sources (
                    source_id TEXT PRIMARY KEY,
                    job_id TEXT REFERENCES jobs(job_id),
                    case_id TEXT NOT NULL REFERENCES cases(case_id),
                    evidence_id TEXT NOT NULL REFERENCES evidence(evidence_id),
                    source_file_node_id TEXT NOT NULL REFERENCES fs_nodes(node_id),
                    source_path TEXT NOT NULL,
                    source_kind TEXT NOT NULL,
                    comparison_key TEXT NOT NULL,
                    analyzer_id TEXT NOT NULL,
                    analyzer_version TEXT NOT NULL,
                    parser_backend TEXT NOT NULL,
                    parser_backend_version TEXT NOT NULL,
                    option_fingerprint TEXT NOT NULL,
                    source_fingerprint TEXT,
                    source_checkpoint_json TEXT,
                    inspected_count INTEGER NOT NULL DEFAULT 0,
                    status TEXT NOT NULL,
                    priority INTEGER NOT NULL,
                    source_order INTEGER NOT NULL,
                    is_partial INTEGER NOT NULL,
                    warning_count INTEGER NOT NULL,
                    error_count INTEGER NOT NULL,
                    artifact_count INTEGER NOT NULL,
                    parse_status TEXT,
                    last_error_json TEXT,
                    discovered_at TEXT NOT NULL,
                    analyzed_at TEXT,
                    updated_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_artifact_sources_job_pick
                    ON artifact_sources(job_id, status, priority, source_order, source_id);
                CREATE INDEX IF NOT EXISTS idx_artifact_sources_duplicate
                    ON artifact_sources(
                        evidence_id, source_file_node_id, analyzer_id,
                        analyzer_version, option_fingerprint, status
                    );

                CREATE TABLE IF NOT EXISTS artifacts (
                    artifact_id TEXT PRIMARY KEY,
                    case_id TEXT NOT NULL REFERENCES cases(case_id),
                    evidence_id TEXT NOT NULL REFERENCES evidence(evidence_id),
                    source_file_node_id TEXT NOT NULL REFERENCES fs_nodes(node_id),
                    artifact_type TEXT NOT NULL,
                    artifact_subtype TEXT NOT NULL,
                    analyzer_id TEXT NOT NULL,
                    analyzer_version TEXT NOT NULL,
                    parser_backend TEXT NOT NULL,
                    parser_backend_version TEXT NOT NULL,
                    source_path TEXT NOT NULL,
                    source_kind TEXT NOT NULL,
                    observed_at_raw TEXT,
                    observed_at_utc TEXT,
                    sort_timestamp TEXT NOT NULL,
                    timezone_source TEXT,
                    timezone_confidence TEXT NOT NULL,
                    title TEXT NOT NULL,
                    summary TEXT NOT NULL,
                    fields_json TEXT NOT NULL,
                    raw_locator_json TEXT NOT NULL,
                    citations_json TEXT NOT NULL,
                    warnings_json TEXT NOT NULL,
                    parse_status TEXT NOT NULL,
                    confidence REAL NOT NULL CHECK (confidence >= 0 AND confidence <= 1),
                    is_partial INTEGER NOT NULL,
                    index_revision INTEGER NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    dedup_key TEXT NOT NULL UNIQUE,
                    schema_version TEXT NOT NULL,
                    event_id INTEGER,
                    registry_path TEXT,
                    registry_path_key TEXT,
                    executable_name TEXT,
                    executable_name_key TEXT,
                    has_warnings INTEGER NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_artifacts_case_sort
                    ON artifacts(case_id, sort_timestamp, artifact_id);
                CREATE INDEX IF NOT EXISTS idx_artifacts_evidence_type
                    ON artifacts(evidence_id, artifact_type, sort_timestamp, artifact_id);
                CREATE INDEX IF NOT EXISTS idx_artifacts_source
                    ON artifacts(source_file_node_id, sort_timestamp, artifact_id);
                CREATE INDEX IF NOT EXISTS idx_artifacts_event_id
                    ON artifacts(event_id, sort_timestamp, artifact_id);
                CREATE INDEX IF NOT EXISTS idx_artifacts_registry_path
                    ON artifacts(registry_path_key, sort_timestamp, artifact_id);
                CREATE INDEX IF NOT EXISTS idx_artifacts_executable
                    ON artifacts(executable_name_key, sort_timestamp, artifact_id);

                CREATE TABLE IF NOT EXISTS artifact_warnings (
                    warning_id TEXT PRIMARY KEY,
                    job_id TEXT REFERENCES jobs(job_id),
                    case_id TEXT NOT NULL REFERENCES cases(case_id),
                    evidence_id TEXT NOT NULL REFERENCES evidence(evidence_id),
                    source_id TEXT REFERENCES artifact_sources(source_id),
                    source_file_node_id TEXT REFERENCES fs_nodes(node_id),
                    artifact_id TEXT REFERENCES artifacts(artifact_id),
                    severity TEXT NOT NULL,
                    code TEXT NOT NULL,
                    message_key TEXT NOT NULL,
                    developer_message TEXT NOT NULL,
                    source_path TEXT,
                    details_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_artifact_warnings_job
                    ON artifact_warnings(job_id, created_at, warning_id);
                CREATE INDEX IF NOT EXISTS idx_artifact_warnings_artifact
                    ON artifact_warnings(artifact_id, created_at, warning_id);

                CREATE TABLE IF NOT EXISTS artifact_checkpoints (
                    job_id TEXT PRIMARY KEY REFERENCES jobs(job_id),
                    current_source_id TEXT REFERENCES artifact_sources(source_id),
                    current_source_path TEXT,
                    pending_source_count INTEGER NOT NULL,
                    processed_sources INTEGER NOT NULL,
                    artifact_count INTEGER NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS artifact_coverage (
                    job_id TEXT PRIMARY KEY REFERENCES jobs(job_id),
                    case_id TEXT NOT NULL REFERENCES cases(case_id),
                    evidence_id TEXT NOT NULL REFERENCES evidence(evidence_id),
                    profile_type TEXT NOT NULL,
                    option_fingerprint TEXT NOT NULL,
                    status TEXT NOT NULL,
                    source_count INTEGER NOT NULL,
                    processed_sources INTEGER NOT NULL,
                    skipped_sources INTEGER NOT NULL,
                    artifact_count INTEGER NOT NULL,
                    warning_count INTEGER NOT NULL,
                    error_count INTEGER NOT NULL,
                    current_analyzer TEXT,
                    current_source_path TEXT,
                    elapsed_seconds REAL NOT NULL,
                    throughput_items_per_second REAL,
                    estimated_remaining_seconds REAL,
                    eta_confidence TEXT NOT NULL,
                    is_partial INTEGER NOT NULL,
                    index_revision INTEGER NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_artifact_coverage_evidence
                    ON artifact_coverage(evidence_id, updated_at, job_id);

                CREATE TABLE IF NOT EXISTS browser_profiles (
                    profile_id TEXT PRIMARY KEY,
                    case_id TEXT NOT NULL REFERENCES cases(case_id),
                    evidence_id TEXT NOT NULL REFERENCES evidence(evidence_id),
                    browser_family TEXT NOT NULL,
                    browser_name TEXT NOT NULL,
                    profile_name TEXT NOT NULL,
                    profile_path TEXT NOT NULL,
                    source_node_id TEXT NOT NULL REFERENCES fs_nodes(node_id),
                    operating_system TEXT NOT NULL,
                    user_candidate TEXT,
                    discovery_method TEXT NOT NULL,
                    source_revision INTEGER NOT NULL,
                    raw_locator_json TEXT NOT NULL,
                    citations_json TEXT NOT NULL,
                    warnings_json TEXT NOT NULL,
                    is_partial INTEGER NOT NULL,
                    discovered_at TEXT NOT NULL,
                    UNIQUE(case_id, evidence_id, browser_family, browser_name, profile_path)
                );
                CREATE INDEX IF NOT EXISTS idx_browser_profiles_case
                    ON browser_profiles(case_id, evidence_id, browser_family, browser_name);

                CREATE TABLE IF NOT EXISTS browser_analysis_jobs (
                    job_id TEXT PRIMARY KEY REFERENCES jobs(job_id),
                    case_id TEXT NOT NULL REFERENCES cases(case_id),
                    evidence_id TEXT NOT NULL REFERENCES evidence(evidence_id),
                    profile_type TEXT NOT NULL,
                    options_json TEXT NOT NULL,
                    option_fingerprint TEXT NOT NULL,
                    source_revision INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    pause_requested INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS browser_checkpoints (
                    job_id TEXT PRIMARY KEY REFERENCES jobs(job_id),
                    current_profile_id TEXT,
                    current_source_node_id TEXT,
                    current_path TEXT,
                    pending_items INTEGER NOT NULL,
                    processed_items INTEGER NOT NULL,
                    artifact_count INTEGER NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS browser_source_revisions (
                    source_revision_id TEXT PRIMARY KEY,
                    case_id TEXT NOT NULL REFERENCES cases(case_id),
                    evidence_id TEXT NOT NULL REFERENCES evidence(evidence_id),
                    source_node_id TEXT NOT NULL REFERENCES fs_nodes(node_id),
                    source_path TEXT NOT NULL,
                    source_revision INTEGER NOT NULL,
                    source_fingerprint TEXT NOT NULL,
                    analyzer_id TEXT NOT NULL,
                    analyzer_version TEXT NOT NULL,
                    observed_at TEXT NOT NULL,
                    UNIQUE(evidence_id, source_node_id, source_revision, analyzer_id)
                );

                CREATE TABLE IF NOT EXISTS browser_snapshot_records (
                    snapshot_id TEXT PRIMARY KEY,
                    case_id TEXT NOT NULL REFERENCES cases(case_id),
                    evidence_id TEXT NOT NULL REFERENCES evidence(evidence_id),
                    source_node_id TEXT NOT NULL REFERENCES fs_nodes(node_id),
                    source_path TEXT NOT NULL,
                    source_fingerprint TEXT NOT NULL,
                    snapshot_hash TEXT NOT NULL,
                    component_hashes_json TEXT NOT NULL,
                    wal_preserved INTEGER NOT NULL,
                    shm_preserved INTEGER NOT NULL,
                    cleanup_policy TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS browser_artifacts (
                    artifact_id TEXT PRIMARY KEY REFERENCES artifacts(artifact_id),
                    case_id TEXT NOT NULL REFERENCES cases(case_id),
                    evidence_id TEXT NOT NULL REFERENCES evidence(evidence_id),
                    profile_id TEXT NOT NULL,
                    browser_family TEXT NOT NULL,
                    browser_name TEXT NOT NULL,
                    artifact_type TEXT NOT NULL,
                    artifact_subtype TEXT NOT NULL,
                    title TEXT NOT NULL,
                    url TEXT,
                    domain TEXT,
                    search_term TEXT,
                    download_url TEXT,
                    download_path TEXT,
                    referrer_url TEXT,
                    visit_count INTEGER,
                    typed_count INTEGER,
                    transition TEXT,
                    raw_timestamp TEXT,
                    timestamp_semantics TEXT NOT NULL,
                    normalized_utc TEXT,
                    case_timezone TEXT NOT NULL,
                    displayed_case_time TEXT,
                    fields_json TEXT NOT NULL,
                    source_path TEXT NOT NULL,
                    source_node_id TEXT NOT NULL REFERENCES fs_nodes(node_id),
                    source_revision INTEGER NOT NULL,
                    analyzer_id TEXT NOT NULL,
                    analyzer_version TEXT NOT NULL,
                    raw_locator_json TEXT NOT NULL,
                    citations_json TEXT NOT NULL,
                    is_partial INTEGER NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_browser_artifacts_case_profile
                    ON browser_artifacts(
                        case_id, profile_id, artifact_type, normalized_utc, artifact_id
                    );

                CREATE TABLE IF NOT EXISTS media_analysis_jobs (
                    job_id TEXT PRIMARY KEY REFERENCES jobs(job_id),
                    case_id TEXT NOT NULL REFERENCES cases(case_id),
                    evidence_id TEXT NOT NULL REFERENCES evidence(evidence_id),
                    profile_type TEXT NOT NULL,
                    options_json TEXT NOT NULL,
                    option_fingerprint TEXT NOT NULL,
                    source_revision INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    pause_requested INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS media_checkpoints (
                    job_id TEXT PRIMARY KEY REFERENCES jobs(job_id),
                    current_source_node_id TEXT,
                    current_path TEXT,
                    pending_items INTEGER NOT NULL,
                    processed_items INTEGER NOT NULL,
                    artifact_count INTEGER NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS media_source_revisions (
                    source_revision_id TEXT PRIMARY KEY,
                    case_id TEXT NOT NULL REFERENCES cases(case_id),
                    evidence_id TEXT NOT NULL REFERENCES evidence(evidence_id),
                    source_node_id TEXT NOT NULL REFERENCES fs_nodes(node_id),
                    source_path TEXT NOT NULL,
                    source_revision INTEGER NOT NULL,
                    source_fingerprint TEXT NOT NULL,
                    analyzer_id TEXT NOT NULL,
                    analyzer_version TEXT NOT NULL,
                    observed_at TEXT NOT NULL,
                    UNIQUE(evidence_id, source_node_id, source_revision, analyzer_id)
                );

                CREATE TABLE IF NOT EXISTS media_artifacts (
                    media_artifact_id TEXT PRIMARY KEY REFERENCES artifacts(artifact_id),
                    case_id TEXT NOT NULL REFERENCES cases(case_id),
                    evidence_id TEXT NOT NULL REFERENCES evidence(evidence_id),
                    source_node_id TEXT NOT NULL REFERENCES fs_nodes(node_id),
                    source_path TEXT NOT NULL,
                    media_type TEXT NOT NULL,
                    format TEXT,
                    mime_candidate TEXT,
                    size_bytes INTEGER,
                    width INTEGER,
                    height INTEGER,
                    duration_ms INTEGER,
                    frame_rate TEXT,
                    video_codec TEXT,
                    audio_codec TEXT,
                    sample_rate INTEGER,
                    channels INTEGER,
                    bit_rate INTEGER,
                    creation_time_raw TEXT,
                    creation_time_utc TEXT,
                    modified_time_raw TEXT,
                    gps_latitude REAL,
                    gps_longitude REAL,
                    gps_altitude REAL,
                    camera_make TEXT,
                    camera_model TEXT,
                    software TEXT,
                    orientation TEXT,
                    metadata_json TEXT NOT NULL,
                    thumbnail_status TEXT NOT NULL,
                    analyzer_id TEXT NOT NULL,
                    analyzer_version TEXT NOT NULL,
                    backend_id TEXT NOT NULL,
                    backend_version TEXT NOT NULL,
                    source_revision INTEGER NOT NULL,
                    raw_locator_json TEXT NOT NULL,
                    citations_json TEXT NOT NULL,
                    is_partial INTEGER NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_media_artifacts_case_type
                    ON media_artifacts(case_id, media_type, source_path, media_artifact_id);

                CREATE TABLE IF NOT EXISTS thumbnail_records (
                    thumbnail_id TEXT PRIMARY KEY,
                    case_id TEXT NOT NULL REFERENCES cases(case_id),
                    evidence_id TEXT NOT NULL REFERENCES evidence(evidence_id),
                    source_node_id TEXT NOT NULL REFERENCES fs_nodes(node_id),
                    source_artifact_id TEXT REFERENCES artifacts(artifact_id),
                    source_fingerprint TEXT NOT NULL,
                    cache_key TEXT NOT NULL,
                    relative_path TEXT NOT NULL,
                    output_format TEXT NOT NULL,
                    width INTEGER,
                    height INTEGER,
                    size_bytes INTEGER NOT NULL,
                    content_sha256 TEXT NOT NULL,
                    status TEXT NOT NULL,
                    analyzer_id TEXT NOT NULL,
                    analyzer_version TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    UNIQUE(case_id, source_node_id, cache_key)
                );

                CREATE TABLE IF NOT EXISTS machine_extracted_candidates (
                    candidate_id TEXT PRIMARY KEY,
                    case_id TEXT NOT NULL REFERENCES cases(case_id),
                    evidence_id TEXT NOT NULL REFERENCES evidence(evidence_id),
                    source_node_id TEXT NOT NULL REFERENCES fs_nodes(node_id),
                    source_type TEXT NOT NULL,
                    extraction_type TEXT NOT NULL,
                    text TEXT NOT NULL,
                    language TEXT,
                    confidence REAL NOT NULL CHECK (confidence >= 0 AND confidence <= 1),
                    provider_id TEXT NOT NULL,
                    provider_version TEXT NOT NULL,
                    model_id TEXT,
                    region_json TEXT,
                    frame_number INTEGER,
                    media_timestamp_ms INTEGER,
                    audio_start_ms INTEGER,
                    audio_end_ms INTEGER,
                    raw_locator_json TEXT NOT NULL,
                    citations_json TEXT NOT NULL,
                    review_status TEXT NOT NULL,
                    reviewed_by TEXT,
                    reviewed_at TEXT,
                    correction_text TEXT,
                    source_revision INTEGER NOT NULL,
                    is_partial INTEGER NOT NULL,
                    created_at TEXT NOT NULL,
                    CHECK (review_status <> 'CORRECTED' OR correction_text IS NOT NULL)
                );
                CREATE INDEX IF NOT EXISTS idx_machine_candidates_case
                    ON machine_extracted_candidates(case_id, review_status, candidate_id);

                CREATE TABLE IF NOT EXISTS candidate_review_events (
                    review_event_id TEXT PRIMARY KEY,
                    candidate_id TEXT NOT NULL
                        REFERENCES machine_extracted_candidates(candidate_id),
                    case_id TEXT NOT NULL REFERENCES cases(case_id),
                    review_status TEXT NOT NULL,
                    reviewed_by TEXT NOT NULL,
                    reviewed_at TEXT NOT NULL,
                    correction_text TEXT,
                    previous_review_status TEXT,
                    reason TEXT,
                    CHECK (review_status <> 'CORRECTED' OR correction_text IS NOT NULL)
                );
                CREATE INDEX IF NOT EXISTS idx_candidate_review_events_candidate
                    ON candidate_review_events(candidate_id, reviewed_at, review_event_id);

                CREATE TABLE IF NOT EXISTS provider_capabilities (
                    provider_id TEXT NOT NULL,
                    provider_version TEXT NOT NULL,
                    capability_type TEXT NOT NULL,
                    is_available INTEGER NOT NULL,
                    supported_inputs_json TEXT NOT NULL,
                    supported_outputs_json TEXT NOT NULL,
                    unavailable_reason TEXT,
                    warnings_json TEXT NOT NULL,
                    metadata_json TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY (provider_id, provider_version, capability_type)
                );

                CREATE TABLE IF NOT EXISTS secret_provider_capabilities (
                    provider_id TEXT NOT NULL,
                    provider_version TEXT NOT NULL,
                    capability_type TEXT NOT NULL,
                    runtime_status TEXT NOT NULL,
                    supported_key_sources_json TEXT NOT NULL,
                    supported_algorithms_json TEXT NOT NULL,
                    requires_host INTEGER NOT NULL,
                    requires_network INTEGER NOT NULL,
                    warnings_json TEXT NOT NULL,
                    generated_at TEXT NOT NULL,
                    capability_version TEXT NOT NULL,
                    capability_json TEXT NOT NULL,
                    PRIMARY KEY (provider_id, provider_version, capability_type)
                );
                CREATE INDEX IF NOT EXISTS idx_secret_capabilities_status
                    ON secret_provider_capabilities(capability_type, runtime_status);

                CREATE TABLE IF NOT EXISTS decryption_attempts (
                    attempt_id TEXT PRIMARY KEY,
                    case_id TEXT NOT NULL REFERENCES cases(case_id),
                    evidence_id TEXT REFERENCES evidence(evidence_id),
                    provider_id TEXT NOT NULL,
                    provider_version TEXT NOT NULL,
                    algorithm TEXT NOT NULL,
                    key_source_kind TEXT NOT NULL,
                    status TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    completed_at TEXT,
                    error_code TEXT,
                    error_message TEXT,
                    warnings_json TEXT NOT NULL,
                    attempt_fingerprint TEXT NOT NULL,
                    attempt_json TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_decryption_attempts_case
                    ON decryption_attempts(case_id, started_at DESC, attempt_id);
                CREATE INDEX IF NOT EXISTS idx_decryption_attempts_provider
                    ON decryption_attempts(provider_id, provider_version, status);

                CREATE TABLE IF NOT EXISTS decryption_results (
                    attempt_id TEXT PRIMARY KEY
                        REFERENCES decryption_attempts(attempt_id),
                    case_id TEXT NOT NULL REFERENCES cases(case_id),
                    evidence_id TEXT REFERENCES evidence(evidence_id),
                    status TEXT NOT NULL,
                    output_kind TEXT,
                    content_sha256 TEXT,
                    content_length INTEGER,
                    partial INTEGER NOT NULL,
                    citations_json TEXT NOT NULL,
                    metadata_json TEXT NOT NULL,
                    result_fingerprint TEXT NOT NULL,
                    result_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_decryption_results_case
                    ON decryption_results(case_id, status, attempt_id);

                CREATE TABLE IF NOT EXISTS cache_entries (
                    key_sha256 TEXT PRIMARY KEY,
                    case_id TEXT NOT NULL REFERENCES cases(case_id),
                    kind TEXT NOT NULL,
                    relative_path TEXT NOT NULL,
                    size_bytes INTEGER NOT NULL,
                    content_sha256 TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    last_accessed_at TEXT NOT NULL,
                    expires_at TEXT,
                    producer_json TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_cache_entries_case_kind_lru
                    ON cache_entries(case_id, kind, last_accessed_at);
                CREATE INDEX IF NOT EXISTS idx_cache_entries_expires
                    ON cache_entries(expires_at);

                CREATE TABLE IF NOT EXISTS search_index_metadata (
                    case_id TEXT PRIMARY KEY REFERENCES cases(case_id),
                    index_revision INTEGER NOT NULL,
                    backend TEXT NOT NULL,
                    backend_version TEXT NOT NULL,
                    fts5_available INTEGER NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS search_documents (
                    document_id TEXT PRIMARY KEY,
                    case_id TEXT NOT NULL REFERENCES cases(case_id),
                    evidence_id TEXT NOT NULL REFERENCES evidence(evidence_id),
                    source_type TEXT NOT NULL,
                    source_id TEXT NOT NULL,
                    source_revision INTEGER NOT NULL,
                    document_type TEXT NOT NULL,
                    title TEXT NOT NULL,
                    path TEXT,
                    normalized_path TEXT,
                    searchable_text TEXT NOT NULL,
                    structured_fields_json TEXT NOT NULL,
                    observed_at_utc TEXT,
                    raw_locator_json TEXT NOT NULL,
                    citations_json TEXT NOT NULL,
                    analyzer_id TEXT,
                    analyzer_version TEXT,
                    is_partial INTEGER NOT NULL,
                    index_revision INTEGER NOT NULL,
                    search_backend TEXT NOT NULL,
                    search_backend_version TEXT NOT NULL,
                    is_stale INTEGER NOT NULL DEFAULT 0,
                    fts_rowid INTEGER,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    UNIQUE(
                        case_id, evidence_id, source_type, source_id,
                        source_revision, document_type
                    )
                );
                CREATE INDEX IF NOT EXISTS idx_search_documents_case_revision
                    ON search_documents(case_id, index_revision, document_id);
                CREATE INDEX IF NOT EXISTS idx_search_documents_source
                    ON search_documents(
                        case_id, evidence_id, source_type, source_id, source_revision
                    );
                CREATE INDEX IF NOT EXISTS idx_search_documents_type_time
                    ON search_documents(case_id, document_type, observed_at_utc, document_id);

                CREATE TABLE IF NOT EXISTS search_jobs (
                    job_id TEXT PRIMARY KEY REFERENCES jobs(job_id),
                    case_id TEXT NOT NULL REFERENCES cases(case_id),
                    evidence_id TEXT REFERENCES evidence(evidence_id),
                    profile_type TEXT NOT NULL,
                    options_json TEXT NOT NULL,
                    option_fingerprint TEXT NOT NULL,
                    index_revision INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    pause_requested INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_search_jobs_case_status
                    ON search_jobs(case_id, status, created_at);

                CREATE TABLE IF NOT EXISTS search_checkpoints (
                    job_id TEXT PRIMARY KEY REFERENCES jobs(job_id),
                    current_source_type TEXT,
                    current_source_id TEXT,
                    processed_items INTEGER NOT NULL,
                    indexed_items INTEGER NOT NULL,
                    skipped_items INTEGER NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS search_queries (
                    query_id TEXT PRIMARY KEY,
                    query_text TEXT NOT NULL,
                    query_mode TEXT NOT NULL,
                    case_id TEXT NOT NULL REFERENCES cases(case_id),
                    evidence_ids_json TEXT NOT NULL,
                    source_types_json TEXT NOT NULL,
                    document_types_json TEXT NOT NULL,
                    time_range_json TEXT NOT NULL,
                    path_scope TEXT,
                    filters_json TEXT NOT NULL,
                    keyword_set_id TEXT,
                    keyword_set_version INTEGER,
                    index_revision INTEGER,
                    options_fingerprint TEXT NOT NULL,
                    sort TEXT NOT NULL,
                    limit_value INTEGER NOT NULL,
                    case_sensitive INTEGER NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_search_queries_case_created
                    ON search_queries(case_id, created_at, query_id);

                CREATE TABLE IF NOT EXISTS search_executions (
                    execution_id TEXT PRIMARY KEY,
                    query_id TEXT NOT NULL REFERENCES search_queries(query_id),
                    case_id TEXT NOT NULL REFERENCES cases(case_id),
                    query_text TEXT NOT NULL,
                    query_mode TEXT NOT NULL,
                    keyword_set_id TEXT,
                    keyword_set_version INTEGER,
                    options_json TEXT NOT NULL,
                    options_fingerprint TEXT NOT NULL,
                    search_backend TEXT NOT NULL,
                    search_backend_version TEXT NOT NULL,
                    index_revision INTEGER NOT NULL,
                    source_revision_fingerprint TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    completed_at TEXT,
                    status TEXT NOT NULL,
                    is_partial INTEGER NOT NULL,
                    result_count INTEGER NOT NULL,
                    warnings_json TEXT NOT NULL,
                    cache_key TEXT,
                    cache_hit INTEGER NOT NULL,
                    zero_result_keyword_ids_json TEXT NOT NULL,
                    execution_revision INTEGER NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_search_executions_case_started
                    ON search_executions(case_id, started_at DESC, execution_id);

                CREATE TABLE IF NOT EXISTS search_results (
                    result_id TEXT PRIMARY KEY,
                    query_id TEXT NOT NULL REFERENCES search_queries(query_id),
                    document_id TEXT NOT NULL REFERENCES search_documents(document_id),
                    source_type TEXT NOT NULL,
                    source_id TEXT NOT NULL,
                    rank REAL NOT NULL,
                    matched_fields_json TEXT NOT NULL,
                    matched_terms_json TEXT NOT NULL,
                    snippet TEXT NOT NULL,
                    raw_locator_json TEXT NOT NULL,
                    citations_json TEXT NOT NULL,
                    is_partial INTEGER NOT NULL,
                    index_revision INTEGER NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_search_results_query_rank
                    ON search_results(query_id, rank, document_id);

                CREATE TABLE IF NOT EXISTS search_cache (
                    cache_key TEXT PRIMARY KEY,
                    case_id TEXT NOT NULL REFERENCES cases(case_id),
                    query_fingerprint TEXT NOT NULL,
                    keyword_set_version INTEGER,
                    index_revision INTEGER NOT NULL,
                    source_revision_fingerprint TEXT NOT NULL,
                    is_partial INTEGER NOT NULL,
                    result_count INTEGER NOT NULL,
                    results_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    expires_at TEXT,
                    hit_count INTEGER NOT NULL,
                    invalidated_at TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_search_cache_case_revision
                    ON search_cache(case_id, index_revision, invalidated_at);

                CREATE TABLE IF NOT EXISTS keyword_sets (
                    keyword_set_id TEXT PRIMARY KEY,
                    case_id TEXT NOT NULL REFERENCES cases(case_id),
                    name TEXT NOT NULL,
                    description TEXT,
                    current_version INTEGER NOT NULL,
                    current_version_id TEXT NOT NULL,
                    current_status TEXT NOT NULL,
                    created_by TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_keyword_sets_case
                    ON keyword_sets(case_id, current_status, updated_at);

                CREATE TABLE IF NOT EXISTS keyword_set_versions (
                    keyword_set_version_id TEXT PRIMARY KEY,
                    keyword_set_id TEXT NOT NULL REFERENCES keyword_sets(keyword_set_id),
                    case_id TEXT NOT NULL REFERENCES cases(case_id),
                    name TEXT NOT NULL,
                    description TEXT,
                    version INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    created_by TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    default_options_json TEXT NOT NULL,
                    previous_version_id TEXT,
                    UNIQUE(keyword_set_id, version)
                );
                CREATE INDEX IF NOT EXISTS idx_keyword_set_versions_set
                    ON keyword_set_versions(keyword_set_id, version DESC);

                CREATE TABLE IF NOT EXISTS keywords (
                    keyword_id TEXT NOT NULL,
                    keyword_set_version_id TEXT NOT NULL
                        REFERENCES keyword_set_versions(keyword_set_version_id),
                    term TEXT NOT NULL,
                    normalized_term TEXT NOT NULL,
                    keyword_type TEXT NOT NULL,
                    match_mode TEXT NOT NULL,
                    case_sensitive INTEGER NOT NULL,
                    enabled INTEGER NOT NULL,
                    notes TEXT,
                    source TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    PRIMARY KEY(keyword_set_version_id, keyword_id),
                    UNIQUE(keyword_set_version_id, normalized_term, match_mode, case_sensitive)
                );

                CREATE TABLE IF NOT EXISTS timeline_revisions (
                    case_id TEXT NOT NULL REFERENCES cases(case_id),
                    timeline_revision INTEGER NOT NULL,
                    created_at TEXT NOT NULL,
                    PRIMARY KEY(case_id, timeline_revision)
                );

                CREATE TABLE IF NOT EXISTS timeline_jobs (
                    job_id TEXT PRIMARY KEY REFERENCES jobs(job_id),
                    case_id TEXT NOT NULL REFERENCES cases(case_id),
                    evidence_id TEXT REFERENCES evidence(evidence_id),
                    profile_type TEXT NOT NULL,
                    options_json TEXT NOT NULL,
                    option_fingerprint TEXT NOT NULL,
                    timeline_revision INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    pause_requested INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_timeline_jobs_case_status
                    ON timeline_jobs(case_id, status, created_at);

                CREATE TABLE IF NOT EXISTS timeline_checkpoints (
                    job_id TEXT PRIMARY KEY REFERENCES jobs(job_id),
                    current_source_type TEXT,
                    current_source_id TEXT,
                    processed_items INTEGER NOT NULL,
                    event_count INTEGER NOT NULL,
                    skipped_items INTEGER NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS timeline_events (
                    timeline_event_id TEXT PRIMARY KEY,
                    case_id TEXT NOT NULL REFERENCES cases(case_id),
                    evidence_id TEXT NOT NULL REFERENCES evidence(evidence_id),
                    source_type TEXT NOT NULL,
                    source_id TEXT NOT NULL,
                    source_revision INTEGER NOT NULL,
                    event_type TEXT NOT NULL,
                    event_subtype TEXT NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL,
                    raw_timestamp TEXT,
                    raw_timezone TEXT,
                    timestamp_semantics TEXT NOT NULL,
                    normalized_utc TEXT,
                    sort_timestamp TEXT NOT NULL,
                    case_timezone TEXT NOT NULL,
                    displayed_case_time TEXT,
                    timezone_source TEXT NOT NULL,
                    timezone_confidence TEXT NOT NULL,
                    precision TEXT NOT NULL,
                    analyzer_id TEXT,
                    analyzer_version TEXT,
                    raw_locator_json TEXT NOT NULL,
                    citations_json TEXT NOT NULL,
                    fields_json TEXT NOT NULL,
                    is_partial INTEGER NOT NULL,
                    timeline_revision INTEGER NOT NULL,
                    created_at TEXT NOT NULL,
                    dedup_key TEXT NOT NULL UNIQUE,
                    artifact_type TEXT,
                    path_key TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_timeline_events_case_sort
                    ON timeline_events(case_id, sort_timestamp, timeline_event_id);
                CREATE INDEX IF NOT EXISTS idx_timeline_events_evidence_sort
                    ON timeline_events(evidence_id, sort_timestamp, timeline_event_id);
                CREATE INDEX IF NOT EXISTS idx_timeline_events_type_sort
                    ON timeline_events(case_id, event_type, sort_timestamp, timeline_event_id);
                CREATE INDEX IF NOT EXISTS idx_timeline_events_source
                    ON timeline_events(source_type, source_id, source_revision);
                CREATE INDEX IF NOT EXISTS idx_timeline_events_path
                    ON timeline_events(case_id, path_key, sort_timestamp, timeline_event_id);

                CREATE TABLE IF NOT EXISTS timeline_coverage (
                    job_id TEXT PRIMARY KEY REFERENCES jobs(job_id),
                    case_id TEXT NOT NULL REFERENCES cases(case_id),
                    evidence_id TEXT REFERENCES evidence(evidence_id),
                    status TEXT NOT NULL,
                    discovered_items INTEGER NOT NULL,
                    processed_items INTEGER NOT NULL,
                    skipped_items INTEGER NOT NULL,
                    event_count INTEGER NOT NULL,
                    warning_count INTEGER NOT NULL,
                    error_count INTEGER NOT NULL,
                    current_source TEXT,
                    is_partial INTEGER NOT NULL,
                    timeline_revision INTEGER NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS timezone_mappings (
                    mapping_id TEXT PRIMARY KEY,
                    windows_time_zone_key_name TEXT NOT NULL,
                    iana_timezone TEXT NOT NULL,
                    confidence TEXT NOT NULL,
                    source TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    UNIQUE(windows_time_zone_key_name, iana_timezone)
                );

                CREATE TABLE IF NOT EXISTS gui_session_contexts (
                    session_context_id TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    case_id TEXT NOT NULL REFERENCES cases(case_id),
                    actor_id TEXT,
                    locale TEXT NOT NULL,
                    timezone TEXT NOT NULL,
                    current_route TEXT NOT NULL,
                    current_panel TEXT,
                    active_evidence_id TEXT REFERENCES evidence(evidence_id),
                    selected_file_node_ids_json TEXT NOT NULL,
                    selected_artifact_ids_json TEXT NOT NULL,
                    selected_timeline_event_ids_json TEXT NOT NULL,
                    selected_search_result_ids_json TEXT NOT NULL,
                    selected_media_artifact_ids_json TEXT NOT NULL,
                    selected_browser_artifact_ids_json TEXT NOT NULL,
                    selected_candidate_ids_json TEXT NOT NULL,
                    active_filters_json TEXT NOT NULL,
                    active_sort_json TEXT NOT NULL,
                    active_time_range_json TEXT NOT NULL,
                    active_keyword_set_id TEXT,
                    active_keyword_set_version INTEGER,
                    active_search_execution_id TEXT,
                    active_timeline_revision INTEGER,
                    active_context_scope TEXT NOT NULL,
                    ui_preferences_json TEXT NOT NULL,
                    context_revision INTEGER NOT NULL CHECK (context_revision >= 1),
                    source_revision_fingerprint TEXT NOT NULL,
                    is_partial INTEGER NOT NULL,
                    stale_reasons_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    expires_at TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_gui_session_contexts_case
                    ON gui_session_contexts(case_id, updated_at, session_context_id);

                CREATE TABLE IF NOT EXISTS gui_session_context_revisions (
                    session_context_id TEXT NOT NULL
                        REFERENCES gui_session_contexts(session_context_id),
                    context_revision INTEGER NOT NULL,
                    context_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    PRIMARY KEY (session_context_id, context_revision)
                );

                CREATE TABLE IF NOT EXISTS analysis_context_snapshots (
                    context_snapshot_id TEXT PRIMARY KEY,
                    case_id TEXT NOT NULL REFERENCES cases(case_id),
                    session_context_id TEXT,
                    session_context_revision INTEGER,
                    actor_id TEXT,
                    purpose TEXT NOT NULL,
                    scopes_json TEXT NOT NULL,
                    included_resource_ids_json TEXT NOT NULL,
                    excluded_resource_ids_json TEXT NOT NULL,
                    filters_json TEXT NOT NULL,
                    time_range_json TEXT NOT NULL,
                    source_revisions_json TEXT NOT NULL,
                    analyzer_versions_json TEXT NOT NULL,
                    search_index_revision INTEGER,
                    timeline_revision INTEGER,
                    keyword_set_id TEXT,
                    keyword_set_version INTEGER,
                    search_execution_id TEXT,
                    partial_state_json TEXT NOT NULL,
                    stale_state_json TEXT NOT NULL,
                    warnings_json TEXT NOT NULL,
                    citations_json TEXT NOT NULL,
                    context_fingerprint TEXT NOT NULL,
                    previous_snapshot_id TEXT
                        REFERENCES analysis_context_snapshots(context_snapshot_id),
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_analysis_context_snapshots_case
                    ON analysis_context_snapshots(case_id, created_at, context_snapshot_id);

                CREATE TABLE IF NOT EXISTS analysis_scope_contexts (
                    scope_context_id TEXT PRIMARY KEY,
                    context_snapshot_id TEXT NOT NULL
                        REFERENCES analysis_context_snapshots(context_snapshot_id),
                    scope_type TEXT NOT NULL,
                    case_id TEXT NOT NULL REFERENCES cases(case_id),
                    evidence_ids_json TEXT NOT NULL,
                    resource_ids_json TEXT NOT NULL,
                    source_revisions_json TEXT NOT NULL,
                    analyzer_versions_json TEXT NOT NULL,
                    filters_json TEXT NOT NULL,
                    sort_json TEXT NOT NULL,
                    time_range_json TEXT NOT NULL,
                    result_count INTEGER NOT NULL,
                    included_count INTEGER NOT NULL,
                    excluded_count INTEGER NOT NULL,
                    is_partial INTEGER NOT NULL,
                    coverage_json TEXT NOT NULL,
                    stale_reasons_json TEXT NOT NULL,
                    warnings_json TEXT NOT NULL,
                    citations_json TEXT NOT NULL,
                    continuation_cursor TEXT,
                    scope_fingerprint TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    UNIQUE(context_snapshot_id, scope_type)
                );

                CREATE TABLE IF NOT EXISTS context_snapshot_resources (
                    context_snapshot_id TEXT NOT NULL
                        REFERENCES analysis_context_snapshots(context_snapshot_id),
                    resource_type TEXT NOT NULL,
                    resource_id TEXT NOT NULL,
                    source_revision TEXT,
                    included INTEGER NOT NULL,
                    PRIMARY KEY (context_snapshot_id, resource_type, resource_id)
                );

                CREATE TABLE IF NOT EXISTS context_revision_states (
                    state_id TEXT PRIMARY KEY,
                    context_snapshot_id TEXT
                        REFERENCES analysis_context_snapshots(context_snapshot_id),
                    resource_type TEXT NOT NULL,
                    resource_id TEXT NOT NULL,
                    expected_revision TEXT,
                    current_revision TEXT,
                    status TEXT NOT NULL,
                    reason TEXT,
                    detected_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS ai_assistance_requests (
                    assistance_request_id TEXT PRIMARY KEY,
                    case_id TEXT NOT NULL REFERENCES cases(case_id),
                    context_snapshot_id TEXT NOT NULL
                        REFERENCES analysis_context_snapshots(context_snapshot_id),
                    purpose TEXT NOT NULL,
                    requested_operations_json TEXT NOT NULL,
                    requested_scopes_json TEXT NOT NULL,
                    scope_context_ids_json TEXT NOT NULL,
                    locale TEXT NOT NULL,
                    timezone TEXT NOT NULL,
                    context_fingerprint TEXT NOT NULL,
                    source_revision_fingerprint TEXT NOT NULL,
                    is_partial INTEGER NOT NULL,
                    is_stale INTEGER NOT NULL,
                    coverage_summary_json TEXT NOT NULL,
                    warnings_json TEXT NOT NULL,
                    citations_json TEXT NOT NULL,
                    max_keyword_candidates INTEGER NOT NULL,
                    max_summary_length INTEGER NOT NULL,
                    requested_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    request_version TEXT NOT NULL,
                    correlation_id TEXT,
                    request_fingerprint TEXT NOT NULL UNIQUE,
                    resource_count INTEGER NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_ai_assistance_requests_case
                    ON ai_assistance_requests(case_id, requested_at DESC, assistance_request_id);
                CREATE INDEX IF NOT EXISTS idx_ai_assistance_requests_snapshot
                    ON ai_assistance_requests(context_snapshot_id, requested_at DESC);

                CREATE TABLE IF NOT EXISTS ai_keyword_recommendation_batches (
                    recommendation_batch_id TEXT PRIMARY KEY,
                    assistance_request_id TEXT NOT NULL
                        REFERENCES ai_assistance_requests(assistance_request_id),
                    case_id TEXT NOT NULL REFERENCES cases(case_id),
                    context_snapshot_id TEXT NOT NULL
                        REFERENCES analysis_context_snapshots(context_snapshot_id),
                    provider_id TEXT NOT NULL,
                    provider_version TEXT NOT NULL,
                    model_id TEXT NOT NULL,
                    external_request_id TEXT,
                    generation_started_at TEXT NOT NULL,
                    generation_completed_at TEXT NOT NULL,
                    result_hash TEXT NOT NULL,
                    recommendation_count INTEGER NOT NULL,
                    partial_state_json TEXT NOT NULL,
                    stale_state_json TEXT NOT NULL,
                    warnings_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    batch_version TEXT NOT NULL,
                    UNIQUE(assistance_request_id, result_hash)
                );
                CREATE INDEX IF NOT EXISTS idx_ai_keyword_batches_case
                    ON ai_keyword_recommendation_batches(
                        case_id, created_at DESC, recommendation_batch_id
                    );

                CREATE TABLE IF NOT EXISTS ai_keyword_recommendations (
                    recommendation_id TEXT PRIMARY KEY,
                    recommendation_batch_id TEXT NOT NULL
                        REFERENCES ai_keyword_recommendation_batches(recommendation_batch_id),
                    case_id TEXT NOT NULL REFERENCES cases(case_id),
                    context_snapshot_id TEXT NOT NULL
                        REFERENCES analysis_context_snapshots(context_snapshot_id),
                    keyword_type TEXT NOT NULL,
                    value TEXT NOT NULL,
                    normalized_value TEXT NOT NULL,
                    display_value TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    confidence TEXT NOT NULL,
                    recommended_scope TEXT NOT NULL,
                    evidence_ids_json TEXT NOT NULL,
                    source_resource_ids_json TEXT NOT NULL,
                    citations_json TEXT NOT NULL,
                    is_partial INTEGER NOT NULL,
                    stale_reasons_json TEXT NOT NULL,
                    risk_flags_json TEXT NOT NULL,
                    review_status TEXT NOT NULL,
                    current_review_revision INTEGER NOT NULL,
                    content_fingerprint TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    UNIQUE(recommendation_batch_id, content_fingerprint)
                );
                CREATE INDEX IF NOT EXISTS idx_ai_keyword_recommendations_case
                    ON ai_keyword_recommendations(
                        case_id, recommendation_batch_id, recommendation_id
                    );
                CREATE INDEX IF NOT EXISTS idx_ai_keyword_recommendations_content
                    ON ai_keyword_recommendations(case_id, normalized_value, keyword_type);

                CREATE TABLE IF NOT EXISTS ai_scope_summaries (
                    scope_summary_id TEXT PRIMARY KEY,
                    assistance_request_id TEXT NOT NULL
                        REFERENCES ai_assistance_requests(assistance_request_id),
                    case_id TEXT NOT NULL REFERENCES cases(case_id),
                    context_snapshot_id TEXT NOT NULL
                        REFERENCES analysis_context_snapshots(context_snapshot_id),
                    scope_context_id TEXT NOT NULL
                        REFERENCES analysis_scope_contexts(scope_context_id),
                    scope_type TEXT NOT NULL,
                    provider_id TEXT NOT NULL,
                    provider_version TEXT NOT NULL,
                    model_id TEXT NOT NULL,
                    external_request_id TEXT,
                    title TEXT NOT NULL,
                    summary_text TEXT NOT NULL,
                    key_points_json TEXT NOT NULL,
                    referenced_resource_ids_json TEXT NOT NULL,
                    citations_json TEXT NOT NULL,
                    partial_state_json TEXT NOT NULL,
                    stale_state_json TEXT NOT NULL,
                    coverage_json TEXT NOT NULL,
                    warnings_json TEXT NOT NULL,
                    review_status TEXT NOT NULL,
                    current_review_revision INTEGER NOT NULL,
                    content_fingerprint TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    summary_version TEXT NOT NULL,
                    UNIQUE(assistance_request_id, scope_context_id, content_fingerprint)
                );
                CREATE INDEX IF NOT EXISTS idx_ai_scope_summaries_case
                    ON ai_scope_summaries(case_id, created_at DESC, scope_summary_id);
                CREATE INDEX IF NOT EXISTS idx_ai_scope_summaries_scope
                    ON ai_scope_summaries(scope_context_id, created_at DESC);

                CREATE TABLE IF NOT EXISTS ai_verification_events (
                    verification_event_id TEXT PRIMARY KEY,
                    case_id TEXT NOT NULL REFERENCES cases(case_id),
                    target_type TEXT NOT NULL,
                    target_id TEXT NOT NULL,
                    action TEXT NOT NULL,
                    previous_status TEXT NOT NULL,
                    new_status TEXT NOT NULL,
                    actor_id TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    corrected_value TEXT,
                    corrected_reason TEXT,
                    review_revision INTEGER NOT NULL,
                    previous_event_hash TEXT,
                    event_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    UNIQUE(target_type, target_id, review_revision),
                    UNIQUE(target_type, target_id, event_hash)
                );
                CREATE INDEX IF NOT EXISTS idx_ai_verification_events_target
                    ON ai_verification_events(target_type, target_id, review_revision);

                CREATE TABLE IF NOT EXISTS ai_keyword_promotions (
                    promotion_id TEXT PRIMARY KEY,
                    case_id TEXT NOT NULL REFERENCES cases(case_id),
                    recommendation_id TEXT NOT NULL
                        REFERENCES ai_keyword_recommendations(recommendation_id),
                    review_revision INTEGER NOT NULL,
                    keyword_set_id TEXT NOT NULL REFERENCES keyword_sets(keyword_set_id),
                    keyword_set_version_id TEXT,
                    keyword_set_version INTEGER,
                    promoted_keyword_id TEXT,
                    promoted_value TEXT NOT NULL,
                    status TEXT NOT NULL,
                    duplicate INTEGER NOT NULL,
                    source_context_snapshot_id TEXT NOT NULL
                        REFERENCES analysis_context_snapshots(context_snapshot_id),
                    actor_id TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    promotion_fingerprint TEXT NOT NULL UNIQUE,
                    metadata_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    UNIQUE(recommendation_id, review_revision, keyword_set_id)
                );
                CREATE INDEX IF NOT EXISTS idx_ai_keyword_promotions_target
                    ON ai_keyword_promotions(recommendation_id, created_at DESC);

                CREATE TABLE IF NOT EXISTS ai_provider_capabilities (
                    provider_id TEXT NOT NULL,
                    provider_version TEXT NOT NULL,
                    supported_operations_json TEXT NOT NULL,
                    max_request_items INTEGER NOT NULL,
                    max_result_items INTEGER NOT NULL,
                    max_summary_length INTEGER NOT NULL,
                    is_available INTEGER NOT NULL,
                    unavailable_reason TEXT,
                    warnings_json TEXT NOT NULL,
                    generated_at TEXT NOT NULL,
                    capability_version TEXT NOT NULL,
                    PRIMARY KEY(provider_id, provider_version)
                );

                CREATE TABLE IF NOT EXISTS reports (
                    report_id TEXT PRIMARY KEY,
                    case_id TEXT NOT NULL REFERENCES cases(case_id),
                    title TEXT NOT NULL,
                    report_type TEXT NOT NULL,
                    status TEXT NOT NULL,
                    active_version_id TEXT,
                    latest_version_number INTEGER NOT NULL,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    archived_at TEXT,
                    report_fingerprint TEXT NOT NULL,
                    report_json TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_reports_case
                    ON reports(case_id, report_id);
                CREATE INDEX IF NOT EXISTS idx_reports_status
                    ON reports(case_id, status, updated_at DESC);

                CREATE TABLE IF NOT EXISTS report_versions (
                    report_version_id TEXT PRIMARY KEY,
                    report_id TEXT NOT NULL REFERENCES reports(report_id),
                    case_id TEXT NOT NULL REFERENCES cases(case_id),
                    version_number INTEGER NOT NULL,
                    previous_version_id TEXT,
                    source_kind TEXT NOT NULL,
                    source_reference_id TEXT,
                    content_fingerprint TEXT NOT NULL,
                    previous_content_fingerprint TEXT,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    version_json TEXT NOT NULL,
                    UNIQUE(report_id, version_number),
                    UNIQUE(report_id, content_fingerprint)
                );
                CREATE INDEX IF NOT EXISTS idx_report_versions_report
                    ON report_versions(report_id, version_number);
                CREATE INDEX IF NOT EXISTS idx_report_versions_content
                    ON report_versions(case_id, content_fingerprint);

                CREATE TABLE IF NOT EXISTS report_version_sections (
                    report_version_id TEXT NOT NULL REFERENCES report_versions(report_version_id),
                    section_id TEXT NOT NULL,
                    case_id TEXT NOT NULL REFERENCES cases(case_id),
                    report_id TEXT NOT NULL REFERENCES reports(report_id),
                    section_type TEXT NOT NULL,
                    section_order INTEGER NOT NULL,
                    section_fingerprint TEXT NOT NULL,
                    section_json TEXT NOT NULL,
                    PRIMARY KEY(report_version_id, section_id)
                );
                CREATE INDEX IF NOT EXISTS idx_report_sections_order
                    ON report_version_sections(report_version_id, section_order, section_id);

                CREATE TABLE IF NOT EXISTS report_version_references (
                    report_version_id TEXT NOT NULL REFERENCES report_versions(report_version_id),
                    case_id TEXT NOT NULL REFERENCES cases(case_id),
                    reference_type TEXT NOT NULL,
                    reference_id TEXT NOT NULL,
                    reference_json TEXT NOT NULL,
                    PRIMARY KEY(report_version_id, reference_type, reference_id)
                );
                CREATE INDEX IF NOT EXISTS idx_report_references_case
                    ON report_version_references(case_id, reference_type, reference_id);

                CREATE TABLE IF NOT EXISTS report_review_events (
                    review_event_id TEXT PRIMARY KEY,
                    report_id TEXT NOT NULL REFERENCES reports(report_id),
                    report_version_id TEXT NOT NULL REFERENCES report_versions(report_version_id),
                    case_id TEXT NOT NULL REFERENCES cases(case_id),
                    action TEXT NOT NULL,
                    actor_id TEXT NOT NULL,
                    review_revision INTEGER NOT NULL,
                    previous_event_hash TEXT,
                    event_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    event_json TEXT NOT NULL,
                    UNIQUE(report_version_id, review_revision),
                    UNIQUE(report_version_id, event_hash)
                );
                CREATE INDEX IF NOT EXISTS idx_report_review_events_version
                    ON report_review_events(report_version_id, review_revision);

                CREATE TABLE IF NOT EXISTS report_approval_records (
                    approval_id TEXT PRIMARY KEY,
                    report_id TEXT NOT NULL REFERENCES reports(report_id),
                    report_version_id TEXT NOT NULL REFERENCES report_versions(report_version_id),
                    case_id TEXT NOT NULL REFERENCES cases(case_id),
                    decision TEXT NOT NULL,
                    content_fingerprint TEXT NOT NULL,
                    custody_snapshot_id TEXT,
                    approval_revision INTEGER NOT NULL,
                    previous_approval_hash TEXT,
                    approval_hash TEXT NOT NULL,
                    decided_at TEXT NOT NULL,
                    approval_json TEXT NOT NULL,
                    UNIQUE(report_id, approval_revision),
                    UNIQUE(report_id, approval_hash)
                );
                CREATE INDEX IF NOT EXISTS idx_report_approvals_version
                    ON report_approval_records(report_version_id, approval_revision);

                CREATE TABLE IF NOT EXISTS custody_snapshots (
                    custody_snapshot_id TEXT PRIMARY KEY,
                    case_id TEXT NOT NULL REFERENCES cases(case_id),
                    report_id TEXT NOT NULL REFERENCES reports(report_id),
                    report_version_id TEXT NOT NULL REFERENCES report_versions(report_version_id),
                    verification_status TEXT NOT NULL,
                    ledger_head_hash TEXT,
                    snapshot_fingerprint TEXT NOT NULL UNIQUE,
                    captured_at TEXT NOT NULL,
                    snapshot_json TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS custody_snapshot_events (
                    custody_snapshot_id TEXT NOT NULL
                        REFERENCES custody_snapshots(custody_snapshot_id),
                    custody_event_id TEXT NOT NULL REFERENCES custody_events(event_id),
                    event_order INTEGER NOT NULL,
                    PRIMARY KEY(custody_snapshot_id, custody_event_id)
                );

                CREATE TABLE IF NOT EXISTS report_render_packages (
                    package_id TEXT PRIMARY KEY,
                    report_id TEXT NOT NULL REFERENCES reports(report_id),
                    report_version_id TEXT NOT NULL REFERENCES report_versions(report_version_id),
                    case_id TEXT NOT NULL REFERENCES cases(case_id),
                    custody_snapshot_id TEXT,
                    package_fingerprint TEXT NOT NULL UNIQUE,
                    created_at TEXT NOT NULL,
                    package_json TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_report_packages_version
                    ON report_render_packages(report_version_id, created_at DESC);

                CREATE TABLE IF NOT EXISTS report_export_manifests (
                    export_manifest_id TEXT PRIMARY KEY,
                    report_id TEXT NOT NULL REFERENCES reports(report_id),
                    report_version_id TEXT NOT NULL REFERENCES report_versions(report_version_id),
                    case_id TEXT NOT NULL REFERENCES cases(case_id),
                    format TEXT NOT NULL,
                    render_package_id TEXT NOT NULL REFERENCES report_render_packages(package_id),
                    approval_id TEXT NOT NULL REFERENCES report_approval_records(approval_id),
                    custody_snapshot_id TEXT,
                    status TEXT NOT NULL,
                    requested_filename TEXT NOT NULL,
                    content_fingerprint TEXT NOT NULL,
                    manifest_fingerprint TEXT NOT NULL UNIQUE,
                    created_at TEXT NOT NULL,
                    manifest_json TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_report_exports_version
                    ON report_export_manifests(report_version_id, created_at DESC);

                CREATE TABLE IF NOT EXISTS rendered_report_artifacts (
                    rendered_artifact_id TEXT PRIMARY KEY,
                    export_manifest_id TEXT NOT NULL
                        REFERENCES report_export_manifests(export_manifest_id),
                    report_version_id TEXT NOT NULL REFERENCES report_versions(report_version_id),
                    format TEXT NOT NULL,
                    output_reference TEXT NOT NULL,
                    filename TEXT NOT NULL,
                    size_bytes INTEGER NOT NULL,
                    sha256 TEXT NOT NULL,
                    artifact_fingerprint TEXT NOT NULL UNIQUE,
                    rendered_at TEXT NOT NULL,
                    artifact_json TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS report_export_audit_events (
                    audit_event_id TEXT PRIMARY KEY,
                    export_manifest_id TEXT NOT NULL
                        REFERENCES report_export_manifests(export_manifest_id),
                    report_id TEXT NOT NULL REFERENCES reports(report_id),
                    report_version_id TEXT NOT NULL REFERENCES report_versions(report_version_id),
                    case_id TEXT NOT NULL REFERENCES cases(case_id),
                    action TEXT NOT NULL,
                    status TEXT NOT NULL,
                    previous_event_hash TEXT,
                    event_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    event_json TEXT NOT NULL,
                    UNIQUE(export_manifest_id, event_hash)
                );

                CREATE TABLE IF NOT EXISTS report_renderer_capabilities (
                    renderer_id TEXT NOT NULL,
                    renderer_version TEXT NOT NULL,
                    supported_formats_json TEXT NOT NULL,
                    is_available INTEGER NOT NULL,
                    unavailable_reason TEXT,
                    warnings_json TEXT NOT NULL,
                    generated_at TEXT NOT NULL,
                    capability_version TEXT NOT NULL,
                    capability_json TEXT NOT NULL,
                    PRIMARY KEY(renderer_id, renderer_version)
                );

                CREATE TABLE IF NOT EXISTS case_ai_policies (
                    policy_id TEXT PRIMARY KEY,
                    case_id TEXT NOT NULL REFERENCES cases(case_id),
                    revision INTEGER NOT NULL CHECK(revision > 0),
                    ai_enabled INTEGER NOT NULL CHECK(ai_enabled IN (0, 1)),
                    external_allowed INTEGER NOT NULL CHECK(external_allowed IN (0, 1)),
                    local_only INTEGER NOT NULL CHECK(local_only IN (0, 1)),
                    allowed_classifications_json TEXT NOT NULL,
                    secret_handling TEXT NOT NULL
                        CHECK(secret_handling IN ('DENY','REDACT','ALLOW')),
                    raw_allowed INTEGER NOT NULL CHECK(raw_allowed IN (0, 1)),
                    redaction_required INTEGER NOT NULL CHECK(redaction_required IN (0, 1)),
                    projection_required INTEGER NOT NULL CHECK(projection_required IN (0, 1)),
                    content_fingerprint TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    schema_version TEXT NOT NULL CHECK(schema_version = '1.0.0'),
                    UNIQUE(case_id, revision),
                    UNIQUE(case_id, policy_id, revision, content_fingerprint)
                );
                CREATE TABLE IF NOT EXISTS ai_egress_audit_records (
                    audit_id TEXT PRIMARY KEY,
                    case_id TEXT NOT NULL REFERENCES cases(case_id),
                    source_id TEXT NOT NULL,
                    source_type TEXT NOT NULL CHECK(source_type IN (
                        'ARTIFACT','CONTEXT_SNAPSHOT','AI_ASSISTANCE_REQUEST'
                    )),
                    source_fingerprint TEXT NOT NULL,
                    classification TEXT NOT NULL CHECK(classification IN (
                        'PUBLIC','INTERNAL','SENSITIVE','SECRET'
                    )),
                    contains_secrets INTEGER NOT NULL CHECK(contains_secrets IN (0, 1)),
                    data_form TEXT NOT NULL CHECK(data_form IN (
                        'RAW','STRUCTURED','REDACTED','SAFE_PROJECTION'
                    )),
                    content_fingerprint TEXT,
                    destination TEXT NOT NULL CHECK(destination IN ('LOCAL','EXTERNAL')),
                    decision TEXT NOT NULL CHECK(decision IN (
                        'ALLOW','DENY','ALLOW_WITH_REDACTION','ALLOW_PROJECTION_ONLY'
                    )),
                    reason TEXT NOT NULL,
                    reason_codes_json TEXT NOT NULL,
                    required_transformations_json TEXT NOT NULL,
                    policy_id TEXT,
                    policy_revision INTEGER,
                    policy_fingerprint TEXT,
                    redaction_applied INTEGER NOT NULL CHECK(redaction_applied IN (0, 1)),
                    projection_applied INTEGER NOT NULL CHECK(projection_applied IN (0, 1)),
                    created_at TEXT NOT NULL,
                    schema_version TEXT NOT NULL CHECK(schema_version = '1.0.0'),
                    FOREIGN KEY(case_id, policy_id, policy_revision, policy_fingerprint)
                        REFERENCES case_ai_policies(
                            case_id, policy_id, revision, content_fingerprint
                        ),
                    CHECK((policy_id IS NULL AND policy_revision IS NULL
                        AND policy_fingerprint IS NULL AND decision = 'DENY') OR
                        (policy_id IS NOT NULL AND policy_revision IS NOT NULL
                        AND policy_fingerprint IS NOT NULL)),
                    CHECK(redaction_applied = (data_form IN ('REDACTED','SAFE_PROJECTION'))),
                    CHECK(projection_applied = (data_form = 'SAFE_PROJECTION')),
                    CHECK(contains_secrets = 0 OR classification = 'SECRET'),
                    CHECK(data_form = 'RAW' OR content_fingerprint IS NOT NULL)
                );
                CREATE INDEX IF NOT EXISTS idx_ai_egress_audit_case_source
                    ON ai_egress_audit_records(case_id, source_id, created_at, audit_id);
                CREATE TRIGGER IF NOT EXISTS ai_egress_audit_source_case
                BEFORE INSERT ON ai_egress_audit_records
                WHEN NOT (
                    (NEW.source_type = 'ARTIFACT' AND EXISTS (
                        SELECT 1 FROM artifacts WHERE artifact_id = NEW.source_id
                        AND case_id = NEW.case_id
                    )) OR
                    (NEW.source_type = 'CONTEXT_SNAPSHOT' AND EXISTS (
                        SELECT 1 FROM analysis_context_snapshots
                        WHERE context_snapshot_id = NEW.source_id AND case_id = NEW.case_id
                    )) OR
                    (NEW.source_type = 'AI_ASSISTANCE_REQUEST' AND EXISTS (
                        SELECT 1 FROM ai_assistance_requests
                        WHERE assistance_request_id = NEW.source_id AND case_id = NEW.case_id
                    ))
                )
                BEGIN
                    SELECT RAISE(ABORT, 'AI egress source must belong to the case');
                END;
                CREATE TRIGGER IF NOT EXISTS case_ai_policies_no_update
                BEFORE UPDATE ON case_ai_policies
                BEGIN
                    SELECT RAISE(ABORT, 'case_ai_policies are immutable');
                END;
                CREATE TRIGGER IF NOT EXISTS case_ai_policies_no_delete
                BEFORE DELETE ON case_ai_policies
                BEGIN
                    SELECT RAISE(ABORT, 'case_ai_policies are immutable');
                END;
                CREATE TRIGGER IF NOT EXISTS ai_egress_audit_no_update
                BEFORE UPDATE ON ai_egress_audit_records
                BEGIN
                    SELECT RAISE(ABORT, 'ai_egress_audit_records are immutable');
                END;
                CREATE TRIGGER IF NOT EXISTS ai_egress_audit_no_delete
                BEFORE DELETE ON ai_egress_audit_records
                BEGIN
                    SELECT RAISE(ABORT, 'ai_egress_audit_records are immutable');
                END;

                CREATE TABLE IF NOT EXISTS view_projections (
                    projection_id TEXT PRIMARY KEY,
                    case_id TEXT NOT NULL REFERENCES cases(case_id),
                    resource_type TEXT NOT NULL,
                    resource_id TEXT NOT NULL,
                    view_mode TEXT NOT NULL,
                    projection_json TEXT NOT NULL,
                    source_revision TEXT,
                    projection_version TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_view_projections_resource
                    ON view_projections(
                        case_id, resource_type, resource_id, view_mode, source_revision
                    );

                CREATE TABLE IF NOT EXISTS view_projection_cache (
                    cache_key TEXT PRIMARY KEY,
                    case_id TEXT NOT NULL REFERENCES cases(case_id),
                    resource_type TEXT NOT NULL,
                    resource_id TEXT NOT NULL,
                    view_mode TEXT NOT NULL,
                    source_revision TEXT,
                    projection_id TEXT REFERENCES view_projections(projection_id),
                    expires_at TEXT,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS raw_read_audit_records (
                    audit_id TEXT PRIMARY KEY,
                    case_id TEXT NOT NULL REFERENCES cases(case_id),
                    evidence_id TEXT,
                    resource_type TEXT NOT NULL,
                    resource_id TEXT NOT NULL,
                    raw_locator_json TEXT NOT NULL,
                    requested_offset INTEGER,
                    requested_length INTEGER,
                    returned_offset INTEGER,
                    returned_length INTEGER,
                    range_hash TEXT,
                    correlation_id TEXT,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS engine_interface_versions (
                    interface_name TEXT NOT NULL,
                    interface_version TEXT NOT NULL,
                    engine_version TEXT NOT NULL,
                    schema_version TEXT NOT NULL,
                    capabilities_json TEXT NOT NULL,
                    unavailable_capabilities_json TEXT NOT NULL,
                    generated_at TEXT NOT NULL,
                    PRIMARY KEY (interface_name, interface_version)
                );

                CREATE TABLE IF NOT EXISTS engine_tool_descriptors (
                    tool_name TEXT NOT NULL,
                    tool_version TEXT NOT NULL,
                    description_key TEXT NOT NULL,
                    input_schema_ref TEXT NOT NULL,
                    output_schema_ref TEXT NOT NULL,
                    required_capabilities_json TEXT NOT NULL,
                    mutates_state INTEGER NOT NULL,
                    requires_confirmation INTEGER NOT NULL,
                    supports_pagination INTEGER NOT NULL,
                    supports_partial INTEGER NOT NULL,
                    supports_citation INTEGER NOT NULL,
                    max_result_items INTEGER NOT NULL,
                    PRIMARY KEY (tool_name, tool_version)
                );

                CREATE TRIGGER IF NOT EXISTS analysis_context_snapshots_no_update
                BEFORE UPDATE ON analysis_context_snapshots
                BEGIN
                    SELECT RAISE(ABORT, 'analysis_context_snapshots are append-only');
                END;

                CREATE TRIGGER IF NOT EXISTS analysis_context_snapshots_no_delete
                BEFORE DELETE ON analysis_context_snapshots
                BEGIN
                    SELECT RAISE(ABORT, 'analysis_context_snapshots are append-only');
                END;

                CREATE TRIGGER IF NOT EXISTS raw_read_audit_records_no_update
                BEFORE UPDATE ON raw_read_audit_records
                BEGIN
                    SELECT RAISE(ABORT, 'raw_read_audit_records are append-only');
                END;

                CREATE TRIGGER IF NOT EXISTS raw_read_audit_records_no_delete
                BEFORE DELETE ON raw_read_audit_records
                BEGIN
                    SELECT RAISE(ABORT, 'raw_read_audit_records are append-only');
                END;

                CREATE TRIGGER IF NOT EXISTS custody_events_no_update
                BEFORE UPDATE ON custody_events
                BEGIN
                    SELECT RAISE(ABORT, 'custody_events are append-only');
                END;

                CREATE TRIGGER IF NOT EXISTS custody_events_no_delete
                BEFORE DELETE ON custody_events
                BEGIN
                    SELECT RAISE(ABORT, 'custody_events are append-only');
                END;

                CREATE TRIGGER IF NOT EXISTS candidate_review_events_no_update
                BEFORE UPDATE ON candidate_review_events
                BEGIN
                    SELECT RAISE(ABORT, 'candidate_review_events are append-only');
                END;

                CREATE TRIGGER IF NOT EXISTS candidate_review_events_no_delete
                BEFORE DELETE ON candidate_review_events
                BEGIN
                    SELECT RAISE(ABORT, 'candidate_review_events are append-only');
                END;

                CREATE TRIGGER IF NOT EXISTS decryption_attempts_no_update
                BEFORE UPDATE ON decryption_attempts
                BEGIN
                    SELECT RAISE(ABORT, 'decryption_attempts are append-only');
                END;

                CREATE TRIGGER IF NOT EXISTS decryption_attempts_no_delete
                BEFORE DELETE ON decryption_attempts
                BEGIN
                    SELECT RAISE(ABORT, 'decryption_attempts are append-only');
                END;

                CREATE TRIGGER IF NOT EXISTS decryption_results_no_update
                BEFORE UPDATE ON decryption_results
                BEGIN
                    SELECT RAISE(ABORT, 'decryption_results are append-only');
                END;

                CREATE TRIGGER IF NOT EXISTS decryption_results_no_delete
                BEFORE DELETE ON decryption_results
                BEGIN
                    SELECT RAISE(ABORT, 'decryption_results are append-only');
                END;

                CREATE TRIGGER IF NOT EXISTS ai_keyword_recommendations_no_update
                BEFORE UPDATE ON ai_keyword_recommendations
                BEGIN
                    SELECT RAISE(ABORT, 'ai_keyword_recommendations are immutable');
                END;

                CREATE TRIGGER IF NOT EXISTS ai_keyword_recommendations_no_delete
                BEFORE DELETE ON ai_keyword_recommendations
                BEGIN
                    SELECT RAISE(ABORT, 'ai_keyword_recommendations are immutable');
                END;

                CREATE TRIGGER IF NOT EXISTS ai_scope_summaries_no_update
                BEFORE UPDATE ON ai_scope_summaries
                BEGIN
                    SELECT RAISE(ABORT, 'ai_scope_summaries are immutable');
                END;

                CREATE TRIGGER IF NOT EXISTS ai_scope_summaries_no_delete
                BEFORE DELETE ON ai_scope_summaries
                BEGIN
                    SELECT RAISE(ABORT, 'ai_scope_summaries are immutable');
                END;

                CREATE TRIGGER IF NOT EXISTS ai_verification_events_no_update
                BEFORE UPDATE ON ai_verification_events
                BEGIN
                    SELECT RAISE(ABORT, 'ai_verification_events are append-only');
                END;

                CREATE TRIGGER IF NOT EXISTS ai_verification_events_no_delete
                BEFORE DELETE ON ai_verification_events
                BEGIN
                    SELECT RAISE(ABORT, 'ai_verification_events are append-only');
                END;

                CREATE TRIGGER IF NOT EXISTS ai_keyword_promotions_no_update
                BEFORE UPDATE ON ai_keyword_promotions
                BEGIN
                    SELECT RAISE(ABORT, 'ai_keyword_promotions are append-only');
                END;

                CREATE TRIGGER IF NOT EXISTS ai_keyword_promotions_no_delete
                BEFORE DELETE ON ai_keyword_promotions
                BEGIN
                    SELECT RAISE(ABORT, 'ai_keyword_promotions are append-only');
                END;

                CREATE TRIGGER IF NOT EXISTS report_versions_no_update
                BEFORE UPDATE ON report_versions
                BEGIN
                    SELECT RAISE(ABORT, 'report_versions are immutable');
                END;

                CREATE TRIGGER IF NOT EXISTS report_versions_no_delete
                BEFORE DELETE ON report_versions
                BEGIN
                    SELECT RAISE(ABORT, 'report_versions are immutable');
                END;

                CREATE TRIGGER IF NOT EXISTS report_review_events_no_update
                BEFORE UPDATE ON report_review_events
                BEGIN
                    SELECT RAISE(ABORT, 'report_review_events are append-only');
                END;

                CREATE TRIGGER IF NOT EXISTS report_review_events_no_delete
                BEFORE DELETE ON report_review_events
                BEGIN
                    SELECT RAISE(ABORT, 'report_review_events are append-only');
                END;

                CREATE TRIGGER IF NOT EXISTS report_approval_records_no_update
                BEFORE UPDATE ON report_approval_records
                BEGIN
                    SELECT RAISE(ABORT, 'report_approval_records are append-only');
                END;

                CREATE TRIGGER IF NOT EXISTS report_approval_records_no_delete
                BEFORE DELETE ON report_approval_records
                BEGIN
                    SELECT RAISE(ABORT, 'report_approval_records are append-only');
                END;

                CREATE TRIGGER IF NOT EXISTS custody_snapshots_no_update
                BEFORE UPDATE ON custody_snapshots
                BEGIN
                    SELECT RAISE(ABORT, 'custody_snapshots are immutable');
                END;

                CREATE TRIGGER IF NOT EXISTS custody_snapshots_no_delete
                BEFORE DELETE ON custody_snapshots
                BEGIN
                    SELECT RAISE(ABORT, 'custody_snapshots are immutable');
                END;

                CREATE TRIGGER IF NOT EXISTS rendered_report_artifacts_no_update
                BEFORE UPDATE ON rendered_report_artifacts
                BEGIN
                    SELECT RAISE(ABORT, 'rendered_report_artifacts are immutable');
                END;

                CREATE TRIGGER IF NOT EXISTS rendered_report_artifacts_no_delete
                BEFORE DELETE ON rendered_report_artifacts
                BEGIN
                    SELECT RAISE(ABORT, 'rendered_report_artifacts are immutable');
                END;

                CREATE TRIGGER IF NOT EXISTS report_export_audit_events_no_update
                BEFORE UPDATE ON report_export_audit_events
                BEGIN
                    SELECT RAISE(ABORT, 'report_export_audit_events are append-only');
                END;

                CREATE TRIGGER IF NOT EXISTS report_export_audit_events_no_delete
                BEFORE DELETE ON report_export_audit_events
                BEGIN
                    SELECT RAISE(ABORT, 'report_export_audit_events are append-only');
                END;
                """
            )
            self._ensure_column("jobs", "job_revision", "INTEGER NOT NULL DEFAULT 1")
            self._ensure_column("jobs", "index_revision", "INTEGER")
            self._ensure_column(
                "hash_verifications",
                "case_id",
                "TEXT REFERENCES cases(case_id)",
            )
            self.connection.execute(
                """
                UPDATE hash_verifications
                SET case_id = (
                    SELECT evidence.case_id
                    FROM evidence
                    WHERE evidence.evidence_id = hash_verifications.evidence_id
                )
                WHERE case_id IS NULL
                """
            )
            unresolved_verifications = self.connection.execute(
                "SELECT COUNT(*) AS count FROM hash_verifications WHERE case_id IS NULL"
            ).fetchone()
            if unresolved_verifications is not None and int(
                unresolved_verifications["count"]
            ):
                raise PersistenceError(
                    "DATABASE_MIGRATION_FAILED",
                    "Existing hash verifications could not be assigned to an evidence case.",
                    retryable=False,
                    details={"table": "hash_verifications"},
                )
            self.connection.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_hash_verifications_case_evidence
                ON hash_verifications(case_id, evidence_id, verified_at)
                """
            )
            self._ensure_column("artifact_sources", "source_fingerprint", "TEXT")
            self._ensure_column("artifact_sources", "source_checkpoint_json", "TEXT")
            self._ensure_column(
                "artifact_sources", "inspected_count", "INTEGER NOT NULL DEFAULT 0"
            )
            self.connection.execute(
                """
                INSERT OR IGNORE INTO schema_migrations(version, applied_at)
                VALUES (?, ?)
                """,
                ("phase1-core-foundation", to_json_timestamp(utc_now())),
            )
            self.connection.execute(
                """
                INSERT OR IGNORE INTO schema_migrations(version, applied_at)
                VALUES (?, ?)
                """,
                ("phase2-progressive-filesystem-indexing", to_json_timestamp(utc_now())),
            )
            self.connection.execute(
                """
                INSERT OR IGNORE INTO schema_migrations(version, applied_at)
                VALUES (?, ?)
                """,
                ("phase3-windows-artifact-analysis", to_json_timestamp(utc_now())),
            )
            if self._fts5_available():
                self.connection.execute(
                    """
                    CREATE VIRTUAL TABLE IF NOT EXISTS search_documents_fts
                    USING fts5(
                        document_id UNINDEXED,
                        title,
                        path,
                        searchable_text,
                        tokenize = 'unicode61'
                    )
                    """
                )
            self.connection.execute(
                """
                INSERT OR IGNORE INTO schema_migrations(version, applied_at)
                VALUES (?, ?)
                """,
                ("phase4-search-keyword-timeline", to_json_timestamp(utc_now())),
            )
            self.connection.execute(
                """
                INSERT OR IGNORE INTO schema_migrations(version, applied_at)
                VALUES (?, ?)
                """,
                ("phase5-browser-media-metadata", to_json_timestamp(utc_now())),
            )
            self.connection.execute(
                """
                INSERT OR IGNORE INTO schema_migrations(version, applied_at)
                VALUES (?, ?)
                """,
                ("phase6-gui-context-view-interface", to_json_timestamp(utc_now())),
            )
            self.connection.execute(
                """
                INSERT OR IGNORE INTO schema_migrations(version, applied_at)
                VALUES (?, ?)
                """,
                ("phase7-ai-assistance-engine-contract", to_json_timestamp(utc_now())),
            )
            self.connection.execute(
                """
                INSERT OR IGNORE INTO schema_migrations(version, applied_at)
                VALUES (?, ?)
                """,
                ("phase8-report-review-export-contract", to_json_timestamp(utc_now())),
            )
            self.connection.execute(
                """
                INSERT OR IGNORE INTO schema_migrations(version, applied_at)
                VALUES (?, ?)
                """,
                ("apex-engine-work-package-a-evidence-readers", to_json_timestamp(utc_now())),
            )
            self.connection.execute(
                """
                INSERT OR IGNORE INTO schema_migrations(version, applied_at)
                VALUES (?, ?)
                """,
                ("apex-engine-advanced-runtime-audit", to_json_timestamp(utc_now())),
            )
            self.connection.execute(
                """
                INSERT OR IGNORE INTO schema_migrations(version, applied_at)
                VALUES (?, ?)
                """,
                ("hash-verification-case-scope", to_json_timestamp(utc_now())),
            )

            self.connection.execute(
                """
                INSERT OR IGNORE INTO schema_migrations(version, applied_at)
                VALUES (?, ?)
                """,
                ("apex-engine-ai-data-governance", to_json_timestamp(utc_now())),
            )

    def save_case(self, case: Case) -> None:
        """Persist a new case."""

        with self.connection:
            self.connection.execute(
                """
                INSERT INTO cases (
                    case_id, name, description, investigator, locale, timezone, status,
                    created_at, updated_at, schema_version, metadata_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                self._case_values(case),
            )

    def update_case(self, case: Case) -> None:
        """Persist changes to an existing case."""

        with self.connection:
            self.connection.execute(
                """
                UPDATE cases
                SET name = ?, description = ?, investigator = ?, locale = ?, timezone = ?,
                    status = ?, updated_at = ?, metadata_json = ?
                WHERE case_id = ?
                """,
                (
                    case.name,
                    case.description,
                    case.investigator,
                    case.locale,
                    case.timezone,
                    case.status.value,
                    to_json_timestamp(case.updated_at),
                    self._json(case.metadata),
                    case.case_id,
                ),
            )

    def get_case(self, case_id: str) -> Case | None:
        """Return a case by ID."""

        row = self.connection.execute(
            "SELECT * FROM cases WHERE case_id = ?",
            (case_id,),
        ).fetchone()
        return None if row is None else self._row_to_case(row)

    def list_cases(self) -> list[Case]:
        """Return all cases in creation order."""

        rows = self.connection.execute(
            "SELECT * FROM cases ORDER BY created_at, case_id"
        ).fetchall()
        return [self._row_to_case(row) for row in rows]

    def save_evidence(self, evidence: Evidence) -> None:
        """Persist a new evidence row."""

        with self.connection:
            self.connection.execute(
                """
                INSERT INTO evidence (
                    evidence_id, case_id, display_name, source_path, evidence_type,
                    size_bytes, status, read_only, fingerprint_json, created_at,
                    updated_at, schema_version, metadata_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                self._evidence_values(evidence),
            )

    def update_evidence(self, evidence: Evidence) -> None:
        """Persist evidence metadata changes."""

        with self.connection:
            self.connection.execute(
                """
                UPDATE evidence
                SET display_name = ?, source_path = ?, evidence_type = ?, size_bytes = ?,
                    status = ?, fingerprint_json = ?, updated_at = ?, metadata_json = ?
                WHERE evidence_id = ?
                """,
                (
                    evidence.display_name,
                    str(evidence.source_path),
                    evidence.evidence_type.value,
                    evidence.size_bytes,
                    evidence.status.value,
                    self._fingerprint_json(evidence.fingerprint),
                    to_json_timestamp(evidence.updated_at),
                    self._json(evidence.metadata),
                    evidence.evidence_id,
                ),
            )

    def get_evidence(self, evidence_id: str) -> Evidence | None:
        """Return evidence by ID."""

        row = self.connection.execute(
            "SELECT * FROM evidence WHERE evidence_id = ?",
            (evidence_id,),
        ).fetchone()
        return None if row is None else self._row_to_evidence(row)

    def list_evidence_for_case(self, case_id: str) -> list[Evidence]:
        """Return evidence rows for a case."""

        rows = self.connection.execute(
            "SELECT * FROM evidence WHERE case_id = ? ORDER BY created_at, evidence_id",
            (case_id,),
        ).fetchall()
        return [self._row_to_evidence(row) for row in rows]

    def replace_evidence_volumes(
        self, evidence_id: str, volumes: list[EvidenceVolume]
    ) -> None:
        """Replace partition enumeration results for an evidence source."""

        with self.connection:
            self.connection.execute(
                "DELETE FROM evidence_volumes WHERE evidence_id = ?",
                (evidence_id,),
            )
            self.connection.executemany(
                """
                INSERT INTO evidence_volumes (
                    volume_id, case_id, evidence_id, reader_id, reader_version,
                    volume_index, scheme, partition_type, start_lba, end_lba,
                    byte_offset, byte_length, sector_size, name, guid, is_allocated,
                    raw_locator_json, warnings_json, created_at, volume_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [self._evidence_volume_values(volume) for volume in volumes],
            )

    def list_evidence_volumes(self, evidence_id: str) -> list[EvidenceVolume]:
        """Return persisted volume rows for an evidence source."""

        rows = self.connection.execute(
            """
            SELECT * FROM evidence_volumes
            WHERE evidence_id = ?
            ORDER BY volume_index, byte_offset, volume_id
            """,
            (evidence_id,),
        ).fetchall()
        return [self._row_to_evidence_volume(row) for row in rows]

    def save_hash_record(self, record: HashRecord) -> None:
        """Persist a hash calculation record."""

        with self.connection:
            self.connection.execute(
                """
                INSERT INTO evidence_hashes (
                    hash_id, evidence_id, algorithm, digest, calculated_at, file_size,
                    chunk_size, verified, verification_status, bytes_hashed,
                    started_at, completed_at, job_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record.hash_id,
                    record.evidence_id,
                    record.algorithm.value,
                    record.digest,
                    to_json_timestamp(record.calculated_at),
                    record.file_size,
                    record.chunk_size,
                    int(record.verified),
                    record.verification_status,
                    record.bytes_hashed,
                    to_json_timestamp(record.started_at),
                    to_json_timestamp(record.completed_at),
                    record.job_id,
                ),
            )

    def latest_hash_record(
        self,
        evidence_id: str,
        algorithm: HashAlgorithm,
    ) -> HashRecord | None:
        """Return the latest stored hash for an algorithm."""

        row = self.connection.execute(
            """
            SELECT * FROM evidence_hashes
            WHERE evidence_id = ? AND algorithm = ?
            ORDER BY calculated_at DESC, hash_id DESC
            LIMIT 1
            """,
            (evidence_id, algorithm.value),
        ).fetchone()
        return None if row is None else self._row_to_hash_record(row)

    def mark_hash_record_verified(self, hash_id: str, status: str) -> None:
        """Update verification status for an existing hash row."""

        with self.connection:
            self.connection.execute(
                """
                UPDATE evidence_hashes
                SET verified = 1, verification_status = ?
                WHERE hash_id = ?
                """,
                (status, hash_id),
            )

    def save_hash_verification(self, verification: HashVerification) -> None:
        """Persist a hash verification history row."""

        data = verification.data
        evidence_row = self.connection.execute(
            "SELECT case_id FROM evidence WHERE evidence_id = ?",
            (data["evidence_id"],),
        ).fetchone()
        if evidence_row is None:
            raise PersistenceError(
                "DATABASE_REFERENCE_INVALID",
                "Hash verification evidence does not exist.",
                retryable=False,
                details={"evidence_id": data["evidence_id"]},
            )
        if str(evidence_row["case_id"]) != str(data["case_id"]):
            raise PersistenceError(
                "CASE_SCOPE_MISMATCH",
                "Hash verification case does not match its evidence case.",
                retryable=False,
                details={
                    "case_id": data["case_id"],
                    "evidence_id": data["evidence_id"],
                },
            )
        with self.connection:
            self.connection.execute(
                """
                INSERT INTO hash_verifications (
                    verification_id, case_id, evidence_id, algorithm, expected_digest,
                    observed_digest, status, verified_at, tool_version, job_id,
                    custody_event_id, error_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    data["id"],
                    data["case_id"],
                    data["evidence_id"],
                    data["algorithm"],
                    data["expected_digest"],
                    data.get("observed_digest"),
                    data["status"],
                    data["verified_at"],
                    data["tool_version"],
                    data.get("job_id"),
                    data.get("custody_event_id"),
                    self._json(data.get("error")),
                ),
            )

    def list_hash_verifications(self, evidence_id: str) -> list[HashVerification]:
        """Return verification history for evidence."""

        rows = self.connection.execute(
            """
            SELECT * FROM hash_verifications
            WHERE evidence_id = ?
            ORDER BY verified_at, verification_id
            """,
            (evidence_id,),
        ).fetchall()
        return [self._row_to_hash_verification(row) for row in rows]

    def save_job(self, job: Job) -> None:
        """Persist a new job."""

        with self.connection:
            self.connection.execute(
                """
                INSERT INTO jobs (
                    job_id, case_id, evidence_id, job_type, status, progress_json,
                    queued_at, started_at, finished_at, cancel_requested_at, warnings_json,
                    errors_json, profile_id, priority, checkpoint_available,
                    job_revision, index_revision
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                self._job_values(job),
            )

    def update_job(self, job: Job) -> None:
        """Persist job changes."""

        with self.connection:
            self.connection.execute(
                """
                UPDATE jobs
                SET status = ?, progress_json = ?, started_at = ?, finished_at = ?,
                    cancel_requested_at = ?, warnings_json = ?, errors_json = ?,
                    priority = ?, checkpoint_available = ?, job_revision = ?, index_revision = ?
                WHERE job_id = ?
                """,
                (
                    job.status.value,
                    self._json(self._progress_dict(job.progress)),
                    self._nullable_timestamp(job.started_at),
                    self._nullable_timestamp(job.finished_at),
                    self._nullable_timestamp(job.cancel_requested_at),
                    self._json(job.warnings),
                    self._json(job.errors),
                    job.priority,
                    int(job.checkpoint_available),
                    job.job_revision,
                    job.index_revision,
                    job.job_id,
                ),
            )

    def get_job(self, job_id: str) -> Job | None:
        """Return a job by ID."""

        row = self.connection.execute(
            "SELECT * FROM jobs WHERE job_id = ?",
            (job_id,),
        ).fetchone()
        return None if row is None else self._row_to_job(row)

    def save_custody_event(self, event: CustodyEvent) -> None:
        """Append a custody event."""

        data = event.to_schema_dict()
        with self.connection:
            self.connection.execute(
                """
                INSERT INTO custody_events (
                    event_id, case_id, evidence_id, event_type, immutable_revision,
                    previous_event_hash, event_hash, occurred_at_utc, created_at, event_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    data["event_id"],
                    data["case_id"],
                    data["evidence_id"],
                    data["event_type"],
                    data["immutable_revision"],
                    data["previous_event_hash"],
                    data["event_hash"],
                    data["occurred_at_utc"],
                    data["created_at"],
                    self._json(data),
                ),
            )

    def list_custody_events(self, evidence_id: str) -> list[CustodyEvent]:
        """Return custody events ordered by immutable revision."""

        rows = self.connection.execute(
            """
            SELECT event_json FROM custody_events
            WHERE evidence_id = ?
            ORDER BY immutable_revision
            """,
            (evidence_id,),
        ).fetchall()
        return [CustodyEvent(json.loads(row["event_json"])) for row in rows]

    def get_custody_event(self, event_id: str) -> CustodyEvent | None:
        """Return one custody event."""

        row = self.connection.execute(
            "SELECT event_json FROM custody_events WHERE event_id = ?",
            (event_id,),
        ).fetchone()
        return None if row is None else CustodyEvent(json.loads(row["event_json"]))

    def save_fs_provider(
        self,
        provider_id: str,
        provider_version: str,
        capabilities: list[str],
        metadata: dict[str, Any],
    ) -> None:
        """Persist a provider capability statement."""

        with self.connection:
            self.connection.execute(
                """
                INSERT INTO fs_providers (
                    provider_id, provider_version, capabilities_json, metadata_json, registered_at
                ) VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(provider_id, provider_version) DO UPDATE SET
                    capabilities_json = excluded.capabilities_json,
                    metadata_json = excluded.metadata_json,
                    registered_at = excluded.registered_at
                """,
                (
                    provider_id,
                    provider_version,
                    self._json(capabilities),
                    self._json(metadata),
                    to_json_timestamp(utc_now()),
                ),
            )

    def next_index_revision(self, evidence_id: str, provider_id: str, provider_version: str) -> int:
        """Return the next monotonic index revision for one provider/evidence pair."""

        row = self.connection.execute(
            """
            SELECT COALESCE(MAX(index_revision), 0) AS latest
            FROM fs_nodes
            WHERE evidence_id = ? AND provider_id = ? AND provider_version = ?
            """,
            (evidence_id, provider_id, provider_version),
        ).fetchone()
        return int(row["latest"]) + 1

    def upsert_fs_node(self, node: FileSystemNode) -> FileSystemNode:
        """Insert or update a filesystem node without creating duplicates."""

        with self.connection:
            self.connection.execute(
                """
                INSERT INTO fs_nodes (
                    node_id, case_id, evidence_id, provider_id, provider_version,
                    parent_node_id, original_name, original_relative_path, display_path,
                    comparison_path, node_type, file_size, extension, mime_candidate,
                    mime_confidence, fs_metadata_json, platform, timestamp_meanings_json,
                    raw_timestamps_json, utc_timestamps_json, timestamp_sources_json,
                    is_deleted, is_readable, is_link, is_traversed, raw_locator_json,
                    provider_metadata_json, is_partial, index_revision, created_at, updated_at
                ) VALUES (
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                )
                ON CONFLICT(
                    case_id, evidence_id, provider_id, provider_version, original_relative_path
                )
                DO UPDATE SET
                    parent_node_id = excluded.parent_node_id,
                    original_name = excluded.original_name,
                    display_path = excluded.display_path,
                    comparison_path = excluded.comparison_path,
                    node_type = excluded.node_type,
                    file_size = excluded.file_size,
                    extension = excluded.extension,
                    mime_candidate = excluded.mime_candidate,
                    mime_confidence = excluded.mime_confidence,
                    fs_metadata_json = excluded.fs_metadata_json,
                    platform = excluded.platform,
                    timestamp_meanings_json = excluded.timestamp_meanings_json,
                    raw_timestamps_json = excluded.raw_timestamps_json,
                    utc_timestamps_json = excluded.utc_timestamps_json,
                    timestamp_sources_json = excluded.timestamp_sources_json,
                    is_deleted = excluded.is_deleted,
                    is_readable = excluded.is_readable,
                    is_link = excluded.is_link,
                    is_traversed = excluded.is_traversed,
                    raw_locator_json = excluded.raw_locator_json,
                    provider_metadata_json = excluded.provider_metadata_json,
                    is_partial = excluded.is_partial,
                    index_revision = excluded.index_revision,
                    updated_at = excluded.updated_at
                """,
                self._fs_node_values(node),
            )
        return self.get_fs_node(node.node_id) or node

    def save_fs_nodes(self, nodes: list[FileSystemNode]) -> None:
        """Batch upsert filesystem nodes."""

        for node in nodes:
            self.upsert_fs_node(node)

    def get_fs_node(self, node_id: str) -> FileSystemNode | None:
        """Return one filesystem node."""

        row = self.connection.execute(
            "SELECT * FROM fs_nodes WHERE node_id = ?", (node_id,)
        ).fetchone()
        return None if row is None else self._row_to_fs_node(row)

    def get_fs_node_by_relative_path(
        self,
        evidence_id: str,
        provider_id: str,
        provider_version: str,
        relative_path: str,
    ) -> FileSystemNode | None:
        """Return a node by original provider relative path."""

        row = self.connection.execute(
            """
            SELECT * FROM fs_nodes
            WHERE evidence_id = ? AND provider_id = ? AND provider_version = ?
              AND original_relative_path = ?
            """,
            (evidence_id, provider_id, provider_version, relative_path),
        ).fetchone()
        return None if row is None else self._row_to_fs_node(row)

    def list_fs_roots(self, evidence_id: str) -> list[FileSystemNode]:
        """Return root nodes for evidence."""

        rows = self.connection.execute(
            """
            SELECT * FROM fs_nodes
            WHERE evidence_id = ? AND parent_node_id IS NULL
            ORDER BY comparison_path, node_id
            """,
            (evidence_id,),
        ).fetchall()
        return [self._row_to_fs_node(row) for row in rows]

    def list_fs_nodes_for_evidence(self, evidence_id: str) -> list[FileSystemNode]:
        """Return all indexed nodes for evidence in stable path order."""

        rows = self.connection.execute(
            """
            SELECT * FROM fs_nodes
            WHERE evidence_id = ?
            ORDER BY comparison_path, node_id
            """,
            (evidence_id,),
        ).fetchall()
        return [self._row_to_fs_node(row) for row in rows]

    def create_fs_index_job(
        self,
        *,
        job_id: str,
        case_id: str,
        evidence_id: str,
        provider_id: str,
        provider_version: str,
        profile_type: str,
        options: dict[str, Any],
        option_fingerprint: str,
        index_revision: int,
        status: str,
        created_at: str,
    ) -> None:
        """Persist Phase 2 index job metadata."""

        with self.connection:
            self.connection.execute(
                """
                INSERT INTO fs_index_jobs (
                    job_id, case_id, evidence_id, provider_id, provider_version,
                    profile_type, options_json, option_fingerprint, index_revision,
                    status, pause_requested, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?)
                """,
                (
                    job_id,
                    case_id,
                    evidence_id,
                    provider_id,
                    provider_version,
                    profile_type,
                    self._json(options),
                    option_fingerprint,
                    index_revision,
                    status,
                    created_at,
                    created_at,
                ),
            )

    def update_fs_index_job_status(
        self,
        job_id: str,
        status: str,
        *,
        pause_requested: bool | None = None,
    ) -> None:
        """Update Phase 2 index job metadata status."""

        assignments = ["status = ?", "updated_at = ?"]
        params: list[Any] = [status, to_json_timestamp(utc_now())]
        if pause_requested is not None:
            assignments.append("pause_requested = ?")
            params.append(int(pause_requested))
        params.append(job_id)
        with self.connection:
            self.connection.execute(
                f"UPDATE fs_index_jobs SET {', '.join(assignments)} WHERE job_id = ?",
                tuple(params),
            )

    def get_fs_index_job(self, job_id: str) -> dict[str, Any] | None:
        """Return Phase 2 index job metadata."""

        row = self.connection.execute(
            "SELECT * FROM fs_index_jobs WHERE job_id = ?",
            (job_id,),
        ).fetchone()
        if row is None:
            return None
        data = dict(row)
        data["options"] = json.loads(str(data.pop("options_json")))
        return data

    def list_fs_index_jobs_for_evidence(self, evidence_id: str) -> list[dict[str, Any]]:
        """Return index jobs for an evidence source."""

        rows = self.connection.execute(
            """
            SELECT * FROM fs_index_jobs
            WHERE evidence_id = ?
            ORDER BY created_at, job_id
            """,
            (evidence_id,),
        ).fetchall()
        result: list[dict[str, Any]] = []
        for row in rows:
            data = dict(row)
            data["options"] = json.loads(str(data.pop("options_json")))
            result.append(data)
        return result

    def enqueue_fs_queue_item(
        self,
        *,
        queue_id: str,
        job_id: str,
        node_id: str,
        priority: int,
        depth: int,
        sequence: int,
        reason: str,
    ) -> None:
        """Add a node traversal request to the persistent priority queue."""

        now = to_json_timestamp(utc_now())
        with self.connection:
            self.connection.execute(
                """
                INSERT INTO fs_index_queue (
                    queue_id, job_id, node_id, priority, depth, cursor_key,
                    status, sequence, reason, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, NULL, 'QUEUED', ?, ?, ?, ?)
                ON CONFLICT(job_id, node_id, reason) DO UPDATE SET
                    priority = MIN(priority, excluded.priority),
                    updated_at = excluded.updated_at
                """,
                (queue_id, job_id, node_id, priority, depth, sequence, reason, now, now),
            )

    def next_fs_queue_item(self, job_id: str) -> dict[str, Any] | None:
        """Claim the next queued filesystem item."""

        with self.connection:
            row = self.connection.execute(
                """
                SELECT * FROM fs_index_queue
                WHERE job_id = ? AND status = 'QUEUED'
                ORDER BY priority, sequence, queue_id
                LIMIT 1
                """,
                (job_id,),
            ).fetchone()
            if row is None:
                return None
            self.connection.execute(
                (
                    "UPDATE fs_index_queue "
                    "SET status = 'PROCESSING', updated_at = ? "
                    "WHERE queue_id = ?"
                ),
                (to_json_timestamp(utc_now()), row["queue_id"]),
            )
        return dict(row)

    def reset_interrupted_fs_queue(self, job_id: str) -> None:
        """Return interrupted processing rows to queued state for resume."""

        with self.connection:
            self.connection.execute(
                """
                UPDATE fs_index_queue
                SET status = 'QUEUED', updated_at = ?
                WHERE job_id = ? AND status = 'PROCESSING'
                """,
                (to_json_timestamp(utc_now()), job_id),
            )

    def update_fs_queue_cursor(self, queue_id: str, cursor_key: str | None) -> None:
        """Checkpoint a partially scanned directory and requeue it."""

        with self.connection:
            self.connection.execute(
                """
                UPDATE fs_index_queue
                SET cursor_key = ?, status = 'QUEUED', updated_at = ?
                WHERE queue_id = ?
                """,
                (cursor_key, to_json_timestamp(utc_now()), queue_id),
            )

    def mark_fs_queue_done(self, queue_id: str) -> None:
        """Mark a queue item completed."""

        with self.connection:
            self.connection.execute(
                """
                UPDATE fs_index_queue
                SET status = 'DONE', updated_at = ?
                WHERE queue_id = ?
                """,
                (to_json_timestamp(utc_now()), queue_id),
            )

    def count_pending_fs_queue(self, job_id: str) -> int:
        """Return remaining queued work for a job."""

        row = self.connection.execute(
            """
            SELECT COUNT(*) AS count
            FROM fs_index_queue
            WHERE job_id = ? AND status IN ('QUEUED', 'PROCESSING')
            """,
            (job_id,),
        ).fetchone()
        return int(row["count"])

    def save_fs_checkpoint(
        self,
        *,
        job_id: str,
        current_node_id: str | None,
        current_path: str | None,
        pending_queue_count: int,
        processed_items: int,
        discovered_items: int,
    ) -> None:
        """Persist resumable indexing checkpoint state."""

        now = to_json_timestamp(utc_now())
        with self.connection:
            self.connection.execute(
                """
                INSERT INTO fs_index_checkpoints (
                    job_id, current_node_id, current_path, pending_queue_count,
                    processed_items, discovered_items, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(job_id) DO UPDATE SET
                    current_node_id = excluded.current_node_id,
                    current_path = excluded.current_path,
                    pending_queue_count = excluded.pending_queue_count,
                    processed_items = excluded.processed_items,
                    discovered_items = excluded.discovered_items,
                    updated_at = excluded.updated_at
                """,
                (
                    job_id,
                    current_node_id,
                    current_path,
                    pending_queue_count,
                    processed_items,
                    discovered_items,
                    now,
                ),
            )

    def upsert_fs_coverage(self, coverage: IndexCoverage) -> IndexCoverage:
        """Insert or update index coverage counters."""

        now = utc_now()
        created_at = coverage.created_at or now
        updated_at = coverage.updated_at or now
        with self.connection:
            self.connection.execute(
                """
                INSERT INTO fs_index_coverage (
                    case_id, evidence_id, provider_id, provider_version, profile_type,
                    option_fingerprint, status, discovered_items, processed_items,
                    skipped_items, warning_count, error_count, current_path,
                    elapsed_seconds, throughput_items_per_second, estimated_remaining_seconds,
                    eta_confidence, index_revision, job_id, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(
                    case_id, evidence_id, provider_id, provider_version,
                    profile_type, option_fingerprint
                ) DO UPDATE SET
                    status = excluded.status,
                    discovered_items = excluded.discovered_items,
                    processed_items = excluded.processed_items,
                    skipped_items = excluded.skipped_items,
                    warning_count = excluded.warning_count,
                    error_count = excluded.error_count,
                    current_path = excluded.current_path,
                    elapsed_seconds = excluded.elapsed_seconds,
                    throughput_items_per_second = excluded.throughput_items_per_second,
                    estimated_remaining_seconds = excluded.estimated_remaining_seconds,
                    eta_confidence = excluded.eta_confidence,
                    index_revision = excluded.index_revision,
                    job_id = excluded.job_id,
                    updated_at = excluded.updated_at
                """,
                (
                    coverage.case_id,
                    coverage.evidence_id,
                    coverage.provider_id,
                    coverage.provider_version,
                    coverage.profile_type.value,
                    coverage.option_fingerprint,
                    coverage.status.value,
                    coverage.discovered_items,
                    coverage.processed_items,
                    coverage.skipped_items,
                    coverage.warning_count,
                    coverage.error_count,
                    coverage.current_path,
                    coverage.elapsed_seconds,
                    coverage.throughput_items_per_second,
                    coverage.estimated_remaining_seconds,
                    coverage.eta_confidence,
                    coverage.index_revision,
                    coverage.job_id,
                    to_json_timestamp(created_at),
                    to_json_timestamp(updated_at),
                ),
            )
        coverage.created_at = created_at
        coverage.updated_at = updated_at
        return coverage

    def get_fs_coverage(
        self,
        evidence_id: str,
        provider_id: str,
        provider_version: str,
        profile_type: str,
        option_fingerprint: str,
    ) -> IndexCoverage | None:
        """Return one coverage row."""

        row = self.connection.execute(
            """
            SELECT * FROM fs_index_coverage
            WHERE evidence_id = ? AND provider_id = ? AND provider_version = ?
              AND profile_type = ? AND option_fingerprint = ?
            """,
            (evidence_id, provider_id, provider_version, profile_type, option_fingerprint),
        ).fetchone()
        return None if row is None else self._row_to_coverage(row)

    def latest_fs_coverage(self, evidence_id: str) -> IndexCoverage | None:
        """Return latest coverage for evidence."""

        row = self.connection.execute(
            """
            SELECT * FROM fs_index_coverage
            WHERE evidence_id = ?
            ORDER BY updated_at DESC, index_revision DESC
            LIMIT 1
            """,
            (evidence_id,),
        ).fetchone()
        return None if row is None else self._row_to_coverage(row)

    def save_fs_scan_event(self, event: dict[str, Any]) -> None:
        """Persist a scan warning or error."""

        with self.connection:
            self.connection.execute(
                """
                INSERT INTO fs_scan_events (
                    event_id, job_id, case_id, evidence_id, node_id, severity, code,
                    message_key, developer_message, path, details_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.get("event_id") or str(uuid4()),
                    event.get("job_id"),
                    event["case_id"],
                    event["evidence_id"],
                    event.get("node_id"),
                    event["severity"],
                    event["code"],
                    event["message_key"],
                    event["developer_message"],
                    event.get("path"),
                    self._json(event.get("details")),
                    event.get("created_at") or to_json_timestamp(utc_now()),
                ),
            )

    def list_fs_scan_events(self, job_id: str) -> list[dict[str, Any]]:
        """Return scan events for a job."""

        rows = self.connection.execute(
            """
            SELECT * FROM fs_scan_events
            WHERE job_id = ?
            ORDER BY created_at, event_id
            """,
            (job_id,),
        ).fetchall()
        result: list[dict[str, Any]] = []
        for row in rows:
            data = dict(row)
            data["details"] = json.loads(str(data.pop("details_json")))
            result.append(data)
        return result

    def query_fs_nodes(
        self,
        *,
        evidence_id: str,
        parent_node_id: str | None,
        all_nodes: bool,
        directories_only: bool,
        files_only: bool,
        extension: str | None,
        name_or_path: str | None,
        after: tuple[str, str] | None,
        limit: int,
    ) -> list[FileSystemNode]:
        """Query filesystem nodes with stable path/id ordering."""

        clauses = ["evidence_id = ?"]
        params: list[Any] = [evidence_id]
        if not all_nodes:
            if parent_node_id is None:
                clauses.append("parent_node_id IS NULL")
            else:
                clauses.append("parent_node_id = ?")
                params.append(parent_node_id)
        if directories_only:
            clauses.append("node_type IN ('ROOT', 'DIRECTORY')")
        if files_only:
            clauses.append("node_type = 'FILE'")
        if extension is not None:
            clauses.append("extension = ?")
            params.append(extension.casefold().lstrip("."))
        if name_or_path is not None:
            clauses.append("comparison_path LIKE ?")
            params.append(f"%{name_or_path.casefold()}%")
        if after is not None:
            clauses.append("(comparison_path > ? OR (comparison_path = ? AND node_id > ?))")
            params.extend([after[0], after[0], after[1]])
        sql = f"""
            SELECT * FROM fs_nodes
            WHERE {" AND ".join(clauses)}
            ORDER BY comparison_path, node_id
            LIMIT ?
        """
        params.append(limit)
        rows = self.connection.execute(sql, tuple(params)).fetchall()
        return [self._row_to_fs_node(row) for row in rows]

    def save_artifact_analyzer(self, capability: ArtifactCapability) -> None:
        """Persist an artifact analyzer capability statement."""

        with self.connection:
            self.connection.execute(
                """
                INSERT INTO artifact_analyzers (
                    analyzer_id, analyzer_version, parser_backend, parser_backend_version,
                    capabilities_json, metadata_json, registered_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(analyzer_id, analyzer_version) DO UPDATE SET
                    parser_backend = excluded.parser_backend,
                    parser_backend_version = excluded.parser_backend_version,
                    capabilities_json = excluded.capabilities_json,
                    metadata_json = excluded.metadata_json,
                    registered_at = excluded.registered_at
                """,
                (
                    capability.analyzer_id,
                    capability.analyzer_version,
                    capability.parser_backend,
                    capability.parser_backend_version,
                    self._json(capability.to_schema_dict()),
                    self._json(capability.metadata),
                    to_json_timestamp(utc_now()),
                ),
            )

    def save_analyzer_option_fingerprint(
        self,
        *,
        option_fingerprint: str,
        analyzer_id: str,
        analyzer_version: str,
        options: dict[str, Any],
        created_at: str,
    ) -> None:
        """Persist the options represented by an analyzer option fingerprint."""

        with self.connection:
            self.connection.execute(
                """
                INSERT INTO analyzer_option_fingerprints (
                    option_fingerprint, analyzer_id, analyzer_version, options_json, created_at
                ) VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(option_fingerprint, analyzer_id, analyzer_version) DO UPDATE SET
                    options_json = excluded.options_json
                """,
                (
                    option_fingerprint,
                    analyzer_id,
                    analyzer_version,
                    self._json(options),
                    created_at,
                ),
            )

    def next_artifact_index_revision(self, evidence_id: str) -> int:
        """Return the next monotonic artifact index revision for an evidence source."""

        row = self.connection.execute(
            """
            SELECT COALESCE(MAX(index_revision), 0) AS latest
            FROM artifacts
            WHERE evidence_id = ?
            """,
            (evidence_id,),
        ).fetchone()
        return int(row["latest"]) + 1

    def create_artifact_analysis_job(
        self,
        *,
        job_id: str,
        case_id: str,
        evidence_id: str,
        profile_type: str,
        options: dict[str, Any],
        option_fingerprint: str,
        index_revision: int,
        status: str,
        created_at: str,
    ) -> None:
        """Persist Phase 3 artifact analysis job metadata."""

        with self.connection:
            self.connection.execute(
                """
                INSERT INTO artifact_analysis_jobs (
                    job_id, case_id, evidence_id, profile_type, options_json,
                    option_fingerprint, index_revision, status, pause_requested,
                    created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?)
                """,
                (
                    job_id,
                    case_id,
                    evidence_id,
                    profile_type,
                    self._json(options),
                    option_fingerprint,
                    index_revision,
                    status,
                    created_at,
                    created_at,
                ),
            )
            for table in ("browser_analysis_jobs", "media_analysis_jobs"):
                self.connection.execute(
                    f"""
                    INSERT OR IGNORE INTO {table} (
                        job_id, case_id, evidence_id, profile_type, options_json,
                        option_fingerprint, source_revision, status, pause_requested,
                        created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?)
                    """,
                    (
                        job_id,
                        case_id,
                        evidence_id,
                        profile_type,
                        self._json(options),
                        option_fingerprint,
                        index_revision,
                        status,
                        created_at,
                        created_at,
                    ),
                )

    def update_artifact_analysis_job_status(
        self,
        job_id: str,
        status: str,
        *,
        pause_requested: bool | None = None,
    ) -> None:
        """Update artifact job metadata status."""

        assignments = ["status = ?", "updated_at = ?"]
        params: list[Any] = [status, to_json_timestamp(utc_now())]
        if pause_requested is not None:
            assignments.append("pause_requested = ?")
            params.append(int(pause_requested))
        params.append(job_id)
        with self.connection:
            self.connection.execute(
                f"UPDATE artifact_analysis_jobs SET {', '.join(assignments)} WHERE job_id = ?",
                tuple(params),
            )
            for table in ("browser_analysis_jobs", "media_analysis_jobs"):
                self.connection.execute(
                    f"UPDATE {table} SET {', '.join(assignments)} WHERE job_id = ?",
                    tuple(params),
                )

    def get_artifact_analysis_job(self, job_id: str) -> dict[str, Any] | None:
        """Return artifact analysis job metadata."""

        row = self.connection.execute(
            "SELECT * FROM artifact_analysis_jobs WHERE job_id = ?",
            (job_id,),
        ).fetchone()
        if row is None:
            return None
        data = dict(row)
        data["options"] = json.loads(str(data.pop("options_json")))
        return data

    def save_artifact_sources(self, sources: list[ArtifactSource]) -> None:
        """Batch insert artifact source queue rows."""

        with self.connection:
            self.connection.executemany(
                """
                INSERT INTO artifact_sources (
                    source_id, job_id, case_id, evidence_id, source_file_node_id,
                    source_path, source_kind, comparison_key, analyzer_id, analyzer_version,
                    parser_backend, parser_backend_version, option_fingerprint,
                    source_fingerprint, source_checkpoint_json, inspected_count, status,
                    priority, source_order, is_partial, warning_count, error_count,
                    artifact_count, parse_status, last_error_json, discovered_at, analyzed_at,
                    updated_at
                ) VALUES (
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                    ?, ?, ?, ?, ?, ?, ?, ?
                )
                ON CONFLICT(source_id) DO UPDATE SET
                    job_id = excluded.job_id,
                    status = excluded.status,
                    priority = excluded.priority,
                    source_order = excluded.source_order,
                    is_partial = excluded.is_partial,
                    source_fingerprint = excluded.source_fingerprint,
                    source_checkpoint_json = excluded.source_checkpoint_json,
                    inspected_count = excluded.inspected_count,
                    warning_count = excluded.warning_count,
                    error_count = excluded.error_count,
                    artifact_count = excluded.artifact_count,
                    parse_status = excluded.parse_status,
                    last_error_json = excluded.last_error_json,
                    discovered_at = excluded.discovered_at,
                    analyzed_at = excluded.analyzed_at,
                    updated_at = excluded.updated_at
                """,
                [self._artifact_source_values(source) for source in sources],
            )

    def next_artifact_source(self, job_id: str) -> ArtifactSource | None:
        """Claim the next queued artifact source."""

        with self.connection:
            row = self.connection.execute(
                """
                SELECT * FROM artifact_sources
                WHERE job_id = ? AND status = 'QUEUED'
                ORDER BY priority, source_order, source_id
                LIMIT 1
                """,
                (job_id,),
            ).fetchone()
            if row is None:
                return None
            self.connection.execute(
                """
                UPDATE artifact_sources
                SET status = 'PROCESSING', updated_at = ?
                WHERE source_id = ?
                """,
                (to_json_timestamp(utc_now()), row["source_id"]),
            )
        data = dict(row)
        data["status"] = "PROCESSING"
        return self._row_dict_to_artifact_source(data)

    def reset_interrupted_artifact_sources(self, job_id: str) -> None:
        """Return interrupted artifact sources to queued state for resume."""

        with self.connection:
            self.connection.execute(
                """
                UPDATE artifact_sources
                SET status = 'QUEUED', updated_at = ?
                WHERE job_id = ? AND status = 'PROCESSING'
                """,
                (to_json_timestamp(utc_now()), job_id),
            )

    def mark_artifact_source_done(
        self,
        source_id: str,
        *,
        status: str,
        parse_status: str | None,
        warning_count: int,
        error_count: int,
        artifact_count: int,
        last_error: dict[str, Any] | None,
        analyzed_at: str | None,
        source_checkpoint: dict[str, Any] | None = None,
        inspected_count: int | None = None,
        source_fingerprint: str | None = None,
    ) -> None:
        """Persist final source queue state."""

        assignments = [
            "status = ?",
            "parse_status = ?",
            "warning_count = ?",
            "error_count = ?",
            "artifact_count = ?",
            "last_error_json = ?",
            "analyzed_at = ?",
            "updated_at = ?",
        ]
        params: list[Any] = [
            status,
            parse_status,
            warning_count,
            error_count,
            artifact_count,
            self._json(last_error) if last_error is not None else None,
            analyzed_at,
            to_json_timestamp(utc_now()),
        ]
        if source_checkpoint is not None:
            assignments.append("source_checkpoint_json = ?")
            params.append(self._json(source_checkpoint) if source_checkpoint else None)
        if inspected_count is not None:
            assignments.append("inspected_count = ?")
            params.append(inspected_count)
        if source_fingerprint is not None:
            assignments.append("source_fingerprint = ?")
            params.append(source_fingerprint)
        params.append(source_id)
        with self.connection:
            self.connection.execute(
                f"""
                UPDATE artifact_sources
                SET {", ".join(assignments)}
                WHERE source_id = ?
                """,
                tuple(params),
            )

    def count_pending_artifact_sources(self, job_id: str) -> int:
        """Return remaining queued or processing sources for an artifact job."""

        row = self.connection.execute(
            """
            SELECT COUNT(*) AS count
            FROM artifact_sources
            WHERE job_id = ? AND status IN ('QUEUED', 'PROCESSING')
            """,
            (job_id,),
        ).fetchone()
        return int(row["count"])

    def has_completed_artifact_source(
        self,
        *,
        evidence_id: str,
        source_file_node_id: str,
        analyzer_id: str,
        analyzer_version: str,
        option_fingerprint: str,
        source_fingerprint: str | None = None,
    ) -> bool:
        """Return whether the same source/analyzer/options already completed."""

        fingerprint_clause = ""
        params: list[Any] = [
            evidence_id,
            source_file_node_id,
            analyzer_id,
            analyzer_version,
            option_fingerprint,
        ]
        if source_fingerprint is not None:
            fingerprint_clause = "AND source_fingerprint = ?"
            params.append(source_fingerprint)
        row = self.connection.execute(
            f"""
            SELECT 1
            FROM artifact_sources
            WHERE evidence_id = ?
              AND source_file_node_id = ?
              AND analyzer_id = ?
              AND analyzer_version = ?
              AND option_fingerprint = ?
              {fingerprint_clause}
              AND status IN ('SUCCEEDED', 'PARTIAL')
            LIMIT 1
            """,
            tuple(params),
        ).fetchone()
        return row is not None

    def save_artifacts(self, artifacts: list[ArtifactRecord]) -> int:
        """Batch insert immutable artifacts and ignore exact duplicates."""

        inserted = 0
        with self.connection:
            for artifact in artifacts:
                cursor = self.connection.execute(
                    """
                    INSERT OR IGNORE INTO artifacts (
                        artifact_id, case_id, evidence_id, source_file_node_id,
                        artifact_type, artifact_subtype, analyzer_id, analyzer_version,
                        parser_backend, parser_backend_version, source_path, source_kind,
                        observed_at_raw, observed_at_utc, sort_timestamp, timezone_source,
                        timezone_confidence, title, summary, fields_json,
                        raw_locator_json, citations_json, warnings_json, parse_status,
                        confidence, is_partial, index_revision, created_at, updated_at,
                        dedup_key, schema_version, event_id, registry_path,
                        registry_path_key, executable_name, executable_name_key, has_warnings
                    ) VALUES (
                        ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                        ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                    )
                    """,
                    self._artifact_values(artifact),
                )
                inserted += cursor.rowcount
                if cursor.rowcount:
                    self._save_phase5_artifact_projection(artifact)
        return inserted

    def _case_timezone(self, case_id: str) -> str:
        row = self.connection.execute(
            "SELECT timezone FROM cases WHERE case_id = ?",
            (case_id,),
        ).fetchone()
        return "UTC" if row is None else str(row["timezone"])

    def _save_phase5_artifact_projection(self, artifact: ArtifactRecord) -> None:
        if artifact.artifact_type is ArtifactType.BROWSER_PROFILE:
            profile = self._browser_profile_from_artifact(artifact)
            self._save_browser_profile_projection(profile)
            self._save_browser_source_revision(artifact)
            self._save_browser_snapshot_record(artifact)
            return
        if artifact.artifact_type in {
            ArtifactType.BROWSER_VISIT,
            ArtifactType.BROWSER_SEARCH,
            ArtifactType.BROWSER_DOWNLOAD,
            ArtifactType.BROWSER_COOKIE,
            ArtifactType.BROWSER_CREDENTIAL,
            ArtifactType.BROWSER_CACHE_ENTRY,
            ArtifactType.BROWSER_DELETED_SQLITE_ROW,
            ArtifactType.BROWSER_PRIVATE_MODE_CANDIDATE,
        }:
            browser_artifact = self._browser_artifact_from_artifact(artifact)
            self._save_browser_artifact_projection(browser_artifact)
            self._save_browser_source_revision(artifact)
            self._save_browser_snapshot_record(artifact)
            return
        if artifact.artifact_type in {
            ArtifactType.MEDIA_IMAGE,
            ArtifactType.MEDIA_VIDEO,
            ArtifactType.MEDIA_AUDIO,
        }:
            media_artifact = self._media_artifact_from_artifact(artifact)
            self._save_media_artifact_projection(media_artifact)
            self._save_media_source_revision(artifact)
            thumbnail = self._thumbnail_record_from_artifact(artifact)
            if thumbnail is not None:
                self._save_thumbnail_projection(thumbnail)

    def _browser_profile_from_artifact(self, artifact: ArtifactRecord) -> BrowserProfile:
        fields = artifact.fields
        profile = _dict_value(fields.get("browser_profile"))
        profile_path = str(
            profile.get("path") or profile.get("profile_path") or artifact.source_path
        )
        browser_family = str(
            profile.get("browser_family")
            or fields.get("browser_family")
            or profile.get("family")
            or "UNKNOWN"
        )
        browser_name = str(
            profile.get("browser_name")
            or fields.get("browser_name")
            or profile.get("browser")
            or fields.get("browser")
            or "UNKNOWN"
        )
        return BrowserProfile(
            profile_id=str(
                profile.get("profile_id")
                or _phase5_id(
                    "browser-profile",
                    artifact.case_id,
                    artifact.evidence_id,
                    profile_path,
                    browser_name,
                )
            ),
            case_id=artifact.case_id,
            evidence_id=artifact.evidence_id,
            browser_family=browser_family,
            browser_name=browser_name,
            profile_name=str(profile.get("name") or profile.get("profile_name") or "UNKNOWN"),
            profile_path=profile_path,
            source_node_id=artifact.source_file_node_id,
            operating_system=str(
                profile.get("operating_system") or fields.get("operating_system") or "UNKNOWN"
            ),
            user_candidate=None
            if profile.get("user_candidate") is None
            else str(profile.get("user_candidate")),
            discovery_method=str(
                profile.get("discovery_method")
                or fields.get("discovery_method")
                or "FS_NODE_BROWSER_ALLOWLIST"
            ),
            source_revision=artifact.index_revision,
            raw_locator=artifact.raw_locator,
            citations=artifact.citations,
            warnings=artifact.warnings,
            is_partial=artifact.is_partial,
            discovered_at=artifact.created_at,
        )

    def _browser_artifact_from_artifact(self, artifact: ArtifactRecord) -> BrowserArtifact:
        fields = dict(artifact.fields)
        profile = _dict_value(fields.get("browser_profile"))
        profile_path = str(
            profile.get("path") or profile.get("profile_path") or artifact.source_path
        )
        browser_name = str(
            profile.get("browser_name")
            or fields.get("browser_name")
            or profile.get("browser")
            or fields.get("browser")
            or "UNKNOWN"
        )
        url = _str_or_none(fields.get("url") or fields.get("origin_url") or fields.get("cache_url"))
        download_url = _str_or_none(fields.get("download_url"))
        referrer_url = _str_or_none(fields.get("referrer_url") or fields.get("tab_referrer_url"))
        timestamp = artifact.observed_at_utc
        case_timezone = self._case_timezone(artifact.case_id)
        displayed_case_time, effective_timezone, timezone_warning = _displayed_case_time(
            timestamp, case_timezone
        )
        if timezone_warning is not None:
            fields["projection_warnings"] = [
                *_list_value(fields.get("projection_warnings")),
                timezone_warning,
            ]
        return BrowserArtifact(
            artifact_id=artifact.artifact_id,
            case_id=artifact.case_id,
            evidence_id=artifact.evidence_id,
            profile_id=str(
                profile.get("profile_id")
                or _phase5_id(
                    "browser-profile",
                    artifact.case_id,
                    artifact.evidence_id,
                    profile_path,
                    browser_name,
                )
            ),
            browser_family=str(
                profile.get("browser_family")
                or fields.get("browser_family")
                or profile.get("family")
                or "UNKNOWN"
            ),
            browser_name=browser_name,
            artifact_type=_phase5_browser_artifact_type(artifact.artifact_type),
            artifact_subtype=artifact.artifact_subtype,
            title=artifact.title,
            url=url,
            domain=_str_or_none(
                fields.get("domain")
                or fields.get("cookie_domain")
                or fields.get("credential_origin_domain")
            )
            or _domain_from_url(url or download_url),
            search_term=_str_or_none(fields.get("search_term")),
            download_url=download_url,
            download_path=_str_or_none(fields.get("download_path")),
            referrer_url=referrer_url,
            visit_count=_int_or_none(fields.get("visit_count")),
            typed_count=_int_or_none(fields.get("typed_count")),
            transition=_str_or_none(fields.get("transition")),
            raw_timestamp=artifact.observed_at_raw,
            timestamp_semantics=str(
                fields.get("timestamp_semantics") or "browser_native_timestamp"
            ),
            normalized_utc=timestamp,
            case_timezone=effective_timezone,
            displayed_case_time=displayed_case_time,
            fields=fields,
            source_path=artifact.source_path,
            source_node_id=artifact.source_file_node_id,
            source_revision=artifact.index_revision,
            analyzer_id=artifact.analyzer_id,
            analyzer_version=artifact.analyzer_version,
            raw_locator=artifact.raw_locator,
            citations=artifact.citations,
            is_partial=artifact.is_partial,
            created_at=artifact.created_at,
        )

    def _media_artifact_from_artifact(self, artifact: ArtifactRecord) -> MediaArtifact:
        fields = artifact.fields
        classification = _dict_value(fields.get("classification"))
        exif = _dict_value(fields.get("exif"))
        gps = _dict_value(fields.get("gps_normalized"))
        media_times = _list_value(fields.get("media_timestamps"))
        file_times = _list_value(fields.get("file_timestamps"))
        creation = _first_timestamp_candidate(media_times)
        modified = _first_file_timestamp_candidate(file_times, "FILESYSTEM:modified")
        media_type = str(fields.get("media_type") or fields.get("media_kind") or "UNKNOWN")
        codec = _str_or_none(fields.get("codec"))
        thumbnail_status = _thumbnail_status(fields)
        return MediaArtifact(
            media_artifact_id=artifact.artifact_id,
            case_id=artifact.case_id,
            evidence_id=artifact.evidence_id,
            source_node_id=artifact.source_file_node_id,
            source_path=artifact.source_path,
            media_type=media_type,
            format=_str_or_none(fields.get("format") or classification.get("format")),
            mime_candidate=_str_or_none(fields.get("mime") or classification.get("mime")),
            size_bytes=_int_or_none(fields.get("file_size") or fields.get("size_bytes")),
            width=_int_or_none(fields.get("width")),
            height=_int_or_none(fields.get("height")),
            duration_ms=_duration_ms(fields.get("duration_seconds") or fields.get("duration_ms")),
            frame_rate=_str_or_none(fields.get("frame_rate")),
            video_codec=codec if media_type == "VIDEO" else _str_or_none(fields.get("video_codec")),
            audio_codec=codec if media_type == "AUDIO" else _str_or_none(fields.get("audio_codec")),
            sample_rate=_int_or_none(fields.get("sample_rate")),
            channels=_int_or_none(fields.get("channels")),
            bit_rate=_int_or_none(fields.get("bit_rate")),
            creation_time_raw=creation[0],
            creation_time_utc=creation[1],
            modified_time_raw=modified,
            gps_latitude=_float_or_none(gps.get("latitude")),
            gps_longitude=_float_or_none(gps.get("longitude")),
            gps_altitude=_float_or_none(gps.get("altitude_meters") or gps.get("altitude")),
            camera_make=_str_or_none(exif.get("camera_make")),
            camera_model=_str_or_none(exif.get("camera_model")),
            software=_str_or_none(exif.get("software")),
            orientation=_str_or_none(exif.get("orientation")),
            metadata=fields,
            thumbnail_status=thumbnail_status,
            analyzer_id=artifact.analyzer_id,
            analyzer_version=artifact.analyzer_version,
            backend_id=artifact.parser_backend,
            backend_version=artifact.parser_backend_version,
            source_revision=artifact.index_revision,
            raw_locator=artifact.raw_locator,
            citations=artifact.citations,
            is_partial=artifact.is_partial,
            created_at=artifact.created_at,
        )

    def _thumbnail_record_from_artifact(self, artifact: ArtifactRecord) -> ThumbnailRecord | None:
        thumbnail = _dict_value(artifact.fields.get("thumbnail_cache"))
        cache_key = _str_or_none(thumbnail.get("cache_key"))
        if cache_key is None:
            return None
        producer = _dict_value(thumbnail.get("producer"))
        return ThumbnailRecord(
            thumbnail_id=_phase5_id("thumbnail", artifact.case_id, artifact.artifact_id, cache_key),
            case_id=artifact.case_id,
            evidence_id=artifact.evidence_id,
            source_node_id=artifact.source_file_node_id,
            source_artifact_id=artifact.artifact_id,
            source_fingerprint=str(
                thumbnail.get("source_content_sha256")
                or producer.get("source_content_sha256")
                or artifact.dedup_key
            ),
            cache_key=cache_key,
            relative_path=str(thumbnail.get("relative_path") or ""),
            output_format=str(thumbnail.get("output_format") or "JSON_CONTRACT"),
            width=_int_or_none(artifact.fields.get("width")),
            height=_int_or_none(artifact.fields.get("height")),
            size_bytes=int(thumbnail.get("size_bytes") or 0),
            content_sha256=str(thumbnail.get("content_sha256") or artifact.dedup_key),
            status=str(thumbnail.get("status") or "GENERATED"),
            analyzer_id=artifact.analyzer_id,
            analyzer_version=artifact.analyzer_version,
            created_at=artifact.created_at,
        )

    def _save_browser_profile_projection(self, profile: BrowserProfile) -> None:
        self.connection.execute(
            """
            INSERT OR IGNORE INTO browser_profiles (
                profile_id, case_id, evidence_id, browser_family, browser_name, profile_name,
                profile_path, source_node_id, operating_system, user_candidate, discovery_method,
                source_revision, raw_locator_json, citations_json, warnings_json, is_partial,
                discovered_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                profile.profile_id,
                profile.case_id,
                profile.evidence_id,
                profile.browser_family,
                profile.browser_name,
                profile.profile_name,
                profile.profile_path,
                profile.source_node_id,
                profile.operating_system,
                profile.user_candidate,
                profile.discovery_method,
                profile.source_revision,
                self._json(profile.raw_locator),
                self._json(profile.citations),
                self._json(profile.warnings),
                int(profile.is_partial),
                to_json_timestamp(profile.discovered_at or utc_now()),
            ),
        )

    def _save_browser_artifact_projection(self, artifact: BrowserArtifact) -> None:
        self.connection.execute(
            """
            INSERT OR IGNORE INTO browser_artifacts (
                artifact_id, case_id, evidence_id, profile_id, browser_family, browser_name,
                artifact_type, artifact_subtype, title, url, domain, search_term, download_url,
                download_path, referrer_url, visit_count, typed_count, transition, raw_timestamp,
                timestamp_semantics, normalized_utc, case_timezone, displayed_case_time,
                fields_json, source_path, source_node_id, source_revision, analyzer_id,
                analyzer_version, raw_locator_json, citations_json, is_partial, created_at
            ) VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
            )
            """,
            (
                artifact.artifact_id,
                artifact.case_id,
                artifact.evidence_id,
                artifact.profile_id,
                artifact.browser_family,
                artifact.browser_name,
                artifact.artifact_type,
                artifact.artifact_subtype,
                artifact.title,
                artifact.url,
                artifact.domain,
                artifact.search_term,
                artifact.download_url,
                artifact.download_path,
                artifact.referrer_url,
                artifact.visit_count,
                artifact.typed_count,
                artifact.transition,
                artifact.raw_timestamp,
                artifact.timestamp_semantics,
                self._nullable_timestamp(artifact.normalized_utc),
                artifact.case_timezone,
                artifact.displayed_case_time,
                self._json(artifact.fields),
                artifact.source_path,
                artifact.source_node_id,
                artifact.source_revision,
                artifact.analyzer_id,
                artifact.analyzer_version,
                self._json(artifact.raw_locator),
                self._json(artifact.citations),
                int(artifact.is_partial),
                to_json_timestamp(artifact.created_at or utc_now()),
            ),
        )

    def _save_media_artifact_projection(self, artifact: MediaArtifact) -> None:
        self.connection.execute(
            """
            INSERT OR IGNORE INTO media_artifacts (
                media_artifact_id, case_id, evidence_id, source_node_id, source_path, media_type,
                format, mime_candidate, size_bytes, width, height, duration_ms, frame_rate,
                video_codec, audio_codec, sample_rate, channels, bit_rate, creation_time_raw,
                creation_time_utc, modified_time_raw, gps_latitude, gps_longitude, gps_altitude,
                camera_make, camera_model, software, orientation, metadata_json,
                thumbnail_status, analyzer_id, analyzer_version, backend_id, backend_version,
                source_revision, raw_locator_json, citations_json, is_partial, created_at
            ) VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
            )
            """,
            (
                artifact.media_artifact_id,
                artifact.case_id,
                artifact.evidence_id,
                artifact.source_node_id,
                artifact.source_path,
                artifact.media_type,
                artifact.format,
                artifact.mime_candidate,
                artifact.size_bytes,
                artifact.width,
                artifact.height,
                artifact.duration_ms,
                artifact.frame_rate,
                artifact.video_codec,
                artifact.audio_codec,
                artifact.sample_rate,
                artifact.channels,
                artifact.bit_rate,
                artifact.creation_time_raw,
                self._nullable_timestamp(artifact.creation_time_utc),
                artifact.modified_time_raw,
                artifact.gps_latitude,
                artifact.gps_longitude,
                artifact.gps_altitude,
                artifact.camera_make,
                artifact.camera_model,
                artifact.software,
                artifact.orientation,
                self._json(artifact.metadata),
                artifact.thumbnail_status,
                artifact.analyzer_id,
                artifact.analyzer_version,
                artifact.backend_id,
                artifact.backend_version,
                artifact.source_revision,
                self._json(artifact.raw_locator),
                self._json(artifact.citations),
                int(artifact.is_partial),
                to_json_timestamp(artifact.created_at or utc_now()),
            ),
        )

    def _save_thumbnail_projection(self, thumbnail: ThumbnailRecord) -> None:
        self.connection.execute(
            """
            INSERT OR IGNORE INTO thumbnail_records (
                thumbnail_id, case_id, evidence_id, source_node_id, source_artifact_id,
                source_fingerprint, cache_key, relative_path, output_format, width, height,
                size_bytes, content_sha256, status, analyzer_id, analyzer_version, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                thumbnail.thumbnail_id,
                thumbnail.case_id,
                thumbnail.evidence_id,
                thumbnail.source_node_id,
                thumbnail.source_artifact_id,
                thumbnail.source_fingerprint,
                thumbnail.cache_key,
                thumbnail.relative_path,
                thumbnail.output_format,
                thumbnail.width,
                thumbnail.height,
                thumbnail.size_bytes,
                thumbnail.content_sha256,
                thumbnail.status,
                thumbnail.analyzer_id,
                thumbnail.analyzer_version,
                to_json_timestamp(thumbnail.created_at or utc_now()),
            ),
        )

    def _save_browser_source_revision(self, artifact: ArtifactRecord) -> None:
        fingerprint = _browser_source_fingerprint(artifact)
        self.connection.execute(
            """
            INSERT OR IGNORE INTO browser_source_revisions (
                source_revision_id, case_id, evidence_id, source_node_id, source_path,
                source_revision, source_fingerprint, analyzer_id, analyzer_version, observed_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                _phase5_id(
                    "browser-source-revision",
                    artifact.evidence_id,
                    artifact.source_file_node_id,
                    str(artifact.index_revision),
                    artifact.analyzer_id,
                ),
                artifact.case_id,
                artifact.evidence_id,
                artifact.source_file_node_id,
                artifact.source_path,
                artifact.index_revision,
                fingerprint,
                artifact.analyzer_id,
                artifact.analyzer_version,
                to_json_timestamp(artifact.created_at),
            ),
        )

    def _save_media_source_revision(self, artifact: ArtifactRecord) -> None:
        fingerprint = _media_source_fingerprint(artifact)
        self.connection.execute(
            """
            INSERT OR IGNORE INTO media_source_revisions (
                source_revision_id, case_id, evidence_id, source_node_id, source_path,
                source_revision, source_fingerprint, analyzer_id, analyzer_version, observed_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                _phase5_id(
                    "media-source-revision",
                    artifact.evidence_id,
                    artifact.source_file_node_id,
                    str(artifact.index_revision),
                    artifact.analyzer_id,
                ),
                artifact.case_id,
                artifact.evidence_id,
                artifact.source_file_node_id,
                artifact.source_path,
                artifact.index_revision,
                fingerprint,
                artifact.analyzer_id,
                artifact.analyzer_version,
                to_json_timestamp(artifact.created_at),
            ),
        )

    def _save_browser_snapshot_record(self, artifact: ArtifactRecord) -> None:
        snapshot = _dict_value(artifact.fields.get("snapshot"))
        if not snapshot:
            return
        component_hashes = _dict_value(snapshot.get("component_hashes"))
        snapshot_hash = str(snapshot.get("snapshot_hash") or canonical_sha256(component_hashes))
        self.connection.execute(
            """
            INSERT OR IGNORE INTO browser_snapshot_records (
                snapshot_id, case_id, evidence_id, source_node_id, source_path,
                source_fingerprint, snapshot_hash, component_hashes_json, wal_preserved,
                shm_preserved, cleanup_policy, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                _phase5_id(
                    "browser-snapshot", artifact.case_id, artifact.artifact_id, snapshot_hash
                ),
                artifact.case_id,
                artifact.evidence_id,
                artifact.source_file_node_id,
                artifact.source_path,
                _browser_source_fingerprint(artifact),
                snapshot_hash,
                self._json(component_hashes),
                int(bool(snapshot.get("wal_preserved"))),
                int(bool(snapshot.get("shm_preserved"))),
                str(snapshot.get("cleanup_policy") or "temporary_directory_cleanup_after_analysis"),
                to_json_timestamp(artifact.created_at),
            ),
        )

    def save_cache_entries(self, entries: list[dict[str, Any]]) -> int:
        """Persist generic content-addressed cache metadata."""

        inserted = 0
        with self.connection:
            for entry in entries:
                cursor = self.connection.execute(
                    """
                    INSERT OR IGNORE INTO cache_entries (
                        key_sha256, case_id, kind, relative_path, size_bytes,
                        content_sha256, created_at, last_accessed_at, expires_at,
                        producer_json
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        str(entry["key_sha256"]),
                        str(entry["case_id"]),
                        str(entry["kind"]),
                        str(entry["relative_path"]),
                        int(entry["size_bytes"]),
                        str(entry["content_sha256"]),
                        str(entry["created_at"]),
                        str(entry["last_accessed_at"]),
                        None if entry.get("expires_at") is None else str(entry["expires_at"]),
                        self._json(dict(entry.get("producer", {}))),
                    ),
                )
                inserted += cursor.rowcount
        return inserted

    def save_provider_capability(self, capability: ProviderCapability) -> None:
        """Persist a Phase 5 optional provider capability statement."""

        updated_at = to_json_timestamp(capability.updated_at or utc_now())
        with self.connection:
            self.connection.execute(
                """
                INSERT INTO provider_capabilities (
                    provider_id, provider_version, capability_type, is_available,
                    supported_inputs_json, supported_outputs_json, unavailable_reason,
                    warnings_json, metadata_json, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(provider_id, provider_version, capability_type) DO UPDATE SET
                    is_available = excluded.is_available,
                    supported_inputs_json = excluded.supported_inputs_json,
                    supported_outputs_json = excluded.supported_outputs_json,
                    unavailable_reason = excluded.unavailable_reason,
                    warnings_json = excluded.warnings_json,
                    metadata_json = excluded.metadata_json,
                    updated_at = excluded.updated_at
                """,
                (
                    capability.provider_id,
                    capability.provider_version,
                    capability.capability_type,
                    int(capability.is_available),
                    self._json(capability.supported_inputs),
                    self._json(capability.supported_outputs),
                    capability.unavailable_reason,
                    self._json(capability.warnings),
                    self._json(capability.metadata),
                    updated_at,
                ),
            )

    def list_provider_capabilities(
        self,
        *,
        capability_type: str | None = None,
    ) -> list[ProviderCapability]:
        """Return stored provider capabilities."""

        if capability_type is None:
            rows = self.connection.execute(
                """
                SELECT * FROM provider_capabilities
                ORDER BY capability_type, provider_id, provider_version
                """
            ).fetchall()
        else:
            rows = self.connection.execute(
                """
                SELECT * FROM provider_capabilities
                WHERE capability_type = ?
                ORDER BY provider_id, provider_version
                """,
                (capability_type,),
            ).fetchall()
        return [self._row_to_provider_capability(row) for row in rows]

    def save_secret_provider_capability(self, capability: SecretProviderCapability) -> None:
        """Persist a secret/decryption provider capability statement without key material."""

        generated_at = to_json_timestamp(capability.generated_at or utc_now())
        data = capability.to_schema_dict()
        with self.connection:
            self.connection.execute(
                """
                INSERT INTO secret_provider_capabilities (
                    provider_id, provider_version, capability_type, runtime_status,
                    supported_key_sources_json, supported_algorithms_json, requires_host,
                    requires_network, warnings_json, generated_at, capability_version,
                    capability_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(provider_id, provider_version, capability_type) DO UPDATE SET
                    runtime_status = excluded.runtime_status,
                    supported_key_sources_json = excluded.supported_key_sources_json,
                    supported_algorithms_json = excluded.supported_algorithms_json,
                    requires_host = excluded.requires_host,
                    requires_network = excluded.requires_network,
                    warnings_json = excluded.warnings_json,
                    generated_at = excluded.generated_at,
                    capability_version = excluded.capability_version,
                    capability_json = excluded.capability_json
                """,
                (
                    capability.provider_id,
                    capability.provider_version,
                    capability.capability_type,
                    capability.runtime_status,
                    self._json(capability.supported_key_sources),
                    self._json(capability.supported_algorithms),
                    int(capability.requires_host),
                    int(capability.requires_network),
                    self._json(data["warnings"]),
                    generated_at,
                    capability.capability_version,
                    self._json(data),
                ),
            )

    def list_secret_provider_capabilities(
        self,
        *,
        capability_type: str | None = None,
    ) -> list[SecretProviderCapability]:
        """Return stored secret/decryption provider capabilities."""

        if capability_type is None:
            rows = self.connection.execute(
                """
                SELECT * FROM secret_provider_capabilities
                ORDER BY capability_type, provider_id, provider_version
                """
            ).fetchall()
        else:
            rows = self.connection.execute(
                """
                SELECT * FROM secret_provider_capabilities
                WHERE capability_type = ?
                ORDER BY provider_id, provider_version
                """,
                (capability_type,),
            ).fetchall()
        return [self._row_to_secret_provider_capability(row) for row in rows]

    def save_decryption_attempt(self, attempt: DecryptionAttempt) -> None:
        """Insert one sanitized decryption attempt audit row."""

        with self.connection:
            self._insert_decryption_attempt(attempt)

    def save_decryption_result(self, result: DecryptionResult) -> None:
        """Persist one sanitized decryption result and its attempt metadata."""

        data = result.to_schema_dict(include_plaintext=False)
        if "plaintext_b64" in data:
            raise ValueError("decryption result audit payload must not include plaintext")
        attempt = result.attempt
        created_at = attempt.completed_at or utc_now()
        with self.connection:
            self._insert_decryption_attempt(attempt)
            self.connection.execute(
                """
                INSERT INTO decryption_results (
                    attempt_id, case_id, evidence_id, status, output_kind, content_sha256,
                    content_length, partial, citations_json, metadata_json,
                    result_fingerprint, result_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    attempt.attempt_id,
                    attempt.case_id,
                    attempt.evidence_id,
                    result.status,
                    result.output_kind,
                    result.content_sha256,
                    result.content_length,
                    int(result.partial),
                    self._json(data["citations"]),
                    self._json(data["metadata"]),
                    canonical_sha256(data),
                    self._json(data),
                    to_json_timestamp(created_at),
                ),
            )

    def _insert_decryption_attempt(self, attempt: DecryptionAttempt) -> None:
        data = attempt.to_schema_dict()
        self.connection.execute(
            """
            INSERT INTO decryption_attempts (
                attempt_id, case_id, evidence_id, provider_id, provider_version,
                algorithm, key_source_kind, status, started_at, completed_at,
                error_code, error_message, warnings_json, attempt_fingerprint,
                attempt_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                attempt.attempt_id,
                attempt.case_id,
                attempt.evidence_id,
                attempt.provider_id,
                attempt.provider_version,
                attempt.algorithm,
                attempt.key_source_kind,
                attempt.status,
                to_json_timestamp(attempt.started_at),
                self._nullable_timestamp(attempt.completed_at),
                attempt.error_code,
                data.get("error_message"),
                self._json(data["warnings"]),
                canonical_sha256(data),
                self._json(data),
            ),
        )

    def get_decryption_result(self, attempt_id: str) -> dict[str, Any] | None:
        """Return one stored decryption result schema payload without plaintext bytes."""

        row = self.connection.execute(
            "SELECT result_json FROM decryption_results WHERE attempt_id = ?",
            (attempt_id,),
        ).fetchone()
        if row is None:
            return None
        return dict(json.loads(str(row["result_json"])))

    def list_decryption_results(
        self,
        *,
        case_id: str,
        status: str | None = None,
    ) -> list[dict[str, Any]]:
        """List stored decryption result schema payloads for one case."""

        if status is None:
            rows = self.connection.execute(
                """
                SELECT result_json FROM decryption_results
                WHERE case_id = ?
                ORDER BY created_at DESC, attempt_id
                """,
                (case_id,),
            ).fetchall()
        else:
            rows = self.connection.execute(
                """
                SELECT result_json FROM decryption_results
                WHERE case_id = ? AND status = ?
                ORDER BY created_at DESC, attempt_id
                """,
                (case_id, status),
            ).fetchall()
        return [dict(json.loads(str(row["result_json"]))) for row in rows]

    def save_machine_candidate(self, candidate: MachineExtractedCandidate) -> None:
        """Insert one immutable machine-extracted candidate."""

        with self.connection:
            self.connection.execute(
                """
                INSERT INTO machine_extracted_candidates (
                    candidate_id, case_id, evidence_id, source_node_id, source_type,
                    extraction_type, text, language, confidence, provider_id, provider_version,
                    model_id, region_json, frame_number, media_timestamp_ms, audio_start_ms,
                    audio_end_ms, raw_locator_json, citations_json, review_status, reviewed_by,
                    reviewed_at, correction_text, source_revision, is_partial, created_at
                ) VALUES (
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                    ?, ?, ?, ?, ?, ?
                )
                """,
                (
                    candidate.candidate_id,
                    candidate.case_id,
                    candidate.evidence_id,
                    candidate.source_node_id,
                    candidate.source_type,
                    candidate.extraction_type,
                    candidate.text,
                    candidate.language,
                    candidate.confidence,
                    candidate.provider_id,
                    candidate.provider_version,
                    candidate.model_id,
                    None if candidate.region is None else self._json(candidate.region),
                    candidate.frame_number,
                    candidate.media_timestamp_ms,
                    candidate.audio_start_ms,
                    candidate.audio_end_ms,
                    self._json(candidate.raw_locator),
                    self._json(candidate.citations),
                    candidate.review_status,
                    candidate.reviewed_by,
                    self._nullable_timestamp(candidate.reviewed_at),
                    candidate.correction_text,
                    candidate.source_revision,
                    int(candidate.is_partial),
                    to_json_timestamp(candidate.created_at or utc_now()),
                ),
            )

    def get_machine_candidate(self, candidate_id: str) -> MachineExtractedCandidate | None:
        """Return one machine-extracted candidate."""

        row = self.connection.execute(
            "SELECT * FROM machine_extracted_candidates WHERE candidate_id = ?",
            (candidate_id,),
        ).fetchone()
        return None if row is None else self._row_to_machine_candidate(row)

    def list_machine_candidates(
        self,
        *,
        case_id: str,
        evidence_id: str | None = None,
        review_status: str | None = None,
        after_candidate_id: str | None = None,
        limit: int = 100,
    ) -> list[MachineExtractedCandidate]:
        """List machine candidates using stable candidate_id pagination."""

        clauses = ["case_id = ?"]
        params: list[Any] = [case_id]
        if evidence_id is not None:
            clauses.append("evidence_id = ?")
            params.append(evidence_id)
        if review_status is not None:
            clauses.append("review_status = ?")
            params.append(review_status)
        if after_candidate_id is not None:
            clauses.append("candidate_id > ?")
            params.append(after_candidate_id)
        params.append(limit)
        rows = self.connection.execute(
            f"""
            SELECT * FROM machine_extracted_candidates
            WHERE {" AND ".join(clauses)}
            ORDER BY candidate_id
            LIMIT ?
            """,
            tuple(params),
        ).fetchall()
        return [self._row_to_machine_candidate(row) for row in rows]

    def append_candidate_review(
        self,
        event: CandidateReviewEvent,
        *,
        correction_text: str | None,
    ) -> MachineExtractedCandidate:
        """Append a review event and update the current review projection."""

        with self.connection:
            self.connection.execute(
                """
                INSERT INTO candidate_review_events (
                    review_event_id, candidate_id, case_id, review_status, reviewed_by,
                    reviewed_at, correction_text, previous_review_status, reason
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.review_event_id,
                    event.candidate_id,
                    event.case_id,
                    event.review_status,
                    event.reviewed_by,
                    to_json_timestamp(event.reviewed_at),
                    event.correction_text,
                    event.previous_review_status,
                    event.reason,
                ),
            )
            self.connection.execute(
                """
                UPDATE machine_extracted_candidates
                SET review_status = ?, reviewed_by = ?, reviewed_at = ?, correction_text = ?
                WHERE candidate_id = ?
                """,
                (
                    event.review_status,
                    event.reviewed_by,
                    to_json_timestamp(event.reviewed_at),
                    correction_text,
                    event.candidate_id,
                ),
            )
        candidate = self.get_machine_candidate(event.candidate_id)
        if candidate is None:
            raise sqlite3.IntegrityError("candidate disappeared after review insert")
        return candidate

    def list_candidate_reviews(self, candidate_id: str) -> list[CandidateReviewEvent]:
        """Return append-only review events for one candidate."""

        rows = self.connection.execute(
            """
            SELECT * FROM candidate_review_events
            WHERE candidate_id = ?
            ORDER BY reviewed_at, review_event_id
            """,
            (candidate_id,),
        ).fetchall()
        return [self._row_to_candidate_review(row) for row in rows]

    def get_artifact(self, artifact_id: str) -> ArtifactRecord | None:
        """Return one artifact by ID."""

        row = self.connection.execute(
            "SELECT * FROM artifacts WHERE artifact_id = ?",
            (artifact_id,),
        ).fetchone()
        return None if row is None else self._row_to_artifact(row)

    def query_artifacts(
        self,
        *,
        query: ArtifactQuery,
        after: tuple[str, str] | None,
        limit: int,
    ) -> list[ArtifactRecord]:
        """Query artifacts by typed filters with stable cursor ordering."""

        clauses = ["case_id = ?"]
        params: list[Any] = [query.case_id]
        if query.evidence_id is not None:
            clauses.append("evidence_id = ?")
            params.append(query.evidence_id)
        if query.source_file_node_id is not None:
            clauses.append("source_file_node_id = ?")
            params.append(query.source_file_node_id)
        if query.artifact_type is not None:
            clauses.append("artifact_type = ?")
            params.append(query.artifact_type.value)
        if query.artifact_subtype is not None:
            clauses.append("artifact_subtype = ?")
            params.append(query.artifact_subtype)
        if query.analyzer_id is not None:
            clauses.append("analyzer_id = ?")
            params.append(query.analyzer_id)
        if query.event_id is not None:
            clauses.append("event_id = ?")
            params.append(query.event_id)
        if query.registry_path is not None:
            clauses.append("registry_path_key LIKE ?")
            params.append(f"%{query.registry_path.casefold()}%")
        if query.executable_name is not None:
            clauses.append("executable_name_key LIKE ?")
            params.append(f"%{query.executable_name.casefold()}%")
        if query.media_kind is not None:
            clauses.append("json_extract(fields_json, '$.media_kind') = ?")
            params.append(query.media_kind.upper())
        if query.browser_profile is not None:
            clauses.append(
                """
                (
                    lower(json_extract(fields_json, '$.browser_profile.name')) LIKE ?
                    OR lower(json_extract(fields_json, '$.browser_profile_name')) LIKE ?
                )
                """
            )
            profile = f"%{query.browser_profile.casefold()}%"
            params.extend([profile, profile])
        if query.browser_database is not None:
            clauses.append(
                """
                (
                    lower(json_extract(fields_json, '$.database.path')) LIKE ?
                    OR lower(json_extract(fields_json, '$.database_path')) LIKE ?
                )
                """
            )
            database = f"%{query.browser_database.casefold()}%"
            params.extend([database, database])
        if query.browser_table is not None:
            clauses.append(
                """
                (
                    json_extract(fields_json, '$.row_provenance.table') = ?
                    OR json_extract(fields_json, '$.table') = ?
                )
                """
            )
            params.extend([query.browser_table, query.browser_table])
        if query.browser_row_id is not None:
            clauses.append(
                """
                (
                    CAST(json_extract(fields_json, '$.row_provenance.row_id') AS INTEGER) = ?
                    OR CAST(json_extract(fields_json, '$.row_id') AS INTEGER) = ?
                )
                """
            )
            params.extend([query.browser_row_id, query.browser_row_id])
        if query.observed_from is not None:
            clauses.append("sort_timestamp >= ?")
            params.append(to_json_timestamp(query.observed_from))
        if query.observed_to is not None:
            clauses.append("sort_timestamp <= ?")
            params.append(to_json_timestamp(query.observed_to))
        if query.parse_status is not None:
            clauses.append("parse_status = ?")
            params.append(query.parse_status.value)
        if query.has_warnings is not None:
            clauses.append("has_warnings = ?")
            params.append(int(query.has_warnings))
        if after is not None:
            clauses.append("(sort_timestamp > ? OR (sort_timestamp = ? AND artifact_id > ?))")
            params.extend([after[0], after[0], after[1]])
        sql = f"""
            SELECT * FROM artifacts
            WHERE {" AND ".join(clauses)}
            ORDER BY sort_timestamp, artifact_id
            LIMIT ?
        """
        params.append(limit)
        rows = self.connection.execute(sql, tuple(params)).fetchall()
        return [self._row_to_artifact(row) for row in rows]

    def save_artifact_warning(
        self,
        warning_id: str,
        *,
        job_id: str | None,
        case_id: str,
        evidence_id: str,
        source_id: str | None,
        source_file_node_id: str | None,
        artifact_id: str | None,
        severity: str,
        code: str,
        message_key: str,
        developer_message: str,
        source_path: str | None,
        details: dict[str, Any],
        created_at: str,
    ) -> None:
        """Persist an artifact analysis warning or parse error."""

        with self.connection:
            self.connection.execute(
                """
                INSERT INTO artifact_warnings (
                    warning_id, job_id, case_id, evidence_id, source_id,
                    source_file_node_id, artifact_id, severity, code, message_key,
                    developer_message, source_path, details_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    warning_id,
                    job_id,
                    case_id,
                    evidence_id,
                    source_id,
                    source_file_node_id,
                    artifact_id,
                    severity,
                    code,
                    message_key,
                    developer_message,
                    source_path,
                    self._json(details),
                    created_at,
                ),
            )

    def list_artifact_warnings(
        self,
        *,
        job_id: str | None = None,
        artifact_id: str | None = None,
        evidence_id: str | None = None,
    ) -> list[dict[str, Any]]:
        """Return stored artifact warnings and parse errors."""

        clauses: list[str] = []
        params: list[Any] = []
        if job_id is not None:
            clauses.append("job_id = ?")
            params.append(job_id)
        if artifact_id is not None:
            clauses.append("artifact_id = ?")
            params.append(artifact_id)
        if evidence_id is not None:
            clauses.append("evidence_id = ?")
            params.append(evidence_id)
        where = "" if not clauses else "WHERE " + " AND ".join(clauses)
        rows = self.connection.execute(
            f"""
            SELECT * FROM artifact_warnings
            {where}
            ORDER BY created_at, warning_id
            """,
            tuple(params),
        ).fetchall()
        result: list[dict[str, Any]] = []
        for row in rows:
            data = dict(row)
            data["details"] = json.loads(str(data.pop("details_json")))
            result.append(data)
        return result

    def upsert_artifact_coverage(self, coverage: ArtifactCoverage) -> ArtifactCoverage:
        """Insert or update artifact coverage counters."""

        now = utc_now()
        created_at = coverage.created_at or now
        updated_at = coverage.updated_at or now
        with self.connection:
            self.connection.execute(
                """
                INSERT INTO artifact_coverage (
                    job_id, case_id, evidence_id, profile_type, option_fingerprint,
                    status, source_count, processed_sources, skipped_sources,
                    artifact_count, warning_count, error_count, current_analyzer,
                    current_source_path, elapsed_seconds, throughput_items_per_second,
                    estimated_remaining_seconds, eta_confidence, is_partial,
                    index_revision, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(job_id) DO UPDATE SET
                    status = excluded.status,
                    source_count = excluded.source_count,
                    processed_sources = excluded.processed_sources,
                    skipped_sources = excluded.skipped_sources,
                    artifact_count = excluded.artifact_count,
                    warning_count = excluded.warning_count,
                    error_count = excluded.error_count,
                    current_analyzer = excluded.current_analyzer,
                    current_source_path = excluded.current_source_path,
                    elapsed_seconds = excluded.elapsed_seconds,
                    throughput_items_per_second = excluded.throughput_items_per_second,
                    estimated_remaining_seconds = excluded.estimated_remaining_seconds,
                    eta_confidence = excluded.eta_confidence,
                    is_partial = excluded.is_partial,
                    index_revision = excluded.index_revision,
                    updated_at = excluded.updated_at
                """,
                (
                    coverage.job_id,
                    coverage.case_id,
                    coverage.evidence_id,
                    coverage.profile_type.value,
                    coverage.option_fingerprint,
                    coverage.status.value,
                    coverage.source_count,
                    coverage.processed_sources,
                    coverage.skipped_sources,
                    coverage.artifact_count,
                    coverage.warning_count,
                    coverage.error_count,
                    coverage.current_analyzer,
                    coverage.current_source_path,
                    coverage.elapsed_seconds,
                    coverage.throughput_items_per_second,
                    coverage.estimated_remaining_seconds,
                    coverage.eta_confidence,
                    int(coverage.is_partial),
                    coverage.index_revision,
                    to_json_timestamp(created_at),
                    to_json_timestamp(updated_at),
                ),
            )
        coverage.created_at = created_at
        coverage.updated_at = updated_at
        return coverage

    def get_artifact_coverage(self, job_id: str) -> ArtifactCoverage | None:
        """Return coverage for one artifact job."""

        row = self.connection.execute(
            "SELECT * FROM artifact_coverage WHERE job_id = ?",
            (job_id,),
        ).fetchone()
        return None if row is None else self._row_to_artifact_coverage(row)

    def latest_artifact_coverage(self, evidence_id: str) -> ArtifactCoverage | None:
        """Return latest artifact coverage for evidence."""

        row = self.connection.execute(
            """
            SELECT * FROM artifact_coverage
            WHERE evidence_id = ?
            ORDER BY updated_at DESC, job_id DESC
            LIMIT 1
            """,
            (evidence_id,),
        ).fetchone()
        return None if row is None else self._row_to_artifact_coverage(row)

    def save_artifact_checkpoint(
        self,
        *,
        job_id: str,
        current_source_id: str | None,
        current_source_path: str | None,
        pending_source_count: int,
        processed_sources: int,
        artifact_count: int,
    ) -> None:
        """Persist resumable artifact analysis checkpoint state."""

        now = to_json_timestamp(utc_now())
        with self.connection:
            self.connection.execute(
                """
                INSERT INTO artifact_checkpoints (
                    job_id, current_source_id, current_source_path, pending_source_count,
                    processed_sources, artifact_count, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(job_id) DO UPDATE SET
                    current_source_id = excluded.current_source_id,
                    current_source_path = excluded.current_source_path,
                    pending_source_count = excluded.pending_source_count,
                    processed_sources = excluded.processed_sources,
                    artifact_count = excluded.artifact_count,
                    updated_at = excluded.updated_at
                """,
                (
                    job_id,
                    current_source_id,
                    current_source_path,
                    pending_source_count,
                    processed_sources,
                    artifact_count,
                    now,
                ),
            )
            self.connection.execute(
                """
                INSERT INTO browser_checkpoints (
                    job_id, current_profile_id, current_source_node_id, current_path,
                    pending_items, processed_items, artifact_count, updated_at
                ) VALUES (?, NULL, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(job_id) DO UPDATE SET
                    current_source_node_id = excluded.current_source_node_id,
                    current_path = excluded.current_path,
                    pending_items = excluded.pending_items,
                    processed_items = excluded.processed_items,
                    artifact_count = excluded.artifact_count,
                    updated_at = excluded.updated_at
                """,
                (
                    job_id,
                    current_source_id,
                    current_source_path,
                    pending_source_count,
                    processed_sources,
                    artifact_count,
                    now,
                ),
            )
            self.connection.execute(
                """
                INSERT INTO media_checkpoints (
                    job_id, current_source_node_id, current_path,
                    pending_items, processed_items, artifact_count, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(job_id) DO UPDATE SET
                    current_source_node_id = excluded.current_source_node_id,
                    current_path = excluded.current_path,
                    pending_items = excluded.pending_items,
                    processed_items = excluded.processed_items,
                    artifact_count = excluded.artifact_count,
                    updated_at = excluded.updated_at
                """,
                (
                    job_id,
                    current_source_id,
                    current_source_path,
                    pending_source_count,
                    processed_sources,
                    artifact_count,
                    now,
                ),
            )

    def search_capability(self) -> SearchIndexCapability:
        """Return SQLite FTS5 capability without pretending fallback search is equivalent."""

        available = self._fts5_available()
        unavailable = [] if available else ["SQLITE_FTS5"]
        warnings = []
        if not available:
            warnings.append(
                {
                    "code": "SQLITE_FTS5_UNAVAILABLE",
                    "developer_message": "SQLite was built without FTS5 support.",
                }
            )
        return SearchIndexCapability(
            backend="sqlite-fts5",
            backend_version=sqlite3.sqlite_version,
            fts5_available=available,
            tokenizer="unicode61+apex-search-normalization-ko-v1",
            capabilities=[
                "METADATA_SEARCH",
                "ARTIFACT_FIELD_SEARCH",
                "VERSIONED_SEARCH_COPY_NORMALIZATION",
                "KOREAN_NFC_CASEFOLD_PATH_NORMALIZATION",
                "SQLITE_FTS5_UNICODE61_TOKENIZER",
                "MORPHOLOGICAL_ANALYSIS_NOT_CLAIMED",
                "TERM",
                "PHRASE",
                "PREFIX",
                "EXACT",
                "REGEX_METADATA_CANDIDATE_FILTER",
            ]
            if available
            else [],
            unavailable_capabilities=unavailable,
            warnings=warnings,
        )

    def search_backend_version(self) -> str:
        """Return the SQLite runtime version used by the search backend."""

        return sqlite3.sqlite_version

    def next_search_index_revision(self, case_id: str) -> int:
        """Reserve and return the next search index revision for a case."""

        current = self.current_search_index_revision(case_id)
        next_revision = current + 1
        now = to_json_timestamp(utc_now())
        with self.connection:
            self.connection.execute(
                """
                INSERT INTO search_index_metadata (
                    case_id, index_revision, backend, backend_version,
                    fts5_available, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(case_id) DO UPDATE SET
                    index_revision = excluded.index_revision,
                    backend = excluded.backend,
                    backend_version = excluded.backend_version,
                    fts5_available = excluded.fts5_available,
                    updated_at = excluded.updated_at
                """,
                (
                    case_id,
                    next_revision,
                    "sqlite-fts5",
                    sqlite3.sqlite_version,
                    int(self._fts5_available()),
                    now,
                ),
            )
        return next_revision

    def current_search_index_revision(self, case_id: str) -> int:
        """Return the latest search index revision known for a case."""

        row = self.connection.execute(
            "SELECT index_revision FROM search_index_metadata WHERE case_id = ?",
            (case_id,),
        ).fetchone()
        if row is not None:
            return int(row["index_revision"])
        row = self.connection.execute(
            """
            SELECT COALESCE(MAX(index_revision), 0) AS latest
            FROM search_documents
            WHERE case_id = ?
            """,
            (case_id,),
        ).fetchone()
        return int(row["latest"])

    def index_search_document(self, document: SearchDocument) -> None:
        """Index one search document."""

        self.batch_index_search_documents([document])

    def batch_index_search_documents(self, documents: list[SearchDocument]) -> int:
        """Batch insert metadata search documents and their FTS rows."""

        if not documents:
            return 0
        self._ensure_fts_available()
        indexed = 0
        with self.connection:
            for document in documents:
                self.connection.execute(
                    """
                    INSERT INTO search_documents (
                        document_id, case_id, evidence_id, source_type, source_id,
                        source_revision, document_type, title, path, normalized_path,
                        searchable_text, structured_fields_json, observed_at_utc,
                        raw_locator_json, citations_json, analyzer_id, analyzer_version,
                        is_partial, index_revision, search_backend, search_backend_version,
                        is_stale, fts_rowid, created_at, updated_at
                    ) VALUES (
                        ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                    )
                    ON CONFLICT(document_id) DO UPDATE SET
                        source_revision = excluded.source_revision,
                        title = excluded.title,
                        path = excluded.path,
                        normalized_path = excluded.normalized_path,
                        searchable_text = excluded.searchable_text,
                        structured_fields_json = excluded.structured_fields_json,
                        observed_at_utc = excluded.observed_at_utc,
                        raw_locator_json = excluded.raw_locator_json,
                        citations_json = excluded.citations_json,
                        analyzer_id = excluded.analyzer_id,
                        analyzer_version = excluded.analyzer_version,
                        is_partial = excluded.is_partial,
                        index_revision = excluded.index_revision,
                        search_backend = excluded.search_backend,
                        search_backend_version = excluded.search_backend_version,
                        is_stale = excluded.is_stale,
                        updated_at = excluded.updated_at
                    """,
                    self._search_document_values(document),
                )
                row = self.connection.execute(
                    "SELECT fts_rowid FROM search_documents WHERE document_id = ?",
                    (document.document_id,),
                ).fetchone()
                fts_rowid = None if row is None else row["fts_rowid"]
                if fts_rowid is not None:
                    self.connection.execute(
                        "DELETE FROM search_documents_fts WHERE rowid = ?",
                        (int(fts_rowid),),
                    )
                    self.connection.execute(
                        """
                        INSERT INTO search_documents_fts(
                            rowid, document_id, title, path, searchable_text
                        ) VALUES (?, ?, ?, ?, ?)
                        """,
                        (
                            int(fts_rowid),
                            document.document_id,
                            document.title,
                            document.path or "",
                            document.searchable_text,
                        ),
                    )
                else:
                    cursor = self.connection.execute(
                        """
                        INSERT INTO search_documents_fts(
                            document_id, title, path, searchable_text
                        ) VALUES (?, ?, ?, ?)
                        """,
                        (
                            document.document_id,
                            document.title,
                            document.path or "",
                            document.searchable_text,
                        ),
                    )
                    fts_rowid = cursor.lastrowid
                    self.connection.execute(
                        "UPDATE search_documents SET fts_rowid = ? WHERE document_id = ?",
                        (fts_rowid, document.document_id),
                    )
                self._upsert_search_index_metadata(document.case_id, document.index_revision)
                indexed += 1
        return indexed

    def mark_search_source_stale(
        self,
        *,
        case_id: str,
        evidence_id: str,
        source_type: str,
        source_id: str,
        current_source_revision: int,
    ) -> None:
        """Mark old document revisions for one source as stale."""

        with self.connection:
            self.connection.execute(
                """
                UPDATE search_documents
                SET is_stale = 1, updated_at = ?
                WHERE case_id = ? AND evidence_id = ? AND source_type = ?
                  AND source_id = ? AND source_revision != ?
                """,
                (
                    to_json_timestamp(utc_now()),
                    case_id,
                    evidence_id,
                    source_type,
                    source_id,
                    current_source_revision,
                ),
            )

    def query_search_documents(
        self,
        *,
        query: SearchQuery,
        after: tuple[float, str] | None,
        limit: int,
    ) -> list[dict[str, Any]]:
        """Execute a parameterized search query and return result-row dictionaries."""

        self._ensure_fts_available()
        if query.query_mode is SearchQueryMode.REGEX_METADATA:
            return self._query_search_regex(query=query, after=after, limit=limit)
        fts_query = self._fts_query(query.query_text, query.query_mode)
        clauses, params = self._search_filter_clauses(query, "d")
        clauses.append("search_documents_fts MATCH ?")
        params.append(fts_query)
        if after is not None:
            clauses.append(
                """
                (
                    bm25(search_documents_fts) > ?
                    OR (
                        bm25(search_documents_fts) = ?
                        AND d.document_id > ?
                    )
                )
                """
            )
            params.extend([after[0], after[0], after[1]])
        sql = f"""
            SELECT
                d.*,
                bm25(search_documents_fts) AS rank,
                snippet(search_documents_fts, 3, '[', ']', '...', 16) AS snippet
            FROM search_documents_fts
            JOIN search_documents d ON d.fts_rowid = search_documents_fts.rowid
            WHERE {" AND ".join(clauses)}
            ORDER BY rank, d.document_id
            LIMIT ?
        """
        params.append(limit)
        rows = self.connection.execute(sql, tuple(params)).fetchall()
        results = [self._search_hit_from_row(row, query) for row in rows]
        if query.query_mode is SearchQueryMode.EXACT:
            needle = query.query_text if query.case_sensitive else query.query_text.casefold()
            results = [
                result
                for result in results
                if needle
                in (
                    result["_haystack"]
                    if query.case_sensitive
                    else str(result["_haystack"]).casefold()
                )
            ]
        for result in results:
            result.pop("_haystack", None)
        return results[:limit]

    def count_search_documents(self, query: SearchQuery) -> int:
        """Count matching documents using the same filters as query."""

        self._ensure_fts_available()
        if query.query_mode is SearchQueryMode.REGEX_METADATA:
            return len(self._query_search_regex(query=query, after=None, limit=5000))
        clauses, params = self._search_filter_clauses(query, "d")
        clauses.append("search_documents_fts MATCH ?")
        params.append(self._fts_query(query.query_text, query.query_mode))
        sql = f"""
            SELECT COUNT(*) AS count
            FROM search_documents_fts
            JOIN search_documents d ON d.fts_rowid = search_documents_fts.rowid
            WHERE {" AND ".join(clauses)}
        """
        row = self.connection.execute(sql, tuple(params)).fetchone()
        return int(row["count"])

    def rebuild_search_index(self, *, case_id: str | None = None) -> int:
        """Rebuild the FTS table from persisted search documents."""

        self._ensure_fts_available()
        with self.connection:
            if case_id is None:
                self.connection.execute("DELETE FROM search_documents_fts")
                self.connection.execute("UPDATE search_documents SET fts_rowid = NULL")
                rows = self.connection.execute(
                    "SELECT * FROM search_documents WHERE is_stale = 0 ORDER BY document_id"
                ).fetchall()
            else:
                existing = self.connection.execute(
                    """
                    SELECT fts_rowid FROM search_documents
                    WHERE case_id = ? AND fts_rowid IS NOT NULL
                    """,
                    (case_id,),
                ).fetchall()
                for row in existing:
                    self.connection.execute(
                        "DELETE FROM search_documents_fts WHERE rowid = ?",
                        (int(row["fts_rowid"]),),
                    )
                self.connection.execute(
                    "UPDATE search_documents SET fts_rowid = NULL WHERE case_id = ?",
                    (case_id,),
                )
                rows = self.connection.execute(
                    """
                    SELECT * FROM search_documents
                    WHERE case_id = ? AND is_stale = 0
                    ORDER BY document_id
                    """,
                    (case_id,),
                ).fetchall()
            count = 0
            for row in rows:
                cursor = self.connection.execute(
                    """
                    INSERT INTO search_documents_fts(document_id, title, path, searchable_text)
                    VALUES (?, ?, ?, ?)
                    """,
                    (
                        row["document_id"],
                        row["title"],
                        row["path"] or "",
                        row["searchable_text"],
                    ),
                )
                self.connection.execute(
                    "UPDATE search_documents SET fts_rowid = ? WHERE document_id = ?",
                    (cursor.lastrowid, row["document_id"]),
                )
                count += 1
        return count

    def optimize_search_index(self) -> None:
        """Optimize the SQLite FTS5 index."""

        self._ensure_fts_available()
        with self.connection:
            self.connection.execute(
                "INSERT INTO search_documents_fts(search_documents_fts) VALUES('optimize')"
            )

    def create_search_job(
        self,
        *,
        job_id: str,
        case_id: str,
        evidence_id: str | None,
        profile_type: str,
        options: dict[str, Any],
        option_fingerprint: str,
        index_revision: int,
        status: str,
        created_at: str,
    ) -> None:
        """Persist search index job metadata."""

        with self.connection:
            self.connection.execute(
                """
                INSERT INTO search_jobs (
                    job_id, case_id, evidence_id, profile_type, options_json,
                    option_fingerprint, index_revision, status, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    job_id,
                    case_id,
                    evidence_id,
                    profile_type,
                    self._json(options),
                    option_fingerprint,
                    index_revision,
                    status,
                    created_at,
                    created_at,
                ),
            )

    def update_search_job_status(
        self,
        job_id: str,
        status: str,
        *,
        pause_requested: bool | None = None,
    ) -> None:
        """Update search index job status."""

        assignments = ["status = ?", "updated_at = ?"]
        params: list[Any] = [status, to_json_timestamp(utc_now())]
        if pause_requested is not None:
            assignments.append("pause_requested = ?")
            params.append(int(pause_requested))
        params.append(job_id)
        with self.connection:
            self.connection.execute(
                f"UPDATE search_jobs SET {', '.join(assignments)} WHERE job_id = ?",
                tuple(params),
            )

    def get_search_job(self, job_id: str) -> dict[str, Any] | None:
        """Return search index job metadata."""

        row = self.connection.execute(
            "SELECT * FROM search_jobs WHERE job_id = ?",
            (job_id,),
        ).fetchone()
        if row is None:
            return None
        data = dict(row)
        data["options"] = json.loads(str(data.pop("options_json")))
        data["pause_requested"] = bool(data["pause_requested"])
        return data

    def save_search_checkpoint(
        self,
        *,
        job_id: str,
        current_source_type: str | None,
        current_source_id: str | None,
        processed_items: int,
        indexed_items: int,
        skipped_items: int,
    ) -> None:
        """Persist search index checkpoint."""

        now = to_json_timestamp(utc_now())
        with self.connection:
            self.connection.execute(
                """
                INSERT INTO search_checkpoints (
                    job_id, current_source_type, current_source_id, processed_items,
                    indexed_items, skipped_items, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(job_id) DO UPDATE SET
                    current_source_type = excluded.current_source_type,
                    current_source_id = excluded.current_source_id,
                    processed_items = excluded.processed_items,
                    indexed_items = excluded.indexed_items,
                    skipped_items = excluded.skipped_items,
                    updated_at = excluded.updated_at
                """,
                (
                    job_id,
                    current_source_type,
                    current_source_id,
                    processed_items,
                    indexed_items,
                    skipped_items,
                    now,
                ),
            )

    def get_search_checkpoint(self, job_id: str) -> dict[str, Any] | None:
        """Return search checkpoint."""

        row = self.connection.execute(
            "SELECT * FROM search_checkpoints WHERE job_id = ?",
            (job_id,),
        ).fetchone()
        return None if row is None else dict(row)

    def iter_search_source_rows(
        self,
        *,
        case_id: str,
        evidence_ids: tuple[str, ...],
        source_types: tuple[str, ...],
        after_source: tuple[str, str] | None,
        limit: int,
    ) -> list[dict[str, Any]]:
        """Return existing source rows projected into search-document input rows."""

        selected = set(source_types)
        if not selected:
            selected = {
                SearchSourceType.FILE_SYSTEM_NODE.value,
                SearchSourceType.WINDOWS_ARTIFACT.value,
            }
        rows: list[dict[str, Any]] = []
        for source_type in sorted(
            (
                SearchSourceType.FILE_SYSTEM_NODE.value,
                SearchSourceType.WINDOWS_ARTIFACT.value,
                SearchSourceType.TIMELINE_EVENT.value,
            )
        ):
            if source_type not in selected or len(rows) >= limit:
                continue
            if after_source is not None:
                if source_type < after_source[0]:
                    continue
                after_id = after_source[1] if source_type == after_source[0] else None
            else:
                after_id = None
            remaining = limit - len(rows)
            if source_type == SearchSourceType.FILE_SYSTEM_NODE.value:
                rows.extend(
                    self._iter_fs_search_rows(
                        case_id=case_id,
                        evidence_ids=evidence_ids,
                        after_id=after_id,
                        limit=remaining,
                    )
                )
            elif source_type == SearchSourceType.WINDOWS_ARTIFACT.value:
                rows.extend(
                    self._iter_artifact_search_rows(
                        case_id=case_id,
                        evidence_ids=evidence_ids,
                        after_id=after_id,
                        limit=remaining,
                    )
                )
            else:
                rows.extend(
                    self._iter_timeline_search_rows(
                        case_id=case_id,
                        evidence_ids=evidence_ids,
                        after_id=after_id,
                        limit=remaining,
                    )
                )
        return sorted(
            rows,
            key=lambda item: (str(item["source_type"]), str(item["source_id"])),
        )[:limit]

    def search_document_exists_current(
        self,
        *,
        case_id: str,
        evidence_id: str,
        source_type: str,
        source_id: str,
        source_revision: int,
        document_type: str,
    ) -> bool:
        """Return whether an up-to-date document projection already exists."""

        row = self.connection.execute(
            """
            SELECT 1 FROM search_documents
            WHERE case_id = ? AND evidence_id = ? AND source_type = ?
              AND source_id = ? AND source_revision = ?
              AND document_type = ? AND is_stale = 0
            LIMIT 1
            """,
            (case_id, evidence_id, source_type, source_id, source_revision, document_type),
        ).fetchone()
        return row is not None

    def search_source_revision_fingerprint(
        self,
        *,
        case_id: str,
        evidence_ids: tuple[str, ...],
        source_types: tuple[str, ...],
    ) -> str:
        """Return a deterministic source-revision fingerprint for cache keys."""

        sources = self.iter_search_source_rows(
            case_id=case_id,
            evidence_ids=evidence_ids,
            source_types=source_types,
            after_source=None,
            limit=1_000_000,
        )
        return canonical_sha256(
            [
                {
                    "source_type": source["source_type"],
                    "source_id": source["source_id"],
                    "source_revision": source["source_revision"],
                }
                for source in sources
            ]
        )

    def save_search_query(self, query: SearchQuery) -> None:
        """Persist an immutable search query."""

        created_at = query.created_at or utc_now()
        with self.connection:
            self.connection.execute(
                """
                INSERT INTO search_queries (
                    query_id, query_text, query_mode, case_id, evidence_ids_json,
                    source_types_json, document_types_json, time_range_json, path_scope,
                    filters_json, keyword_set_id, keyword_set_version, index_revision,
                    options_fingerprint, sort, limit_value, case_sensitive, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    query.query_id,
                    query.query_text,
                    query.query_mode.value,
                    query.case_id,
                    self._json(list(query.evidence_ids)),
                    self._json([item.value for item in query.source_types]),
                    self._json([item.value for item in query.document_types]),
                    self._json(query.time_range),
                    query.path_scope,
                    self._json(query.filters),
                    query.keyword_set_id,
                    query.keyword_set_version,
                    query.index_revision,
                    query.options_fingerprint,
                    query.sort,
                    query.limit,
                    int(query.case_sensitive),
                    to_json_timestamp(created_at),
                ),
            )

    def save_search_execution(self, execution: SearchExecution) -> None:
        """Persist a search execution reproduction record."""

        with self.connection:
            self.connection.execute(
                """
                INSERT INTO search_executions (
                    execution_id, query_id, case_id, query_text, query_mode,
                    keyword_set_id, keyword_set_version, options_json,
                    options_fingerprint, search_backend, search_backend_version,
                    index_revision, source_revision_fingerprint, started_at,
                    completed_at, status, is_partial, result_count, warnings_json,
                    cache_key, cache_hit, zero_result_keyword_ids_json, execution_revision
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                self._search_execution_values(execution),
            )

    def update_search_execution(self, execution: SearchExecution) -> None:
        """Update completion fields for a persisted execution."""

        with self.connection:
            self.connection.execute(
                """
                UPDATE search_executions
                SET completed_at = ?, status = ?, is_partial = ?, result_count = ?,
                    warnings_json = ?, cache_key = ?, cache_hit = ?,
                    zero_result_keyword_ids_json = ?, execution_revision = ?
                WHERE execution_id = ?
                """,
                (
                    self._nullable_timestamp(execution.completed_at),
                    execution.status,
                    int(execution.is_partial),
                    execution.result_count,
                    self._json(execution.warnings),
                    execution.cache_key,
                    int(execution.cache_hit),
                    self._json(execution.zero_result_keyword_ids),
                    execution.execution_revision,
                    execution.execution_id,
                ),
            )

    def get_search_query(self, query_id: str) -> SearchQuery | None:
        """Return a persisted search query."""

        row = self.connection.execute(
            "SELECT * FROM search_queries WHERE query_id = ?",
            (query_id,),
        ).fetchone()
        return None if row is None else self._row_to_search_query(row)

    def get_search_execution(self, execution_id: str) -> SearchExecution | None:
        """Return a persisted search execution."""

        row = self.connection.execute(
            "SELECT * FROM search_executions WHERE execution_id = ?",
            (execution_id,),
        ).fetchone()
        return None if row is None else self._row_to_search_execution(row)

    def list_search_executions(
        self,
        *,
        case_id: str,
        limit: int,
    ) -> list[SearchExecution]:
        """List recent search executions for a case."""

        rows = self.connection.execute(
            """
            SELECT * FROM search_executions
            WHERE case_id = ?
            ORDER BY started_at DESC, execution_id
            LIMIT ?
            """,
            (case_id, limit),
        ).fetchall()
        return [self._row_to_search_execution(row) for row in rows]

    def save_search_results(self, results: list[SearchResult]) -> None:
        """Persist search result rows."""

        with self.connection:
            for result in results:
                self.connection.execute(
                    """
                    INSERT INTO search_results (
                        result_id, query_id, document_id, source_type, source_id, rank,
                        matched_fields_json, matched_terms_json, snippet,
                        raw_locator_json, citations_json, is_partial, index_revision, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    self._search_result_values(result),
                )

    def list_search_results(
        self,
        *,
        query_id: str,
        after: tuple[float, str] | None,
        limit: int,
    ) -> list[SearchResult]:
        """List persisted search results with stable rank/document ordering."""

        clauses = ["query_id = ?"]
        params: list[Any] = [query_id]
        if after is not None:
            clauses.append("(rank > ? OR (rank = ? AND document_id > ?))")
            params.extend([after[0], after[0], after[1]])
        sql = f"""
            SELECT * FROM search_results
            WHERE {" AND ".join(clauses)}
            ORDER BY rank, document_id
            LIMIT ?
        """
        params.append(limit)
        rows = self.connection.execute(sql, tuple(params)).fetchall()
        return [self._row_to_search_result(row) for row in rows]

    def get_search_cache(self, cache_key: str) -> SearchCacheEntry | None:
        """Return a valid cache entry, if present."""

        row = self.connection.execute(
            """
            SELECT * FROM search_cache
            WHERE cache_key = ? AND invalidated_at IS NULL
              AND (expires_at IS NULL OR expires_at > ?)
            """,
            (cache_key, to_json_timestamp(utc_now())),
        ).fetchone()
        return None if row is None else self._row_to_search_cache(row)

    def save_search_cache(self, entry: SearchCacheEntry) -> None:
        """Persist a search cache entry."""

        with self.connection:
            self.connection.execute(
                """
                INSERT INTO search_cache (
                    cache_key, case_id, query_fingerprint, keyword_set_version,
                    index_revision, source_revision_fingerprint, is_partial,
                    result_count, results_json, created_at, expires_at, hit_count,
                    invalidated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(cache_key) DO UPDATE SET
                    result_count = excluded.result_count,
                    results_json = excluded.results_json,
                    created_at = excluded.created_at,
                    expires_at = excluded.expires_at,
                    invalidated_at = NULL
                """,
                (
                    entry.cache_key,
                    entry.case_id,
                    entry.query_fingerprint,
                    entry.keyword_set_version,
                    entry.index_revision,
                    entry.source_revision_fingerprint,
                    int(entry.is_partial),
                    entry.result_count,
                    self._json(entry.results),
                    to_json_timestamp(entry.created_at),
                    self._nullable_timestamp(entry.expires_at),
                    entry.hit_count,
                    self._nullable_timestamp(entry.invalidated_at),
                ),
            )

    def record_search_cache_hit(self, cache_key: str) -> None:
        """Increment cache hit counter."""

        with self.connection:
            self.connection.execute(
                "UPDATE search_cache SET hit_count = hit_count + 1 WHERE cache_key = ?",
                (cache_key,),
            )

    def invalidate_search_cache(
        self,
        *,
        case_id: str | None,
        index_revision: int | None,
        source_revision_fingerprint: str | None,
        invalidated_at: str,
    ) -> int:
        """Invalidate search cache entries globally or by case and optional revision keys."""

        clauses = ["invalidated_at IS NULL"]
        params: list[Any] = []
        if case_id is not None:
            clauses.append("case_id = ?")
            params.append(case_id)
        if index_revision is not None:
            clauses.append("index_revision != ?")
            params.append(index_revision)
        if source_revision_fingerprint is not None:
            clauses.append("source_revision_fingerprint != ?")
            params.append(source_revision_fingerprint)
        sql = f"UPDATE search_cache SET invalidated_at = ? WHERE {' AND '.join(clauses)}"
        with self.connection:
            cursor = self.connection.execute(sql, (invalidated_at, *params))
        return cursor.rowcount

    def search_cache_status(self, case_id: str) -> dict[str, Any]:
        """Return cache state counters for a case."""

        row = self.connection.execute(
            """
            SELECT
                COUNT(*) AS entries,
                COALESCE(SUM(hit_count), 0) AS hit_count,
                SUM(CASE WHEN invalidated_at IS NULL THEN 1 ELSE 0 END) AS active_entries,
                SUM(CASE WHEN invalidated_at IS NOT NULL THEN 1 ELSE 0 END) AS invalidated_entries
            FROM search_cache
            WHERE case_id = ?
            """,
            (case_id,),
        ).fetchone()
        return {
            "case_id": case_id,
            "entries": int(row["entries"]),
            "hit_count": int(row["hit_count"]),
            "active_entries": int(row["active_entries"] or 0),
            "invalidated_entries": int(row["invalidated_entries"] or 0),
            "ttl_seconds": None,
        }

    def save_keyword_set(self, keyword_set: KeywordSet) -> None:
        """Persist a keyword-set version and update the set's current pointer."""

        version_id = keyword_set.keyword_set_version_id or keyword_set.keyword_set_id
        with self.connection:
            self.connection.execute(
                """
                INSERT INTO keyword_sets (
                    keyword_set_id, case_id, name, description, current_version,
                    current_version_id, current_status, created_by, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(keyword_set_id) DO UPDATE SET
                    name = excluded.name,
                    description = excluded.description,
                    current_version = excluded.current_version,
                    current_version_id = excluded.current_version_id,
                    current_status = excluded.current_status,
                    updated_at = excluded.updated_at
                """,
                (
                    keyword_set.keyword_set_id,
                    keyword_set.case_id,
                    keyword_set.name,
                    keyword_set.description,
                    keyword_set.version,
                    version_id,
                    keyword_set.status.value,
                    keyword_set.created_by,
                    to_json_timestamp(keyword_set.created_at),
                    to_json_timestamp(keyword_set.updated_at),
                ),
            )
            self.connection.execute(
                """
                INSERT INTO keyword_set_versions (
                    keyword_set_version_id, keyword_set_id, case_id, name, description,
                    version, status, created_by, created_at, updated_at,
                    default_options_json, previous_version_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    version_id,
                    keyword_set.keyword_set_id,
                    keyword_set.case_id,
                    keyword_set.name,
                    keyword_set.description,
                    keyword_set.version,
                    keyword_set.status.value,
                    keyword_set.created_by,
                    to_json_timestamp(keyword_set.created_at),
                    to_json_timestamp(keyword_set.updated_at),
                    self._json(keyword_set.default_options),
                    keyword_set.previous_version_id,
                ),
            )
            self.save_keywords_for_version(
                keyword_set_version_id=version_id,
                keywords=keyword_set.keywords,
            )

    def save_keywords_for_version(
        self,
        *,
        keyword_set_version_id: str,
        keywords: list[Keyword],
    ) -> None:
        """Persist keywords for one immutable keyword-set version."""

        with self.connection:
            for keyword in keywords:
                self.connection.execute(
                    """
                    INSERT INTO keywords (
                        keyword_id, keyword_set_version_id, term, normalized_term,
                        keyword_type, match_mode, case_sensitive, enabled, notes,
                        source, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        keyword.keyword_id,
                        keyword_set_version_id,
                        keyword.term,
                        keyword.term if keyword.case_sensitive else keyword.term.casefold(),
                        keyword.keyword_type.value,
                        keyword.match_mode.value,
                        int(keyword.case_sensitive),
                        int(keyword.enabled),
                        keyword.notes,
                        keyword.source,
                        to_json_timestamp(keyword.created_at),
                    ),
                )

    def get_keyword_set(
        self,
        *,
        keyword_set_id: str,
        version: int | None = None,
    ) -> KeywordSet | None:
        """Return a keyword set version."""

        if version is None:
            row = self.connection.execute(
                """
                SELECT v.* FROM keyword_sets s
                JOIN keyword_set_versions v ON v.keyword_set_version_id = s.current_version_id
                WHERE s.keyword_set_id = ?
                """,
                (keyword_set_id,),
            ).fetchone()
        else:
            row = self.connection.execute(
                """
                SELECT * FROM keyword_set_versions
                WHERE keyword_set_id = ? AND version = ?
                """,
                (keyword_set_id, version),
            ).fetchone()
        return None if row is None else self._row_to_keyword_set(row)

    def list_keyword_sets(
        self,
        *,
        case_id: str,
        status: str | None = None,
    ) -> list[KeywordSet]:
        """List current keyword-set versions for a case."""

        clauses = ["s.case_id = ?"]
        params: list[Any] = [case_id]
        if status is not None:
            clauses.append("s.current_status = ?")
            params.append(status)
        sql = f"""
            SELECT v.* FROM keyword_sets s
            JOIN keyword_set_versions v ON v.keyword_set_version_id = s.current_version_id
            WHERE {" AND ".join(clauses)}
            ORDER BY s.updated_at DESC, s.keyword_set_id
        """
        rows = self.connection.execute(sql, tuple(params)).fetchall()
        return [self._row_to_keyword_set(row) for row in rows]

    def next_timeline_revision(self, case_id: str) -> int:
        """Reserve and return the next timeline revision for a case."""

        row = self.connection.execute(
            """
            SELECT COALESCE(MAX(timeline_revision), 0) AS latest
            FROM timeline_revisions
            WHERE case_id = ?
            """,
            (case_id,),
        ).fetchone()
        revision = int(row["latest"]) + 1
        with self.connection:
            self.connection.execute(
                """
                INSERT OR IGNORE INTO timeline_revisions(case_id, timeline_revision, created_at)
                VALUES (?, ?, ?)
                """,
                (case_id, revision, to_json_timestamp(utc_now())),
            )
        return revision

    def create_timeline_job(
        self,
        *,
        job_id: str,
        case_id: str,
        evidence_id: str | None,
        profile_type: str,
        options: dict[str, Any],
        option_fingerprint: str,
        timeline_revision: int,
        status: str,
        created_at: str,
    ) -> None:
        """Persist timeline job metadata."""

        with self.connection:
            self.connection.execute(
                """
                INSERT INTO timeline_jobs (
                    job_id, case_id, evidence_id, profile_type, options_json,
                    option_fingerprint, timeline_revision, status, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    job_id,
                    case_id,
                    evidence_id,
                    profile_type,
                    self._json(options),
                    option_fingerprint,
                    timeline_revision,
                    status,
                    created_at,
                    created_at,
                ),
            )

    def update_timeline_job_status(
        self,
        job_id: str,
        status: str,
        *,
        pause_requested: bool | None = None,
    ) -> None:
        """Update timeline job status."""

        assignments = ["status = ?", "updated_at = ?"]
        params: list[Any] = [status, to_json_timestamp(utc_now())]
        if pause_requested is not None:
            assignments.append("pause_requested = ?")
            params.append(int(pause_requested))
        params.append(job_id)
        with self.connection:
            self.connection.execute(
                f"UPDATE timeline_jobs SET {', '.join(assignments)} WHERE job_id = ?",
                tuple(params),
            )

    def get_timeline_job(self, job_id: str) -> dict[str, Any] | None:
        """Return timeline job metadata."""

        row = self.connection.execute(
            "SELECT * FROM timeline_jobs WHERE job_id = ?",
            (job_id,),
        ).fetchone()
        if row is None:
            return None
        data = dict(row)
        data["options"] = json.loads(str(data.pop("options_json")))
        data["pause_requested"] = bool(data["pause_requested"])
        return data

    def save_timeline_checkpoint(
        self,
        *,
        job_id: str,
        current_source_type: str | None,
        current_source_id: str | None,
        processed_items: int,
        event_count: int,
        skipped_items: int,
    ) -> None:
        """Persist timeline checkpoint."""

        now = to_json_timestamp(utc_now())
        with self.connection:
            self.connection.execute(
                """
                INSERT INTO timeline_checkpoints (
                    job_id, current_source_type, current_source_id,
                    processed_items, event_count, skipped_items, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(job_id) DO UPDATE SET
                    current_source_type = excluded.current_source_type,
                    current_source_id = excluded.current_source_id,
                    processed_items = excluded.processed_items,
                    event_count = excluded.event_count,
                    skipped_items = excluded.skipped_items,
                    updated_at = excluded.updated_at
                """,
                (
                    job_id,
                    current_source_type,
                    current_source_id,
                    processed_items,
                    event_count,
                    skipped_items,
                    now,
                ),
            )

    def get_timeline_checkpoint(self, job_id: str) -> dict[str, Any] | None:
        """Return timeline checkpoint."""

        row = self.connection.execute(
            "SELECT * FROM timeline_checkpoints WHERE job_id = ?",
            (job_id,),
        ).fetchone()
        return None if row is None else dict(row)

    def iter_timeline_source_rows(
        self,
        *,
        case_id: str,
        evidence_id: str | None,
        source_types: tuple[str, ...],
        after_source: tuple[str, str] | None,
        limit: int,
    ) -> list[dict[str, Any]]:
        """Return existing source rows projected for timeline generation."""

        selected = set(source_types)
        if not selected:
            selected = {
                TimelineSourceType.FILE_SYSTEM_NODE.value,
                TimelineSourceType.REGISTRY_ARTIFACT.value,
                TimelineSourceType.EVENT_LOG_ARTIFACT.value,
                TimelineSourceType.PREFETCH_ARTIFACT.value,
                TimelineSourceType.MEDIA_ARTIFACT.value,
                TimelineSourceType.BROWSER_ARTIFACT.value,
                TimelineSourceType.COMMUNICATION_ARTIFACT.value,
            }
        rows: list[dict[str, Any]] = []
        for source_type in sorted(
            (
                TimelineSourceType.FILE_SYSTEM_NODE.value,
                TimelineSourceType.REGISTRY_ARTIFACT.value,
                TimelineSourceType.EVENT_LOG_ARTIFACT.value,
                TimelineSourceType.PREFETCH_ARTIFACT.value,
                TimelineSourceType.MEDIA_ARTIFACT.value,
                TimelineSourceType.BROWSER_ARTIFACT.value,
                TimelineSourceType.COMMUNICATION_ARTIFACT.value,
            )
        ):
            if source_type not in selected or len(rows) >= limit:
                continue
            if after_source is not None:
                if source_type < after_source[0]:
                    continue
                after_id = after_source[1] if source_type == after_source[0] else None
            else:
                after_id = None
            remaining = limit - len(rows)
            if source_type == TimelineSourceType.FILE_SYSTEM_NODE.value:
                rows.extend(
                    self._iter_fs_timeline_rows(
                        case_id=case_id,
                        evidence_id=evidence_id,
                        after_id=after_id,
                        limit=remaining,
                    )
                )
            else:
                rows.extend(
                    self._iter_artifact_timeline_rows(
                        case_id=case_id,
                        evidence_id=evidence_id,
                        source_type=source_type,
                        after_id=after_id,
                        limit=remaining,
                    )
                )
        return sorted(
            rows,
            key=lambda item: (str(item["source_type"]), str(item["source_id"])),
        )[:limit]

    def save_timeline_events(self, events: list[TimelineEvent]) -> int:
        """Persist timeline events, preventing duplicate source/event/timestamp rows."""

        saved = 0
        with self.connection:
            for event in events:
                cursor = self.connection.execute(
                    """
                    INSERT OR IGNORE INTO timeline_events (
                        timeline_event_id, case_id, evidence_id, source_type, source_id,
                        source_revision, event_type, event_subtype, title, description,
                        raw_timestamp, raw_timezone, timestamp_semantics, normalized_utc,
                        sort_timestamp, case_timezone, displayed_case_time, timezone_source,
                        timezone_confidence, precision, analyzer_id, analyzer_version,
                        raw_locator_json, citations_json, fields_json, is_partial,
                        timeline_revision, created_at, dedup_key, artifact_type, path_key
                    ) VALUES (
                        ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                        ?, ?, ?, ?, ?, ?, ?
                    )
                    """,
                    self._timeline_event_values(event),
                )
                saved += cursor.rowcount
        return saved

    def get_timeline_event(self, timeline_event_id: str) -> TimelineEvent | None:
        """Return a timeline event by ID."""

        row = self.connection.execute(
            "SELECT * FROM timeline_events WHERE timeline_event_id = ?",
            (timeline_event_id,),
        ).fetchone()
        return None if row is None else self._row_to_timeline_event(row)

    def query_timeline_events(self, query: TimelineQuery) -> list[TimelineEvent]:
        """Query timeline events with stable cursor pagination."""

        clauses = ["case_id = ?"]
        params: list[Any] = [query.case_id]
        if query.evidence_id is not None:
            clauses.append("evidence_id = ?")
            params.append(query.evidence_id)
        if query.source_types:
            clauses.append("source_type IN (" + ", ".join("?" for _ in query.source_types) + ")")
            params.extend(item.value for item in query.source_types)
        if query.event_types:
            clauses.append("event_type IN (" + ", ".join("?" for _ in query.event_types) + ")")
            params.extend(item.value for item in query.event_types)
        if query.analyzer_id is not None:
            clauses.append("analyzer_id = ?")
            params.append(query.analyzer_id)
        if query.artifact_type is not None:
            clauses.append("artifact_type = ?")
            params.append(query.artifact_type)
        if query.path is not None:
            clauses.append("path_key LIKE ?")
            params.append(f"%{query.path.casefold()}%")
        if query.keyword is not None:
            clauses.append(
                "(title LIKE ? OR description LIKE ? OR fields_json LIKE ? OR path_key LIKE ?)"
            )
            keyword = f"%{query.keyword}%"
            params.extend([keyword, keyword, keyword, keyword.casefold()])
        if query.is_partial is not None:
            clauses.append("is_partial = ?")
            params.append(int(query.is_partial))
        if query.confidence is not None:
            clauses.append("timezone_confidence = ?")
            params.append(query.confidence.value)
        if query.time_from is not None:
            clauses.append("normalized_utc >= ?")
            params.append(to_json_timestamp(query.time_from))
        if query.time_to is not None:
            clauses.append("normalized_utc <= ?")
            params.append(to_json_timestamp(query.time_to))
        cursor_data = self._decode_timeline_cursor(query.cursor)
        order = "DESC" if query.order == "DESC" else "ASC"
        if cursor_data is not None:
            cursor_sort = cursor_data.get("sort") or "9999-12-31T23:59:59.999999Z"
            cursor_id = str(cursor_data["timeline_event_id"])
            operator = "<" if order == "DESC" else ">"
            clauses.append(
                f"(sort_timestamp {operator} ? "
                f"OR (sort_timestamp = ? AND timeline_event_id {operator} ?))"
            )
            params.extend([cursor_sort, cursor_sort, cursor_id])
        sql = f"""
            SELECT * FROM timeline_events
            WHERE {" AND ".join(clauses)}
            ORDER BY sort_timestamp {order}, timeline_event_id {order}
            LIMIT ?
        """
        params.append(query.limit)
        rows = self.connection.execute(sql, tuple(params)).fetchall()
        return [self._row_to_timeline_event(row) for row in rows]

    def upsert_timeline_coverage(self, coverage: TimelineBuildCoverage) -> None:
        """Persist timeline build coverage."""

        now = utc_now()
        with self.connection:
            self.connection.execute(
                """
                INSERT INTO timeline_coverage (
                    job_id, case_id, evidence_id, status, discovered_items,
                    processed_items, skipped_items, event_count, warning_count,
                    error_count, current_source, is_partial, timeline_revision,
                    created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(job_id) DO UPDATE SET
                    status = excluded.status,
                    discovered_items = excluded.discovered_items,
                    processed_items = excluded.processed_items,
                    skipped_items = excluded.skipped_items,
                    event_count = excluded.event_count,
                    warning_count = excluded.warning_count,
                    error_count = excluded.error_count,
                    current_source = excluded.current_source,
                    is_partial = excluded.is_partial,
                    timeline_revision = excluded.timeline_revision,
                    updated_at = excluded.updated_at
                """,
                (
                    coverage.job_id,
                    coverage.case_id,
                    coverage.evidence_id,
                    coverage.status,
                    coverage.discovered_items,
                    coverage.processed_items,
                    coverage.skipped_items,
                    coverage.event_count,
                    coverage.warning_count,
                    coverage.error_count,
                    coverage.current_source,
                    int(coverage.is_partial),
                    coverage.timeline_revision,
                    to_json_timestamp(coverage.created_at or now),
                    to_json_timestamp(coverage.updated_at or now),
                ),
            )

    def get_timeline_coverage(self, job_id: str) -> TimelineBuildCoverage | None:
        """Return timeline build coverage."""

        row = self.connection.execute(
            "SELECT * FROM timeline_coverage WHERE job_id = ?",
            (job_id,),
        ).fetchone()
        return None if row is None else self._row_to_timeline_coverage(row)


    def save_gui_session_context(self, context: GuiSessionContext) -> None:
        """Persist the latest live GUI session context and its revision snapshot."""

        with self.connection:
            self.connection.execute(
                """
                INSERT INTO gui_session_contexts (
                    session_context_id, session_id, case_id, actor_id, locale, timezone,
                    current_route, current_panel, active_evidence_id, selected_file_node_ids_json,
                    selected_artifact_ids_json, selected_timeline_event_ids_json,
                    selected_search_result_ids_json, selected_media_artifact_ids_json,
                    selected_browser_artifact_ids_json, selected_candidate_ids_json,
                    active_filters_json, active_sort_json, active_time_range_json,
                    active_keyword_set_id, active_keyword_set_version, active_search_execution_id,
                    active_timeline_revision, active_context_scope, ui_preferences_json,
                    context_revision, source_revision_fingerprint, is_partial, stale_reasons_json,
                    created_at, updated_at, expires_at
                ) VALUES (
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                    ?, ?, ?, ?, ?, ?
                )
                ON CONFLICT(session_context_id) DO UPDATE SET
                    session_id = excluded.session_id,
                    actor_id = excluded.actor_id,
                    locale = excluded.locale,
                    timezone = excluded.timezone,
                    current_route = excluded.current_route,
                    current_panel = excluded.current_panel,
                    active_evidence_id = excluded.active_evidence_id,
                    selected_file_node_ids_json = excluded.selected_file_node_ids_json,
                    selected_artifact_ids_json = excluded.selected_artifact_ids_json,
                    selected_timeline_event_ids_json = excluded.selected_timeline_event_ids_json,
                    selected_search_result_ids_json = excluded.selected_search_result_ids_json,
                    selected_media_artifact_ids_json = excluded.selected_media_artifact_ids_json,
                    selected_browser_artifact_ids_json =
                        excluded.selected_browser_artifact_ids_json,
                    selected_candidate_ids_json = excluded.selected_candidate_ids_json,
                    active_filters_json = excluded.active_filters_json,
                    active_sort_json = excluded.active_sort_json,
                    active_time_range_json = excluded.active_time_range_json,
                    active_keyword_set_id = excluded.active_keyword_set_id,
                    active_keyword_set_version = excluded.active_keyword_set_version,
                    active_search_execution_id = excluded.active_search_execution_id,
                    active_timeline_revision = excluded.active_timeline_revision,
                    active_context_scope = excluded.active_context_scope,
                    ui_preferences_json = excluded.ui_preferences_json,
                    context_revision = excluded.context_revision,
                    source_revision_fingerprint = excluded.source_revision_fingerprint,
                    is_partial = excluded.is_partial,
                    stale_reasons_json = excluded.stale_reasons_json,
                    updated_at = excluded.updated_at,
                    expires_at = excluded.expires_at
                """,
                self._gui_session_context_values(context),
            )
            self.connection.execute(
                """
                INSERT OR IGNORE INTO gui_session_context_revisions (
                    session_context_id, context_revision, context_json, created_at
                ) VALUES (?, ?, ?, ?)
                """,
                (
                    context.session_context_id,
                    context.context_revision,
                    self._json(context.to_schema_dict()),
                    to_json_timestamp(context.updated_at or utc_now()),
                ),
            )

    def get_gui_session_context(self, session_context_id: str) -> GuiSessionContext | None:
        """Return the latest live GUI session context."""

        row = self.connection.execute(
            "SELECT * FROM gui_session_contexts WHERE session_context_id = ?",
            (session_context_id,),
        ).fetchone()
        return None if row is None else self._row_to_gui_session_context(row)

    def list_gui_session_contexts(self, case_id: str) -> list[GuiSessionContext]:
        """List live GUI session contexts for a case."""

        rows = self.connection.execute(
            """
            SELECT * FROM gui_session_contexts
            WHERE case_id = ?
            ORDER BY updated_at DESC, session_context_id
            """,
            (case_id,),
        ).fetchall()
        return [self._row_to_gui_session_context(row) for row in rows]

    def get_gui_session_context_revision(
        self,
        session_context_id: str,
        context_revision: int,
    ) -> GuiSessionContext | None:
        """Return a persisted GUI session context revision."""

        row = self.connection.execute(
            """
            SELECT context_json FROM gui_session_context_revisions
            WHERE session_context_id = ? AND context_revision = ?
            """,
            (session_context_id, context_revision),
        ).fetchone()
        if row is None:
            return None
        return self._gui_session_context_from_dict(json.loads(str(row["context_json"])))

    def save_analysis_context_snapshot(self, snapshot: AnalysisContextSnapshot) -> None:
        """Persist an immutable analysis context snapshot."""

        with self.connection:
            self.connection.execute(
                """
                INSERT INTO analysis_context_snapshots (
                    context_snapshot_id, case_id, session_context_id, session_context_revision,
                    actor_id, purpose, scopes_json, included_resource_ids_json,
                    excluded_resource_ids_json, filters_json, time_range_json,
                    source_revisions_json, analyzer_versions_json, search_index_revision,
                    timeline_revision, keyword_set_id, keyword_set_version, search_execution_id,
                    partial_state_json, stale_state_json, warnings_json, citations_json,
                    context_fingerprint, previous_snapshot_id, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                self._analysis_context_snapshot_values(snapshot),
            )
            for resource_type, resource_ids in snapshot.included_resource_ids.items():
                for resource_id in resource_ids:
                    revision = self._revision_for(
                        snapshot.source_revisions,
                        resource_type,
                        resource_id,
                    )
                    self.connection.execute(
                        """
                        INSERT OR IGNORE INTO context_snapshot_resources (
                            context_snapshot_id, resource_type, resource_id, source_revision,
                            included
                        ) VALUES (?, ?, ?, ?, 1)
                        """,
                        (snapshot.context_snapshot_id, resource_type, resource_id, revision),
                    )
            for resource_type, resource_ids in snapshot.excluded_resource_ids.items():
                for resource_id in resource_ids:
                    revision = self._revision_for(
                        snapshot.source_revisions,
                        resource_type,
                        resource_id,
                    )
                    self.connection.execute(
                        """
                        INSERT OR IGNORE INTO context_snapshot_resources (
                            context_snapshot_id, resource_type, resource_id, source_revision,
                            included
                        ) VALUES (?, ?, ?, ?, 0)
                        """,
                        (snapshot.context_snapshot_id, resource_type, resource_id, revision),
                    )

    def get_analysis_context_snapshot(
        self,
        context_snapshot_id: str,
    ) -> AnalysisContextSnapshot | None:
        """Return an immutable analysis context snapshot."""

        row = self.connection.execute(
            "SELECT * FROM analysis_context_snapshots WHERE context_snapshot_id = ?",
            (context_snapshot_id,),
        ).fetchone()
        return None if row is None else self._row_to_analysis_context_snapshot(row)

    def save_analysis_scope_context(self, scope: AnalysisScopeContext) -> None:
        """Persist one snapshot scope context."""

        with self.connection:
            self.connection.execute(
                """
                INSERT INTO analysis_scope_contexts (
                    scope_context_id, context_snapshot_id, scope_type, case_id, evidence_ids_json,
                    resource_ids_json, source_revisions_json, analyzer_versions_json,
                    filters_json, sort_json, time_range_json, result_count, included_count,
                    excluded_count, is_partial, coverage_json, stale_reasons_json, warnings_json,
                    citations_json, continuation_cursor, scope_fingerprint, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                self._analysis_scope_context_values(scope),
            )

    def get_analysis_scope_context(
        self,
        context_snapshot_id: str,
        scope_type: str,
    ) -> AnalysisScopeContext | None:
        """Return one scope context for a snapshot."""

        row = self.connection.execute(
            """
            SELECT * FROM analysis_scope_contexts
            WHERE context_snapshot_id = ? AND scope_type = ?
            """,
            (context_snapshot_id, scope_type),
        ).fetchone()
        return None if row is None else self._row_to_analysis_scope_context(row)

    def list_analysis_scope_contexts(self, context_snapshot_id: str) -> list[AnalysisScopeContext]:
        """Return all scope contexts for a snapshot."""

        rows = self.connection.execute(
            """
            SELECT * FROM analysis_scope_contexts
            WHERE context_snapshot_id = ?
            ORDER BY scope_type
            """,
            (context_snapshot_id,),
        ).fetchall()
        return [self._row_to_analysis_scope_context(row) for row in rows]

    def save_context_revision_states(
        self,
        context_snapshot_id: str,
        states: list[RevisionState],
    ) -> None:
        """Persist source revision checks for a snapshot."""

        with self.connection:
            for state in states:
                self.connection.execute(
                    """
                    INSERT INTO context_revision_states (
                        state_id, context_snapshot_id, resource_type, resource_id,
                        expected_revision, current_revision, status, reason, detected_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        str(uuid4()),
                        context_snapshot_id,
                        str(state.resource_type),
                        state.resource_id,
                        None if state.expected_revision is None else str(state.expected_revision),
                        None if state.current_revision is None else str(state.current_revision),
                        str(state.status),
                        state.reason,
                        to_json_timestamp(state.detected_at),
                    ),
                )

    def list_context_revision_states(self, context_snapshot_id: str) -> list[RevisionState]:
        """Return persisted revision states for a snapshot."""

        rows = self.connection.execute(
            """
            SELECT * FROM context_revision_states
            WHERE context_snapshot_id = ?
            ORDER BY resource_type, resource_id
            """,
            (context_snapshot_id,),
        ).fetchall()
        return [self._row_to_revision_state(row) for row in rows]

    def save_case_ai_policy(self, policy: CaseAiPolicy, *, expected_revision: int) -> None:
        """Append a revision only if the caller observed the current revision."""

        if (type(expected_revision) is not int or expected_revision < 0
                or policy.revision != expected_revision + 1):
            raise ValidationError("Invalid expected policy revision.")
        data = policy.to_schema_dict()
        with self.connection:
            cursor = self.connection.execute(
                """
                INSERT INTO case_ai_policies (
                    policy_id, case_id, revision, ai_enabled, external_allowed, local_only,
                    allowed_classifications_json, secret_handling, raw_allowed,
                    redaction_required, projection_required, content_fingerprint, created_at,
                    schema_version
                ) SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                WHERE COALESCE((SELECT MAX(revision) FROM case_ai_policies
                    WHERE case_id = ?), 0) = ?
                """,
                (
                    policy.policy_id, policy.case_id, policy.revision, int(policy.ai_enabled),
                    int(policy.external_allowed), int(policy.local_only),
                    self._json(data["allowed_classifications"]), policy.secret_handling.value,
                    int(policy.raw_allowed), int(policy.redaction_required),
                    int(policy.projection_required), policy.content_fingerprint, data["created_at"],
                    SCHEMA_VERSION, policy.case_id, expected_revision,
                ),
            )
            if cursor.rowcount != 1:
                raise StateConflictError("Case AI policy revision changed.")

    def get_case_ai_policy(self, case_id: str) -> CaseAiPolicy | None:
        row = self.connection.execute(
            "SELECT * FROM case_ai_policies WHERE case_id = ? ORDER BY revision DESC LIMIT 1",
            (case_id,),
        ).fetchone()
        if row is None:
            return None
        data = dict(row)
        fingerprint = data.pop("content_fingerprint")
        data["allowed_classifications"] = json.loads(data.pop("allowed_classifications_json"))
        for name in (
            "ai_enabled", "external_allowed", "local_only", "raw_allowed",
            "redaction_required", "projection_required",
        ):
            data[name] = bool(data[name])
        policy = CaseAiPolicy.from_schema_dict(data)
        if policy.content_fingerprint != fingerprint:
            raise ValidationError("Stored case AI policy fingerprint mismatch.")
        return policy

    def append_ai_egress_audit(self, record: AiEgressAuditRecord) -> None:
        """Persist metadata only, rejecting a policy changed since the evaluation."""

        result = record.result
        data = result.data
        source = data.source
        with self.connection:
            cursor = self.connection.execute(
                """
                INSERT INTO ai_egress_audit_records (
                    audit_id, case_id, source_id, source_type, source_fingerprint,
                    classification, contains_secrets, data_form, content_fingerprint,
                    destination, decision, reason, reason_codes_json, required_transformations_json,
                    policy_id, policy_revision, policy_fingerprint, redaction_applied,
                    projection_applied, created_at, schema_version
                ) SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                WHERE (SELECT policy_id FROM case_ai_policies WHERE case_id = ?
                    ORDER BY revision DESC LIMIT 1) IS ?
                """,
                (
                    record.audit_id, source.case_id, source.source_id, source.source_type.value,
                    source.source_fingerprint, data.classification.value,
                    int(data.contains_secrets),
                    data.data_form.value, data.content_fingerprint, result.destination.value,
                    result.decision.value, result.reason,
                    self._json([item.value for item in result.reason_codes]),
                    self._json([item.value for item in result.required_transformations]),
                    result.policy_id, result.policy_revision, result.policy_fingerprint,
                    int(data.redaction_applied), int(data.projection_applied),
                    to_json_timestamp(record.created_at), SCHEMA_VERSION,
                    source.case_id, result.policy_id,
                ),
            )
            if cursor.rowcount != 1:
                raise StateConflictError("Case AI policy changed; evaluate egress again.")

    def list_ai_egress_audits(
        self, *, case_id: str, source_id: str | None = None,
    ) -> list[AiEgressAuditRecord]:
        rows = self.connection.execute(
            """SELECT * FROM ai_egress_audit_records WHERE case_id = ?
            AND (? IS NULL OR source_id = ?) ORDER BY created_at, audit_id""",
            (case_id, source_id, source_id),
        ).fetchall()
        return [self._row_to_ai_egress_audit(row) for row in rows]

    @staticmethod
    def _row_to_ai_egress_audit(row: sqlite3.Row) -> AiEgressAuditRecord:
        return AiEgressAuditRecord.from_schema_dict({
            "schema_version": row["schema_version"], "audit_id": row["audit_id"],
            "created_at": row["created_at"],
            "redaction_applied": bool(row["redaction_applied"]),
            "projection_applied": bool(row["projection_applied"]),
            "result": {
                "schema_version": row["schema_version"],
                "data": {
                    "source": {
                        "case_id": row["case_id"], "source_id": row["source_id"],
                        "source_type": row["source_type"],
                        "source_fingerprint": row["source_fingerprint"],
                    },
                    "classification": row["classification"],
                    "contains_secrets": bool(row["contains_secrets"]),
                    "data_form": row["data_form"],
                    "content_fingerprint": row["content_fingerprint"],
                },
                "destination": row["destination"], "decision": row["decision"],
                "reason": row["reason"], "reason_codes": json.loads(row["reason_codes_json"]),
                "required_transformations": json.loads(row["required_transformations_json"]),
                "policy_id": row["policy_id"], "policy_revision": row["policy_revision"],
                "policy_fingerprint": row["policy_fingerprint"],
            },
        })

    def save_ai_assistance_request(self, request: AiAssistanceRequest) -> None:
        """Persist one immutable AI assistance request contract."""

        with self.connection:
            self.connection.execute(
                """
                INSERT INTO ai_assistance_requests (
                    assistance_request_id, case_id, context_snapshot_id, purpose,
                    requested_operations_json, requested_scopes_json, scope_context_ids_json,
                    locale, timezone, context_fingerprint, source_revision_fingerprint,
                    is_partial, is_stale, coverage_summary_json, warnings_json, citations_json,
                    max_keyword_candidates, max_summary_length, requested_at, expires_at,
                    request_version, correlation_id, request_fingerprint, resource_count
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                self._ai_assistance_request_values(request),
            )

    def get_ai_assistance_request(
        self, assistance_request_id: str
    ) -> AiAssistanceRequest | None:
        """Return one AI assistance request."""

        row = self.connection.execute(
            "SELECT * FROM ai_assistance_requests WHERE assistance_request_id = ?",
            (assistance_request_id,),
        ).fetchone()
        return None if row is None else self._row_to_ai_assistance_request(row)

    def get_ai_assistance_request_by_fingerprint(
        self, request_fingerprint: str
    ) -> AiAssistanceRequest | None:
        """Return a request with the same canonical fingerprint."""

        row = self.connection.execute(
            "SELECT * FROM ai_assistance_requests WHERE request_fingerprint = ?",
            (request_fingerprint,),
        ).fetchone()
        return None if row is None else self._row_to_ai_assistance_request(row)

    def list_ai_assistance_requests(
        self, *, case_id: str, limit: int
    ) -> list[AiAssistanceRequest]:
        """List AI assistance requests for a case."""

        rows = self.connection.execute(
            """
            SELECT * FROM ai_assistance_requests
            WHERE case_id = ?
            ORDER BY requested_at DESC, assistance_request_id
            LIMIT ?
            """,
            (case_id, limit),
        ).fetchall()
        return [self._row_to_ai_assistance_request(row) for row in rows]

    def expire_ai_assistance_request(
        self, assistance_request_id: str, *, expires_at: datetime
    ) -> None:
        """Set an AI assistance request expiration timestamp."""

        with self.connection:
            self.connection.execute(
                """
                UPDATE ai_assistance_requests
                SET expires_at = ?
                WHERE assistance_request_id = ?
                """,
                (to_json_timestamp(expires_at), assistance_request_id),
            )

    def save_ai_keyword_batch(
        self,
        batch: AiKeywordRecommendationBatch,
        recommendations: list[AiKeywordRecommendation],
    ) -> None:
        """Persist one keyword batch and its immutable recommendations transactionally."""

        with self.connection:
            self.connection.execute(
                """
                INSERT INTO ai_keyword_recommendation_batches (
                    recommendation_batch_id, assistance_request_id, case_id,
                    context_snapshot_id, provider_id, provider_version, model_id,
                    external_request_id, generation_started_at, generation_completed_at,
                    result_hash, recommendation_count, partial_state_json, stale_state_json,
                    warnings_json, created_at, batch_version
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                self._ai_keyword_batch_values(batch),
            )
            for recommendation in recommendations:
                self.connection.execute(
                    """
                    INSERT INTO ai_keyword_recommendations (
                        recommendation_id, recommendation_batch_id, case_id,
                        context_snapshot_id, keyword_type, value, normalized_value,
                        display_value, reason, confidence, recommended_scope,
                        evidence_ids_json, source_resource_ids_json, citations_json,
                        is_partial, stale_reasons_json, risk_flags_json, review_status,
                        current_review_revision, content_fingerprint, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    self._ai_keyword_recommendation_values(recommendation),
                )

    def get_ai_keyword_batch(
        self, recommendation_batch_id: str
    ) -> AiKeywordRecommendationBatch | None:
        """Return one AI keyword recommendation batch."""

        row = self.connection.execute(
            """
            SELECT * FROM ai_keyword_recommendation_batches
            WHERE recommendation_batch_id = ?
            """,
            (recommendation_batch_id,),
        ).fetchone()
        return None if row is None else self._row_to_ai_keyword_batch(row)

    def get_ai_keyword_recommendation(
        self, recommendation_id: str
    ) -> AiKeywordRecommendation | None:
        """Return one immutable AI keyword recommendation."""

        row = self.connection.execute(
            """
            SELECT * FROM ai_keyword_recommendations
            WHERE recommendation_id = ?
            """,
            (recommendation_id,),
        ).fetchone()
        return None if row is None else self._row_to_ai_keyword_recommendation(row)

    def list_ai_keyword_recommendations(
        self,
        *,
        case_id: str,
        recommendation_batch_id: str | None = None,
        after_recommendation_id: str | None = None,
        limit: int,
    ) -> list[AiKeywordRecommendation]:
        """List AI keyword recommendations using stable recommendation_id pagination."""

        clauses = ["case_id = ?"]
        params: list[Any] = [case_id]
        if recommendation_batch_id is not None:
            clauses.append("recommendation_batch_id = ?")
            params.append(recommendation_batch_id)
        if after_recommendation_id is not None:
            clauses.append("recommendation_id > ?")
            params.append(after_recommendation_id)
        params.append(limit)
        rows = self.connection.execute(
            f"""
            SELECT * FROM ai_keyword_recommendations
            WHERE {" AND ".join(clauses)}
            ORDER BY recommendation_id
            LIMIT ?
            """,
            tuple(params),
        ).fetchall()
        return [self._row_to_ai_keyword_recommendation(row) for row in rows]

    def save_ai_scope_summary(self, summary: AiScopeSummaryRecord) -> None:
        """Persist one immutable AI scope summary."""

        with self.connection:
            self.connection.execute(
                """
                INSERT INTO ai_scope_summaries (
                    scope_summary_id, assistance_request_id, case_id, context_snapshot_id,
                    scope_context_id, scope_type, provider_id, provider_version, model_id,
                    external_request_id, title, summary_text, key_points_json,
                    referenced_resource_ids_json, citations_json, partial_state_json,
                    stale_state_json, coverage_json, warnings_json, review_status,
                    current_review_revision, content_fingerprint, created_at, summary_version
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                self._ai_scope_summary_values(summary),
            )

    def get_ai_scope_summary(self, scope_summary_id: str) -> AiScopeSummaryRecord | None:
        """Return one AI scope summary."""

        row = self.connection.execute(
            "SELECT * FROM ai_scope_summaries WHERE scope_summary_id = ?",
            (scope_summary_id,),
        ).fetchone()
        return None if row is None else self._row_to_ai_scope_summary(row)

    def list_ai_scope_summaries(
        self,
        *,
        case_id: str,
        context_snapshot_id: str | None = None,
        scope_context_id: str | None = None,
        limit: int,
    ) -> list[AiScopeSummaryRecord]:
        """List AI scope summaries for a case/snapshot/scope."""

        clauses = ["case_id = ?"]
        params: list[Any] = [case_id]
        if context_snapshot_id is not None:
            clauses.append("context_snapshot_id = ?")
            params.append(context_snapshot_id)
        if scope_context_id is not None:
            clauses.append("scope_context_id = ?")
            params.append(scope_context_id)
        params.append(limit)
        rows = self.connection.execute(
            f"""
            SELECT * FROM ai_scope_summaries
            WHERE {" AND ".join(clauses)}
            ORDER BY created_at DESC, scope_summary_id
            LIMIT ?
            """,
            tuple(params),
        ).fetchall()
        return [self._row_to_ai_scope_summary(row) for row in rows]

    def append_ai_verification_event(self, event: AiVerificationEvent) -> None:
        """Append one AI verification event."""

        with self.connection:
            self.connection.execute(
                """
                INSERT INTO ai_verification_events (
                    verification_event_id, case_id, target_type, target_id, action,
                    previous_status, new_status, actor_id, reason, corrected_value,
                    corrected_reason, review_revision, previous_event_hash, event_hash,
                    created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                self._ai_verification_event_values(event),
            )

    def list_ai_verification_events(
        self, *, target_type: str, target_id: str
    ) -> list[AiVerificationEvent]:
        """Return append-only review events for one AI result target."""

        rows = self.connection.execute(
            """
            SELECT * FROM ai_verification_events
            WHERE target_type = ? AND target_id = ?
            ORDER BY review_revision, verification_event_id
            """,
            (target_type, target_id),
        ).fetchall()
        return [self._row_to_ai_verification_event(row) for row in rows]

    def save_ai_keyword_promotion(self, promotion: AiKeywordPromotion) -> None:
        """Persist one idempotent keyword promotion record."""

        with self.connection:
            self.connection.execute(
                """
                INSERT INTO ai_keyword_promotions (
                    promotion_id, case_id, recommendation_id, review_revision,
                    keyword_set_id, keyword_set_version_id, keyword_set_version,
                    promoted_keyword_id, promoted_value, status, duplicate,
                    source_context_snapshot_id, actor_id, reason, promotion_fingerprint,
                    metadata_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                self._ai_keyword_promotion_values(promotion),
            )

    def get_ai_keyword_promotion_by_fingerprint(
        self, promotion_fingerprint: str
    ) -> AiKeywordPromotion | None:
        """Return an existing promotion for idempotent replay."""

        row = self.connection.execute(
            """
            SELECT * FROM ai_keyword_promotions
            WHERE promotion_fingerprint = ?
            """,
            (promotion_fingerprint,),
        ).fetchone()
        return None if row is None else self._row_to_ai_keyword_promotion(row)

    def list_ai_keyword_promotions(
        self,
        *,
        recommendation_id: str | None = None,
        keyword_set_id: str | None = None,
    ) -> list[AiKeywordPromotion]:
        """List AI keyword promotion history."""

        clauses: list[str] = []
        params: list[Any] = []
        if recommendation_id is not None:
            clauses.append("recommendation_id = ?")
            params.append(recommendation_id)
        if keyword_set_id is not None:
            clauses.append("keyword_set_id = ?")
            params.append(keyword_set_id)
        where = "WHERE " + " AND ".join(clauses) if clauses else ""
        rows = self.connection.execute(
            f"""
            SELECT * FROM ai_keyword_promotions
            {where}
            ORDER BY created_at DESC, promotion_id
            """,
            tuple(params),
        ).fetchall()
        return [self._row_to_ai_keyword_promotion(row) for row in rows]

    def save_ai_provider_capability(self, capability: AiProviderCapability) -> None:
        """Persist a provider capability statement."""

        generated_at = capability.generated_at or utc_now()
        with self.connection:
            self.connection.execute(
                """
                INSERT INTO ai_provider_capabilities (
                    provider_id, provider_version, supported_operations_json,
                    max_request_items, max_result_items, max_summary_length, is_available,
                    unavailable_reason, warnings_json, generated_at, capability_version
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(provider_id, provider_version) DO UPDATE SET
                    supported_operations_json = excluded.supported_operations_json,
                    max_request_items = excluded.max_request_items,
                    max_result_items = excluded.max_result_items,
                    max_summary_length = excluded.max_summary_length,
                    is_available = excluded.is_available,
                    unavailable_reason = excluded.unavailable_reason,
                    warnings_json = excluded.warnings_json,
                    generated_at = excluded.generated_at,
                    capability_version = excluded.capability_version
                """,
                (
                    capability.provider_id,
                    capability.provider_version,
                    self._json(capability.supported_operations),
                    capability.max_request_items,
                    capability.max_result_items,
                    capability.max_summary_length,
                    int(capability.is_available),
                    capability.unavailable_reason,
                    self._json(capability.warnings),
                    to_json_timestamp(generated_at),
                    capability.capability_version,
                ),
            )

    def save_report(self, report: ReportRecord) -> None:
        """Persist a report aggregate header."""

        data = report.to_schema_dict()
        with self.connection:
            self.connection.execute(
                """
                INSERT INTO reports (
                    report_id, case_id, title, report_type, status, active_version_id,
                    latest_version_number, created_by, created_at, updated_at, archived_at,
                    report_fingerprint, report_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    report.report_id,
                    report.case_id,
                    report.title,
                    report.report_type,
                    report.status,
                    report.active_version_id,
                    report.latest_version_number,
                    report.created_by,
                    to_json_timestamp(report.created_at),
                    to_json_timestamp(report.updated_at),
                    None if report.archived_at is None else to_json_timestamp(report.archived_at),
                    report.report_fingerprint,
                    self._json(data),
                ),
            )

    def _update_report_row(self, report: ReportRecord) -> None:
        self.connection.execute(
            """
            UPDATE reports
            SET title = ?,
                report_type = ?,
                status = ?,
                active_version_id = ?,
                latest_version_number = ?,
                updated_at = ?,
                archived_at = ?,
                report_json = ?
            WHERE report_id = ?
            """,
            (
                report.title,
                report.report_type,
                report.status,
                report.active_version_id,
                report.latest_version_number,
                to_json_timestamp(report.updated_at),
                None if report.archived_at is None else to_json_timestamp(report.archived_at),
                self._json(report.to_schema_dict()),
                report.report_id,
            ),
        )

    def update_report(self, report: ReportRecord) -> None:
        """Update mutable report aggregate header state."""

        with self.connection:
            self._update_report_row(report)

    def get_report(self, report_id: str) -> ReportRecord | None:
        """Return one report aggregate."""

        row = self.connection.execute(
            "SELECT report_json FROM reports WHERE report_id = ?",
            (report_id,),
        ).fetchone()
        if row is None:
            return None
        return ReportRecord.from_schema_dict(json.loads(str(row["report_json"])))

    def list_reports(
        self, *, case_id: str, after_report_id: str | None = None, limit: int
    ) -> list[ReportRecord]:
        """List reports for a case using stable report_id pagination."""

        clauses = ["case_id = ?"]
        params: list[Any] = [case_id]
        if after_report_id is not None:
            clauses.append("report_id > ?")
            params.append(after_report_id)
        params.append(limit)
        rows = self.connection.execute(
            f"""
            SELECT report_json FROM reports
            WHERE {" AND ".join(clauses)}
            ORDER BY report_id
            LIMIT ?
            """,
            tuple(params),
        ).fetchall()
        return [ReportRecord.from_schema_dict(json.loads(str(row["report_json"]))) for row in rows]

    def save_report_version(self, version: ReportVersion, report: ReportRecord) -> None:
        """Persist an immutable report version and move the report header pointer."""

        with self.connection:
            self.connection.execute(
                """
                INSERT INTO report_versions (
                    report_version_id, report_id, case_id, version_number,
                    previous_version_id, source_kind, source_reference_id,
                    content_fingerprint, previous_content_fingerprint, created_by,
                    created_at, version_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    version.report_version_id,
                    version.report_id,
                    version.case_id,
                    version.version_number,
                    version.previous_version_id,
                    version.source_kind,
                    version.source_reference_id,
                    version.content_fingerprint,
                    version.previous_content_fingerprint,
                    version.created_by,
                    to_json_timestamp(version.created_at),
                    self._json(version.to_schema_dict()),
                ),
            )
            for section in version.sections:
                self.connection.execute(
                    """
                    INSERT INTO report_version_sections (
                        report_version_id, section_id, case_id, report_id, section_type,
                        section_order, section_fingerprint, section_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        version.report_version_id,
                        section.section_id,
                        version.case_id,
                        version.report_id,
                        section.section_type,
                        section.order,
                        section.section_fingerprint,
                        self._json(section.to_schema_dict()),
                    ),
                )
            for reference_type, values in {
                "CONTEXT_SNAPSHOT": version.context_snapshot_ids,
                "EVIDENCE": version.evidence_ids,
                "SEARCH_EXECUTION": version.search_execution_ids,
                "AI_ASSISTANCE_REQUEST": version.ai_assistance_request_ids,
                "AI_RESULT": version.ai_result_ids,
                "CITATION": version.citation_ids,
            }.items():
                for reference_id in values:
                    self.connection.execute(
                        """
                        INSERT INTO report_version_references (
                            report_version_id, case_id, reference_type, reference_id,
                            reference_json
                        ) VALUES (?, ?, ?, ?, ?)
                        """,
                        (
                            version.report_version_id,
                            version.case_id,
                            reference_type,
                            reference_id,
                            self._json({"reference_id": reference_id}),
                        ),
                    )
            for timeline_revision in version.timeline_revisions:
                self.connection.execute(
                    """
                    INSERT INTO report_version_references (
                        report_version_id, case_id, reference_type, reference_id,
                        reference_json
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        version.report_version_id,
                        version.case_id,
                        "TIMELINE_REVISION",
                        str(timeline_revision),
                        self._json({"timeline_revision": timeline_revision}),
                    ),
                )
            self._update_report_row(report)

    def get_report_version(self, report_version_id: str) -> ReportVersion | None:
        """Return one immutable report version."""

        row = self.connection.execute(
            "SELECT version_json FROM report_versions WHERE report_version_id = ?",
            (report_version_id,),
        ).fetchone()
        if row is None:
            return None
        return ReportVersion.from_schema_dict(json.loads(str(row["version_json"])))

    def get_report_version_by_content_fingerprint(
        self, report_id: str, content_fingerprint: str
    ) -> ReportVersion | None:
        """Return an existing version for idempotent draft ingest."""

        row = self.connection.execute(
            """
            SELECT version_json FROM report_versions
            WHERE report_id = ? AND content_fingerprint = ?
            """,
            (report_id, content_fingerprint),
        ).fetchone()
        if row is None:
            return None
        return ReportVersion.from_schema_dict(json.loads(str(row["version_json"])))

    def list_report_versions(self, *, report_id: str) -> list[ReportVersion]:
        """List immutable versions for a report."""

        rows = self.connection.execute(
            """
            SELECT version_json FROM report_versions
            WHERE report_id = ?
            ORDER BY version_number, report_version_id
            """,
            (report_id,),
        ).fetchall()
        return [
            ReportVersion.from_schema_dict(json.loads(str(row["version_json"]))) for row in rows
        ]

    def append_report_review_event(
        self, event: ReportReviewEvent, report: ReportRecord
    ) -> None:
        """Append one report review event and update aggregate state."""

        with self.connection:
            self.connection.execute(
                """
                INSERT INTO report_review_events (
                    review_event_id, report_id, report_version_id, case_id, action,
                    actor_id, review_revision, previous_event_hash, event_hash,
                    created_at, event_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.review_event_id,
                    event.report_id,
                    event.report_version_id,
                    event.case_id,
                    event.action,
                    event.actor_id,
                    event.review_revision,
                    event.previous_event_hash,
                    event.event_hash,
                    to_json_timestamp(event.created_at),
                    self._json(event.to_schema_dict()),
                ),
            )
            self._update_report_row(report)

    def list_report_review_events(
        self, *, report_version_id: str
    ) -> list[ReportReviewEvent]:
        """Return review events for one report version."""

        rows = self.connection.execute(
            """
            SELECT event_json FROM report_review_events
            WHERE report_version_id = ?
            ORDER BY review_revision, review_event_id
            """,
            (report_version_id,),
        ).fetchall()
        return [
            ReportReviewEvent.from_schema_dict(json.loads(str(row["event_json"])))
            for row in rows
        ]

    def append_report_approval_record(
        self, approval: ReportApprovalRecord, report: ReportRecord
    ) -> None:
        """Append one report approval decision and update aggregate state."""

        with self.connection:
            self.connection.execute(
                """
                INSERT INTO report_approval_records (
                    approval_id, report_id, report_version_id, case_id, decision,
                    content_fingerprint, custody_snapshot_id, approval_revision,
                    previous_approval_hash, approval_hash, decided_at, approval_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    approval.approval_id,
                    approval.report_id,
                    approval.report_version_id,
                    approval.case_id,
                    approval.decision,
                    approval.content_fingerprint,
                    approval.custody_snapshot_id,
                    approval.approval_revision,
                    approval.previous_approval_hash,
                    approval.approval_hash,
                    to_json_timestamp(approval.decided_at),
                    self._json(approval.to_schema_dict()),
                ),
            )
            self._update_report_row(report)

    def list_report_approval_records(
        self, *, report_id: str | None = None, report_version_id: str | None = None
    ) -> list[ReportApprovalRecord]:
        """List approval decisions by report or version."""

        clauses: list[str] = []
        params: list[Any] = []
        if report_id is not None:
            clauses.append("report_id = ?")
            params.append(report_id)
        if report_version_id is not None:
            clauses.append("report_version_id = ?")
            params.append(report_version_id)
        where = "WHERE " + " AND ".join(clauses) if clauses else ""
        rows = self.connection.execute(
            f"""
            SELECT approval_json FROM report_approval_records
            {where}
            ORDER BY approval_revision, approval_id
            """,
            tuple(params),
        ).fetchall()
        return [
            ReportApprovalRecord.from_schema_dict(json.loads(str(row["approval_json"])))
            for row in rows
        ]

    def save_custody_snapshot(self, snapshot: CustodySnapshotRecord) -> None:
        """Persist one immutable report custody snapshot."""

        with self.connection:
            self.connection.execute(
                """
                INSERT INTO custody_snapshots (
                    custody_snapshot_id, case_id, report_id, report_version_id,
                    verification_status, ledger_head_hash, snapshot_fingerprint,
                    captured_at, snapshot_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    snapshot.custody_snapshot_id,
                    snapshot.case_id,
                    snapshot.report_id,
                    snapshot.report_version_id,
                    snapshot.verification_status,
                    snapshot.ledger_head_hash,
                    snapshot.snapshot_fingerprint,
                    to_json_timestamp(snapshot.captured_at),
                    self._json(snapshot.to_schema_dict()),
                ),
            )
            for index, event_id in enumerate(snapshot.custody_event_ids, start=1):
                self.connection.execute(
                    """
                    INSERT INTO custody_snapshot_events (
                        custody_snapshot_id, custody_event_id, event_order
                    ) VALUES (?, ?, ?)
                    """,
                    (snapshot.custody_snapshot_id, event_id, index),
                )

    def get_custody_snapshot(
        self, custody_snapshot_id: str
    ) -> CustodySnapshotRecord | None:
        """Return one report custody snapshot."""

        row = self.connection.execute(
            "SELECT snapshot_json FROM custody_snapshots WHERE custody_snapshot_id = ?",
            (custody_snapshot_id,),
        ).fetchone()
        if row is None:
            return None
        return CustodySnapshotRecord.from_schema_dict(json.loads(str(row["snapshot_json"])))

    def get_custody_snapshot_by_fingerprint(
        self, snapshot_fingerprint: str
    ) -> CustodySnapshotRecord | None:
        """Return an existing custody snapshot for the same ledger state."""

        row = self.connection.execute(
            "SELECT snapshot_json FROM custody_snapshots WHERE snapshot_fingerprint = ?",
            (snapshot_fingerprint,),
        ).fetchone()
        if row is None:
            return None
        return CustodySnapshotRecord.from_schema_dict(json.loads(str(row["snapshot_json"])))

    def save_report_render_package(self, package: ReportRenderPackage) -> None:
        """Persist one report render package."""

        with self.connection:
            self.connection.execute(
                """
                INSERT INTO report_render_packages (
                    package_id, report_id, report_version_id, case_id,
                    custody_snapshot_id, package_fingerprint, created_at, package_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    package.package_id,
                    package.report_id,
                    package.report_version_id,
                    package.case_id,
                    package.custody_snapshot_id,
                    package.package_fingerprint,
                    to_json_timestamp(package.created_at),
                    self._json(package.to_schema_dict()),
                ),
            )

    def get_report_render_package(self, package_id: str) -> ReportRenderPackage | None:
        """Return one report render package."""

        row = self.connection.execute(
            "SELECT package_json FROM report_render_packages WHERE package_id = ?",
            (package_id,),
        ).fetchone()
        if row is None:
            return None
        return ReportRenderPackage.from_schema_dict(json.loads(str(row["package_json"])))

    def get_report_render_package_by_fingerprint(
        self, package_fingerprint: str
    ) -> ReportRenderPackage | None:
        """Return an existing package for deterministic regeneration."""

        row = self.connection.execute(
            "SELECT package_json FROM report_render_packages WHERE package_fingerprint = ?",
            (package_fingerprint,),
        ).fetchone()
        if row is None:
            return None
        return ReportRenderPackage.from_schema_dict(json.loads(str(row["package_json"])))

    def save_report_export_manifest(
        self, manifest: ReportExportManifest, report: ReportRecord
    ) -> None:
        """Persist one export manifest and update aggregate state."""

        with self.connection:
            self.connection.execute(
                """
                INSERT INTO report_export_manifests (
                    export_manifest_id, report_id, report_version_id, case_id, format,
                    render_package_id, approval_id, custody_snapshot_id, status,
                    requested_filename, content_fingerprint, manifest_fingerprint,
                    created_at, manifest_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    manifest.export_manifest_id,
                    manifest.report_id,
                    manifest.report_version_id,
                    manifest.case_id,
                    manifest.format,
                    manifest.render_package_id,
                    manifest.approval_id,
                    manifest.custody_snapshot_id,
                    manifest.status,
                    manifest.requested_filename,
                    manifest.content_fingerprint,
                    manifest.manifest_fingerprint,
                    to_json_timestamp(manifest.created_at),
                    self._json(manifest.to_schema_dict()),
                ),
            )
            self._update_report_row(report)

    def get_report_export_manifest(
        self, export_manifest_id: str
    ) -> ReportExportManifest | None:
        """Return one report export manifest."""

        row = self.connection.execute(
            "SELECT manifest_json FROM report_export_manifests WHERE export_manifest_id = ?",
            (export_manifest_id,),
        ).fetchone()
        if row is None:
            return None
        return ReportExportManifest.from_schema_dict(json.loads(str(row["manifest_json"])))

    def get_report_export_manifest_by_fingerprint(
        self, manifest_fingerprint: str
    ) -> ReportExportManifest | None:
        """Return an existing manifest for idempotent export preparation."""

        row = self.connection.execute(
            """
            SELECT manifest_json FROM report_export_manifests
            WHERE manifest_fingerprint = ?
            """,
            (manifest_fingerprint,),
        ).fetchone()
        if row is None:
            return None
        return ReportExportManifest.from_schema_dict(json.loads(str(row["manifest_json"])))

    def update_report_export_manifest(self, manifest: ReportExportManifest) -> None:
        """Update mutable export manifest status/metadata."""

        with self.connection:
            self.connection.execute(
                """
                UPDATE report_export_manifests
                SET status = ?, manifest_json = ?
                WHERE export_manifest_id = ?
                """,
                (
                    manifest.status,
                    self._json(manifest.to_schema_dict()),
                    manifest.export_manifest_id,
                ),
            )

    def save_rendered_report_artifact(
        self,
        artifact: RenderedReportArtifact,
        manifest: ReportExportManifest,
        report: ReportRecord,
    ) -> None:
        """Persist validated renderer output metadata and update manifest/report state."""

        with self.connection:
            self.connection.execute(
                """
                INSERT INTO rendered_report_artifacts (
                    rendered_artifact_id, export_manifest_id, report_version_id, format,
                    output_reference, filename, size_bytes, sha256, artifact_fingerprint,
                    rendered_at, artifact_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    artifact.rendered_artifact_id,
                    artifact.export_manifest_id,
                    artifact.report_version_id,
                    artifact.format,
                    artifact.output_reference,
                    artifact.filename,
                    artifact.size_bytes,
                    artifact.sha256,
                    artifact.artifact_fingerprint,
                    to_json_timestamp(artifact.rendered_at),
                    self._json(artifact.to_schema_dict()),
                ),
            )
            self.connection.execute(
                """
                UPDATE report_export_manifests
                SET status = ?, manifest_json = ?
                WHERE export_manifest_id = ?
                """,
                (
                    manifest.status,
                    self._json(manifest.to_schema_dict()),
                    manifest.export_manifest_id,
                ),
            )
            self._update_report_row(report)

    def list_rendered_report_artifacts(
        self, *, export_manifest_id: str
    ) -> list[RenderedReportArtifact]:
        """List rendered report output metadata for one manifest."""

        rows = self.connection.execute(
            """
            SELECT artifact_json FROM rendered_report_artifacts
            WHERE export_manifest_id = ?
            ORDER BY rendered_at, rendered_artifact_id
            """,
            (export_manifest_id,),
        ).fetchall()
        return [
            RenderedReportArtifact.from_schema_dict(json.loads(str(row["artifact_json"])))
            for row in rows
        ]

    def append_report_export_audit_event(self, event: ReportExportAuditEvent) -> None:
        """Append one export audit event."""

        with self.connection:
            self.connection.execute(
                """
                INSERT INTO report_export_audit_events (
                    audit_event_id, export_manifest_id, report_id, report_version_id,
                    case_id, action, status, previous_event_hash, event_hash,
                    created_at, event_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.audit_event_id,
                    event.export_manifest_id,
                    event.report_id,
                    event.report_version_id,
                    event.case_id,
                    event.action,
                    event.status,
                    event.previous_event_hash,
                    event.event_hash,
                    to_json_timestamp(event.created_at),
                    self._json(event.to_schema_dict()),
                ),
            )

    def list_report_export_audit_events(
        self, *, export_manifest_id: str
    ) -> list[ReportExportAuditEvent]:
        """List append-only export audit events for one manifest."""

        rows = self.connection.execute(
            """
            SELECT event_json FROM report_export_audit_events
            WHERE export_manifest_id = ?
            ORDER BY created_at, audit_event_id
            """,
            (export_manifest_id,),
        ).fetchall()
        return [
            ReportExportAuditEvent.from_schema_dict(json.loads(str(row["event_json"])))
            for row in rows
        ]

    def save_report_renderer_capability(self, capability: ReportRendererCapability) -> None:
        """Persist a report renderer capability statement."""

        generated_at = capability.generated_at or utc_now()
        with self.connection:
            self.connection.execute(
                """
                INSERT INTO report_renderer_capabilities (
                    renderer_id, renderer_version, supported_formats_json, is_available,
                    unavailable_reason, warnings_json, generated_at, capability_version,
                    capability_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(renderer_id, renderer_version) DO UPDATE SET
                    supported_formats_json = excluded.supported_formats_json,
                    is_available = excluded.is_available,
                    unavailable_reason = excluded.unavailable_reason,
                    warnings_json = excluded.warnings_json,
                    generated_at = excluded.generated_at,
                    capability_version = excluded.capability_version,
                    capability_json = excluded.capability_json
                """,
                (
                    capability.renderer_id,
                    capability.renderer_version,
                    self._json(capability.supported_formats),
                    int(capability.is_available),
                    capability.unavailable_reason,
                    self._json(capability.warnings),
                    to_json_timestamp(generated_at),
                    capability.capability_version,
                    self._json(capability.to_schema_dict()),
                ),
            )

    def save_view_projection(self, projection: ViewProjection) -> None:
        """Persist a view projection row for audit/cache inspection."""

        self.connection.execute(
            """
            INSERT OR REPLACE INTO view_projections (
                projection_id, case_id, resource_type, resource_id, view_mode, projection_json,
                source_revision, projection_version, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                projection.projection_id,
                projection.case_id,
                str(projection.resource_type),
                projection.resource_id,
                str(projection.view_mode),
                self._json(projection.to_schema_dict()),
                None if projection.source_revision is None else str(projection.source_revision),
                projection.projection_version,
                to_json_timestamp(projection.created_at),
            ),
        )

    def get_view_projection(self, projection_id: str) -> ViewProjection | None:
        """Return a stored view projection."""

        row = self.connection.execute(
            "SELECT projection_json FROM view_projections WHERE projection_id = ?",
            (projection_id,),
        ).fetchone()
        if row is None:
            return None
        return self._view_projection_from_dict(json.loads(str(row["projection_json"])))

    def save_raw_read_audit(self, record: dict[str, Any]) -> None:
        """Append one raw read audit record."""

        with self.connection:
            self.connection.execute(
                """
                INSERT INTO raw_read_audit_records (
                    audit_id, case_id, evidence_id, resource_type, resource_id, raw_locator_json,
                    requested_offset, requested_length, returned_offset, returned_length,
                    range_hash, correlation_id, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record["audit_id"],
                    record["case_id"],
                    record.get("evidence_id"),
                    record["resource_type"],
                    record["resource_id"],
                    self._json(record.get("raw_locator", {})),
                    record.get("requested_offset"),
                    record.get("requested_length"),
                    record.get("returned_offset"),
                    record.get("returned_length"),
                    record.get("range_hash"),
                    record.get("correlation_id"),
                    record["created_at"],
                ),
            )

    def list_raw_read_audit_records(
        self,
        *,
        case_id: str | None = None,
        resource_id: str | None = None,
    ) -> list[dict[str, Any]]:
        """List raw read audit records for tests and reports."""

        clauses: list[str] = []
        params: list[Any] = []
        if case_id is not None:
            clauses.append("case_id = ?")
            params.append(case_id)
        if resource_id is not None:
            clauses.append("resource_id = ?")
            params.append(resource_id)
        where = "WHERE " + " AND ".join(clauses) if clauses else ""
        rows = self.connection.execute(
            f"SELECT * FROM raw_read_audit_records {where} ORDER BY created_at, audit_id",
            tuple(params),
        ).fetchall()
        result: list[dict[str, Any]] = []
        for row in rows:
            data = dict(row)
            data["raw_locator"] = json.loads(str(data.pop("raw_locator_json")))
            result.append(data)
        return result

    def save_engine_interface_version(self, version: EngineInterfaceVersion) -> None:
        """Persist the public engine interface version statement."""

        self.connection.execute(
            """
            INSERT INTO engine_interface_versions (
                interface_name, interface_version, engine_version, schema_version,
                capabilities_json, unavailable_capabilities_json, generated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(interface_name, interface_version) DO UPDATE SET
                engine_version = excluded.engine_version,
                schema_version = excluded.schema_version,
                capabilities_json = excluded.capabilities_json,
                unavailable_capabilities_json = excluded.unavailable_capabilities_json,
                generated_at = excluded.generated_at
            """,
            (
                version.interface_name,
                version.interface_version,
                version.engine_version,
                version.schema_version,
                self._json(version.capabilities),
                self._json(version.unavailable_capabilities),
                to_json_timestamp(version.generated_at),
            ),
        )

    def save_engine_tool_descriptor(self, descriptor: EngineToolDescriptor) -> None:
        """Persist a public interface tool descriptor."""

        self.connection.execute(
            """
            INSERT INTO engine_tool_descriptors (
                tool_name, tool_version, description_key, input_schema_ref, output_schema_ref,
                required_capabilities_json, mutates_state, requires_confirmation,
                supports_pagination, supports_partial, supports_citation, max_result_items
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(tool_name, tool_version) DO UPDATE SET
                description_key = excluded.description_key,
                input_schema_ref = excluded.input_schema_ref,
                output_schema_ref = excluded.output_schema_ref,
                required_capabilities_json = excluded.required_capabilities_json,
                mutates_state = excluded.mutates_state,
                requires_confirmation = excluded.requires_confirmation,
                supports_pagination = excluded.supports_pagination,
                supports_partial = excluded.supports_partial,
                supports_citation = excluded.supports_citation,
                max_result_items = excluded.max_result_items
            """,
            (
                descriptor.tool_name,
                descriptor.tool_version,
                descriptor.description_key,
                descriptor.input_schema_ref,
                descriptor.output_schema_ref,
                self._json(descriptor.required_capabilities),
                int(descriptor.mutates_state),
                int(descriptor.requires_confirmation),
                int(descriptor.supports_pagination),
                int(descriptor.supports_partial),
                int(descriptor.supports_citation),
                descriptor.max_result_items,
            ),
        )

    def list_engine_tool_descriptors(self) -> list[EngineToolDescriptor]:
        """Return public engine tool descriptors."""

        rows = self.connection.execute(
            "SELECT * FROM engine_tool_descriptors ORDER BY tool_name, tool_version"
        ).fetchall()
        return [self._row_to_engine_tool_descriptor(row) for row in rows]

    def get_search_result(self, result_id: str) -> SearchResult | None:
        """Return a persisted search result by ID."""

        row = self.connection.execute(
            "SELECT * FROM search_results WHERE result_id = ?",
            (result_id,),
        ).fetchone()
        return None if row is None else self._row_to_search_result(row)

    def case_id_for_search_result(self, result_id: str) -> str:
        """Resolve the owning case for a search result."""

        row = self.connection.execute(
            """
            SELECT q.case_id AS case_id
            FROM search_results r
            JOIN search_queries q ON q.query_id = r.query_id
            WHERE r.result_id = ?
            """,
            (result_id,),
        ).fetchone()
        if row is None:
            return ""
        return str(row["case_id"])

    def list_resource_ids(
        self,
        table_name: str,
        id_column: str,
        case_id: str,
        limit: int,
    ) -> list[str]:
        """List resource IDs from a small whitelist of Phase 1-6 tables."""

        allowed = {
            "evidence": "evidence_id",
            "fs_nodes": "node_id",
            "timeline_events": "timeline_event_id",
            "machine_extracted_candidates": "candidate_id",
            "custody_events": "event_id",
        }
        if allowed.get(table_name) != id_column:
            raise ValueError("unsupported resource id table")
        rows = self.connection.execute(
            f"SELECT {id_column} AS resource_id FROM {table_name} "
            "WHERE case_id = ? ORDER BY resource_id LIMIT ?",
            (case_id, limit),
        ).fetchall()
        return [str(row["resource_id"]) for row in rows]

    def list_artifact_ids_for_types(
        self,
        case_id: str,
        artifact_types: list[str],
        limit: int,
    ) -> list[str]:
        """List artifact IDs matching artifact types for scope building."""

        if not artifact_types:
            return []
        placeholders = ", ".join("?" for _ in artifact_types)
        rows = self.connection.execute(
            f"""
            SELECT artifact_id FROM artifacts
            WHERE case_id = ? AND artifact_type IN ({placeholders})
            ORDER BY artifact_id
            LIMIT ?
            """,
            (case_id, *artifact_types, limit),
        ).fetchall()
        return [str(row["artifact_id"]) for row in rows]

    def list_search_result_ids_for_case(self, case_id: str, limit: int) -> list[str]:
        """List search result IDs for a case through their query owner."""

        rows = self.connection.execute(
            """
            SELECT r.result_id
            FROM search_results r
            JOIN search_queries q ON q.query_id = r.query_id
            WHERE q.case_id = ?
            ORDER BY r.rank, r.document_id
            LIMIT ?
            """,
            (case_id, limit),
        ).fetchall()
        return [str(row["result_id"]) for row in rows]

    def coverage_summary_for_scope(self, case_id: str, scope: str) -> dict[str, Any]:
        """Return compact coverage metadata for a Phase 6 scope."""

        if scope == "filesystem":
            rows = self.connection.execute(
                """
                SELECT status, COUNT(*) AS count
                FROM fs_index_coverage
                WHERE case_id = ?
                GROUP BY status
                """,
                (case_id,),
            ).fetchall()
            return {
                "scope": scope,
                "status_counts": {str(row["status"]): int(row["count"]) for row in rows},
            }
        if scope in {"registry", "eventlog", "prefetch", "browser", "media"}:
            rows = self.connection.execute(
                """
                SELECT status, COUNT(*) AS count
                FROM artifact_coverage
                WHERE case_id = ?
                GROUP BY status
                """,
                (case_id,),
            ).fetchall()
            return {
                "scope": scope,
                "status_counts": {str(row["status"]): int(row["count"]) for row in rows},
            }
        if scope == "timeline":
            rows = self.connection.execute(
                """
                SELECT status, COUNT(*) AS count
                FROM timeline_coverage
                WHERE case_id = ?
                GROUP BY status
                """,
                (case_id,),
            ).fetchall()
            return {
                "scope": scope,
                "status_counts": {str(row["status"]): int(row["count"]) for row in rows},
            }
        return {"scope": scope, "status_counts": {}}

    def _ai_assistance_request_values(self, request: AiAssistanceRequest) -> tuple[Any, ...]:
        return (
            request.assistance_request_id,
            request.case_id,
            request.context_snapshot_id,
            request.purpose,
            self._json(request.requested_operations),
            self._json(request.requested_scopes),
            self._json(request.scope_context_ids),
            request.locale,
            request.timezone,
            request.context_fingerprint,
            request.source_revision_fingerprint,
            int(request.is_partial),
            int(request.is_stale),
            self._json(request.coverage_summary),
            self._json(request.warnings),
            self._json(request.citations),
            request.max_keyword_candidates,
            request.max_summary_length,
            to_json_timestamp(request.requested_at),
            to_json_timestamp(request.expires_at),
            request.request_version,
            request.correlation_id,
            request.request_fingerprint,
            request.resource_count,
        )

    def _ai_keyword_batch_values(
        self, batch: AiKeywordRecommendationBatch
    ) -> tuple[Any, ...]:
        return (
            batch.recommendation_batch_id,
            batch.assistance_request_id,
            batch.case_id,
            batch.context_snapshot_id,
            batch.provider_id,
            batch.provider_version,
            batch.model_id,
            batch.external_request_id,
            to_json_timestamp(batch.generation_started_at),
            to_json_timestamp(batch.generation_completed_at),
            batch.result_hash,
            batch.recommendation_count,
            self._json(batch.partial_state),
            self._json(batch.stale_state),
            self._json(batch.warnings),
            to_json_timestamp(batch.created_at),
            batch.batch_version,
        )

    def _ai_keyword_recommendation_values(
        self, recommendation: AiKeywordRecommendation
    ) -> tuple[Any, ...]:
        return (
            recommendation.recommendation_id,
            recommendation.recommendation_batch_id,
            recommendation.case_id,
            recommendation.context_snapshot_id,
            recommendation.keyword_type,
            recommendation.value,
            recommendation.normalized_value,
            recommendation.display_value,
            recommendation.reason,
            recommendation.confidence,
            recommendation.recommended_scope,
            self._json(recommendation.evidence_ids),
            self._json(recommendation.source_resource_ids),
            self._json(recommendation.citations),
            int(recommendation.is_partial),
            self._json(recommendation.stale_reasons),
            self._json(recommendation.risk_flags),
            recommendation.review_status,
            recommendation.current_review_revision,
            recommendation.content_fingerprint,
            to_json_timestamp(recommendation.created_at),
        )

    def _ai_scope_summary_values(self, summary: AiScopeSummaryRecord) -> tuple[Any, ...]:
        return (
            summary.scope_summary_id,
            summary.assistance_request_id,
            summary.case_id,
            summary.context_snapshot_id,
            summary.scope_context_id,
            summary.scope_type,
            summary.provider_id,
            summary.provider_version,
            summary.model_id,
            summary.external_request_id,
            summary.title,
            summary.summary_text,
            self._json(summary.key_points),
            self._json(summary.referenced_resource_ids),
            self._json(summary.citations),
            self._json(summary.partial_state),
            self._json(summary.stale_state),
            self._json(summary.coverage),
            self._json(summary.warnings),
            summary.review_status,
            summary.current_review_revision,
            summary.content_fingerprint,
            to_json_timestamp(summary.created_at),
            summary.summary_version,
        )

    @staticmethod
    def _ai_verification_event_values(event: AiVerificationEvent) -> tuple[Any, ...]:
        return (
            event.verification_event_id,
            event.case_id,
            event.target_type,
            event.target_id,
            event.action,
            event.previous_status,
            event.new_status,
            event.actor_id,
            event.reason,
            event.corrected_value,
            event.corrected_reason,
            event.review_revision,
            event.previous_event_hash,
            event.event_hash,
            to_json_timestamp(event.created_at),
        )

    def _ai_keyword_promotion_values(self, promotion: AiKeywordPromotion) -> tuple[Any, ...]:
        return (
            promotion.promotion_id,
            promotion.case_id,
            promotion.recommendation_id,
            promotion.review_revision,
            promotion.keyword_set_id,
            promotion.keyword_set_version_id,
            promotion.keyword_set_version,
            promotion.promoted_keyword_id,
            promotion.promoted_value,
            promotion.status,
            int(promotion.duplicate),
            promotion.source_context_snapshot_id,
            promotion.actor_id,
            promotion.reason,
            promotion.promotion_fingerprint,
            self._json(promotion.metadata),
            to_json_timestamp(promotion.created_at),
        )

    def _gui_session_context_values(self, context: GuiSessionContext) -> tuple[Any, ...]:
        return (
            context.session_context_id,
            context.session_id,
            context.case_id,
            context.actor_id,
            context.locale,
            context.timezone,
            str(context.current_route),
            context.current_panel,
            context.active_evidence_id,
            self._json(context.selected_file_node_ids),
            self._json(context.selected_artifact_ids),
            self._json(context.selected_timeline_event_ids),
            self._json(context.selected_search_result_ids),
            self._json(context.selected_media_artifact_ids),
            self._json(context.selected_browser_artifact_ids),
            self._json(context.selected_candidate_ids),
            self._json(context.active_filters),
            self._json(context.active_sort),
            self._json(context.active_time_range),
            context.active_keyword_set_id,
            context.active_keyword_set_version,
            context.active_search_execution_id,
            context.active_timeline_revision,
            str(context.active_context_scope),
            self._json(context.ui_preferences),
            context.context_revision,
            context.source_revision_fingerprint,
            int(context.is_partial),
            self._json(context.stale_reasons),
            to_json_timestamp(context.created_at or utc_now()),
            to_json_timestamp(context.updated_at or utc_now()),
            None if context.expires_at is None else to_json_timestamp(context.expires_at),
        )

    def _analysis_context_snapshot_values(
        self,
        snapshot: AnalysisContextSnapshot,
    ) -> tuple[Any, ...]:
        return (
            snapshot.context_snapshot_id,
            snapshot.case_id,
            snapshot.session_context_id,
            snapshot.session_context_revision,
            snapshot.actor_id,
            str(snapshot.purpose),
            self._json(snapshot.scopes),
            self._json(snapshot.included_resource_ids),
            self._json(snapshot.excluded_resource_ids),
            self._json(snapshot.filters),
            self._json(snapshot.time_range),
            self._json([state.to_schema_dict() for state in snapshot.source_revisions]),
            self._json(snapshot.analyzer_versions),
            snapshot.search_index_revision,
            snapshot.timeline_revision,
            snapshot.keyword_set_id,
            snapshot.keyword_set_version,
            snapshot.search_execution_id,
            self._json(snapshot.partial_state),
            self._json(snapshot.stale_state),
            self._json(snapshot.warnings),
            self._json(snapshot.citations),
            snapshot.context_fingerprint,
            snapshot.previous_snapshot_id,
            to_json_timestamp(snapshot.created_at),
        )

    def _analysis_scope_context_values(self, scope: AnalysisScopeContext) -> tuple[Any, ...]:
        return (
            scope.scope_context_id,
            scope.context_snapshot_id,
            str(scope.scope_type),
            scope.case_id,
            self._json(scope.evidence_ids),
            self._json(scope.resource_ids),
            self._json([state.to_schema_dict() for state in scope.source_revisions]),
            self._json(scope.analyzer_versions),
            self._json(scope.filters),
            self._json(scope.sort),
            self._json(scope.time_range),
            scope.result_count,
            scope.included_count,
            scope.excluded_count,
            int(scope.is_partial),
            self._json(scope.coverage),
            self._json(scope.stale_reasons),
            self._json(scope.warnings),
            self._json(scope.citations),
            scope.continuation_cursor,
            scope.scope_fingerprint,
            to_json_timestamp(scope.created_at),
        )

    @staticmethod
    def _revision_for(
        states: list[RevisionState],
        resource_type: str,
        resource_id: str,
    ) -> str | None:
        for state in states:
            if str(state.resource_type) == resource_type and state.resource_id == resource_id:
                return None if state.expected_revision is None else str(state.expected_revision)
        return None

    def _row_to_ai_assistance_request(self, row: sqlite3.Row) -> AiAssistanceRequest:
        return AiAssistanceRequest(
            assistance_request_id=str(row["assistance_request_id"]),
            case_id=str(row["case_id"]),
            context_snapshot_id=str(row["context_snapshot_id"]),
            purpose=str(row["purpose"]),
            requested_operations=list(json.loads(str(row["requested_operations_json"]))),
            requested_scopes=list(json.loads(str(row["requested_scopes_json"]))),
            scope_context_ids=list(json.loads(str(row["scope_context_ids_json"]))),
            locale=str(row["locale"]),
            timezone=str(row["timezone"]),
            context_fingerprint=str(row["context_fingerprint"]),
            source_revision_fingerprint=str(row["source_revision_fingerprint"]),
            is_partial=bool(row["is_partial"]),
            is_stale=bool(row["is_stale"]),
            coverage_summary=dict(json.loads(str(row["coverage_summary_json"]))),
            warnings=list(json.loads(str(row["warnings_json"]))),
            citations=list(json.loads(str(row["citations_json"]))),
            max_keyword_candidates=int(row["max_keyword_candidates"]),
            max_summary_length=int(row["max_summary_length"]),
            requested_at=parse_timestamp(str(row["requested_at"])),
            expires_at=parse_timestamp(str(row["expires_at"])),
            request_version=str(row["request_version"]),
            correlation_id=row["correlation_id"],
            request_fingerprint=str(row["request_fingerprint"]),
            resource_count=int(row["resource_count"]),
        )

    def _row_to_ai_keyword_batch(self, row: sqlite3.Row) -> AiKeywordRecommendationBatch:
        return AiKeywordRecommendationBatch(
            recommendation_batch_id=str(row["recommendation_batch_id"]),
            assistance_request_id=str(row["assistance_request_id"]),
            case_id=str(row["case_id"]),
            context_snapshot_id=str(row["context_snapshot_id"]),
            provider_id=str(row["provider_id"]),
            provider_version=str(row["provider_version"]),
            model_id=str(row["model_id"]),
            external_request_id=row["external_request_id"],
            generation_started_at=parse_timestamp(str(row["generation_started_at"])),
            generation_completed_at=parse_timestamp(str(row["generation_completed_at"])),
            result_hash=str(row["result_hash"]),
            recommendation_count=int(row["recommendation_count"]),
            partial_state=dict(json.loads(str(row["partial_state_json"]))),
            stale_state=dict(json.loads(str(row["stale_state_json"]))),
            warnings=list(json.loads(str(row["warnings_json"]))),
            created_at=parse_timestamp(str(row["created_at"])),
            batch_version=str(row["batch_version"]),
        )

    def _row_to_ai_keyword_recommendation(
        self, row: sqlite3.Row
    ) -> AiKeywordRecommendation:
        return AiKeywordRecommendation(
            recommendation_id=str(row["recommendation_id"]),
            recommendation_batch_id=str(row["recommendation_batch_id"]),
            case_id=str(row["case_id"]),
            context_snapshot_id=str(row["context_snapshot_id"]),
            keyword_type=str(row["keyword_type"]),
            value=str(row["value"]),
            normalized_value=str(row["normalized_value"]),
            display_value=str(row["display_value"]),
            reason=str(row["reason"]),
            confidence=str(row["confidence"]),
            recommended_scope=str(row["recommended_scope"]),
            evidence_ids=list(json.loads(str(row["evidence_ids_json"]))),
            source_resource_ids=list(json.loads(str(row["source_resource_ids_json"]))),
            citations=list(json.loads(str(row["citations_json"]))),
            is_partial=bool(row["is_partial"]),
            stale_reasons=list(json.loads(str(row["stale_reasons_json"]))),
            risk_flags=list(json.loads(str(row["risk_flags_json"]))),
            review_status=str(row["review_status"]),
            current_review_revision=int(row["current_review_revision"]),
            content_fingerprint=str(row["content_fingerprint"]),
            created_at=parse_timestamp(str(row["created_at"])),
        )

    def _row_to_ai_scope_summary(self, row: sqlite3.Row) -> AiScopeSummaryRecord:
        return AiScopeSummaryRecord(
            scope_summary_id=str(row["scope_summary_id"]),
            assistance_request_id=str(row["assistance_request_id"]),
            case_id=str(row["case_id"]),
            context_snapshot_id=str(row["context_snapshot_id"]),
            scope_context_id=str(row["scope_context_id"]),
            scope_type=str(row["scope_type"]),
            provider_id=str(row["provider_id"]),
            provider_version=str(row["provider_version"]),
            model_id=str(row["model_id"]),
            external_request_id=row["external_request_id"],
            title=str(row["title"]),
            summary_text=str(row["summary_text"]),
            key_points=list(json.loads(str(row["key_points_json"]))),
            referenced_resource_ids=list(json.loads(str(row["referenced_resource_ids_json"]))),
            citations=list(json.loads(str(row["citations_json"]))),
            partial_state=dict(json.loads(str(row["partial_state_json"]))),
            stale_state=dict(json.loads(str(row["stale_state_json"]))),
            coverage=dict(json.loads(str(row["coverage_json"]))),
            warnings=list(json.loads(str(row["warnings_json"]))),
            review_status=str(row["review_status"]),
            current_review_revision=int(row["current_review_revision"]),
            content_fingerprint=str(row["content_fingerprint"]),
            created_at=parse_timestamp(str(row["created_at"])),
            summary_version=str(row["summary_version"]),
        )

    @staticmethod
    def _row_to_ai_verification_event(row: sqlite3.Row) -> AiVerificationEvent:
        return AiVerificationEvent(
            verification_event_id=str(row["verification_event_id"]),
            case_id=str(row["case_id"]),
            target_type=str(row["target_type"]),
            target_id=str(row["target_id"]),
            action=str(row["action"]),
            previous_status=str(row["previous_status"]),
            new_status=str(row["new_status"]),
            actor_id=str(row["actor_id"]),
            reason=str(row["reason"]),
            corrected_value=row["corrected_value"],
            corrected_reason=row["corrected_reason"],
            review_revision=int(row["review_revision"]),
            previous_event_hash=row["previous_event_hash"],
            event_hash=str(row["event_hash"]),
            created_at=parse_timestamp(str(row["created_at"])),
        )

    def _row_to_ai_keyword_promotion(self, row: sqlite3.Row) -> AiKeywordPromotion:
        return AiKeywordPromotion(
            promotion_id=str(row["promotion_id"]),
            case_id=str(row["case_id"]),
            recommendation_id=str(row["recommendation_id"]),
            review_revision=int(row["review_revision"]),
            keyword_set_id=str(row["keyword_set_id"]),
            keyword_set_version_id=row["keyword_set_version_id"],
            keyword_set_version=row["keyword_set_version"],
            promoted_keyword_id=row["promoted_keyword_id"],
            promoted_value=str(row["promoted_value"]),
            status=str(row["status"]),
            duplicate=bool(row["duplicate"]),
            source_context_snapshot_id=str(row["source_context_snapshot_id"]),
            actor_id=str(row["actor_id"]),
            reason=str(row["reason"]),
            promotion_fingerprint=str(row["promotion_fingerprint"]),
            metadata=dict(json.loads(str(row["metadata_json"]))),
            created_at=parse_timestamp(str(row["created_at"])),
        )

    def _row_to_gui_session_context(self, row: sqlite3.Row) -> GuiSessionContext:
        return GuiSessionContext(
            session_context_id=str(row["session_context_id"]),
            session_id=str(row["session_id"]),
            case_id=str(row["case_id"]),
            actor_id=row["actor_id"],
            locale=str(row["locale"]),
            timezone=str(row["timezone"]),
            current_route=GuiRoute(str(row["current_route"])),
            current_panel=row["current_panel"],
            active_evidence_id=row["active_evidence_id"],
            selected_file_node_ids=list(json.loads(str(row["selected_file_node_ids_json"]))),
            selected_artifact_ids=list(json.loads(str(row["selected_artifact_ids_json"]))),
            selected_timeline_event_ids=list(json.loads(str(row["selected_timeline_event_ids_json"]))),
            selected_search_result_ids=list(json.loads(str(row["selected_search_result_ids_json"]))),
            selected_media_artifact_ids=list(json.loads(str(row["selected_media_artifact_ids_json"]))),
            selected_browser_artifact_ids=list(json.loads(str(row["selected_browser_artifact_ids_json"]))),
            selected_candidate_ids=list(json.loads(str(row["selected_candidate_ids_json"]))),
            active_filters=dict(json.loads(str(row["active_filters_json"]))),
            active_sort=dict(json.loads(str(row["active_sort_json"]))),
            active_time_range=dict(json.loads(str(row["active_time_range_json"]))),
            active_keyword_set_id=row["active_keyword_set_id"],
            active_keyword_set_version=row["active_keyword_set_version"],
            active_search_execution_id=row["active_search_execution_id"],
            active_timeline_revision=row["active_timeline_revision"],
            active_context_scope=AnalysisScopeType(str(row["active_context_scope"])),
            ui_preferences=dict(json.loads(str(row["ui_preferences_json"]))),
            context_revision=int(row["context_revision"]),
            source_revision_fingerprint=str(row["source_revision_fingerprint"]),
            is_partial=bool(row["is_partial"]),
            stale_reasons=list(json.loads(str(row["stale_reasons_json"]))),
            created_at=parse_timestamp(str(row["created_at"])),
            updated_at=parse_timestamp(str(row["updated_at"])),
            expires_at=None
            if row["expires_at"] is None
            else parse_timestamp(str(row["expires_at"])),
        )

    def _gui_session_context_from_dict(self, data: dict[str, Any]) -> GuiSessionContext:
        return GuiSessionContext(
            session_context_id=str(data["session_context_id"]),
            session_id=str(data["session_id"]),
            case_id=str(data["case_id"]),
            actor_id=data.get("actor_id"),
            locale=str(data["locale"]),
            timezone=str(data["timezone"]),
            current_route=GuiRoute(str(data["current_route"])),
            current_panel=data.get("current_panel"),
            active_evidence_id=data.get("active_evidence_id"),
            selected_file_node_ids=list(data.get("selected_file_node_ids", [])),
            selected_artifact_ids=list(data.get("selected_artifact_ids", [])),
            selected_timeline_event_ids=list(data.get("selected_timeline_event_ids", [])),
            selected_search_result_ids=list(data.get("selected_search_result_ids", [])),
            selected_media_artifact_ids=list(data.get("selected_media_artifact_ids", [])),
            selected_browser_artifact_ids=list(data.get("selected_browser_artifact_ids", [])),
            selected_candidate_ids=list(data.get("selected_candidate_ids", [])),
            active_filters=dict(data.get("active_filters", {})),
            active_sort=dict(data.get("active_sort", {})),
            active_time_range=dict(data.get("active_time_range", {})),
            active_keyword_set_id=data.get("active_keyword_set_id"),
            active_keyword_set_version=data.get("active_keyword_set_version"),
            active_search_execution_id=data.get("active_search_execution_id"),
            active_timeline_revision=data.get("active_timeline_revision"),
            active_context_scope=AnalysisScopeType(str(data.get("active_context_scope", "case"))),
            ui_preferences=dict(data.get("ui_preferences", {})),
            context_revision=int(data.get("context_revision", 1)),
            source_revision_fingerprint=str(data.get("source_revision_fingerprint", "")),
            is_partial=bool(data.get("is_partial", False)),
            stale_reasons=list(data.get("stale_reasons", [])),
            created_at=parse_timestamp(str(data["created_at"])),
            updated_at=parse_timestamp(str(data["updated_at"])),
            expires_at=None
            if data.get("expires_at") is None
            else parse_timestamp(str(data["expires_at"])),
        )

    def _row_to_analysis_context_snapshot(self, row: sqlite3.Row) -> AnalysisContextSnapshot:
        return AnalysisContextSnapshot(
            context_snapshot_id=str(row["context_snapshot_id"]),
            case_id=str(row["case_id"]),
            session_context_id=row["session_context_id"],
            session_context_revision=row["session_context_revision"],
            actor_id=row["actor_id"],
            purpose=AnalysisContextPurpose(str(row["purpose"])),
            scopes=list(json.loads(str(row["scopes_json"]))),
            included_resource_ids=dict(json.loads(str(row["included_resource_ids_json"]))),
            excluded_resource_ids=dict(json.loads(str(row["excluded_resource_ids_json"]))),
            filters=dict(json.loads(str(row["filters_json"]))),
            time_range=dict(json.loads(str(row["time_range_json"]))),
            source_revisions=self._revision_states_from_json(str(row["source_revisions_json"])),
            analyzer_versions=dict(json.loads(str(row["analyzer_versions_json"]))),
            search_index_revision=row["search_index_revision"],
            timeline_revision=row["timeline_revision"],
            keyword_set_id=row["keyword_set_id"],
            keyword_set_version=row["keyword_set_version"],
            search_execution_id=row["search_execution_id"],
            partial_state=dict(json.loads(str(row["partial_state_json"]))),
            stale_state=dict(json.loads(str(row["stale_state_json"]))),
            warnings=list(json.loads(str(row["warnings_json"]))),
            citations=list(json.loads(str(row["citations_json"]))),
            context_fingerprint=str(row["context_fingerprint"]),
            previous_snapshot_id=row["previous_snapshot_id"],
            created_at=parse_timestamp(str(row["created_at"])),
        )

    def _row_to_analysis_scope_context(self, row: sqlite3.Row) -> AnalysisScopeContext:
        return AnalysisScopeContext(
            scope_context_id=str(row["scope_context_id"]),
            context_snapshot_id=str(row["context_snapshot_id"]),
            scope_type=AnalysisScopeType(str(row["scope_type"])),
            case_id=str(row["case_id"]),
            evidence_ids=list(json.loads(str(row["evidence_ids_json"]))),
            resource_ids=list(json.loads(str(row["resource_ids_json"]))),
            source_revisions=self._revision_states_from_json(str(row["source_revisions_json"])),
            analyzer_versions=dict(json.loads(str(row["analyzer_versions_json"]))),
            filters=dict(json.loads(str(row["filters_json"]))),
            sort=dict(json.loads(str(row["sort_json"]))),
            time_range=dict(json.loads(str(row["time_range_json"]))),
            result_count=int(row["result_count"]),
            included_count=int(row["included_count"]),
            excluded_count=int(row["excluded_count"]),
            is_partial=bool(row["is_partial"]),
            coverage=dict(json.loads(str(row["coverage_json"]))),
            stale_reasons=list(json.loads(str(row["stale_reasons_json"]))),
            warnings=list(json.loads(str(row["warnings_json"]))),
            citations=list(json.loads(str(row["citations_json"]))),
            continuation_cursor=row["continuation_cursor"],
            scope_fingerprint=str(row["scope_fingerprint"]),
            created_at=parse_timestamp(str(row["created_at"])),
        )

    def _revision_states_from_json(self, value: str) -> list[RevisionState]:
        return [self._revision_state_from_dict(item) for item in json.loads(value)]

    def _row_to_revision_state(self, row: sqlite3.Row) -> RevisionState:
        return RevisionState(
            resource_type=ResourceType(str(row["resource_type"])),
            resource_id=str(row["resource_id"]),
            expected_revision=row["expected_revision"],
            current_revision=row["current_revision"],
            status=RevisionStatus(str(row["status"])),
            reason=row["reason"],
            detected_at=parse_timestamp(str(row["detected_at"])),
        )

    @staticmethod
    def _revision_state_from_dict(data: dict[str, Any]) -> RevisionState:
        return RevisionState(
            resource_type=ResourceType(str(data["resource_type"])),
            resource_id=str(data["resource_id"]),
            expected_revision=data.get("expected_revision"),
            current_revision=data.get("current_revision"),
            status=RevisionStatus(str(data["status"])),
            reason=data.get("reason"),
            detected_at=parse_timestamp(str(data["detected_at"])),
        )

    @staticmethod
    def _view_projection_from_dict(data: dict[str, Any]) -> ViewProjection:
        return ViewProjection(
            projection_id=str(data["projection_id"]),
            case_id=str(data["case_id"]),
            resource_type=ResourceType(str(data["resource_type"])),
            resource_id=str(data["resource_id"]),
            view_mode=ViewMode(str(data["view_mode"])),
            title=str(data["title"]),
            subtitle=data.get("subtitle"),
            summary=data.get("summary"),
            severity=data.get("severity"),
            badges=list(data.get("badges", [])),
            primary_fields=dict(data.get("primary_fields", {})),
            secondary_fields=dict(data.get("secondary_fields", {})),
            technical_fields=dict(data.get("technical_fields", {})),
            raw_fields=dict(data.get("raw_fields", {})),
            timestamps=dict(data.get("timestamps", {})),
            timezone=data.get("timezone"),
            confidence=data.get("confidence"),
            partial_state=dict(data.get("partial_state", {})),
            stale_state=dict(data.get("stale_state", {})),
            warnings=list(data.get("warnings", [])),
            citations=list(data.get("citations", [])),
            raw_locator=data.get("raw_locator"),
            available_actions=list(data.get("available_actions", [])),
            source_revision=data.get("source_revision"),
            analyzer_id=data.get("analyzer_id"),
            analyzer_version=data.get("analyzer_version"),
            projection_version=str(data["projection_version"]),
            created_at=parse_timestamp(str(data["created_at"])),
        )

    @staticmethod
    def _row_to_engine_tool_descriptor(row: sqlite3.Row) -> EngineToolDescriptor:
        return EngineToolDescriptor(
            tool_name=str(row["tool_name"]),
            tool_version=str(row["tool_version"]),
            description_key=str(row["description_key"]),
            input_schema_ref=str(row["input_schema_ref"]),
            output_schema_ref=str(row["output_schema_ref"]),
            required_capabilities=list(json.loads(str(row["required_capabilities_json"]))),
            mutates_state=bool(row["mutates_state"]),
            requires_confirmation=bool(row["requires_confirmation"]),
            supports_pagination=bool(row["supports_pagination"]),
            supports_partial=bool(row["supports_partial"]),
            supports_citation=bool(row["supports_citation"]),
            max_result_items=int(row["max_result_items"]),
        )

    def _configure_connection(self) -> None:
        self.connection.execute("PRAGMA foreign_keys = ON")
        self.connection.execute("PRAGMA journal_mode = WAL")
        self.connection.execute("PRAGMA synchronous = FULL")
        self.connection.execute("PRAGMA busy_timeout = 5000")

    @staticmethod
    def _json(value: Any) -> str:
        return json.dumps(value if value is not None else {}, ensure_ascii=False, sort_keys=True)

    @staticmethod
    def _nullable_timestamp(value: Any) -> str | None:
        return None if value is None else to_json_timestamp(value)

    @staticmethod
    def _fingerprint_json(fingerprint: EvidenceFingerprint | None) -> str | None:
        if fingerprint is None:
            return None
        return json.dumps(fingerprint.to_schema_dict(), ensure_ascii=False, sort_keys=True)

    def _ensure_column(self, table: str, column: str, definition: str) -> None:
        columns = {
            str(row["name"])
            for row in self.connection.execute(f"PRAGMA table_info({table})").fetchall()
        }
        if column not in columns:
            self.connection.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")

    def _fts5_available(self) -> bool:
        try:
            self.connection.execute(
                "CREATE VIRTUAL TABLE IF NOT EXISTS temp.apex_fts5_probe USING fts5(value)"
            )
            self.connection.execute("DROP TABLE IF EXISTS temp.apex_fts5_probe")
        except (sqlite3.Error, PersistenceError):
            return False
        return True

    def _ensure_fts_available(self) -> None:
        if not self._fts5_available():
            from apex_forensic.domain.errors import UnsupportedCapabilityError

            raise UnsupportedCapabilityError(
                "SQLite FTS5 is not available; search cannot be executed.",
                required_capability="SQLITE_FTS5",
            )
        self.connection.execute(
            """
            CREATE VIRTUAL TABLE IF NOT EXISTS search_documents_fts
            USING fts5(
                document_id UNINDEXED,
                title,
                path,
                searchable_text,
                tokenize = 'unicode61'
            )
            """
        )

    def _upsert_search_index_metadata(self, case_id: str, index_revision: int) -> None:
        self.connection.execute(
            """
            INSERT INTO search_index_metadata (
                case_id, index_revision, backend, backend_version, fts5_available, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(case_id) DO UPDATE SET
                index_revision = MAX(search_index_metadata.index_revision, excluded.index_revision),
                backend = excluded.backend,
                backend_version = excluded.backend_version,
                fts5_available = excluded.fts5_available,
                updated_at = excluded.updated_at
            """,
            (
                case_id,
                index_revision,
                "sqlite-fts5",
                sqlite3.sqlite_version,
                int(self._fts5_available()),
                to_json_timestamp(utc_now()),
            ),
        )

    def _search_document_values(self, document: SearchDocument) -> tuple[Any, ...]:
        return (
            document.document_id,
            document.case_id,
            document.evidence_id,
            document.source_type.value,
            document.source_id,
            document.source_revision,
            document.document_type.value,
            document.title,
            document.path,
            document.normalized_path,
            document.searchable_text,
            self._json(document.structured_fields),
            self._nullable_timestamp(document.observed_at_utc),
            self._json(document.raw_locator),
            self._json(document.citations),
            document.analyzer_id,
            document.analyzer_version,
            int(document.is_partial),
            document.index_revision,
            document.search_backend,
            document.search_backend_version,
            int(document.is_stale),
            None,
            to_json_timestamp(document.created_at),
            to_json_timestamp(document.updated_at),
        )

    def _search_filter_clauses(
        self,
        query: SearchQuery,
        alias: str,
    ) -> tuple[list[str], list[Any]]:
        clauses = [f"{alias}.case_id = ?", f"{alias}.is_stale = 0"]
        params: list[Any] = [query.case_id]
        if query.evidence_ids:
            placeholders = ", ".join("?" for _ in query.evidence_ids)
            clauses.append(f"{alias}.evidence_id IN ({placeholders})")
            params.extend(query.evidence_ids)
        if query.source_types:
            placeholders = ", ".join("?" for _ in query.source_types)
            clauses.append(f"{alias}.source_type IN ({placeholders})")
            params.extend(item.value for item in query.source_types)
        if query.document_types:
            placeholders = ", ".join("?" for _ in query.document_types)
            clauses.append(f"{alias}.document_type IN ({placeholders})")
            params.extend(item.value for item in query.document_types)
        if query.time_range.get("from") is not None:
            clauses.append(f"{alias}.observed_at_utc >= ?")
            params.append(query.time_range["from"])
        if query.time_range.get("to") is not None:
            clauses.append(f"{alias}.observed_at_utc <= ?")
            params.append(query.time_range["to"])
        if query.path_scope:
            clauses.append(f"{alias}.normalized_path LIKE ?")
            params.append(f"%{query.path_scope.casefold()}%")
        return clauses, params

    def _query_search_regex(
        self,
        *,
        query: SearchQuery,
        after: tuple[float, str] | None,
        limit: int,
    ) -> list[dict[str, Any]]:
        flags = 0 if query.case_sensitive else re.IGNORECASE
        pattern = re.compile(query.query_text, flags)
        clauses, params = self._search_filter_clauses(query, "d")
        if after is not None:
            clauses.append("d.document_id > ?")
            params.append(after[1])
        candidate_limit = min(max(limit * 20, 500), 5000)
        sql = f"""
            SELECT d.*, 0.0 AS rank, '' AS snippet
            FROM search_documents d
            WHERE {" AND ".join(clauses)}
            ORDER BY d.document_id
            LIMIT ?
        """
        params.append(candidate_limit)
        rows = self.connection.execute(sql, tuple(params)).fetchall()
        results = []
        for row in rows:
            structured = json.loads(str(row["structured_fields_json"]))
            metadata_text = " ".join(str(value) for value in structured.values())
            if pattern.search(metadata_text):
                hit = self._search_hit_from_row(row, query)
                hit["matched_terms"] = [query.query_text]
                hit["matched_fields"] = ["structured_fields"]
                hit.pop("_haystack", None)
                results.append(hit)
            if len(results) >= limit:
                break
        return results

    def _search_hit_from_row(self, row: sqlite3.Row, query: SearchQuery) -> dict[str, Any]:
        structured = json.loads(str(row["structured_fields_json"]))
        title = str(row["title"])
        path = "" if row["path"] is None else str(row["path"])
        searchable = str(row["searchable_text"])
        structured_text = " ".join(str(value) for value in structured.values())
        haystack = " ".join([title, path, searchable, structured_text])
        terms = _query_terms(query.query_text)
        return {
            "document_id": str(row["document_id"]),
            "source_type": str(row["source_type"]),
            "source_id": str(row["source_id"]),
            "rank": float(row["rank"]),
            "matched_fields": _matched_fields(terms, title, path, searchable, structured),
            "matched_terms": terms,
            "snippet": str(row["snippet"] or title),
            "raw_locator": json.loads(str(row["raw_locator_json"])),
            "citations": json.loads(str(row["citations_json"])),
            "is_partial": bool(row["is_partial"]),
            "index_revision": int(row["index_revision"]),
            "_haystack": haystack,
        }

    @staticmethod
    def _fts_query(query_text: str, query_mode: SearchQueryMode) -> str:
        if query_mode is SearchQueryMode.PHRASE or query_mode is SearchQueryMode.EXACT:
            return _quote_fts(query_text)
        tokens = _query_terms(query_text)
        if query_mode is SearchQueryMode.PREFIX:
            return " ".join(_prefix_fts_token(token) for token in tokens)
        return " ".join(_quote_fts(token) for token in tokens)

    def _iter_fs_search_rows(
        self,
        *,
        case_id: str,
        evidence_ids: tuple[str, ...],
        after_id: str | None,
        limit: int,
    ) -> list[dict[str, Any]]:
        clauses = ["case_id = ?"]
        params: list[Any] = [case_id]
        if evidence_ids:
            clauses.append("evidence_id IN (" + ", ".join("?" for _ in evidence_ids) + ")")
            params.extend(evidence_ids)
        if after_id is not None:
            clauses.append("node_id > ?")
            params.append(after_id)
        sql = f"""
            SELECT * FROM fs_nodes
            WHERE {" AND ".join(clauses)}
            ORDER BY node_id
            LIMIT ?
        """
        params.append(limit)
        rows = self.connection.execute(sql, tuple(params)).fetchall()
        return [self._fs_search_row(row) for row in rows]

    def _fs_search_row(self, row: sqlite3.Row) -> dict[str, Any]:
        fs_metadata = json.loads(str(row["fs_metadata_json"]))
        provider_metadata = json.loads(str(row["provider_metadata_json"]))
        structured = {
            "original_name": row["original_name"],
            "original_relative_path": row["original_relative_path"],
            "display_path": row["display_path"],
            "extension": row["extension"],
            "mime_candidate": row["mime_candidate"],
            "platform": row["platform"],
            "node_type": row["node_type"],
            "file_size": row["file_size"],
            **_safe_field_map(fs_metadata, _FS_METADATA_ALLOWLIST),
            **_safe_field_map(provider_metadata, _PROVIDER_METADATA_ALLOWLIST),
        }
        text_values = [value for value in structured.values() if value is not None]
        return {
            "case_id": str(row["case_id"]),
            "evidence_id": str(row["evidence_id"]),
            "source_type": SearchSourceType.FILE_SYSTEM_NODE.value,
            "source_id": str(row["node_id"]),
            "source_revision": int(row["index_revision"]),
            "document_type": _fs_document_type(str(row["node_type"])).value,
            "title": str(row["original_name"]),
            "path": row["display_path"],
            "normalized_path": row["comparison_path"],
            "searchable_text": _join_search_text(text_values),
            "structured_fields": structured,
            "observed_at_utc": None,
            "raw_locator": json.loads(str(row["raw_locator_json"])),
            "citations": [],
            "analyzer_id": str(row["provider_id"]),
            "analyzer_version": str(row["provider_version"]),
            "is_partial": bool(row["is_partial"]),
        }

    def _iter_artifact_search_rows(
        self,
        *,
        case_id: str,
        evidence_ids: tuple[str, ...],
        after_id: str | None,
        limit: int,
    ) -> list[dict[str, Any]]:
        clauses = ["case_id = ?"]
        params: list[Any] = [case_id]
        if evidence_ids:
            clauses.append("evidence_id IN (" + ", ".join("?" for _ in evidence_ids) + ")")
            params.extend(evidence_ids)
        if after_id is not None:
            clauses.append("artifact_id > ?")
            params.append(after_id)
        sql = f"""
            SELECT * FROM artifacts
            WHERE {" AND ".join(clauses)}
            ORDER BY artifact_id
            LIMIT ?
        """
        params.append(limit)
        rows = self.connection.execute(sql, tuple(params)).fetchall()
        return [self._artifact_search_row(row) for row in rows]

    def _artifact_search_row(self, row: sqlite3.Row) -> dict[str, Any]:
        fields = json.loads(str(row["fields_json"]))
        structured = {
            "title": row["title"],
            "summary": row["summary"],
            "artifact_type": row["artifact_type"],
            "artifact_subtype": row["artifact_subtype"],
            "source_path": row["source_path"],
            "source_kind": row["source_kind"],
            **_safe_field_map(fields, _ARTIFACT_FIELD_ALLOWLIST),
        }
        return {
            "case_id": str(row["case_id"]),
            "evidence_id": str(row["evidence_id"]),
            "source_type": SearchSourceType.WINDOWS_ARTIFACT.value,
            "source_id": str(row["artifact_id"]),
            "source_revision": int(row["index_revision"]),
            "document_type": _artifact_document_type(str(row["artifact_type"])).value,
            "title": str(row["title"]),
            "path": row["source_path"],
            "normalized_path": str(row["source_path"]).casefold(),
            "searchable_text": _join_search_text(structured.values()),
            "structured_fields": structured,
            "observed_at_utc": row["observed_at_utc"],
            "raw_locator": json.loads(str(row["raw_locator_json"])),
            "citations": json.loads(str(row["citations_json"])),
            "analyzer_id": row["analyzer_id"],
            "analyzer_version": row["analyzer_version"],
            "is_partial": bool(row["is_partial"]),
        }

    def _iter_timeline_search_rows(
        self,
        *,
        case_id: str,
        evidence_ids: tuple[str, ...],
        after_id: str | None,
        limit: int,
    ) -> list[dict[str, Any]]:
        clauses = ["case_id = ?"]
        params: list[Any] = [case_id]
        if evidence_ids:
            clauses.append("evidence_id IN (" + ", ".join("?" for _ in evidence_ids) + ")")
            params.extend(evidence_ids)
        if after_id is not None:
            clauses.append("timeline_event_id > ?")
            params.append(after_id)
        sql = f"""
            SELECT * FROM timeline_events
            WHERE {" AND ".join(clauses)}
            ORDER BY timeline_event_id
            LIMIT ?
        """
        params.append(limit)
        rows = self.connection.execute(sql, tuple(params)).fetchall()
        return [self._timeline_search_row(row) for row in rows]

    def _timeline_search_row(self, row: sqlite3.Row) -> dict[str, Any]:
        fields = json.loads(str(row["fields_json"]))
        structured = {
            "title": row["title"],
            "description": row["description"],
            "event_type": row["event_type"],
            "event_subtype": row["event_subtype"],
            "source_type": row["source_type"],
            **_safe_field_map(fields, _TIMELINE_FIELD_ALLOWLIST),
        }
        return {
            "case_id": str(row["case_id"]),
            "evidence_id": str(row["evidence_id"]),
            "source_type": SearchSourceType.TIMELINE_EVENT.value,
            "source_id": str(row["timeline_event_id"]),
            "source_revision": int(row["timeline_revision"]),
            "document_type": SearchDocumentType.TIMELINE.value,
            "title": str(row["title"]),
            "path": fields.get("path") or fields.get("source_path"),
            "normalized_path": None if row["path_key"] is None else str(row["path_key"]),
            "searchable_text": _join_search_text(structured.values()),
            "structured_fields": structured,
            "observed_at_utc": row["normalized_utc"],
            "raw_locator": json.loads(str(row["raw_locator_json"])),
            "citations": json.loads(str(row["citations_json"])),
            "analyzer_id": row["analyzer_id"],
            "analyzer_version": row["analyzer_version"],
            "is_partial": bool(row["is_partial"]),
        }

    def _iter_fs_timeline_rows(
        self,
        *,
        case_id: str,
        evidence_id: str | None,
        after_id: str | None,
        limit: int,
    ) -> list[dict[str, Any]]:
        clauses = ["case_id = ?"]
        params: list[Any] = [case_id]
        if evidence_id is not None:
            clauses.append("evidence_id = ?")
            params.append(evidence_id)
        if after_id is not None:
            clauses.append("node_id > ?")
            params.append(after_id)
        sql = f"""
            SELECT * FROM fs_nodes
            WHERE {" AND ".join(clauses)}
            ORDER BY node_id
            LIMIT ?
        """
        params.append(limit)
        rows = self.connection.execute(sql, tuple(params)).fetchall()
        result: list[dict[str, Any]] = []
        for row in rows:
            result.append(
                {
                    "case_id": str(row["case_id"]),
                    "evidence_id": str(row["evidence_id"]),
                    "source_type": TimelineSourceType.FILE_SYSTEM_NODE.value,
                    "source_id": str(row["node_id"]),
                    "source_revision": int(row["index_revision"]),
                    "title": str(row["display_path"]),
                    "description": str(row["original_name"]),
                    "path": row["display_path"],
                    "node_type": row["node_type"],
                    "platform": row["platform"],
                    "raw_timestamps": json.loads(str(row["raw_timestamps_json"])),
                    "utc_timestamps": json.loads(str(row["utc_timestamps_json"])),
                    "timestamp_meanings": json.loads(str(row["timestamp_meanings_json"])),
                    "timestamp_sources": json.loads(str(row["timestamp_sources_json"])),
                    "raw_locator": json.loads(str(row["raw_locator_json"])),
                    "citations": [],
                    "analyzer_id": row["provider_id"],
                    "analyzer_version": row["provider_version"],
                    "is_partial": bool(row["is_partial"]),
                }
            )
        return result

    def _iter_artifact_timeline_rows(
        self,
        *,
        case_id: str,
        evidence_id: str | None,
        source_type: str,
        after_id: str | None,
        limit: int,
    ) -> list[dict[str, Any]]:
        clauses = ["case_id = ?"]
        params: list[Any] = [case_id]
        artifact_types = _timeline_source_artifact_types(source_type)
        clauses.append("artifact_type IN (" + ", ".join("?" for _ in artifact_types) + ")")
        params.extend(artifact_types)
        if evidence_id is not None:
            clauses.append("evidence_id = ?")
            params.append(evidence_id)
        if after_id is not None:
            clauses.append("artifact_id > ?")
            params.append(after_id)
        sql = f"""
            SELECT * FROM artifacts
            WHERE {" AND ".join(clauses)}
            ORDER BY artifact_id
            LIMIT ?
        """
        params.append(limit)
        rows = self.connection.execute(sql, tuple(params)).fetchall()
        result: list[dict[str, Any]] = []
        for row in rows:
            result.append(
                {
                    "case_id": str(row["case_id"]),
                    "evidence_id": str(row["evidence_id"]),
                    "source_type": source_type,
                    "source_id": str(row["artifact_id"]),
                    "source_revision": int(row["index_revision"]),
                    "title": str(row["title"]),
                    "description": str(row["summary"]),
                    "path": row["source_path"],
                    "artifact_type": row["artifact_type"],
                    "raw_timestamp": row["observed_at_raw"],
                    "normalized_utc": row["observed_at_utc"],
                    "timestamp_semantics": "artifact_observed_at",
                    "fields": json.loads(str(row["fields_json"])),
                    "raw_locator": json.loads(str(row["raw_locator_json"])),
                    "citations": json.loads(str(row["citations_json"])),
                    "analyzer_id": row["analyzer_id"],
                    "analyzer_version": row["analyzer_version"],
                    "is_partial": bool(row["is_partial"]),
                }
            )
        return result

    def _search_execution_values(self, execution: SearchExecution) -> tuple[Any, ...]:
        return (
            execution.execution_id,
            execution.query_id,
            execution.case_id,
            execution.query_text,
            execution.query_mode.value,
            execution.keyword_set_id,
            execution.keyword_set_version,
            self._json(execution.options),
            execution.options_fingerprint,
            execution.search_backend,
            execution.search_backend_version,
            execution.index_revision,
            execution.source_revision_fingerprint,
            to_json_timestamp(execution.started_at),
            self._nullable_timestamp(execution.completed_at),
            execution.status,
            int(execution.is_partial),
            execution.result_count,
            self._json(execution.warnings),
            execution.cache_key,
            int(execution.cache_hit),
            self._json(execution.zero_result_keyword_ids),
            execution.execution_revision,
        )

    def _search_result_values(self, result: SearchResult) -> tuple[Any, ...]:
        return (
            result.result_id,
            result.query_id,
            result.document_id,
            result.source_type.value,
            result.source_id,
            result.rank,
            self._json(result.matched_fields),
            self._json(result.matched_terms),
            result.snippet,
            self._json(result.raw_locator),
            self._json(result.citations),
            int(result.is_partial),
            result.index_revision,
            to_json_timestamp(result.created_at),
        )

    def _timeline_event_values(self, event: TimelineEvent) -> tuple[Any, ...]:
        normalized_utc = self._nullable_timestamp(event.normalized_utc)
        sort_timestamp = normalized_utc or "9999-12-31T23:59:59.999999Z"
        artifact_type = event.fields.get("artifact_type")
        path = (
            event.fields.get("path")
            or event.fields.get("source_path")
            or event.fields.get("registry_path")
        )
        return (
            event.timeline_event_id,
            event.case_id,
            event.evidence_id,
            event.source_type.value,
            event.source_id,
            event.source_revision,
            event.event_type.value,
            event.event_subtype,
            event.title,
            event.description,
            event.raw_timestamp,
            event.raw_timezone,
            event.timestamp_semantics,
            normalized_utc,
            sort_timestamp,
            event.case_timezone,
            event.displayed_case_time,
            event.timezone_source.value,
            event.timezone_confidence.value,
            event.precision.value,
            event.analyzer_id,
            event.analyzer_version,
            self._json(event.raw_locator),
            self._json(event.citations),
            self._json(event.fields),
            int(event.is_partial),
            event.timeline_revision,
            to_json_timestamp(event.created_at),
            event.dedup_key,
            None if artifact_type is None else str(artifact_type),
            None if path is None else str(path).casefold(),
        )

    @staticmethod
    def _decode_timeline_cursor(cursor: str | None) -> dict[str, Any] | None:
        if cursor is None:
            return None
        try:
            padded = cursor + "=" * (-len(cursor) % 4)
            data = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8"))
            if not isinstance(data, dict):
                raise ValueError("cursor is not an object")
            return data
        except (ValueError, TypeError, json.JSONDecodeError) as error:
            from apex_forensic.domain.errors import ValidationError

            raise ValidationError("Invalid timeline cursor.", target="cursor") from error

    def _fs_node_values(self, node: FileSystemNode) -> tuple[Any, ...]:
        return (
            node.node_id,
            node.case_id,
            node.evidence_id,
            node.provider_id,
            node.provider_version,
            node.parent_node_id,
            node.original_name,
            node.original_relative_path,
            node.display_path,
            node.comparison_path,
            node.node_type.value,
            node.file_size,
            node.extension,
            node.mime_candidate,
            node.mime_confidence,
            self._json(node.fs_metadata),
            node.platform,
            self._json(node.timestamp_meanings),
            self._json(node.raw_timestamps),
            self._json(
                {
                    key: None if value is None else to_json_timestamp(value)
                    for key, value in node.utc_timestamps.items()
                }
            ),
            self._json(node.timestamp_sources),
            int(node.is_deleted),
            int(node.is_readable),
            int(node.is_link),
            int(node.is_traversed),
            self._json(node.raw_locator),
            self._json(node.provider_metadata),
            int(node.is_partial),
            node.index_revision,
            to_json_timestamp(node.created_at),
            to_json_timestamp(node.updated_at),
        )

    def _artifact_source_values(self, source: ArtifactSource) -> tuple[Any, ...]:
        return (
            source.source_id,
            source.job_id,
            source.case_id,
            source.evidence_id,
            source.source_file_node_id,
            source.source_path,
            source.source_kind.value,
            source.comparison_key,
            source.analyzer_id,
            source.analyzer_version,
            source.parser_backend,
            source.parser_backend_version,
            source.option_fingerprint,
            source.source_fingerprint,
            self._json(source.source_checkpoint) if source.source_checkpoint else None,
            source.inspected_count,
            source.status,
            source.priority,
            source.source_order,
            int(source.is_partial),
            source.warning_count,
            source.error_count,
            source.artifact_count,
            None if source.parse_status is None else source.parse_status.value,
            self._json(source.last_error) if source.last_error is not None else None,
            to_json_timestamp(source.discovered_at),
            self._nullable_timestamp(source.analyzed_at),
            to_json_timestamp(source.updated_at),
        )

    def _artifact_values(self, artifact: ArtifactRecord) -> tuple[Any, ...]:
        event_id = self._artifact_event_id(artifact)
        registry_path = self._artifact_registry_path(artifact)
        executable_name = self._artifact_executable_name(artifact)
        sort_timestamp = artifact.observed_at_utc or artifact.created_at
        return (
            artifact.artifact_id,
            artifact.case_id,
            artifact.evidence_id,
            artifact.source_file_node_id,
            artifact.artifact_type.value,
            artifact.artifact_subtype,
            artifact.analyzer_id,
            artifact.analyzer_version,
            artifact.parser_backend,
            artifact.parser_backend_version,
            artifact.source_path,
            artifact.source_kind.value,
            artifact.observed_at_raw,
            self._nullable_timestamp(artifact.observed_at_utc),
            to_json_timestamp(sort_timestamp),
            artifact.timezone_source,
            artifact.timezone_confidence,
            artifact.title,
            artifact.summary,
            self._json(artifact.fields),
            self._json(artifact.raw_locator),
            self._json(artifact.citations),
            self._json(artifact.warnings),
            artifact.parse_status.value,
            artifact.confidence,
            int(artifact.is_partial),
            artifact.index_revision,
            to_json_timestamp(artifact.created_at),
            to_json_timestamp(artifact.updated_at),
            artifact.dedup_key,
            artifact.schema_version,
            event_id,
            registry_path,
            None if registry_path is None else registry_path.casefold(),
            executable_name,
            None if executable_name is None else executable_name.casefold(),
            int(bool(artifact.warnings)),
        )

    @staticmethod
    def _artifact_event_id(artifact: ArtifactRecord) -> int | None:
        value = artifact.fields.get("event_id")
        if value is None:
            return None
        try:
            return int(value)
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _artifact_registry_path(artifact: ArtifactRecord) -> str | None:
        value = artifact.fields.get("registry_path")
        return None if value is None else str(value)

    @staticmethod
    def _artifact_executable_name(artifact: ArtifactRecord) -> str | None:
        value = artifact.fields.get("executable_name")
        if value is None:
            value = artifact.fields.get("executable_candidate")
        return None if value is None else str(value)

    @staticmethod
    def _timestamp_dict(data: dict[str, Any]) -> dict[str, Any]:
        return {
            key: None if value is None else parse_timestamp(str(value))
            for key, value in data.items()
        }

    def _row_to_fs_node(self, row: sqlite3.Row) -> FileSystemNode:
        return FileSystemNode(
            node_id=str(row["node_id"]),
            case_id=str(row["case_id"]),
            evidence_id=str(row["evidence_id"]),
            provider_id=str(row["provider_id"]),
            provider_version=str(row["provider_version"]),
            parent_node_id=row["parent_node_id"],
            original_name=str(row["original_name"]),
            original_relative_path=str(row["original_relative_path"]),
            display_path=str(row["display_path"]),
            comparison_path=str(row["comparison_path"]),
            node_type=FileSystemNodeType(str(row["node_type"])),
            file_size=row["file_size"],
            extension=row["extension"],
            mime_candidate=row["mime_candidate"],
            mime_confidence=str(row["mime_confidence"]),
            fs_metadata=json.loads(str(row["fs_metadata_json"])),
            platform=str(row["platform"]),
            timestamp_meanings=json.loads(str(row["timestamp_meanings_json"])),
            raw_timestamps=json.loads(str(row["raw_timestamps_json"])),
            utc_timestamps=self._timestamp_dict(json.loads(str(row["utc_timestamps_json"]))),
            timestamp_sources=json.loads(str(row["timestamp_sources_json"])),
            is_deleted=bool(row["is_deleted"]),
            is_readable=bool(row["is_readable"]),
            is_link=bool(row["is_link"]),
            is_traversed=bool(row["is_traversed"]),
            raw_locator=json.loads(str(row["raw_locator_json"])),
            provider_metadata=json.loads(str(row["provider_metadata_json"])),
            is_partial=bool(row["is_partial"]),
            index_revision=int(row["index_revision"]),
            created_at=parse_timestamp(str(row["created_at"])),
            updated_at=parse_timestamp(str(row["updated_at"])),
        )

    def _row_dict_to_artifact_source(self, row: dict[str, Any]) -> ArtifactSource:
        parse_status = row.get("parse_status")
        return ArtifactSource(
            source_id=str(row["source_id"]),
            job_id=row["job_id"],
            case_id=str(row["case_id"]),
            evidence_id=str(row["evidence_id"]),
            source_file_node_id=str(row["source_file_node_id"]),
            source_path=str(row["source_path"]),
            source_kind=ArtifactSourceKind(str(row["source_kind"])),
            comparison_key=str(row["comparison_key"]),
            analyzer_id=str(row["analyzer_id"]),
            analyzer_version=str(row["analyzer_version"]),
            parser_backend=str(row["parser_backend"]),
            parser_backend_version=str(row["parser_backend_version"]),
            option_fingerprint=str(row["option_fingerprint"]),
            status=str(row["status"]),
            priority=int(row["priority"]),
            source_order=int(row["source_order"]),
            is_partial=bool(row["is_partial"]),
            warning_count=int(row["warning_count"]),
            error_count=int(row["error_count"]),
            artifact_count=int(row["artifact_count"]),
            parse_status=None if parse_status is None else ArtifactParseStatus(str(parse_status)),
            last_error=None
            if row.get("last_error_json") is None
            else json.loads(str(row["last_error_json"])),
            discovered_at=parse_timestamp(str(row["discovered_at"])),
            analyzed_at=None
            if row.get("analyzed_at") is None
            else parse_timestamp(str(row["analyzed_at"])),
            updated_at=parse_timestamp(str(row["updated_at"])),
            source_fingerprint=row.get("source_fingerprint"),
            source_checkpoint={}
            if row.get("source_checkpoint_json") is None
            else dict(json.loads(str(row["source_checkpoint_json"]))),
            inspected_count=int(row.get("inspected_count") or 0),
        )

    def _row_to_provider_capability(self, row: sqlite3.Row) -> ProviderCapability:
        return ProviderCapability(
            provider_id=str(row["provider_id"]),
            provider_version=str(row["provider_version"]),
            capability_type=str(row["capability_type"]),
            is_available=bool(row["is_available"]),
            supported_inputs=list(json.loads(str(row["supported_inputs_json"]))),
            supported_outputs=list(json.loads(str(row["supported_outputs_json"]))),
            unavailable_reason=row["unavailable_reason"],
            warnings=list(json.loads(str(row["warnings_json"]))),
            metadata=dict(json.loads(str(row["metadata_json"]))),
            updated_at=parse_timestamp(str(row["updated_at"])),
        )

    def _row_to_secret_provider_capability(
        self,
        row: sqlite3.Row,
    ) -> SecretProviderCapability:
        return SecretProviderCapability(
            provider_id=str(row["provider_id"]),
            provider_version=str(row["provider_version"]),
            capability_type=str(row["capability_type"]),
            runtime_status=str(row["runtime_status"]),
            supported_key_sources=list(json.loads(str(row["supported_key_sources_json"]))),
            supported_algorithms=list(json.loads(str(row["supported_algorithms_json"]))),
            requires_host=bool(row["requires_host"]),
            requires_network=bool(row["requires_network"]),
            warnings=list(json.loads(str(row["warnings_json"]))),
            generated_at=parse_timestamp(str(row["generated_at"])),
            capability_version=str(row["capability_version"]),
        )

    def _row_to_machine_candidate(self, row: sqlite3.Row) -> MachineExtractedCandidate:
        region_json = row["region_json"]
        reviewed_at = row["reviewed_at"]
        return MachineExtractedCandidate(
            candidate_id=str(row["candidate_id"]),
            case_id=str(row["case_id"]),
            evidence_id=str(row["evidence_id"]),
            source_node_id=str(row["source_node_id"]),
            source_type=str(row["source_type"]),
            extraction_type=str(row["extraction_type"]),
            text=str(row["text"]),
            language=row["language"],
            confidence=float(row["confidence"]),
            provider_id=str(row["provider_id"]),
            provider_version=str(row["provider_version"]),
            model_id=row["model_id"],
            region=None if region_json is None else dict(json.loads(str(region_json))),
            frame_number=row["frame_number"],
            media_timestamp_ms=row["media_timestamp_ms"],
            audio_start_ms=row["audio_start_ms"],
            audio_end_ms=row["audio_end_ms"],
            raw_locator=dict(json.loads(str(row["raw_locator_json"]))),
            citations=list(json.loads(str(row["citations_json"]))),
            review_status=str(row["review_status"]),
            reviewed_by=row["reviewed_by"],
            reviewed_at=None if reviewed_at is None else parse_timestamp(str(reviewed_at)),
            correction_text=row["correction_text"],
            source_revision=int(row["source_revision"]),
            is_partial=bool(row["is_partial"]),
            created_at=parse_timestamp(str(row["created_at"])),
        )

    @staticmethod
    def _row_to_candidate_review(row: sqlite3.Row) -> CandidateReviewEvent:
        return CandidateReviewEvent(
            review_event_id=str(row["review_event_id"]),
            candidate_id=str(row["candidate_id"]),
            case_id=str(row["case_id"]),
            review_status=str(row["review_status"]),
            reviewed_by=str(row["reviewed_by"]),
            reviewed_at=parse_timestamp(str(row["reviewed_at"])),
            correction_text=row["correction_text"],
            previous_review_status=row["previous_review_status"],
            reason=row["reason"],
        )

    def _row_to_artifact(self, row: sqlite3.Row) -> ArtifactRecord:
        observed_at_utc = row["observed_at_utc"]
        return ArtifactRecord(
            artifact_id=str(row["artifact_id"]),
            case_id=str(row["case_id"]),
            evidence_id=str(row["evidence_id"]),
            source_file_node_id=str(row["source_file_node_id"]),
            artifact_type=ArtifactType(str(row["artifact_type"])),
            artifact_subtype=str(row["artifact_subtype"]),
            analyzer_id=str(row["analyzer_id"]),
            analyzer_version=str(row["analyzer_version"]),
            parser_backend=str(row["parser_backend"]),
            parser_backend_version=str(row["parser_backend_version"]),
            source_path=str(row["source_path"]),
            source_kind=ArtifactSourceKind(str(row["source_kind"])),
            observed_at_raw=row["observed_at_raw"],
            observed_at_utc=None
            if observed_at_utc is None
            else parse_timestamp(str(observed_at_utc)),
            timezone_source=row["timezone_source"],
            timezone_confidence=str(row["timezone_confidence"]),
            title=str(row["title"]),
            summary=str(row["summary"]),
            fields=json.loads(str(row["fields_json"])),
            raw_locator=json.loads(str(row["raw_locator_json"])),
            citations=json.loads(str(row["citations_json"])),
            warnings=json.loads(str(row["warnings_json"])),
            parse_status=ArtifactParseStatus(str(row["parse_status"])),
            confidence=float(row["confidence"]),
            is_partial=bool(row["is_partial"]),
            index_revision=int(row["index_revision"]),
            created_at=parse_timestamp(str(row["created_at"])),
            updated_at=parse_timestamp(str(row["updated_at"])),
            dedup_key=str(row["dedup_key"]),
            schema_version=str(row["schema_version"]),
        )

    @staticmethod
    def _row_to_artifact_coverage(row: sqlite3.Row) -> ArtifactCoverage:
        return ArtifactCoverage(
            job_id=str(row["job_id"]),
            case_id=str(row["case_id"]),
            evidence_id=str(row["evidence_id"]),
            profile_type=AnalysisProfileType(str(row["profile_type"])),
            option_fingerprint=str(row["option_fingerprint"]),
            status=ArtifactCoverageStatus(str(row["status"])),
            source_count=int(row["source_count"]),
            processed_sources=int(row["processed_sources"]),
            skipped_sources=int(row["skipped_sources"]),
            artifact_count=int(row["artifact_count"]),
            warning_count=int(row["warning_count"]),
            error_count=int(row["error_count"]),
            current_analyzer=row["current_analyzer"],
            current_source_path=row["current_source_path"],
            elapsed_seconds=float(row["elapsed_seconds"]),
            throughput_items_per_second=row["throughput_items_per_second"],
            estimated_remaining_seconds=row["estimated_remaining_seconds"],
            eta_confidence=str(row["eta_confidence"]),
            is_partial=bool(row["is_partial"]),
            index_revision=int(row["index_revision"]),
            created_at=parse_timestamp(str(row["created_at"])),
            updated_at=parse_timestamp(str(row["updated_at"])),
        )

    @staticmethod
    def _row_to_coverage(row: sqlite3.Row) -> IndexCoverage:
        return IndexCoverage(
            case_id=str(row["case_id"]),
            evidence_id=str(row["evidence_id"]),
            provider_id=str(row["provider_id"]),
            provider_version=str(row["provider_version"]),
            profile_type=AnalysisProfileType(str(row["profile_type"])),
            option_fingerprint=str(row["option_fingerprint"]),
            status=IndexCoverageStatus(str(row["status"])),
            discovered_items=int(row["discovered_items"]),
            processed_items=int(row["processed_items"]),
            skipped_items=int(row["skipped_items"]),
            warning_count=int(row["warning_count"]),
            error_count=int(row["error_count"]),
            current_path=row["current_path"],
            elapsed_seconds=float(row["elapsed_seconds"]),
            throughput_items_per_second=row["throughput_items_per_second"],
            estimated_remaining_seconds=row["estimated_remaining_seconds"],
            eta_confidence=str(row["eta_confidence"]),
            index_revision=int(row["index_revision"]),
            job_id=row["job_id"],
            created_at=parse_timestamp(str(row["created_at"])),
            updated_at=parse_timestamp(str(row["updated_at"])),
        )

    def _row_to_search_query(self, row: sqlite3.Row) -> SearchQuery:
        created_at = parse_timestamp(str(row["created_at"]))
        return SearchQuery(
            query_id=str(row["query_id"]),
            query_text=str(row["query_text"]),
            query_mode=SearchQueryMode(str(row["query_mode"])),
            case_id=str(row["case_id"]),
            evidence_ids=tuple(str(item) for item in json.loads(str(row["evidence_ids_json"]))),
            source_types=tuple(
                SearchSourceType(str(item)) for item in json.loads(str(row["source_types_json"]))
            ),
            document_types=tuple(
                SearchDocumentType(str(item))
                for item in json.loads(str(row["document_types_json"]))
            ),
            time_range=json.loads(str(row["time_range_json"])),
            path_scope=row["path_scope"],
            filters=json.loads(str(row["filters_json"])),
            keyword_set_id=row["keyword_set_id"],
            keyword_set_version=row["keyword_set_version"],
            index_revision=row["index_revision"],
            options_fingerprint=str(row["options_fingerprint"]),
            created_at=created_at,
            sort=str(row["sort"]),
            limit=int(row["limit_value"]),
            case_sensitive=bool(row["case_sensitive"]),
        )

    def _row_to_search_execution(self, row: sqlite3.Row) -> SearchExecution:
        completed = row["completed_at"]
        return SearchExecution(
            execution_id=str(row["execution_id"]),
            query_id=str(row["query_id"]),
            case_id=str(row["case_id"]),
            query_text=str(row["query_text"]),
            query_mode=SearchQueryMode(str(row["query_mode"])),
            keyword_set_id=row["keyword_set_id"],
            keyword_set_version=row["keyword_set_version"],
            options=json.loads(str(row["options_json"])),
            options_fingerprint=str(row["options_fingerprint"]),
            search_backend=str(row["search_backend"]),
            search_backend_version=str(row["search_backend_version"]),
            index_revision=int(row["index_revision"]),
            source_revision_fingerprint=str(row["source_revision_fingerprint"]),
            started_at=parse_timestamp(str(row["started_at"])),
            completed_at=None if completed is None else parse_timestamp(str(completed)),
            status=str(row["status"]),
            is_partial=bool(row["is_partial"]),
            result_count=int(row["result_count"]),
            warnings=json.loads(str(row["warnings_json"])),
            cache_key=row["cache_key"],
            cache_hit=bool(row["cache_hit"]),
            zero_result_keyword_ids=json.loads(str(row["zero_result_keyword_ids_json"])),
            execution_revision=int(row["execution_revision"]),
        )

    def _row_to_search_result(self, row: sqlite3.Row) -> SearchResult:
        return SearchResult(
            result_id=str(row["result_id"]),
            query_id=str(row["query_id"]),
            document_id=str(row["document_id"]),
            source_type=SearchSourceType(str(row["source_type"])),
            source_id=str(row["source_id"]),
            rank=float(row["rank"]),
            matched_fields=json.loads(str(row["matched_fields_json"])),
            matched_terms=json.loads(str(row["matched_terms_json"])),
            snippet=str(row["snippet"]),
            raw_locator=json.loads(str(row["raw_locator_json"])),
            citations=json.loads(str(row["citations_json"])),
            is_partial=bool(row["is_partial"]),
            index_revision=int(row["index_revision"]),
            created_at=parse_timestamp(str(row["created_at"])),
        )

    def _row_to_search_cache(self, row: sqlite3.Row) -> SearchCacheEntry:
        expires_at = row["expires_at"]
        invalidated_at = row["invalidated_at"]
        return SearchCacheEntry(
            cache_key=str(row["cache_key"]),
            case_id=str(row["case_id"]),
            query_fingerprint=str(row["query_fingerprint"]),
            keyword_set_version=row["keyword_set_version"],
            index_revision=int(row["index_revision"]),
            source_revision_fingerprint=str(row["source_revision_fingerprint"]),
            is_partial=bool(row["is_partial"]),
            result_count=int(row["result_count"]),
            results=json.loads(str(row["results_json"])),
            created_at=parse_timestamp(str(row["created_at"])),
            expires_at=None if expires_at is None else parse_timestamp(str(expires_at)),
            hit_count=int(row["hit_count"]),
            invalidated_at=None if invalidated_at is None else parse_timestamp(str(invalidated_at)),
        )

    def _row_to_keyword_set(self, row: sqlite3.Row) -> KeywordSet:
        version_id = str(row["keyword_set_version_id"])
        keyword_rows = self.connection.execute(
            """
            SELECT * FROM keywords
            WHERE keyword_set_version_id = ?
            ORDER BY created_at, keyword_id
            """,
            (version_id,),
        ).fetchall()
        return KeywordSet(
            keyword_set_id=str(row["keyword_set_id"]),
            keyword_set_version_id=version_id,
            case_id=str(row["case_id"]),
            name=str(row["name"]),
            description=row["description"],
            version=int(row["version"]),
            status=KeywordSetStatus(str(row["status"])),
            created_by=row["created_by"],
            created_at=parse_timestamp(str(row["created_at"])),
            updated_at=parse_timestamp(str(row["updated_at"])),
            keywords=[self._row_to_keyword(item) for item in keyword_rows],
            default_options=json.loads(str(row["default_options_json"])),
            previous_version_id=row["previous_version_id"],
        )

    @staticmethod
    def _row_to_keyword(row: sqlite3.Row) -> Keyword:
        return Keyword(
            keyword_id=str(row["keyword_id"]),
            term=str(row["term"]),
            keyword_type=KeywordType(str(row["keyword_type"])),
            match_mode=KeywordMatchMode(str(row["match_mode"])),
            case_sensitive=bool(row["case_sensitive"]),
            enabled=bool(row["enabled"]),
            notes=row["notes"],
            source=str(row["source"]),
            created_at=parse_timestamp(str(row["created_at"])),
        )

    def _row_to_timeline_event(self, row: sqlite3.Row) -> TimelineEvent:
        normalized = row["normalized_utc"]
        return TimelineEvent(
            timeline_event_id=str(row["timeline_event_id"]),
            case_id=str(row["case_id"]),
            evidence_id=str(row["evidence_id"]),
            source_type=TimelineSourceType(str(row["source_type"])),
            source_id=str(row["source_id"]),
            source_revision=int(row["source_revision"]),
            event_type=TimelineEventType(str(row["event_type"])),
            event_subtype=str(row["event_subtype"]),
            title=str(row["title"]),
            description=str(row["description"]),
            raw_timestamp=row["raw_timestamp"],
            raw_timezone=row["raw_timezone"],
            timestamp_semantics=str(row["timestamp_semantics"]),
            normalized_utc=None if normalized is None else parse_timestamp(str(normalized)),
            case_timezone=str(row["case_timezone"]),
            displayed_case_time=row["displayed_case_time"],
            timezone_source=TimezoneSource(str(row["timezone_source"])),
            timezone_confidence=TimezoneConfidence(str(row["timezone_confidence"])),
            precision=TimestampPrecision(str(row["precision"])),
            analyzer_id=row["analyzer_id"],
            analyzer_version=row["analyzer_version"],
            raw_locator=json.loads(str(row["raw_locator_json"])),
            citations=json.loads(str(row["citations_json"])),
            fields=json.loads(str(row["fields_json"])),
            is_partial=bool(row["is_partial"]),
            timeline_revision=int(row["timeline_revision"]),
            created_at=parse_timestamp(str(row["created_at"])),
            dedup_key=str(row["dedup_key"]),
        )

    @staticmethod
    def _row_to_timeline_coverage(row: sqlite3.Row) -> TimelineBuildCoverage:
        return TimelineBuildCoverage(
            job_id=str(row["job_id"]),
            case_id=str(row["case_id"]),
            evidence_id=row["evidence_id"],
            status=str(row["status"]),
            discovered_items=int(row["discovered_items"]),
            processed_items=int(row["processed_items"]),
            skipped_items=int(row["skipped_items"]),
            event_count=int(row["event_count"]),
            warning_count=int(row["warning_count"]),
            error_count=int(row["error_count"]),
            current_source=row["current_source"],
            is_partial=bool(row["is_partial"]),
            timeline_revision=int(row["timeline_revision"]),
            created_at=parse_timestamp(str(row["created_at"])),
            updated_at=parse_timestamp(str(row["updated_at"])),
        )

    def _case_values(self, case: Case) -> tuple[Any, ...]:
        return (
            case.case_id,
            case.name,
            case.description,
            case.investigator,
            case.locale,
            case.timezone,
            case.status.value,
            to_json_timestamp(case.created_at),
            to_json_timestamp(case.updated_at),
            case.schema_version,
            self._json(case.metadata),
        )

    def _evidence_values(self, evidence: Evidence) -> tuple[Any, ...]:
        return (
            evidence.evidence_id,
            evidence.case_id,
            evidence.display_name,
            str(evidence.source_path),
            evidence.evidence_type.value,
            evidence.size_bytes,
            evidence.status.value,
            int(evidence.read_only),
            self._fingerprint_json(evidence.fingerprint),
            to_json_timestamp(evidence.created_at),
            to_json_timestamp(evidence.updated_at),
            evidence.schema_version,
            self._json(evidence.metadata),
        )

    def _evidence_volume_values(self, volume: EvidenceVolume) -> tuple[Any, ...]:
        return (
            volume.volume_id,
            volume.case_id,
            volume.evidence_id,
            volume.reader_id,
            volume.reader_version,
            volume.volume_index,
            volume.scheme,
            volume.partition_type,
            volume.start_lba,
            volume.end_lba,
            volume.byte_offset,
            volume.byte_length,
            volume.sector_size,
            volume.name,
            volume.guid,
            int(volume.is_allocated),
            self._json(volume.raw_locator),
            self._json(volume.warnings),
            to_json_timestamp(volume.created_at),
            self._json(volume.to_schema_dict()),
        )

    def _job_values(self, job: Job) -> tuple[Any, ...]:
        return (
            job.job_id,
            job.case_id,
            job.evidence_id,
            job.job_type.value,
            job.status.value,
            self._json(self._progress_dict(job.progress)),
            to_json_timestamp(job.queued_at),
            self._nullable_timestamp(job.started_at),
            self._nullable_timestamp(job.finished_at),
            self._nullable_timestamp(job.cancel_requested_at),
            self._json(job.warnings),
            self._json(job.errors),
            job.profile_id,
            job.priority,
            int(job.checkpoint_available),
            job.job_revision,
            job.index_revision,
        )

    @staticmethod
    def _progress_dict(progress: JobProgress) -> dict[str, Any]:
        return {
            "current": progress.current,
            "total": progress.total,
            "unit": progress.unit.value,
            "processed_items": progress.processed_items,
            "estimated_total_items": progress.estimated_total_items,
            "progress_percent": progress.progress_percent,
            "throughput_items_per_second": progress.throughput_items_per_second,
            "elapsed_seconds": progress.elapsed_seconds,
            "estimated_remaining_seconds": progress.estimated_remaining_seconds,
            "estimate_confidence": progress.estimate_confidence,
            "current_analyzer": progress.current_analyzer,
            "worker_count": progress.worker_count,
            "cache_hits": progress.cache_hits,
            "cache_misses": progress.cache_misses,
            "partial_results_available": progress.partial_results_available,
            "discovered_items": progress.discovered_items,
            "skipped_items": progress.skipped_items,
            "warning_count": progress.warning_count,
            "error_count": progress.error_count,
            "current_path": progress.current_path,
        }

    def _row_to_case(self, row: sqlite3.Row) -> Case:
        return Case(
            case_id=str(row["case_id"]),
            name=str(row["name"]),
            description=row["description"],
            investigator=row["investigator"],
            locale=str(row["locale"]),
            timezone=str(row["timezone"]),
            status=CaseStatus(str(row["status"])),
            created_at=parse_timestamp(str(row["created_at"])),
            updated_at=parse_timestamp(str(row["updated_at"])),
            schema_version=str(row["schema_version"]),
            metadata=json.loads(str(row["metadata_json"])),
        )

    def _row_to_evidence(self, row: sqlite3.Row) -> Evidence:
        fingerprint_json = row["fingerprint_json"]
        fingerprint = None
        if fingerprint_json is not None:
            data = json.loads(str(fingerprint_json))
            fingerprint = EvidenceFingerprint(
                algorithm=HashAlgorithm(str(data["algorithm"])),
                value=str(data["value"]),
                size_bytes=int(data["size_bytes"]),
                reader_id=str(data["reader_id"]),
                reader_version=str(data["reader_version"]),
                created_at=parse_timestamp(str(data["created_at"])),
            )
        evidence_id = str(row["evidence_id"])
        hashes = self._list_hash_records(evidence_id)
        return Evidence(
            evidence_id=evidence_id,
            case_id=str(row["case_id"]),
            display_name=str(row["display_name"]),
            source_path=Path(str(row["source_path"])),
            evidence_type=EvidenceFormat(str(row["evidence_type"])),
            size_bytes=int(row["size_bytes"]),
            status=EvidenceStatus(str(row["status"])),
            read_only=bool(row["read_only"]),
            fingerprint=fingerprint,
            created_at=parse_timestamp(str(row["created_at"])),
            updated_at=parse_timestamp(str(row["updated_at"])),
            schema_version=str(row["schema_version"]),
            hashes=hashes,
            metadata=json.loads(str(row["metadata_json"])),
        )

    def _row_to_evidence_volume(self, row: sqlite3.Row) -> EvidenceVolume:
        return EvidenceVolume(
            volume_id=str(row["volume_id"]),
            case_id=str(row["case_id"]),
            evidence_id=str(row["evidence_id"]),
            volume_index=int(row["volume_index"]),
            scheme=str(row["scheme"]),
            partition_type=str(row["partition_type"]),
            start_lba=int(row["start_lba"]),
            end_lba=int(row["end_lba"]),
            byte_offset=int(row["byte_offset"]),
            byte_length=int(row["byte_length"]),
            sector_size=int(row["sector_size"]),
            is_allocated=bool(row["is_allocated"]),
            raw_locator=json.loads(str(row["raw_locator_json"])),
            reader_id=str(row["reader_id"]),
            reader_version=str(row["reader_version"]),
            created_at=parse_timestamp(str(row["created_at"])),
            name=row["name"],
            guid=row["guid"],
            warnings=list(json.loads(str(row["warnings_json"]))),
        )

    def _list_hash_records(self, evidence_id: str) -> list[HashRecord]:
        rows = self.connection.execute(
            """
            SELECT * FROM evidence_hashes
            WHERE evidence_id = ?
            ORDER BY calculated_at, hash_id
            """,
            (evidence_id,),
        ).fetchall()
        return [self._row_to_hash_record(row) for row in rows]

    @staticmethod
    def _row_to_hash_record(row: sqlite3.Row) -> HashRecord:
        return HashRecord(
            hash_id=str(row["hash_id"]),
            evidence_id=str(row["evidence_id"]),
            algorithm=HashAlgorithm(str(row["algorithm"])),
            digest=str(row["digest"]),
            calculated_at=parse_timestamp(str(row["calculated_at"])),
            file_size=int(row["file_size"]),
            chunk_size=int(row["chunk_size"]),
            verified=bool(row["verified"]),
            verification_status=str(row["verification_status"]),
            bytes_hashed=int(row["bytes_hashed"]),
            started_at=parse_timestamp(str(row["started_at"])),
            completed_at=parse_timestamp(str(row["completed_at"])),
            job_id=row["job_id"],
        )

    @staticmethod
    def _row_to_hash_verification(row: sqlite3.Row) -> HashVerification:
        return HashVerification(
            {
                "id": str(row["verification_id"]),
                "case_id": str(row["case_id"]),
                "evidence_id": str(row["evidence_id"]),
                "algorithm": str(row["algorithm"]),
                "expected_digest": str(row["expected_digest"]),
                "observed_digest": row["observed_digest"],
                "status": str(row["status"]),
                "verified_at": str(row["verified_at"]),
                "tool_version": str(row["tool_version"]),
                "job_id": row["job_id"],
                "custody_event_id": row["custody_event_id"],
                "error": json.loads(row["error_json"]) if row["error_json"] else None,
            }
        )

    @staticmethod
    def _row_to_job(row: sqlite3.Row) -> Job:
        data = json.loads(str(row["progress_json"]))
        progress = JobProgress(
            current=int(data.get("current", 0)),
            total=data.get("total"),
            unit=ProgressUnit(str(data.get("unit", ProgressUnit.UNKNOWN.value))),
            processed_items=int(data.get("processed_items", 0)),
            estimated_total_items=data.get("estimated_total_items"),
            progress_percent=data.get("progress_percent"),
            throughput_items_per_second=data.get("throughput_items_per_second"),
            elapsed_seconds=float(data.get("elapsed_seconds", 0.0)),
            estimated_remaining_seconds=data.get("estimated_remaining_seconds"),
            estimate_confidence=str(data.get("estimate_confidence", "UNKNOWN")),
            current_analyzer=data.get("current_analyzer"),
            worker_count=int(data.get("worker_count", 0)),
            cache_hits=int(data.get("cache_hits", 0)),
            cache_misses=int(data.get("cache_misses", 0)),
            partial_results_available=bool(data.get("partial_results_available", False)),
            discovered_items=int(data.get("discovered_items", 0)),
            skipped_items=int(data.get("skipped_items", 0)),
            warning_count=int(data.get("warning_count", 0)),
            error_count=int(data.get("error_count", 0)),
            current_path=data.get("current_path"),
        )
        return Job(
            job_id=str(row["job_id"]),
            case_id=str(row["case_id"]),
            evidence_id=row["evidence_id"],
            job_type=JobType(str(row["job_type"])),
            status=JobStatus(str(row["status"])),
            progress=progress,
            queued_at=parse_timestamp(str(row["queued_at"])),
            started_at=None
            if row["started_at"] is None
            else parse_timestamp(str(row["started_at"])),
            finished_at=None
            if row["finished_at"] is None
            else parse_timestamp(str(row["finished_at"])),
            cancel_requested_at=None
            if row["cancel_requested_at"] is None
            else parse_timestamp(str(row["cancel_requested_at"])),
            warnings=json.loads(str(row["warnings_json"])),
            errors=json.loads(str(row["errors_json"])),
            profile_id=row["profile_id"],
            priority=int(row["priority"]),
            checkpoint_available=bool(row["checkpoint_available"]),
            job_revision=int(row["job_revision"]),
            index_revision=row["index_revision"],
        )
