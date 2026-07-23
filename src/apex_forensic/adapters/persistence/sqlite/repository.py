"""SQLite repository adapter for Phase 1."""

from __future__ import annotations

import base64
import json
import re
import sqlite3
from pathlib import Path
from typing import Any
from uuid import uuid4

from apex_forensic._time import parse_timestamp, to_json_timestamp, utc_now
from apex_forensic.domain.enums import (
    AnalysisProfileType,
    ArtifactCoverageStatus,
    ArtifactParseStatus,
    ArtifactSourceKind,
    ArtifactType,
    CaseStatus,
    EvidenceFormat,
    EvidenceStatus,
    FileSystemNodeType,
    HashAlgorithm,
    IndexCoverageStatus,
    JobStatus,
    JobType,
    KeywordMatchMode,
    KeywordSetStatus,
    KeywordType,
    ProgressUnit,
    SearchDocumentType,
    SearchQueryMode,
    SearchSourceType,
    TimelineEventType,
    TimelineSourceType,
    TimestampPrecision,
    TimezoneConfidence,
    TimezoneSource,
)
from apex_forensic.domain.models import (
    ArtifactCapability,
    ArtifactCoverage,
    ArtifactQuery,
    ArtifactRecord,
    ArtifactSource,
    Case,
    CustodyEvent,
    Evidence,
    EvidenceFingerprint,
    FileSystemNode,
    HashRecord,
    HashVerification,
    IndexCoverage,
    Job,
    JobProgress,
    Keyword,
    KeywordSet,
    SearchCacheEntry,
    SearchDocument,
    SearchExecution,
    SearchIndexCapability,
    SearchQuery,
    SearchResult,
    TimelineBuildCoverage,
    TimelineEvent,
    TimelineQuery,
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
    return SearchDocumentType.OTHER


def _timeline_source_artifact_types(source_type: str) -> list[str]:
    if source_type == TimelineSourceType.EVENT_LOG_ARTIFACT.value:
        return [ArtifactType.EVENT_LOG_RECORD.value]
    if source_type == TimelineSourceType.PREFETCH_ARTIFACT.value:
        return [ArtifactType.PREFETCH_EXECUTION.value]
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
        self.connection = sqlite3.connect(str(db_path))
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
                """
            )
            self._ensure_column("jobs", "job_revision", "INTEGER NOT NULL DEFAULT 1")
            self._ensure_column("jobs", "index_revision", "INTEGER")
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
        with self.connection:
            self.connection.execute(
                """
                INSERT INTO hash_verifications (
                    verification_id, evidence_id, algorithm, expected_digest,
                    observed_digest, status, verified_at, tool_version, job_id,
                    custody_event_id, error_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    data["id"],
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
                    parser_backend, parser_backend_version, option_fingerprint, status,
                    priority, source_order, is_partial, warning_count, error_count,
                    artifact_count, parse_status, last_error_json, discovered_at,
                    analyzed_at, updated_at
                ) VALUES (
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                    ?, ?, ?, ?, ?
                )
                ON CONFLICT(source_id) DO UPDATE SET
                    job_id = excluded.job_id,
                    status = excluded.status,
                    priority = excluded.priority,
                    source_order = excluded.source_order,
                    is_partial = excluded.is_partial,
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
    ) -> None:
        """Persist final source queue state."""

        with self.connection:
            self.connection.execute(
                """
                UPDATE artifact_sources
                SET status = ?, parse_status = ?, warning_count = ?, error_count = ?,
                    artifact_count = ?, last_error_json = ?, analyzed_at = ?, updated_at = ?
                WHERE source_id = ?
                """,
                (
                    status,
                    parse_status,
                    warning_count,
                    error_count,
                    artifact_count,
                    self._json(last_error) if last_error is not None else None,
                    analyzed_at,
                    to_json_timestamp(utc_now()),
                    source_id,
                ),
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
    ) -> bool:
        """Return whether the same source/analyzer/options already completed."""

        row = self.connection.execute(
            """
            SELECT 1
            FROM artifact_sources
            WHERE evidence_id = ?
              AND source_file_node_id = ?
              AND analyzer_id = ?
              AND analyzer_version = ?
              AND option_fingerprint = ?
              AND status IN ('SUCCEEDED', 'PARTIAL')
            LIMIT 1
            """,
            (
                evidence_id,
                source_file_node_id,
                analyzer_id,
                analyzer_version,
                option_fingerprint,
            ),
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
        return inserted

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
            tokenizer="unicode61",
            capabilities=[
                "METADATA_SEARCH",
                "ARTIFACT_FIELD_SEARCH",
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
        for source_type in (
            SearchSourceType.FILE_SYSTEM_NODE.value,
            SearchSourceType.WINDOWS_ARTIFACT.value,
            SearchSourceType.TIMELINE_EVENT.value,
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
            }
        rows: list[dict[str, Any]] = []
        for source_type in (
            TimelineSourceType.FILE_SYSTEM_NODE.value,
            TimelineSourceType.REGISTRY_ARTIFACT.value,
            TimelineSourceType.EVENT_LOG_ARTIFACT.value,
            TimelineSourceType.PREFETCH_ARTIFACT.value,
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
            clauses.append(
                "source_type IN (" + ", ".join("?" for _ in query.source_types) + ")"
            )
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
        except sqlite3.Error:
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
            "normalized_path": None
            if row["path_key"] is None
            else str(row["path_key"]),
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
                SearchSourceType(str(item))
                for item in json.loads(str(row["source_types_json"]))
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
            invalidated_at=None
            if invalidated_at is None
            else parse_timestamp(str(invalidated_at)),
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
