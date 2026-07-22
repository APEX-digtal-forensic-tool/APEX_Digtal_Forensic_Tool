"""SQLite repository adapter for Phase 1."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any
from uuid import uuid4

from apex_forensic._time import parse_timestamp, to_json_timestamp, utc_now
from apex_forensic.domain.enums import (
    AnalysisProfileType,
    CaseStatus,
    EvidenceFormat,
    EvidenceStatus,
    FileSystemNodeType,
    HashAlgorithm,
    IndexCoverageStatus,
    JobStatus,
    JobType,
    ProgressUnit,
)
from apex_forensic.domain.models import (
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
)


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
