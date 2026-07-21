"""SQLite repository adapter for Phase 1."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

from apex_forensic._time import parse_timestamp, to_json_timestamp, utc_now
from apex_forensic.domain.enums import (
    CaseStatus,
    EvidenceFormat,
    EvidenceStatus,
    HashAlgorithm,
    JobStatus,
    JobType,
    ProgressUnit,
)
from apex_forensic.domain.models import (
    Case,
    CustodyEvent,
    Evidence,
    EvidenceFingerprint,
    HashRecord,
    HashVerification,
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
                    checkpoint_available INTEGER NOT NULL
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
            self.connection.execute(
                """
                INSERT OR IGNORE INTO schema_migrations(version, applied_at)
                VALUES (?, ?)
                """,
                ("phase1-core-foundation", to_json_timestamp(utc_now())),
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
                    errors_json, profile_id, priority, checkpoint_available
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                    priority = ?, checkpoint_available = ?
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
        )
