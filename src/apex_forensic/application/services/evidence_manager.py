"""Evidence registration, hashing, and integrity verification service."""

from __future__ import annotations

import logging
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING, Any

from apex_forensic._time import to_json_timestamp
from apex_forensic.adapters.evidence import (
    EwfEvidenceReader,
    RawImageReader,
    VirtualDiskEvidenceReader,
)
from apex_forensic.constants import DEFAULT_HASH_CHUNK_SIZE, ENGINE_VERSION, SCHEMA_VERSION
from apex_forensic.domain.enums import (
    CustodyEventType,
    EvidenceFormat,
    EvidenceStatus,
    HashAlgorithm,
    HashVerificationStatus,
    JobStatus,
    JobType,
    ProgressUnit,
)
from apex_forensic.domain.errors import (
    ApexError,
    NotFoundError,
    OperationCancelledError,
    UnsupportedCapabilityError,
    ValidationError,
)
from apex_forensic.domain.models import (
    Evidence,
    EvidenceFingerprint,
    HashRecord,
    HashVerification,
    Job,
    JobProgress,
)
from apex_forensic.jobs.cancellation import CancellationToken
from apex_forensic.jobs.progress import HashProgress
from apex_forensic.ports.case_repository import CaseRepository
from apex_forensic.ports.clock import Clock
from apex_forensic.ports.evidence_repository import EvidenceRepository
from apex_forensic.ports.hash_provider import HashProvider
from apex_forensic.ports.id_generator import IdGenerator

if TYPE_CHECKING:
    from apex_forensic.application.services.custody_ledger import CustodyLedger

LOGGER = logging.getLogger(__name__)


class EvidenceManager:
    """Coordinates Phase 1 evidence use cases."""

    def __init__(
        self,
        case_repository: CaseRepository,
        evidence_repository: EvidenceRepository,
        hash_provider: HashProvider,
        clock: Clock,
        id_generator: IdGenerator,
        custody_ledger: CustodyLedger | None = None,
    ) -> None:
        self._case_repository = case_repository
        self._evidence_repository = evidence_repository
        self._hash_provider = hash_provider
        self._clock = clock
        self._id_generator = id_generator
        self._custody_ledger = custody_ledger

    def register_evidence(
        self,
        *,
        case_id: str,
        source_path: Path,
        display_name: str | None = None,
    ) -> Evidence:
        """Register a file or directory evidence source without modifying it."""

        case = self._case_repository.get_case(case_id)
        if case is None:
            raise NotFoundError("CASE_NOT_FOUND", f"Case not found: {case_id}", target="case_id")
        normalized = self._normalize_source_path(source_path)
        stat_result = normalized.stat()
        evidence_type = self._detect_evidence_format(normalized)
        reader_id, reader_version, capabilities, reader_metadata = self._reader_metadata(
            normalized, evidence_type
        )
        fingerprint = None
        if evidence_type is not EvidenceFormat.DIRECTORY:
            if evidence_type in {EvidenceFormat.RAW, EvidenceFormat.DD, EvidenceFormat.IMG}:
                with RawImageReader(normalized, evidence_format=evidence_type) as reader:
                    source_fingerprint = reader.source_fingerprint
                computation_digest = str(source_fingerprint["sha256"])
                size_value = source_fingerprint["size_bytes"]
                if not isinstance(size_value, int):
                    raise ValidationError(
                        "Evidence reader returned an invalid fingerprint size.",
                        target="fingerprint",
                    )
                computation_size = size_value
                completed_at = self._clock.now()
            else:
                computation = self._hash_provider.compute_file(
                    normalized,
                    [HashAlgorithm.SHA256],
                    chunk_size=DEFAULT_HASH_CHUNK_SIZE,
                )
                computation_digest = computation.digests[HashAlgorithm.SHA256]
                computation_size = computation.file_size
                completed_at = computation.completed_at
            fingerprint = EvidenceFingerprint(
                algorithm=HashAlgorithm.SHA256,
                value=computation_digest,
                size_bytes=computation_size,
                reader_id=reader_id,
                reader_version=reader_version,
                created_at=completed_at,
            )

        now = self._clock.now()
        evidence = Evidence(
            evidence_id=self._id_generator.new_id(),
            case_id=case_id,
            display_name=display_name or normalized.name or str(normalized),
            source_path=normalized,
            evidence_type=evidence_type,
            size_bytes=stat_result.st_size,
            status=EvidenceStatus.REGISTERED,
            read_only=True,
            fingerprint=fingerprint,
            created_at=now,
            updated_at=now,
            schema_version=SCHEMA_VERSION,
            metadata={
                "reader_id": reader_id,
                "reader_version": reader_version,
                "capabilities": capabilities,
                "source_path_policy": "NO_SYMLINK_FOLLOW",
                **reader_metadata,
            },
        )
        self._evidence_repository.save_evidence(evidence)
        if self._custody_ledger is not None:
            self._custody_ledger.add_event(
                evidence_id=evidence.evidence_id,
                event_type=CustodyEventType.RECEIVED,
                actor_name=case.investigator or "SYSTEM",
                action="Evidence registered",
                source_location=str(normalized),
                notes="Phase 1 metadata registration; original evidence was not modified.",
            )
        return evidence

    def get_evidence(self, evidence_id: str) -> Evidence:
        """Return one evidence row."""

        evidence = self._evidence_repository.get_evidence(evidence_id)
        if evidence is None:
            raise NotFoundError(
                "EVIDENCE_NOT_FOUND",
                f"Evidence not found: {evidence_id}",
                target="evidence_id",
            )
        return evidence

    def list_evidence(self, case_id: str) -> list[Evidence]:
        """Return evidence rows for a case."""

        if self._case_repository.get_case(case_id) is None:
            raise NotFoundError("CASE_NOT_FOUND", f"Case not found: {case_id}", target="case_id")
        return self._evidence_repository.list_evidence_for_case(case_id)

    def calculate_hash(
        self,
        *,
        evidence_id: str,
        algorithm: HashAlgorithm,
        chunk_size: int = DEFAULT_HASH_CHUNK_SIZE,
        progress_callback: Callable[[HashProgress], None] | None = None,
        cancellation_token: CancellationToken | None = None,
    ) -> tuple[HashRecord, Job]:
        """Run a streaming hash job and persist the result."""

        evidence = self.get_evidence(evidence_id)
        self._ensure_hash_supported(evidence)
        job = self._create_job(evidence, JobType.HASH, ProgressUnit.BYTES)
        self._evidence_repository.save_job(job)
        evidence.status = EvidenceStatus.HASHING
        evidence.updated_at = self._clock.now()
        self._evidence_repository.update_evidence(evidence)

        def update_progress(progress: HashProgress) -> None:
            job.progress.current = progress.processed_bytes
            job.progress.total = progress.total_bytes
            job.progress.processed_items = progress.processed_bytes
            job.progress.estimated_total_items = progress.total_bytes
            job.progress.progress_percent = progress.progress_percent
            self._evidence_repository.update_job(job)
            if progress_callback is not None:
                progress_callback(progress)

        try:
            job.status = JobStatus.RUNNING
            job.started_at = self._clock.now()
            self._evidence_repository.update_job(job)
            computation = self._hash_provider.compute_file(
                evidence.source_path,
                [algorithm],
                chunk_size=chunk_size,
                progress_callback=update_progress,
                cancellation_token=cancellation_token,
            )
            record = HashRecord(
                hash_id=self._id_generator.new_id(),
                evidence_id=evidence_id,
                algorithm=algorithm,
                digest=computation.digests[algorithm],
                calculated_at=computation.completed_at,
                file_size=computation.file_size,
                chunk_size=computation.chunk_size,
                verified=False,
                verification_status=HashVerificationStatus.NOT_CHECKED.value,
                bytes_hashed=computation.bytes_hashed,
                started_at=computation.started_at,
                completed_at=computation.completed_at,
                job_id=job.job_id,
            )
            self._evidence_repository.save_hash_record(record)
            evidence.status = EvidenceStatus.READY
            evidence.updated_at = self._clock.now()
            self._evidence_repository.update_evidence(evidence)
            job.status = JobStatus.SUCCEEDED
            job.finished_at = self._clock.now()
            job.progress.progress_percent = 100.0
            job.progress.current = computation.bytes_hashed
            job.progress.total = computation.file_size
            job.progress.processed_items = computation.bytes_hashed
            job.progress.estimated_total_items = computation.file_size
            self._evidence_repository.update_job(job)
            return record, job
        except OperationCancelledError:
            job.status = JobStatus.CANCELLED
            job.finished_at = self._clock.now()
            self._evidence_repository.update_job(job)
            raise
        except ApexError as error:
            job.status = JobStatus.FAILED
            job.finished_at = self._clock.now()
            job.errors.append(error.to_api_error())
            evidence.status = EvidenceStatus.FAILED
            evidence.updated_at = self._clock.now()
            self._evidence_repository.update_evidence(evidence)
            self._evidence_repository.update_job(job)
            raise

    def verify_evidence(
        self,
        *,
        evidence_id: str,
        algorithm: HashAlgorithm = HashAlgorithm.SHA256,
        chunk_size: int = DEFAULT_HASH_CHUNK_SIZE,
        progress_callback: Callable[[HashProgress], None] | None = None,
        cancellation_token: CancellationToken | None = None,
    ) -> tuple[HashVerification, Job]:
        """Compare a stored hash to a freshly calculated streaming hash."""

        evidence = self.get_evidence(evidence_id)
        self._ensure_hash_supported(evidence)
        expected = self._evidence_repository.latest_hash_record(evidence_id, algorithm)
        if expected is None:
            raise ValidationError(
                "No stored hash exists for verification.",
                target="algorithm",
                details={"algorithm": algorithm.value},
            )
        job = self._create_job(evidence, JobType.VERIFY, ProgressUnit.BYTES)
        self._evidence_repository.save_job(job)

        def update_progress(progress: HashProgress) -> None:
            job.progress.current = progress.processed_bytes
            job.progress.total = progress.total_bytes
            job.progress.processed_items = progress.processed_bytes
            job.progress.estimated_total_items = progress.total_bytes
            job.progress.progress_percent = progress.progress_percent
            self._evidence_repository.update_job(job)
            if progress_callback is not None:
                progress_callback(progress)

        try:
            job.status = JobStatus.RUNNING
            job.started_at = self._clock.now()
            self._evidence_repository.update_job(job)
            computation = self._hash_provider.compute_file(
                evidence.source_path,
                [algorithm],
                chunk_size=chunk_size,
                progress_callback=update_progress,
                cancellation_token=cancellation_token,
            )
            observed_digest = computation.digests[algorithm]
            status = (
                HashVerificationStatus.MATCH
                if observed_digest == expected.digest
                else HashVerificationStatus.MISMATCH
            )
            verification_data: dict[str, Any] = {
                "id": self._id_generator.new_id(),
                "evidence_id": evidence_id,
                "case_id": evidence.case_id,
                "algorithm": algorithm.value,
                "expected_digest": expected.digest,
                "observed_digest": observed_digest,
                "status": status.value,
                "verified_at": to_json_timestamp(computation.completed_at),
                "tool_version": ENGINE_VERSION,
                "job_id": job.job_id,
                "custody_event_id": None,
                "error": None,
            }
            custody_event_id = self._append_hash_verified_event(
                evidence=evidence,
                algorithm=algorithm,
                expected_digest=expected.digest,
                observed_digest=observed_digest,
                status=status,
            )
            verification_data["custody_event_id"] = custody_event_id
            verification = HashVerification(verification_data)
            self._evidence_repository.save_hash_verification(verification)
            self._evidence_repository.mark_hash_record_verified(expected.hash_id, status.value)
            job.status = JobStatus.SUCCEEDED
            job.finished_at = self._clock.now()
            job.progress.progress_percent = 100.0
            job.progress.current = computation.bytes_hashed
            job.progress.total = computation.file_size
            job.progress.processed_items = computation.bytes_hashed
            job.progress.estimated_total_items = computation.file_size
            if status is HashVerificationStatus.MISMATCH:
                job.warnings.append(
                    {
                        "code": "HASH_MISMATCH",
                        "message_key": "warning.evidence.hash_mismatch",
                        "developer_message": "Stored hash does not match recalculated hash.",
                        "source_id": evidence_id,
                        "details": {"algorithm": algorithm.value},
                    }
                )
            self._evidence_repository.update_job(job)
            return verification, job
        except OperationCancelledError:
            job.status = JobStatus.CANCELLED
            job.finished_at = self._clock.now()
            self._evidence_repository.update_job(job)
            raise
        except ApexError as error:
            verification = HashVerification(
                {
                    "id": self._id_generator.new_id(),
                    "evidence_id": evidence_id,
                    "case_id": evidence.case_id,
                    "algorithm": algorithm.value,
                    "expected_digest": expected.digest,
                    "observed_digest": None,
                    "status": HashVerificationStatus.ERROR.value,
                    "verified_at": to_json_timestamp(self._clock.now()),
                    "tool_version": ENGINE_VERSION,
                    "job_id": job.job_id,
                    "custody_event_id": None,
                    "error": error.to_api_error(),
                }
            )
            self._evidence_repository.save_hash_verification(verification)
            job.status = JobStatus.FAILED
            job.finished_at = self._clock.now()
            job.errors.append(error.to_api_error())
            self._evidence_repository.update_job(job)
            raise

    def _append_hash_verified_event(
        self,
        *,
        evidence: Evidence,
        algorithm: HashAlgorithm,
        expected_digest: str,
        observed_digest: str,
        status: HashVerificationStatus,
    ) -> str | None:
        if self._custody_ledger is None:
            return None
        event = self._custody_ledger.add_event(
            evidence_id=evidence.evidence_id,
            event_type=CustodyEventType.HASH_VERIFIED,
            actor_name="SYSTEM",
            action=f"Hash verification completed: {status.value}",
            previous_hash={"algorithm": algorithm.value, "digest_hex": expected_digest},
            current_hash={"algorithm": algorithm.value, "digest_hex": observed_digest},
            notes=None if status is HashVerificationStatus.MATCH else "Hash mismatch recorded.",
        )
        return event.event_id

    def _create_job(self, evidence: Evidence, job_type: JobType, unit: ProgressUnit) -> Job:
        now = self._clock.now()
        return Job(
            job_id=self._id_generator.new_id(),
            case_id=evidence.case_id,
            evidence_id=evidence.evidence_id,
            job_type=job_type,
            status=JobStatus.QUEUED,
            progress=JobProgress(total=evidence.size_bytes, unit=unit),
            queued_at=now,
        )

    @staticmethod
    def _ensure_hash_supported(evidence: Evidence) -> None:
        if evidence.evidence_type is EvidenceFormat.DIRECTORY:
            raise UnsupportedCapabilityError(
                "Directory evidence hashing requires a manifest hash policy from a later phase.",
                target="evidence_id",
                required_capability="DIRECTORY_MANIFEST_HASH",
            )

    @staticmethod
    def _normalize_source_path(path: Path) -> Path:
        expanded = path.expanduser()
        absolute = expanded if expanded.is_absolute() else Path.cwd() / expanded
        EvidenceManager._reject_symlink_components(absolute)
        if not absolute.exists():
            raise ValidationError("Evidence path does not exist.", target="path")
        if not absolute.is_file() and not absolute.is_dir():
            raise ValidationError("Evidence path must be a file or directory.", target="path")
        return absolute.resolve(strict=True)

    @staticmethod
    def _reject_symlink_components(path: Path) -> None:
        parts = path.parts
        if not parts:
            return
        index = 1 if path.anchor else 0
        current = Path(path.anchor) if path.anchor else Path()
        for part in parts[index:]:
            current = current / part
            if current.is_symlink():
                raise UnsupportedCapabilityError(
                    "Symbolic links and reparse points are not followed in Phase 1.",
                    target="path",
                    required_capability="SYMLINK_POLICY",
                )

    @staticmethod
    def _detect_evidence_format(path: Path) -> EvidenceFormat:
        if path.is_dir():
            return EvidenceFormat.DIRECTORY
        suffix = path.suffix.lower()
        if suffix == ".e01":
            return EvidenceFormat.E01
        if suffix == ".dd":
            return EvidenceFormat.DD
        if suffix == ".img":
            return EvidenceFormat.IMG
        if suffix == ".vhdx":
            return EvidenceFormat.VHDX
        if suffix == ".vhd":
            return EvidenceFormat.VHD
        return EvidenceFormat.RAW

    @staticmethod
    def _reader_metadata(
        path: Path, evidence_type: EvidenceFormat
    ) -> tuple[str, str, list[str], dict[str, Any]]:
        if evidence_type is EvidenceFormat.DIRECTORY:
            return (
                "apex.directory_metadata_reader",
                ENGINE_VERSION,
                ["METADATA", "FILESYSTEM_INDEX"],
                {
                    "sector_size": None,
                    "phase_note": "Directory metadata is indexed without reading file bodies.",
                },
            )
        if evidence_type in {EvidenceFormat.RAW, EvidenceFormat.DD, EvidenceFormat.IMG}:
            probe = RawImageReader.probe(path)
            return (
                probe.reader_id,
                probe.reader_version,
                [item.capability for item in probe.capabilities if item.status == "SUPPORTED"],
                {
                    "sector_size": probe.sector_size,
                    "reader_capabilities": [item.to_schema_dict() for item in probe.capabilities],
                    "partition_parser": {
                        "id": "apex.partition_parser",
                        "version": "0.1.0",
                        "status": "AVAILABLE_ON_DEMAND",
                    },
                },
            )
        if evidence_type is EvidenceFormat.E01:
            probe = EwfEvidenceReader.probe(path)
            return (
                probe.reader_id,
                probe.reader_version,
                [item.capability for item in probe.capabilities if item.status == "SUPPORTED"],
                {
                    "sector_size": probe.sector_size,
                    "reader_capabilities": [item.to_schema_dict() for item in probe.capabilities],
                    "reader_unavailable_reason": probe.unavailable_reason,
                    "container_hash_only": True,
                },
            )
        probe = VirtualDiskEvidenceReader.probe(path)
        return (
            probe.reader_id,
            probe.reader_version,
            [item.capability for item in probe.capabilities if item.status == "SUPPORTED"],
            {
                "sector_size": probe.sector_size,
                "reader_capabilities": [item.to_schema_dict() for item in probe.capabilities],
                "reader_unavailable_reason": probe.unavailable_reason,
                "container_hash_only": True,
            },
        )
