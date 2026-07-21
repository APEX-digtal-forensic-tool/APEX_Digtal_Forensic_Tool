"""Evidence repository port."""

from __future__ import annotations

from typing import Protocol

from apex_forensic.domain.enums import HashAlgorithm
from apex_forensic.domain.models import Evidence, HashRecord, HashVerification, Job


class EvidenceRepository(Protocol):
    """Persistence operations required by evidence services."""

    def save_evidence(self, evidence: Evidence) -> None:
        """Persist a new evidence row."""
        ...

    def update_evidence(self, evidence: Evidence) -> None:
        """Persist evidence metadata changes."""
        ...

    def get_evidence(self, evidence_id: str) -> Evidence | None:
        """Return evidence by ID."""
        ...

    def list_evidence_for_case(self, case_id: str) -> list[Evidence]:
        """Return evidence rows for a case."""
        ...

    def save_hash_record(self, record: HashRecord) -> None:
        """Persist a hash calculation result."""
        ...

    def latest_hash_record(
        self,
        evidence_id: str,
        algorithm: HashAlgorithm,
    ) -> HashRecord | None:
        """Return the latest stored hash for an algorithm."""
        ...

    def mark_hash_record_verified(self, hash_id: str, status: str) -> None:
        """Mark a stored hash as checked."""
        ...

    def save_hash_verification(self, verification: HashVerification) -> None:
        """Persist a verification history row."""
        ...

    def list_hash_verifications(self, evidence_id: str) -> list[HashVerification]:
        """Return verification history for evidence."""
        ...

    def save_job(self, job: Job) -> None:
        """Persist a job."""
        ...

    def update_job(self, job: Job) -> None:
        """Persist job changes."""
        ...

    def get_job(self, job_id: str) -> Job | None:
        """Return a job by ID."""
        ...
