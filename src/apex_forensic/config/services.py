"""Service factory for CLI and tests."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from apex_forensic.adapters.filesystem import LogicalDirectoryFileSystemProvider
from apex_forensic.adapters.hashing import HashlibStreamingHashProvider
from apex_forensic.adapters.persistence.sqlite import SQLiteRepository
from apex_forensic.adapters.system import SystemClock, UuidGenerator
from apex_forensic.application.services import (
    CaseManager,
    CustodyLedger,
    EvidenceManager,
    FileSystemIndexService,
)


@dataclass(slots=True)
class ServiceBundle:
    """Concrete Phase 1 services sharing one repository connection."""

    repository: SQLiteRepository
    cases: CaseManager
    evidence: EvidenceManager
    custody: CustodyLedger
    fs: FileSystemIndexService

    def close(self) -> None:
        """Close underlying resources."""

        self.repository.close()


def build_services(db_path: Path, *, initialize: bool = True) -> ServiceBundle:
    """Create concrete services for a SQLite database path."""

    repository = SQLiteRepository(db_path)
    if initialize:
        repository.initialize()
    clock = SystemClock()
    ids = UuidGenerator()
    custody = CustodyLedger(
        case_repository=repository,
        evidence_repository=repository,
        custody_repository=repository,
        clock=clock,
        id_generator=ids,
    )
    evidence = EvidenceManager(
        case_repository=repository,
        evidence_repository=repository,
        hash_provider=HashlibStreamingHashProvider(),
        clock=clock,
        id_generator=ids,
        custody_ledger=custody,
    )
    fs = FileSystemIndexService(
        case_repository=repository,
        evidence_repository=repository,
        repository=repository,
        provider=LogicalDirectoryFileSystemProvider(),
        clock=clock,
        id_generator=ids,
    )
    cases = CaseManager(repository=repository, clock=clock, id_generator=ids)
    return ServiceBundle(
        repository=repository, cases=cases, evidence=evidence, custody=custody, fs=fs
    )
