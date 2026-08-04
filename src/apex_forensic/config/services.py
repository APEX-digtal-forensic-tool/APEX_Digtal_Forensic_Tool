"""Service factory for CLI and tests."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from apex_forensic.adapters.artifacts import (
    BrowserHistoryAnalyzer,
    CommunicationCorePluginAnalyzer,
    MediaMetadataAnalyzer,
    WindowsEventLogAnalyzer,
    WindowsPrefetchAnalyzer,
    WindowsRegistryAnalyzer,
)
from apex_forensic.adapters.filesystem import (
    LogicalDirectoryFileSystemProvider,
    PyTskFileSystemProvider,
)
from apex_forensic.adapters.hashing import HashlibStreamingHashProvider
from apex_forensic.adapters.persistence.sqlite import SQLiteRepository
from apex_forensic.adapters.system import SystemClock, UuidGenerator
from apex_forensic.application.services import (
    AiAssistanceService,
    ArtifactAnalysisService,
    CaseManager,
    ContextService,
    CustodyLedger,
    EngineInterfaceService,
    EvidenceImageService,
    EvidenceManager,
    FileSystemIndexService,
    MachineExtractionService,
    ReportService,
    SearchService,
    TimelineService,
    ViewProjectionService,
)


@dataclass(slots=True)
class ServiceBundle:
    """Concrete Phase 1 services sharing one repository connection."""

    repository: SQLiteRepository
    cases: CaseManager
    evidence: EvidenceManager
    images: EvidenceImageService
    custody: CustodyLedger
    fs: FileSystemIndexService
    artifacts: ArtifactAnalysisService
    search: SearchService
    timeline: TimelineService
    candidates: MachineExtractionService
    ai: AiAssistanceService
    reports: ReportService
    contexts: ContextService
    context: ContextService
    views: ViewProjectionService
    interface: EngineInterfaceService

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
    images = EvidenceImageService(repository=repository, custody_ledger=custody)
    fs = FileSystemIndexService(
        case_repository=repository,
        evidence_repository=repository,
        repository=repository,
        provider=LogicalDirectoryFileSystemProvider(),
        additional_providers=(PyTskFileSystemProvider(),),
        clock=clock,
        id_generator=ids,
    )
    artifacts = ArtifactAnalysisService(
        case_repository=repository,
        evidence_repository=repository,
        artifact_repository=repository,
        fs_repository=repository,
        analyzers=(
            WindowsRegistryAnalyzer(),
            WindowsEventLogAnalyzer(),
            WindowsPrefetchAnalyzer(),
            MediaMetadataAnalyzer(),
            BrowserHistoryAnalyzer(),
            CommunicationCorePluginAnalyzer(),
        ),
        clock=clock,
        id_generator=ids,
    )
    search = SearchService(
        case_repository=repository,
        search_index=repository,
        search_repository=repository,
        clock=clock,
        id_generator=ids,
    )
    timeline = TimelineService(
        case_repository=repository,
        timeline_repository=repository,
        clock=clock,
        id_generator=ids,
    )
    candidates = MachineExtractionService(
        case_repository=repository,
        repository=repository,
        clock=clock,
        id_generator=ids,
    )
    contexts = ContextService(repository=repository, clock=clock, id_generator=ids)
    ai = AiAssistanceService(
        repository=repository,
        contexts=contexts,
        search=search,
        clock=clock,
        id_generator=ids,
    )
    reports = ReportService(
        repository=repository,
        contexts=contexts,
        ai=ai,
        custody=custody,
        clock=clock,
        id_generator=ids,
    )
    views = ViewProjectionService(
        repository=repository,
        contexts=contexts,
        clock=clock,
        id_generator=ids,
    )
    interface = EngineInterfaceService(
        repository=repository,
        contexts=contexts,
        views=views,
        ai=ai,
        reports=reports,
        clock=clock,
        id_generator=ids,
    )
    cases = CaseManager(repository=repository, clock=clock, id_generator=ids)
    return ServiceBundle(
        repository=repository,
        cases=cases,
        evidence=evidence,
        images=images,
        custody=custody,
        fs=fs,
        artifacts=artifacts,
        search=search,
        timeline=timeline,
        candidates=candidates,
        ai=ai,
        reports=reports,
        contexts=contexts,
        context=contexts,
        views=views,
        interface=interface,
    )
