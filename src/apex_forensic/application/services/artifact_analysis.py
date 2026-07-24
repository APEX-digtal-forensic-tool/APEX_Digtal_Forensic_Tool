"""Artifact discovery, analysis, progress, and query service."""

from __future__ import annotations

import base64
import fnmatch
import hashlib
import json
import os
import time
import unicodedata
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field, replace
from pathlib import Path, PurePosixPath
from typing import Any

from apex_forensic._time import parse_timestamp, to_json_timestamp
from apex_forensic.adapters.artifacts.windows.common import source_id_for
from apex_forensic.domain.enums import (
    AnalysisProfileType,
    ArtifactCoverageStatus,
    ArtifactParseStatus,
    ArtifactSourceKind,
    ArtifactType,
    JobStatus,
    JobType,
    ProgressUnit,
)
from apex_forensic.domain.errors import NotFoundError, StateConflictError, ValidationError
from apex_forensic.domain.models import (
    ArtifactCoverage,
    ArtifactIssue,
    ArtifactPage,
    ArtifactQuery,
    ArtifactSource,
    Evidence,
    Job,
    JobProgress,
)
from apex_forensic.domain.services.canonical import canonical_sha256
from apex_forensic.jobs import CancellationToken, PauseToken
from apex_forensic.ports.artifact_analyzer import ArtifactAnalyzer
from apex_forensic.ports.artifact_repository import ArtifactRepository
from apex_forensic.ports.case_repository import CaseRepository
from apex_forensic.ports.clock import Clock
from apex_forensic.ports.evidence_repository import EvidenceRepository
from apex_forensic.ports.file_system_repository import FileSystemIndexRepository
from apex_forensic.ports.id_generator import IdGenerator


@dataclass(frozen=True, slots=True)
class ArtifactAnalysisOptions:
    """Serializable artifact analysis options."""

    profile_type: AnalysisProfileType
    item_budget: int | None
    batch_size: int
    analyzers: tuple[str, ...] = ()
    artifact_types: tuple[ArtifactType, ...] = ()
    include_patterns: tuple[str, ...] = ()
    exclude_patterns: tuple[str, ...] = ()
    selected_paths: tuple[str, ...] = ()
    selected_node_ids: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "profile_type": self.profile_type.value,
            "item_budget": self.item_budget,
            "batch_size": self.batch_size,
            "analyzers": list(self.analyzers),
            "artifact_types": [item.value for item in self.artifact_types],
            "include_patterns": list(self.include_patterns),
            "exclude_patterns": list(self.exclude_patterns),
            "selected_paths": list(self.selected_paths),
            "selected_node_ids": list(self.selected_node_ids),
            "reads_file_body": True,
            "live_system_access": False,
            "credential_extraction": False,
        }


@dataclass(slots=True)
class _ArtifactRunState:
    job: Job
    evidence: Evidence
    options: ArtifactAnalysisOptions
    option_fingerprint: str
    coverage: ArtifactCoverage
    cancellation_token: CancellationToken | None
    pause_token: PauseToken | None
    progress_callback: Callable[[Job], None] | None
    run_started: float = field(default_factory=time.monotonic)
    artifacts_this_run: int = 0


class ArtifactAnalysisService:
    """Coordinates artifact discovery, analyzers, persistence, and queries."""

    def __init__(
        self,
        *,
        case_repository: CaseRepository,
        evidence_repository: EvidenceRepository,
        artifact_repository: ArtifactRepository,
        fs_repository: FileSystemIndexRepository,
        analyzers: Sequence[ArtifactAnalyzer],
        clock: Clock,
        id_generator: IdGenerator,
    ) -> None:
        self._case_repository = case_repository
        self._evidence_repository = evidence_repository
        self._artifact_repository = artifact_repository
        self._fs_repository = fs_repository
        self._analyzers = tuple(analyzers)
        self._clock = clock
        self._id_generator = id_generator

    def capabilities(self) -> list[dict[str, Any]]:
        """Return installed analyzer capabilities."""

        return [analyzer.capabilities().to_schema_dict() for analyzer in self._analyzers]

    def discover_sources(
        self,
        *,
        case_id: str,
        evidence_id: str,
        profile_type: AnalysisProfileType = AnalysisProfileType.QUICK_TRIAGE,
        analyzers: list[str] | None = None,
        artifact_types: list[ArtifactType] | None = None,
        selected_paths: list[str] | None = None,
        selected_node_ids: list[str] | None = None,
        include_patterns: list[str] | None = None,
        exclude_patterns: list[str] | None = None,
        batch_size: int = 100,
    ) -> dict[str, Any]:
        """Discover artifact candidates from existing filesystem nodes."""

        evidence = self._get_evidence_for_case(case_id, evidence_id)
        options = self._options(
            profile_type=profile_type,
            item_budget=None,
            batch_size=batch_size,
            analyzers=tuple(analyzers or ()),
            artifact_types=tuple(artifact_types or ()),
            selected_paths=tuple(selected_paths or ()),
            selected_node_ids=tuple(selected_node_ids or ()),
            include_patterns=tuple(include_patterns or ()),
            exclude_patterns=tuple(exclude_patterns or ()),
        )
        option_fingerprint = canonical_sha256(options.to_dict())
        now = self._clock.now()
        job = Job(
            job_id=self._id_generator.new_id(),
            case_id=case_id,
            evidence_id=evidence_id,
            job_type=JobType.ARTIFACT,
            status=JobStatus.RUNNING,
            progress=JobProgress(unit=ProgressUnit.FILES, current_analyzer="artifact.discovery"),
            queued_at=now,
            started_at=now,
            checkpoint_available=False,
            priority=25 if profile_type is AnalysisProfileType.SELECTED_SCOPE else 50,
            index_revision=self._artifact_repository.next_artifact_index_revision(evidence_id),
        )
        self._artifact_repository.save_job(job)
        self._register_analyzers(options, option_fingerprint)
        self._artifact_repository.create_artifact_analysis_job(
            job_id=job.job_id,
            case_id=case_id,
            evidence_id=evidence_id,
            profile_type=profile_type.value,
            options=options.to_dict(),
            option_fingerprint=option_fingerprint,
            index_revision=job.index_revision or 1,
            status=job.status.value,
            created_at=to_json_timestamp(now),
        )
        sources, discovery_warnings, fs_partial = self._discover_candidate_sources(
            evidence=evidence,
            options=options,
            option_fingerprint=option_fingerprint,
            job_id=job.job_id,
        )
        self._artifact_repository.save_artifact_sources(sources)
        for warning in discovery_warnings:
            self._save_issue(job, evidence, None, warning)
            job.warnings.append(warning.to_warning_dict())
        coverage = ArtifactCoverage(
            job_id=job.job_id,
            case_id=case_id,
            evidence_id=evidence_id,
            profile_type=profile_type,
            option_fingerprint=option_fingerprint,
            status=ArtifactCoverageStatus.PARTIAL
            if fs_partial
            else ArtifactCoverageStatus.COMPLETE,
            source_count=len(sources),
            warning_count=len(discovery_warnings),
            is_partial=fs_partial,
            index_revision=job.index_revision or 1,
            created_at=now,
            updated_at=now,
        )
        job.status = JobStatus.PARTIAL if fs_partial else JobStatus.SUCCEEDED
        job.finished_at = now
        job.progress.discovered_items = len(sources)
        job.progress.current = len(sources)
        job.progress.warning_count = len(discovery_warnings)
        job.progress.partial_results_available = bool(sources)
        self._artifact_repository.upsert_artifact_coverage(coverage)
        self._artifact_repository.update_job(job)
        self._artifact_repository.update_artifact_analysis_job_status(job.job_id, job.status.value)
        return {
            "job": job.to_schema_dict(),
            "sources": [source.to_schema_dict() for source in sources],
            "coverage": coverage.to_schema_dict(),
            "capabilities": self.capabilities(),
        }

    def analyze_evidence(
        self,
        *,
        case_id: str,
        evidence_id: str,
        profile_type: AnalysisProfileType = AnalysisProfileType.QUICK_TRIAGE,
        item_budget: int | None = None,
        batch_size: int = 100,
        analyzers: list[str] | None = None,
        artifact_types: list[ArtifactType] | None = None,
        selected_paths: list[str] | None = None,
        selected_node_ids: list[str] | None = None,
        include_patterns: list[str] | None = None,
        exclude_patterns: list[str] | None = None,
        cancellation_token: CancellationToken | None = None,
        pause_token: PauseToken | None = None,
        progress_callback: Callable[[Job], None] | None = None,
    ) -> tuple[Job, ArtifactCoverage]:
        """Create and run an artifact analysis job synchronously."""

        evidence = self._get_evidence_for_case(case_id, evidence_id)
        options = self._options(
            profile_type=profile_type,
            item_budget=item_budget,
            batch_size=batch_size,
            analyzers=tuple(analyzers or ()),
            artifact_types=tuple(artifact_types or ()),
            selected_paths=tuple(selected_paths or ()),
            selected_node_ids=tuple(selected_node_ids or ()),
            include_patterns=tuple(include_patterns or ()),
            exclude_patterns=tuple(exclude_patterns or ()),
        )
        option_fingerprint = canonical_sha256(options.to_dict())
        now = self._clock.now()
        index_revision = self._artifact_repository.next_artifact_index_revision(evidence_id)
        self._register_analyzers(options, option_fingerprint)
        job = Job(
            job_id=self._id_generator.new_id(),
            case_id=case_id,
            evidence_id=evidence_id,
            job_type=JobType.ARTIFACT,
            status=JobStatus.QUEUED,
            progress=JobProgress(unit=ProgressUnit.FILES, current_analyzer="artifact.discovery"),
            queued_at=now,
            priority=25 if profile_type is AnalysisProfileType.SELECTED_SCOPE else 50,
            checkpoint_available=True,
            index_revision=index_revision,
        )
        self._artifact_repository.save_job(job)
        self._artifact_repository.create_artifact_analysis_job(
            job_id=job.job_id,
            case_id=case_id,
            evidence_id=evidence_id,
            profile_type=profile_type.value,
            options=options.to_dict(),
            option_fingerprint=option_fingerprint,
            index_revision=index_revision,
            status=job.status.value,
            created_at=to_json_timestamp(now),
        )
        sources, discovery_warnings, fs_partial = self._discover_candidate_sources(
            evidence=evidence,
            options=options,
            option_fingerprint=option_fingerprint,
            job_id=job.job_id,
        )
        self._artifact_repository.save_artifact_sources(sources)
        coverage = ArtifactCoverage(
            job_id=job.job_id,
            case_id=case_id,
            evidence_id=evidence_id,
            profile_type=profile_type,
            option_fingerprint=option_fingerprint,
            status=ArtifactCoverageStatus.NOT_STARTED,
            source_count=len(sources),
            warning_count=0,
            is_partial=fs_partial,
            index_revision=index_revision,
            created_at=now,
            updated_at=now,
        )
        for warning in discovery_warnings:
            self._record_issue_for_state(job, coverage, evidence, None, warning)
        self._artifact_repository.upsert_artifact_coverage(coverage)
        state = _ArtifactRunState(
            job=job,
            evidence=evidence,
            options=options,
            option_fingerprint=option_fingerprint,
            coverage=coverage,
            cancellation_token=cancellation_token,
            pause_token=pause_token,
            progress_callback=progress_callback,
        )
        return self._run(state)

    def resume_artifact_job(
        self,
        job_id: str,
        *,
        item_budget: int | None = None,
        cancellation_token: CancellationToken | None = None,
        pause_token: PauseToken | None = None,
        progress_callback: Callable[[Job], None] | None = None,
    ) -> tuple[Job, ArtifactCoverage]:
        """Resume an interrupted artifact job."""

        job = self._get_artifact_job(job_id)
        if job.status is JobStatus.SUCCEEDED:
            raise StateConflictError("Completed artifact jobs cannot be resumed.", target="job_id")
        metadata = self._get_artifact_job_metadata(job_id)
        evidence = self._get_evidence_for_case(
            str(metadata["case_id"]), str(metadata["evidence_id"])
        )
        options = self._options_from_dict(metadata["options"])
        options = replace(options, item_budget=item_budget)
        coverage = self._artifact_repository.get_artifact_coverage(job_id)
        if coverage is None:
            raise StateConflictError("Artifact coverage is missing for resume.", target="job_id")
        self._artifact_repository.reset_interrupted_artifact_sources(job_id)
        job.status = JobStatus.RESUMING
        job.job_revision += 1
        job.finished_at = None
        self._artifact_repository.update_job(job)
        self._artifact_repository.update_artifact_analysis_job_status(
            job_id, job.status.value, pause_requested=False
        )
        state = _ArtifactRunState(
            job=job,
            evidence=evidence,
            options=options,
            option_fingerprint=str(metadata["option_fingerprint"]),
            coverage=coverage,
            cancellation_token=cancellation_token,
            pause_token=pause_token,
            progress_callback=progress_callback,
        )
        return self._run(state)

    def artifact_status(self, job_id: str) -> dict[str, Any]:
        """Return job metadata, coverage, and warnings for an artifact job."""

        job = self._get_artifact_job(job_id)
        metadata = self._get_artifact_job_metadata(job_id)
        coverage = self._artifact_repository.get_artifact_coverage(job_id)
        return {
            "job": job.to_schema_dict(),
            "artifact_job": metadata,
            "coverage": None if coverage is None else coverage.to_schema_dict(),
            "warnings": self._artifact_repository.list_artifact_warnings(job_id=job_id),
        }

    def cancel_artifact_job(self, job_id: str) -> Job:
        """Persist a cooperative cancellation request/result for a non-running CLI context."""

        job = self._get_artifact_job(job_id)
        if job.status is JobStatus.SUCCEEDED:
            raise StateConflictError(
                "Completed artifact jobs cannot be cancelled.", target="job_id"
            )
        job.status = JobStatus.CANCELLED
        job.cancel_requested_at = self._clock.now()
        job.finished_at = job.cancel_requested_at
        job.checkpoint_available = (
            self._artifact_repository.count_pending_artifact_sources(job_id) > 0
        )
        job.job_revision += 1
        self._artifact_repository.update_job(job)
        self._artifact_repository.update_artifact_analysis_job_status(job_id, job.status.value)
        coverage = self._artifact_repository.get_artifact_coverage(job_id)
        if coverage is not None:
            coverage.status = ArtifactCoverageStatus.CANCELLED
            coverage.is_partial = True
            coverage.updated_at = self._clock.now()
            self._artifact_repository.upsert_artifact_coverage(coverage)
        return job

    def pause_artifact_job(self, job_id: str) -> Job:
        """Persist a cooperative pause request/result for a non-running context."""

        job = self._get_artifact_job(job_id)
        if job.status is JobStatus.SUCCEEDED:
            raise StateConflictError("Completed artifact jobs cannot be paused.", target="job_id")
        job.status = JobStatus.PAUSED
        job.checkpoint_available = (
            self._artifact_repository.count_pending_artifact_sources(job_id) > 0
        )
        job.job_revision += 1
        self._artifact_repository.update_job(job)
        self._artifact_repository.update_artifact_analysis_job_status(
            job_id, job.status.value, pause_requested=True
        )
        coverage = self._artifact_repository.get_artifact_coverage(job_id)
        if coverage is not None:
            coverage.status = ArtifactCoverageStatus.PARTIAL
            coverage.is_partial = True
            coverage.updated_at = self._clock.now()
            self._artifact_repository.upsert_artifact_coverage(coverage)
        return job

    def list_artifacts(self, query: ArtifactQuery) -> ArtifactPage:
        """Return stable cursor-paginated artifacts."""

        self._ensure_case_exists(query.case_id)
        if query.evidence_id is not None:
            self._ensure_evidence_exists(query.evidence_id)
        if query.limit < 1 or query.limit > 1000:
            raise ValidationError("limit must be between 1 and 1000.", target="limit")
        query_key = self._query_fingerprint(query)
        after = self._decode_cursor(query.cursor, query_key) if query.cursor is not None else None
        rows = self._artifact_repository.query_artifacts(
            query=query,
            after=after,
            limit=query.limit + 1,
        )
        has_more = len(rows) > query.limit
        items = rows[: query.limit]
        next_cursor = None
        if has_more and items:
            last = items[-1]
            sort_value = (
                (last.observed_at_utc or last.created_at)
                .isoformat(timespec="microseconds")
                .replace("+00:00", "Z")
            )
            next_cursor = self._encode_cursor(query_key, sort_value, last.artifact_id)
        coverage = (
            None
            if query.evidence_id is None
            else self._artifact_repository.latest_artifact_coverage(query.evidence_id)
        )
        return ArtifactPage(
            items=items,
            next_cursor=next_cursor,
            has_more=has_more,
            returned=len(items),
            coverage=coverage,
        )

    def get_artifact(self, artifact_id: str) -> Any:
        """Return one artifact or raise a structured not-found error."""

        artifact = self._artifact_repository.get_artifact(artifact_id)
        if artifact is None:
            raise NotFoundError(
                "ARTIFACT_NOT_FOUND",
                f"Artifact not found: {artifact_id}",
                target="artifact_id",
            )
        return artifact

    def list_warnings(
        self,
        *,
        job_id: str | None = None,
        artifact_id: str | None = None,
        evidence_id: str | None = None,
    ) -> list[dict[str, Any]]:
        return self._artifact_repository.list_artifact_warnings(
            job_id=job_id,
            artifact_id=artifact_id,
            evidence_id=evidence_id,
        )

    def _run(self, state: _ArtifactRunState) -> tuple[Job, ArtifactCoverage]:
        state.job.status = JobStatus.RUNNING
        state.job.started_at = state.job.started_at or self._clock.now()
        state.job.job_revision += 1
        self._sync_progress(state)
        self._artifact_repository.update_job(state.job)
        self._artifact_repository.update_artifact_analysis_job_status(
            state.job.job_id, state.job.status.value, pause_requested=False
        )
        while True:
            if self._cancel_requested(state):
                return self._finish(state, JobStatus.CANCELLED, ArtifactCoverageStatus.CANCELLED)
            if self._pause_requested(state):
                return self._finish(state, JobStatus.PAUSED, ArtifactCoverageStatus.PARTIAL)
            if self._budget_reached(state):
                return self._finish(state, JobStatus.PARTIAL, ArtifactCoverageStatus.PARTIAL)
            source = self._artifact_repository.next_artifact_source(state.job.job_id)
            if source is None:
                final_status = self._final_coverage_status(state)
                final_job_status = (
                    JobStatus.SUCCEEDED
                    if final_status is ArtifactCoverageStatus.COMPLETE
                    else JobStatus.PARTIAL
                )
                return self._finish(state, final_job_status, final_status)
            state.coverage.current_analyzer = source.analyzer_id
            state.coverage.current_source_path = source.source_path
            self._analyze_source(state, source)
            self._sync_progress(state)
            self._emit_progress(state)

    def _analyze_source(self, state: _ArtifactRunState, source: ArtifactSource) -> None:
        analyzer = self._analyzer_for(source.analyzer_id)
        node = self._fs_repository.get_fs_node(source.source_file_node_id)
        if node is None:
            error = ArtifactIssue(
                severity="ERROR",
                code="FS_NODE_NOT_FOUND",
                message_key="error.artifact.fs_node_not_found",
                developer_message="Artifact source filesystem node no longer exists.",
                source_file_node_id=source.source_file_node_id,
                source_path=source.source_path,
            )
            self._record_issue_for_state(state.job, state.coverage, state.evidence, source, error)
            self._artifact_repository.mark_artifact_source_done(
                source.source_id,
                status="FAILED",
                parse_status=ArtifactParseStatus.FAILED.value,
                warning_count=0,
                error_count=1,
                artifact_count=0,
                last_error=error.to_error_dict(),
                analyzed_at=to_json_timestamp(self._clock.now()),
            )
            state.coverage.processed_sources += 1
            return
        try:
            file_path = self._path_for_node(state.evidence, node)
            result = analyzer.analyze(
                evidence=state.evidence,
                node=node,
                source=source,
                file_path=file_path,
                item_budget=self._analyzer_item_budget(state, source),
            )
        except Exception as analyzer_error:
            issue_data = ArtifactIssue(
                severity="ERROR",
                code="ARTIFACT_ANALYZER_FAILED",
                message_key="error.artifact.analyzer_failed",
                developer_message=(
                    "Artifact analyzer failed for one source; remaining sources continue."
                ),
                source_file_node_id=source.source_file_node_id,
                source_path=source.source_path,
                details={"error": str(analyzer_error), "analyzer_id": source.analyzer_id},
            )
            self._record_issue_for_state(
                state.job, state.coverage, state.evidence, source, issue_data
            )
            self._artifact_repository.mark_artifact_source_done(
                source.source_id,
                status="FAILED",
                parse_status=ArtifactParseStatus.FAILED.value,
                warning_count=0,
                error_count=1,
                artifact_count=0,
                last_error=issue_data.to_error_dict(),
                analyzed_at=to_json_timestamp(self._clock.now()),
            )
            state.coverage.processed_sources += 1
            return
        all_artifacts = list(result.artifacts)
        for artifact in all_artifacts:
            artifact.index_revision = state.job.index_revision or artifact.index_revision
        artifacts = all_artifacts
        source_complete = result.source_complete
        inspected_increment = result.inspected_count or len(all_artifacts)
        if result.source_checkpoint is None and state.options.item_budget is not None:
            remaining_budget = max(0, state.options.item_budget - state.artifacts_this_run)
            if len(all_artifacts) > remaining_budget:
                artifacts = all_artifacts[:remaining_budget]
                source_complete = False
                inspected_increment = len(artifacts)
        inserted = 0
        for start in range(0, len(artifacts), state.options.batch_size):
            inserted += self._artifact_repository.save_artifacts(
                artifacts[start : start + state.options.batch_size]
            )
        if result.cache_entries:
            try:
                self._artifact_repository.save_cache_entries(list(result.cache_entries))
            except Exception as cache_error:
                self._record_issue_for_state(
                    state.job,
                    state.coverage,
                    state.evidence,
                    source,
                    ArtifactIssue(
                        severity="WARNING",
                        code="ARTIFACT_CACHE_METADATA_SAVE_FAILED",
                        message_key="warning.artifact.cache_metadata_save_failed",
                        developer_message=(
                            "Artifact cache metadata could not be persisted; analysis continued."
                        ),
                        source_file_node_id=source.source_file_node_id,
                        source_path=source.source_path,
                        details={"error": str(cache_error)},
                    ),
                )
        for warning in result.warnings:
            self._record_issue_for_state(state.job, state.coverage, state.evidence, source, warning)
        for artifact in artifacts:
            for artifact_warning in artifact.warnings:
                self._record_issue_for_state(
                    state.job,
                    state.coverage,
                    state.evidence,
                    source,
                    ArtifactIssue(
                        severity="WARNING",
                        code=str(artifact_warning.get("code", "ARTIFACT_WARNING")),
                        message_key=str(artifact_warning.get("message_key", "warning.artifact")),
                        developer_message=str(artifact_warning.get("developer_message", "")),
                        source_file_node_id=source.source_file_node_id,
                        artifact_id=artifact.artifact_id,
                        source_path=source.source_path,
                        details=dict(artifact_warning.get("details", {})),
                    ),
                )
        for result_error in result.errors:
            self._record_issue_for_state(
                state.job, state.coverage, state.evidence, source, result_error
            )
        source_artifact_count = source.artifact_count + inserted
        source_inspected_count = source.inspected_count + inspected_increment
        state.coverage.artifact_count += inserted
        if source_complete:
            state.coverage.processed_sources += 1
        state.artifacts_this_run += inspected_increment
        status = "QUEUED" if not source_complete else _source_status(result.parse_status)
        parse_status = (
            ArtifactParseStatus.PARTIAL.value if not source_complete else result.parse_status.value
        )
        self._artifact_repository.mark_artifact_source_done(
            source.source_id,
            status=status,
            parse_status=parse_status,
            warning_count=source.warning_count
            + len(result.warnings)
            + sum(len(item.warnings) for item in artifacts),
            error_count=source.error_count + len(result.errors),
            artifact_count=source_artifact_count,
            last_error=result.errors[0].to_error_dict() if result.errors else None,
            analyzed_at=to_json_timestamp(self._clock.now()),
            source_checkpoint=result.source_checkpoint if not source_complete else {},
            inspected_count=source_inspected_count,
            source_fingerprint=result.source_fingerprint,
        )

    def _discover_candidate_sources(
        self,
        *,
        evidence: Evidence,
        options: ArtifactAnalysisOptions,
        option_fingerprint: str,
        job_id: str,
    ) -> tuple[list[ArtifactSource], list[ArtifactIssue], bool]:
        nodes = self._fs_repository.list_fs_nodes_for_evidence(evidence.evidence_id)
        latest_fs_coverage = self._fs_repository.latest_fs_coverage(evidence.evidence_id)
        fs_partial = bool(
            latest_fs_coverage is not None and latest_fs_coverage.status.value != "COMPLETE"
        )
        warnings: list[ArtifactIssue] = []
        if not nodes:
            warnings.append(
                ArtifactIssue(
                    severity="WARNING",
                    code="FILESYSTEM_INDEX_REQUIRED",
                    message_key="warning.artifact.filesystem_index_required",
                    developer_message=(
                        "Artifact discovery uses existing filesystem nodes; no nodes were indexed."
                    ),
                    source_path=str(evidence.source_path),
                )
            )
            return [], warnings, True
        if fs_partial:
            warnings.append(
                ArtifactIssue(
                    severity="WARNING",
                    code="FILESYSTEM_INDEX_PARTIAL",
                    message_key="warning.artifact.filesystem_index_partial",
                    developer_message=(
                        "Latest filesystem index coverage is partial; artifact coverage is partial."
                    ),
                    source_path=str(evidence.source_path),
                )
            )
        selected_node_ids = set(options.selected_node_ids)
        selected_paths = tuple(self._clean_relative_path(path) for path in options.selected_paths)
        sources: list[ArtifactSource] = []
        source_order = 0
        for node in nodes:
            if not self._node_in_scope(node, selected_node_ids, selected_paths):
                continue
            if not self._included(node.original_relative_path, options):
                continue
            for analyzer in self._analyzers:
                if options.analyzers and analyzer.analyzer_id not in options.analyzers:
                    continue
                source = analyzer.detect_source(node)
                if source is None:
                    continue
                if options.artifact_types:
                    supported = analyzer.capabilities().supported_artifact_types
                    if not any(item in supported for item in options.artifact_types):
                        continue
                source.option_fingerprint = option_fingerprint
                source.job_id = job_id
                source.source_order = source_order
                source.source_fingerprint = self._effective_source_fingerprint(
                    evidence=evidence,
                    node=node,
                    source=source,
                )
                source.source_id = source_id_for(
                    node=node,
                    analyzer_id=source.analyzer_id,
                    analyzer_version=source.analyzer_version,
                    option_fingerprint=option_fingerprint,
                    source_fingerprint=source.source_fingerprint,
                )
                source.is_partial = source.is_partial or node.is_partial or fs_partial
                source.status = "QUEUED"
                source.updated_at = self._clock.now()
                source.discovered_at = self._clock.now()
                if self._artifact_repository.has_completed_artifact_source(
                    evidence_id=evidence.evidence_id,
                    source_file_node_id=source.source_file_node_id,
                    analyzer_id=source.analyzer_id,
                    analyzer_version=source.analyzer_version,
                    option_fingerprint=option_fingerprint,
                    source_fingerprint=source.source_fingerprint,
                ):
                    warnings.append(
                        ArtifactIssue(
                            severity="WARNING",
                            code="DUPLICATE_ANALYSIS_SKIPPED",
                            message_key="warning.artifact.duplicate_analysis_skipped",
                            developer_message=(
                                "Completed analysis with the same analyzer version and options "
                                "already exists."
                            ),
                            source_file_node_id=source.source_file_node_id,
                            source_path=source.source_path,
                            details={"analyzer_id": source.analyzer_id},
                        )
                    )
                    continue
                sources.append(source)
                source_order += 1
        sources.sort(
            key=lambda item: (item.priority, item.comparison_key, item.source_file_node_id)
        )
        for order, source in enumerate(sources):
            source.source_order = order
        return sources, warnings, fs_partial

    def _register_analyzers(
        self,
        options: ArtifactAnalysisOptions,
        option_fingerprint: str,
    ) -> None:
        for analyzer in self._analyzers:
            capability = analyzer.capabilities()
            self._artifact_repository.save_artifact_analyzer(capability)
            self._artifact_repository.save_analyzer_option_fingerprint(
                option_fingerprint=option_fingerprint,
                analyzer_id=analyzer.analyzer_id,
                analyzer_version=analyzer.analyzer_version,
                options=options.to_dict(),
                created_at=to_json_timestamp(self._clock.now()),
            )

    def _analyzer_item_budget(
        self,
        state: _ArtifactRunState,
        source: ArtifactSource,
    ) -> int | None:
        if source.source_kind is ArtifactSourceKind.BROWSER_SQLITE_DB:
            if state.options.item_budget is not None:
                return max(1, state.options.item_budget - state.artifacts_this_run)
            return state.options.batch_size
        return None

    def _effective_source_fingerprint(
        self,
        *,
        evidence: Evidence,
        node: Any,
        source: ArtifactSource,
    ) -> str | None:
        try:
            file_path = self._path_for_node(evidence, node)
            if source.source_kind is ArtifactSourceKind.BROWSER_SQLITE_DB:
                return _browser_sqlite_source_fingerprint(file_path)
            if source.source_kind in {
                ArtifactSourceKind.IMAGE_FILE,
                ArtifactSourceKind.VIDEO_FILE,
                ArtifactSourceKind.AUDIO_FILE,
            }:
                return _sha256_file(file_path)
        except (OSError, ValidationError):
            return None
        return None

    def _record_issue_for_state(
        self,
        job: Job,
        coverage: ArtifactCoverage,
        evidence: Evidence,
        source: ArtifactSource | None,
        issue_data: ArtifactIssue,
    ) -> None:
        self._save_issue(job, evidence, source, issue_data)
        if issue_data.code == "ARTIFACT_ITEM_BUDGET_REACHED":
            return
        if issue_data.severity == "WARNING":
            coverage.warning_count += 1
            job.warnings.append(issue_data.to_warning_dict())
        else:
            coverage.error_count += 1
            job.errors.append(issue_data.to_error_dict())

    def _save_issue(
        self,
        job: Job,
        evidence: Evidence,
        source: ArtifactSource | None,
        issue_data: ArtifactIssue,
    ) -> None:
        self._artifact_repository.save_artifact_warning(
            self._id_generator.new_id(),
            job_id=job.job_id,
            case_id=evidence.case_id,
            evidence_id=evidence.evidence_id,
            source_id=None if source is None else source.source_id,
            source_file_node_id=issue_data.source_file_node_id,
            artifact_id=issue_data.artifact_id,
            severity=issue_data.severity,
            code=issue_data.code,
            message_key=issue_data.message_key,
            developer_message=issue_data.developer_message,
            source_path=issue_data.source_path,
            details=issue_data.details,
            created_at=to_json_timestamp(self._clock.now()),
        )

    def _sync_progress(self, state: _ArtifactRunState) -> None:
        elapsed = max(0.0, time.monotonic() - state.run_started)
        state.coverage.elapsed_seconds = elapsed
        state.coverage.throughput_items_per_second = (
            state.artifacts_this_run / elapsed
            if elapsed > 0 and state.artifacts_this_run > 0
            else None
        )
        state.coverage.estimated_remaining_seconds = None
        state.coverage.eta_confidence = "UNKNOWN"
        state.job.progress.current = state.coverage.processed_sources
        state.job.progress.total = state.coverage.source_count
        state.job.progress.processed_items = state.coverage.processed_sources
        state.job.progress.estimated_total_items = state.coverage.source_count
        if state.coverage.source_count:
            state.job.progress.progress_percent = (
                state.coverage.processed_sources / state.coverage.source_count * 100.0
            )
        state.job.progress.throughput_items_per_second = state.coverage.throughput_items_per_second
        state.job.progress.elapsed_seconds = elapsed
        state.job.progress.partial_results_available = state.coverage.artifact_count > 0
        state.job.progress.discovered_items = state.coverage.source_count
        state.job.progress.skipped_items = state.coverage.skipped_sources
        state.job.progress.warning_count = state.coverage.warning_count
        state.job.progress.error_count = state.coverage.error_count
        state.job.progress.current_path = state.coverage.current_source_path
        state.job.progress.current_analyzer = state.coverage.current_analyzer
        self._artifact_repository.upsert_artifact_coverage(state.coverage)
        self._artifact_repository.update_job(state.job)

    def _emit_progress(self, state: _ArtifactRunState) -> None:
        if state.progress_callback is None:
            return
        try:
            state.progress_callback(state.job)
        except Exception as error:
            self._record_issue_for_state(
                state.job,
                state.coverage,
                state.evidence,
                None,
                ArtifactIssue(
                    severity="WARNING",
                    code="PROGRESS_CALLBACK_ERROR",
                    message_key="warning.artifact.progress_callback_error",
                    developer_message=("Progress callback raised; artifact analysis continued."),
                    details={"error": str(error)},
                ),
            )

    def _finish(
        self,
        state: _ArtifactRunState,
        job_status: JobStatus,
        coverage_status: ArtifactCoverageStatus,
    ) -> tuple[Job, ArtifactCoverage]:
        state.coverage.status = coverage_status
        state.coverage.is_partial = coverage_status is not ArtifactCoverageStatus.COMPLETE
        state.coverage.updated_at = self._clock.now()
        state.job.status = job_status
        state.job.finished_at = self._clock.now()
        state.job.checkpoint_available = (
            self._artifact_repository.count_pending_artifact_sources(state.job.job_id) > 0
        )
        if job_status is JobStatus.CANCELLED:
            state.job.cancel_requested_at = state.job.finished_at
        state.job.job_revision += 1
        self._sync_progress(state)
        self._artifact_repository.update_artifact_analysis_job_status(
            state.job.job_id, state.job.status.value
        )
        self._artifact_repository.save_artifact_checkpoint(
            job_id=state.job.job_id,
            current_source_id=None,
            current_source_path=state.coverage.current_source_path,
            pending_source_count=self._artifact_repository.count_pending_artifact_sources(
                state.job.job_id
            ),
            processed_sources=state.coverage.processed_sources,
            artifact_count=state.coverage.artifact_count,
        )
        return state.job, state.coverage

    def _final_coverage_status(self, state: _ArtifactRunState) -> ArtifactCoverageStatus:
        if state.coverage.warning_count > 0 or state.coverage.error_count > 0:
            return ArtifactCoverageStatus.PARTIAL
        return ArtifactCoverageStatus.COMPLETE

    def _budget_reached(self, state: _ArtifactRunState) -> bool:
        return (
            state.options.item_budget is not None
            and state.artifacts_this_run >= state.options.item_budget
        )

    def _cancel_requested(self, state: _ArtifactRunState) -> bool:
        return bool(state.cancellation_token is not None and state.cancellation_token.is_cancelled)

    def _pause_requested(self, state: _ArtifactRunState) -> bool:
        return bool(state.pause_token is not None and state.pause_token.is_pause_requested)

    def _analyzer_for(self, analyzer_id: str) -> ArtifactAnalyzer:
        for analyzer in self._analyzers:
            if analyzer.analyzer_id == analyzer_id:
                return analyzer
        raise ValidationError("Unknown artifact analyzer.", target="analyzer")

    def _get_evidence_for_case(self, case_id: str, evidence_id: str) -> Evidence:
        self._ensure_case_exists(case_id)
        evidence = self._ensure_evidence_exists(evidence_id)
        if evidence.case_id != case_id:
            raise ValidationError(
                "Evidence does not belong to the requested case.", target="evidence_id"
            )
        return evidence

    def _ensure_case_exists(self, case_id: str) -> None:
        if self._case_repository.get_case(case_id) is None:
            raise NotFoundError("CASE_NOT_FOUND", f"Case not found: {case_id}", target="case_id")

    def _ensure_evidence_exists(self, evidence_id: str) -> Evidence:
        evidence = self._evidence_repository.get_evidence(evidence_id)
        if evidence is None:
            raise NotFoundError(
                "EVIDENCE_NOT_FOUND", f"Evidence not found: {evidence_id}", target="evidence_id"
            )
        return evidence

    def _get_artifact_job(self, job_id: str) -> Job:
        job = self._artifact_repository.get_job(job_id)
        if job is None or job.job_type is not JobType.ARTIFACT:
            raise NotFoundError(
                "ARTIFACT_JOB_NOT_FOUND",
                f"Artifact job not found: {job_id}",
                target="job_id",
            )
        return job

    def _get_artifact_job_metadata(self, job_id: str) -> dict[str, Any]:
        metadata = self._artifact_repository.get_artifact_analysis_job(job_id)
        if metadata is None:
            raise NotFoundError(
                "ARTIFACT_JOB_NOT_FOUND",
                f"Artifact job not found: {job_id}",
                target="job_id",
            )
        return metadata

    def _path_for_node(self, evidence: Evidence, node: Any) -> Path:
        root = evidence.source_path.resolve(strict=True)
        if root.is_dir():
            relative_path = self._clean_relative_path(node.original_relative_path)
            candidate = (
                root if relative_path == "" else root.joinpath(*PurePosixPath(relative_path).parts)
            )
        else:
            if node.original_relative_path not in {"", "."}:
                raise ValidationError(
                    "Logical file source path is outside evidence root.",
                    target="source_file_node_id",
                )
            candidate = root
        candidate_absolute = candidate.absolute()
        try:
            common = os.path.commonpath([str(root), str(candidate_absolute)])
        except ValueError as error:
            raise ValidationError(
                "Artifact source escapes evidence root.", target="source_file_node_id"
            ) from error
        if common != str(root):
            raise ValidationError(
                "Artifact source escapes evidence root.", target="source_file_node_id"
            )
        return candidate

    def _options(
        self,
        *,
        profile_type: AnalysisProfileType,
        item_budget: int | None,
        batch_size: int,
        analyzers: tuple[str, ...],
        artifact_types: tuple[ArtifactType, ...],
        selected_paths: tuple[str, ...],
        selected_node_ids: tuple[str, ...],
        include_patterns: tuple[str, ...],
        exclude_patterns: tuple[str, ...],
    ) -> ArtifactAnalysisOptions:
        if batch_size < 1 or batch_size > 10_000:
            raise ValidationError("batch_size must be between 1 and 10000.", target="batch_size")
        if item_budget is not None and item_budget < 1:
            raise ValidationError(
                "item_budget must be positive when provided.", target="item_budget"
            )
        if (
            profile_type is AnalysisProfileType.SELECTED_SCOPE
            and not selected_paths
            and not selected_node_ids
        ):
            raise ValidationError(
                "SELECTED_SCOPE requires at least one selected path or node.",
                target="selected_scope",
            )
        known = {analyzer.analyzer_id for analyzer in self._analyzers}
        unknown = [analyzer_id for analyzer_id in analyzers if analyzer_id not in known]
        if unknown:
            raise ValidationError(
                "Unknown artifact analyzer.",
                target="analyzer",
                details={"unknown_analyzers": unknown},
            )
        return ArtifactAnalysisOptions(
            profile_type=profile_type,
            item_budget=item_budget,
            batch_size=batch_size,
            analyzers=analyzers,
            artifact_types=artifact_types,
            selected_paths=selected_paths,
            selected_node_ids=selected_node_ids,
            include_patterns=include_patterns,
            exclude_patterns=exclude_patterns,
        )

    @staticmethod
    def _options_from_dict(data: dict[str, Any]) -> ArtifactAnalysisOptions:
        return ArtifactAnalysisOptions(
            profile_type=AnalysisProfileType(str(data["profile_type"])),
            item_budget=data.get("item_budget"),
            batch_size=int(data["batch_size"]),
            analyzers=tuple(str(item) for item in data.get("analyzers", [])),
            artifact_types=tuple(
                ArtifactType(str(item)) for item in data.get("artifact_types", [])
            ),
            selected_paths=tuple(str(item) for item in data.get("selected_paths", [])),
            selected_node_ids=tuple(str(item) for item in data.get("selected_node_ids", [])),
            include_patterns=tuple(str(item) for item in data.get("include_patterns", [])),
            exclude_patterns=tuple(str(item) for item in data.get("exclude_patterns", [])),
        )

    @staticmethod
    def _node_in_scope(
        node: Any,
        selected_node_ids: set[str],
        selected_paths: tuple[str, ...],
    ) -> bool:
        if selected_node_ids and node.node_id not in selected_node_ids:
            return False
        if selected_paths:
            node_path = node.original_relative_path
            return any(
                node_path == path or (path != "" and node_path.startswith(f"{path}/"))
                for path in selected_paths
            )
        return True

    @staticmethod
    def _included(path: str, options: ArtifactAnalysisOptions) -> bool:
        normalized = unicodedata.normalize("NFC", path)
        if options.include_patterns and not any(
            fnmatch.fnmatch(normalized, pattern) for pattern in options.include_patterns
        ):
            return False
        return not any(fnmatch.fnmatch(normalized, pattern) for pattern in options.exclude_patterns)

    @staticmethod
    def _clean_relative_path(path: str) -> str:
        pure = PurePosixPath(path.replace("\\", "/"))
        if pure.is_absolute() or any(part == ".." for part in pure.parts):
            raise ValidationError("Selected scope escapes evidence root.", target="selected_paths")
        cleaned = str(pure)
        return "" if cleaned == "." else cleaned

    def _query_fingerprint(self, query: ArtifactQuery) -> str:
        return canonical_sha256(
            {
                "case_id": query.case_id,
                "evidence_id": query.evidence_id,
                "source_file_node_id": query.source_file_node_id,
                "artifact_type": None if query.artifact_type is None else query.artifact_type.value,
                "artifact_subtype": query.artifact_subtype,
                "analyzer_id": query.analyzer_id,
                "event_id": query.event_id,
                "registry_path": self._comparison_text(query.registry_path),
                "executable_name": self._comparison_text(query.executable_name),
                "media_kind": self._comparison_text(query.media_kind),
                "browser_profile": self._comparison_text(query.browser_profile),
                "browser_database": self._comparison_text(query.browser_database),
                "browser_table": self._comparison_text(query.browser_table),
                "browser_row_id": query.browser_row_id,
                "observed_from": None
                if query.observed_from is None
                else to_json_timestamp(query.observed_from),
                "observed_to": None
                if query.observed_to is None
                else to_json_timestamp(query.observed_to),
                "parse_status": None if query.parse_status is None else query.parse_status.value,
                "has_warnings": query.has_warnings,
                "sort": ["observed_or_created_at", "artifact_id"],
            }
        )

    @staticmethod
    def _comparison_text(value: str | None) -> str | None:
        return None if value is None else unicodedata.normalize("NFC", value).casefold()

    @staticmethod
    def _encode_cursor(query_key: str, sort_value: str, artifact_id: str) -> str:
        payload = json.dumps(
            {"query": query_key, "after": [sort_value, artifact_id]},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")

    @staticmethod
    def _decode_cursor(cursor: str, query_key: str) -> tuple[str, str]:
        try:
            padded = cursor + ("=" * (-len(cursor) % 4))
            data = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8"))
        except (ValueError, json.JSONDecodeError) as error:
            raise ValidationError("Invalid artifact cursor.", target="cursor") from error
        if data.get("query") != query_key:
            raise ValidationError(
                "Artifact cursor does not match the current query.", target="cursor"
            )
        after = data.get("after")
        if not isinstance(after, list) or len(after) != 2:
            raise ValidationError("Invalid artifact cursor payload.", target="cursor")
        sort_value, artifact_id = after
        if not isinstance(sort_value, str) or not isinstance(artifact_id, str):
            raise ValidationError("Invalid artifact cursor payload.", target="cursor")
        try:
            parse_timestamp(sort_value)
        except ValueError as error:
            raise ValidationError("Invalid artifact cursor timestamp.", target="cursor") from error
        return sort_value, artifact_id


def _source_status(parse_status: ArtifactParseStatus) -> str:
    if parse_status is ArtifactParseStatus.SUCCESS:
        return "SUCCEEDED"
    if parse_status is ArtifactParseStatus.FAILED:
        return "FAILED"
    return parse_status.value


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _browser_sqlite_source_fingerprint(path: Path) -> str:
    component_hashes = {"main": _sha256_file(path)}
    component_sizes = {"main": path.stat().st_size}
    for suffix, key in (("-wal", "wal"), ("-shm", "shm")):
        component_path = path.with_name(path.name + suffix)
        if not component_path.exists():
            continue
        component_hashes[key] = _sha256_file(component_path)
        component_sizes[key] = component_path.stat().st_size
    return canonical_sha256(
        {
            "source_path": str(path),
            "component_hashes": component_hashes,
            "component_sizes": component_sizes,
        }
    )
