"""Progressive filesystem indexing application service."""

from __future__ import annotations

import base64
import fnmatch
import json
import time
import unicodedata
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from pathlib import PurePosixPath
from typing import Any

from apex_forensic._time import to_json_timestamp
from apex_forensic.domain.enums import (
    AnalysisProfileType,
    FollowLinkPolicy,
    IndexCoverageStatus,
    JobStatus,
    JobType,
    ProgressUnit,
)
from apex_forensic.domain.errors import NotFoundError, StateConflictError, ValidationError
from apex_forensic.domain.models import (
    CursorPage,
    Evidence,
    FileSystemNode,
    FileTreePage,
    IndexCoverage,
    Job,
    JobProgress,
)
from apex_forensic.domain.services.canonical import canonical_sha256
from apex_forensic.jobs import CancellationToken, PauseToken
from apex_forensic.ports.case_repository import CaseRepository
from apex_forensic.ports.clock import Clock
from apex_forensic.ports.evidence_repository import EvidenceRepository
from apex_forensic.ports.file_system_repository import FileSystemIndexRepository
from apex_forensic.ports.filesystem_provider import FileSystemProvider, ProviderScanIssue
from apex_forensic.ports.id_generator import IdGenerator


@dataclass(frozen=True, slots=True)
class IndexOptions:
    """Serializable filesystem indexing options."""

    profile_type: AnalysisProfileType
    max_depth: int | None
    item_budget: int | None
    batch_size: int
    follow_link_policy: FollowLinkPolicy = FollowLinkPolicy.NEVER
    include_patterns: tuple[str, ...] = ()
    exclude_patterns: tuple[str, ...] = ()
    selected_paths: tuple[str, ...] = ()
    selected_node_ids: tuple[str, ...] = ()
    max_queue_size: int = 100_000

    def to_dict(self) -> dict[str, Any]:
        return {
            "profile_type": self.profile_type.value,
            "max_depth": self.max_depth,
            "item_budget": self.item_budget,
            "batch_size": self.batch_size,
            "follow_link_policy": self.follow_link_policy.value,
            "include_patterns": list(self.include_patterns),
            "exclude_patterns": list(self.exclude_patterns),
            "selected_paths": list(self.selected_paths),
            "selected_node_ids": list(self.selected_node_ids),
            "max_queue_size": self.max_queue_size,
            "hashing_mode": "ON_DEMAND",
            "reads_file_body": False,
        }


@dataclass(slots=True)
class _RunState:
    job: Job
    evidence: Evidence
    provider: FileSystemProvider
    options: IndexOptions
    option_fingerprint: str
    coverage: IndexCoverage
    cancellation_token: CancellationToken | None
    pause_token: PauseToken | None
    progress_callback: Callable[[Job], None] | None
    run_started: float = field(default_factory=time.monotonic)
    indexed_this_run: int = 0
    sequence: int = 0


class FileSystemIndexService:
    """Coordinates provider traversal, persistence, progress, and queries."""

    def __init__(
        self,
        *,
        case_repository: CaseRepository,
        evidence_repository: EvidenceRepository,
        repository: FileSystemIndexRepository,
        provider: FileSystemProvider,
        additional_providers: tuple[FileSystemProvider, ...] = (),
        clock: Clock,
        id_generator: IdGenerator,
    ) -> None:
        self._case_repository = case_repository
        self._evidence_repository = evidence_repository
        self._repository = repository
        self._providers = (provider, *additional_providers)
        self._clock = clock
        self._id_generator = id_generator

    def index_evidence(
        self,
        *,
        case_id: str,
        evidence_id: str,
        profile_type: AnalysisProfileType = AnalysisProfileType.QUICK_TRIAGE,
        max_depth: int | None = None,
        item_budget: int | None = None,
        batch_size: int = 100,
        selected_paths: list[str] | None = None,
        selected_node_ids: list[str] | None = None,
        include_patterns: list[str] | None = None,
        exclude_patterns: list[str] | None = None,
        max_queue_size: int = 100_000,
        cancellation_token: CancellationToken | None = None,
        pause_token: PauseToken | None = None,
        progress_callback: Callable[[Job], None] | None = None,
    ) -> tuple[Job, IndexCoverage]:
        """Create and run a filesystem index job synchronously."""

        evidence = self._get_evidence_for_case(case_id, evidence_id)
        provider = self._provider_for_evidence(evidence)
        options = self._options(
            profile_type=profile_type,
            max_depth=max_depth,
            item_budget=item_budget,
            batch_size=batch_size,
            selected_paths=tuple(selected_paths or ()),
            selected_node_ids=tuple(selected_node_ids or ()),
            include_patterns=tuple(include_patterns or ()),
            exclude_patterns=tuple(exclude_patterns or ()),
            max_queue_size=max_queue_size,
        )
        option_fingerprint = canonical_sha256(options.to_dict())
        index_revision = self._repository.next_index_revision(
            evidence_id,
            provider.provider_id,
            provider.provider_version,
        )
        capabilities = provider.capabilities()
        self._repository.save_fs_provider(
            capabilities.provider_id,
            capabilities.provider_version,
            [capability.value for capability in capabilities.capabilities],
            capabilities.to_schema_dict(),
        )
        now = self._clock.now()
        job = Job(
            job_id=self._id_generator.new_id(),
            case_id=case_id,
            evidence_id=evidence_id,
            job_type=JobType.INDEX,
            status=JobStatus.QUEUED,
            progress=JobProgress(
                unit=ProgressUnit.FILES, current_analyzer="filesystem.metadata", worker_count=1
            ),
            queued_at=now,
            priority=25 if profile_type is AnalysisProfileType.SELECTED_SCOPE else 50,
            checkpoint_available=True,
            index_revision=index_revision,
        )
        self._repository.save_job(job)
        self._repository.create_fs_index_job(
            job_id=job.job_id,
            case_id=case_id,
            evidence_id=evidence_id,
            provider_id=provider.provider_id,
            provider_version=provider.provider_version,
            profile_type=profile_type.value,
            options=options.to_dict(),
            option_fingerprint=option_fingerprint,
            index_revision=index_revision,
            status=job.status.value,
            created_at=to_json_timestamp(now),
        )
        coverage = IndexCoverage(
            case_id=case_id,
            evidence_id=evidence_id,
            provider_id=provider.provider_id,
            provider_version=provider.provider_version,
            profile_type=profile_type,
            option_fingerprint=option_fingerprint,
            status=IndexCoverageStatus.NOT_STARTED,
            index_revision=index_revision,
            job_id=job.job_id,
            created_at=now,
            updated_at=now,
        )
        root = self._repository.upsert_fs_node(
            provider.get_root_node(evidence, index_revision=index_revision)
        )
        coverage.discovered_items = 1
        if root.is_directory_like and root.is_traversed:
            self._enqueue(
                job.job_id, root.node_id, priority=10, depth=0, reason="ROOT", state_sequence=0
            )
        selected_inserted = self._prepare_selected_scopes(
            evidence, provider, options, index_revision, job.job_id
        )
        coverage.discovered_items += selected_inserted
        self._repository.upsert_fs_coverage(coverage)
        state = _RunState(
            job=job,
            evidence=evidence,
            provider=provider,
            options=options,
            option_fingerprint=option_fingerprint,
            coverage=coverage,
            cancellation_token=cancellation_token,
            pause_token=pause_token,
            progress_callback=progress_callback,
        )
        return self._run(state)

    def resume_index_job(
        self,
        job_id: str,
        *,
        item_budget: int | None = None,
        cancellation_token: CancellationToken | None = None,
        pause_token: PauseToken | None = None,
        progress_callback: Callable[[Job], None] | None = None,
    ) -> tuple[Job, IndexCoverage]:
        """Resume a partial, paused, or cancelled filesystem index job."""

        job = self._get_job(job_id)
        if job.status is JobStatus.SUCCEEDED:
            raise StateConflictError("Completed index jobs cannot be resumed.", target="job_id")
        metadata = self._get_fs_job(job_id)
        evidence = self._get_evidence_for_case(
            str(metadata["case_id"]), str(metadata["evidence_id"])
        )
        options = self._options_from_dict(metadata["options"])
        options = replace(options, item_budget=item_budget)
        coverage = self._repository.get_fs_coverage(
            str(metadata["evidence_id"]),
            str(metadata["provider_id"]),
            str(metadata["provider_version"]),
            str(metadata["profile_type"]),
            str(metadata["option_fingerprint"]),
        )
        if coverage is None:
            raise StateConflictError("Index coverage is missing for resume.", target="job_id")
        provider = self._provider_for_metadata(
            str(metadata["provider_id"]),
            str(metadata["provider_version"]),
        )
        self._repository.reset_interrupted_fs_queue(job_id)
        job.status = JobStatus.RESUMING
        job.job_revision += 1
        job.finished_at = None
        self._repository.update_job(job)
        self._repository.update_fs_index_job_status(job_id, job.status.value, pause_requested=False)
        state = _RunState(
            job=job,
            evidence=evidence,
            provider=provider,
            options=options,
            option_fingerprint=str(metadata["option_fingerprint"]),
            coverage=coverage,
            cancellation_token=cancellation_token,
            pause_token=pause_token,
            progress_callback=progress_callback,
        )
        return self._run(state)

    def index_status(self, job_id: str) -> dict[str, Any]:
        """Return job, coverage, and scan events for a filesystem index job."""

        job = self._get_job(job_id)
        metadata = self._get_fs_job(job_id)
        coverage = self._repository.get_fs_coverage(
            str(metadata["evidence_id"]),
            str(metadata["provider_id"]),
            str(metadata["provider_version"]),
            str(metadata["profile_type"]),
            str(metadata["option_fingerprint"]),
        )
        return {
            "job": job.to_schema_dict(),
            "index_job": metadata,
            "coverage": None if coverage is None else coverage.to_schema_dict(),
            "events": self._repository.list_fs_scan_events(job_id),
        }

    def cancel_index_job(self, job_id: str) -> Job:
        """Persist a cooperative cancellation request/result for a non-running CLI context."""

        job = self._get_job(job_id)
        if job.status is JobStatus.SUCCEEDED:
            raise StateConflictError("Completed index jobs cannot be cancelled.", target="job_id")
        job.status = JobStatus.CANCELLED
        job.cancel_requested_at = self._clock.now()
        job.finished_at = job.cancel_requested_at
        job.checkpoint_available = self._repository.count_pending_fs_queue(job_id) > 0
        job.job_revision += 1
        self._repository.update_job(job)
        self._repository.update_fs_index_job_status(job_id, job.status.value)
        self._update_latest_coverage_status(job, IndexCoverageStatus.CANCELLED)
        return job

    def pause_index_job(self, job_id: str) -> Job:
        """Persist a cooperative pause request/result for a non-running CLI context."""

        job = self._get_job(job_id)
        if job.status is JobStatus.SUCCEEDED:
            raise StateConflictError("Completed index jobs cannot be paused.", target="job_id")
        job.status = JobStatus.PAUSED
        job.checkpoint_available = self._repository.count_pending_fs_queue(job_id) > 0
        job.job_revision += 1
        self._repository.update_job(job)
        self._repository.update_fs_index_job_status(job_id, job.status.value, pause_requested=True)
        self._update_latest_coverage_status(job, IndexCoverageStatus.PARTIAL)
        return job

    def prioritize_node(self, job_id: str, node_id: str, *, priority: int = 0) -> Job:
        """Put an existing directory node ahead of background queue work."""

        job = self._get_job(job_id)
        metadata = self._get_fs_job(job_id)
        node = self.get_node(node_id)
        if node.evidence_id != metadata["evidence_id"]:
            raise ValidationError(
                "Node does not belong to this index job evidence.", target="node_id"
            )
        if not node.is_directory_like or not node.is_traversed:
            raise ValidationError(
                "Only traversable directory nodes can be prioritized.", target="node_id"
            )
        self._enqueue(
            job_id, node_id, priority=priority, depth=0, reason="SELECTED_SCOPE", state_sequence=-1
        )
        job.priority = min(job.priority, priority)
        job.job_revision += 1
        self._repository.update_job(job)
        return job

    def get_root_nodes(self, evidence_id: str) -> list[FileSystemNode]:
        self._ensure_evidence_exists(evidence_id)
        return self._repository.list_fs_roots(evidence_id)

    def get_node(self, node_id: str) -> FileSystemNode:
        node = self._repository.get_fs_node(node_id)
        if node is None:
            raise NotFoundError(
                "FS_NODE_NOT_FOUND", f"Filesystem node not found: {node_id}", target="node_id"
            )
        return node

    def list_nodes(
        self,
        *,
        evidence_id: str,
        parent_node_id: str | None = None,
        all_nodes: bool = False,
        directories_only: bool = False,
        files_only: bool = False,
        extension: str | None = None,
        name_or_path: str | None = None,
        cursor: str | None = None,
        limit: int = 100,
    ) -> FileTreePage:
        """Return a stable cursor page of filesystem nodes."""

        self._ensure_evidence_exists(evidence_id)
        if directories_only and files_only:
            raise ValidationError("directories_only and files_only are mutually exclusive.")
        if limit < 1 or limit > 500:
            raise ValidationError("limit must be between 1 and 500.", target="limit")
        query_key = self._query_fingerprint(
            evidence_id=evidence_id,
            parent_node_id=parent_node_id,
            all_nodes=all_nodes,
            directories_only=directories_only,
            files_only=files_only,
            extension=extension,
            name_or_path=name_or_path,
        )
        after = self._decode_cursor(cursor, query_key) if cursor is not None else None
        rows = self._repository.query_fs_nodes(
            evidence_id=evidence_id,
            parent_node_id=parent_node_id,
            all_nodes=all_nodes,
            directories_only=directories_only,
            files_only=files_only,
            extension=extension,
            name_or_path=self._comparison_text(name_or_path),
            after=after,
            limit=limit + 1,
        )
        has_more = len(rows) > limit
        items = rows[:limit]
        next_cursor = None
        if has_more and items:
            last = items[-1]
            next_cursor = self._encode_cursor(query_key, last.comparison_path, last.node_id)
        return FileTreePage(
            items=items,
            page=CursorPage(next_cursor=next_cursor, has_more=has_more, returned=len(items)),
            coverage=self._repository.latest_fs_coverage(evidence_id),
        )

    def _run(self, state: _RunState) -> tuple[Job, IndexCoverage]:
        state.job.status = JobStatus.RUNNING
        state.job.started_at = state.job.started_at or self._clock.now()
        state.job.job_revision += 1
        self._sync_progress(state)
        self._repository.update_job(state.job)
        self._repository.update_fs_index_job_status(
            state.job.job_id, state.job.status.value, pause_requested=False
        )
        while True:
            if self._cancel_requested(state):
                return self._finish(state, JobStatus.CANCELLED, IndexCoverageStatus.CANCELLED)
            if self._pause_requested(state):
                return self._finish(state, JobStatus.PAUSED, IndexCoverageStatus.PARTIAL)
            if self._budget_reached(state):
                return self._finish(state, JobStatus.PARTIAL, IndexCoverageStatus.PARTIAL)
            item = self._repository.next_fs_queue_item(state.job.job_id)
            if item is None:
                final_status = self._final_coverage_status(state)
                final_job_status = (
                    JobStatus.SUCCEEDED
                    if final_status is IndexCoverageStatus.COMPLETE
                    else JobStatus.PARTIAL
                )
                return self._finish(state, final_job_status, final_status)
            node = self._repository.get_fs_node(str(item["node_id"]))
            if node is None:
                self._record_issue(
                    state,
                    ProviderScanIssue(
                        severity="ERROR",
                        code="FS_NODE_NOT_FOUND",
                        message_key="error.fs.node_not_found",
                        developer_message="Queued filesystem node no longer exists.",
                        node_id=str(item["node_id"]),
                    ),
                )
                self._repository.mark_fs_queue_done(str(item["queue_id"]))
                continue
            state.coverage.current_path = node.display_path
            self._scan_queue_item(state, item, node)
            self._sync_progress(state)
            self._emit_progress(state)

    def _scan_queue_item(
        self, state: _RunState, item: dict[str, Any], parent: FileSystemNode
    ) -> None:
        batch: list[FileSystemNode] = []
        for entry in state.provider.iter_directory_entries(
            state.evidence,
            parent,
            index_revision=state.coverage.index_revision,
            after_cursor=item.get("cursor_key"),
        ):
            if isinstance(entry, ProviderScanIssue):
                self._record_issue(state, entry)
                if entry.severity == "WARNING":
                    state.coverage.skipped_items += 1
                if self._budget_reached(state):
                    self._repository.update_fs_queue_cursor(
                        str(item["queue_id"]), item.get("cursor_key")
                    )
                    return
                continue
            if not self._included(entry, state.options):
                state.coverage.skipped_items += 1
                continue
            next_depth = int(item["depth"]) + 1
            if (
                entry.is_directory_like
                and entry.is_traversed
                and not self._can_traverse(next_depth, state.options)
            ):
                entry.is_partial = True
                state.coverage.skipped_items += 1
            stored = self._repository.upsert_fs_node(entry)
            batch.append(stored)
            state.coverage.discovered_items += 1
            state.indexed_this_run += 1
            if (
                stored.is_directory_like
                and stored.is_traversed
                and self._can_traverse(next_depth, state.options)
            ):
                if (
                    self._repository.count_pending_fs_queue(state.job.job_id)
                    >= state.options.max_queue_size
                ):
                    state.coverage.skipped_items += 1
                    self._record_issue(
                        state,
                        ProviderScanIssue(
                            severity="WARNING",
                            code="WORK_QUEUE_FULL",
                            message_key="warning.fs.work_queue_full",
                            developer_message=(
                                "Filesystem index queue reached its configured bound."
                            ),
                            path=stored.display_path,
                            node_id=stored.node_id,
                            details={"max_queue_size": state.options.max_queue_size},
                        ),
                    )
                else:
                    self._enqueue(
                        state.job.job_id,
                        stored.node_id,
                        priority=100,
                        depth=next_depth,
                        reason="DISCOVERED_DIRECTORY",
                        state_sequence=self._next_sequence(state),
                    )
            if len(batch) >= state.options.batch_size:
                self._repository.save_fs_nodes(batch)
                batch.clear()
                self._sync_progress(state)
                self._emit_progress(state)
            if self._cancel_requested(state):
                return
            if self._pause_requested(state) or self._budget_reached(state):
                cursor = str(stored.provider_metadata.get("entry_sort_key", ""))
                self._repository.update_fs_queue_cursor(str(item["queue_id"]), cursor)
                return
        if batch:
            self._repository.save_fs_nodes(batch)
        self._repository.mark_fs_queue_done(str(item["queue_id"]))
        state.coverage.processed_items += 1

    def _finish(
        self,
        state: _RunState,
        job_status: JobStatus,
        coverage_status: IndexCoverageStatus,
    ) -> tuple[Job, IndexCoverage]:
        state.coverage.status = coverage_status
        state.coverage.updated_at = self._clock.now()
        state.job.status = job_status
        state.job.finished_at = self._clock.now()
        state.job.checkpoint_available = (
            self._repository.count_pending_fs_queue(state.job.job_id) > 0
        )
        if job_status is JobStatus.CANCELLED:
            state.job.cancel_requested_at = state.job.finished_at
        state.job.job_revision += 1
        self._sync_progress(state)
        self._repository.upsert_fs_coverage(state.coverage)
        self._repository.update_job(state.job)
        self._repository.update_fs_index_job_status(state.job.job_id, state.job.status.value)
        self._repository.save_fs_checkpoint(
            job_id=state.job.job_id,
            current_node_id=None,
            current_path=state.coverage.current_path,
            pending_queue_count=self._repository.count_pending_fs_queue(state.job.job_id),
            processed_items=state.coverage.processed_items,
            discovered_items=state.coverage.discovered_items,
        )
        return state.job, state.coverage

    def _prepare_selected_scopes(
        self,
        evidence: Evidence,
        provider: FileSystemProvider,
        options: IndexOptions,
        index_revision: int,
        job_id: str,
    ) -> int:
        inserted = 0
        for selected_path in options.selected_paths:
            relative_path = self._clean_relative_path(selected_path)
            ancestors = self._ancestor_paths(relative_path)
            for ancestor in ancestors:
                node = self._repository.get_fs_node_by_relative_path(
                    evidence.evidence_id,
                    provider.provider_id,
                    provider.provider_version,
                    ancestor,
                )
                if node is None:
                    node = provider.get_metadata(
                        evidence, ancestor, index_revision=index_revision
                    )
                    self._repository.upsert_fs_node(node)
                    inserted += 1
            node = self._repository.get_fs_node_by_relative_path(
                evidence.evidence_id,
                provider.provider_id,
                provider.provider_version,
                relative_path,
            )
            if node is not None and node.is_directory_like and node.is_traversed:
                self._enqueue(
                    job_id,
                    node.node_id,
                    priority=0,
                    depth=len(PurePosixPath(relative_path).parts),
                    reason="SELECTED_SCOPE",
                    state_sequence=-1,
                )
        for node_id in options.selected_node_ids:
            node = self._repository.get_fs_node(node_id)
            if node is None:
                raise ValidationError("Selected node does not exist.", target="selected_node_ids")
            if node.evidence_id != evidence.evidence_id:
                raise ValidationError(
                    "Selected node belongs to another evidence source.", target="selected_node_ids"
                )
            if node.is_directory_like and node.is_traversed:
                self._enqueue(
                    job_id,
                    node.node_id,
                    priority=0,
                    depth=0,
                    reason="SELECTED_SCOPE",
                    state_sequence=-1,
                )
        return inserted

    def _provider_for_evidence(self, evidence: Evidence) -> FileSystemProvider:
        for provider in self._providers:
            if provider.supports_evidence(evidence):
                return provider
        first = self._providers[0]
        first.get_root_node(evidence, index_revision=1)
        return first

    def _provider_for_metadata(self, provider_id: str, provider_version: str) -> FileSystemProvider:
        for provider in self._providers:
            if (
                provider.provider_id == provider_id
                and provider.provider_version == provider_version
            ):
                return provider
        raise StateConflictError(
            "Filesystem provider for this job is not configured.",
            target="provider_id",
        )

    def _record_issue(self, state: _RunState, issue: ProviderScanIssue) -> None:
        if issue.severity == "WARNING":
            state.coverage.warning_count += 1
            state.job.warnings.append(issue.to_warning_dict(source_id=issue.node_id))
        else:
            state.coverage.error_count += 1
            state.job.errors.append(issue.to_error_dict())
        self._repository.save_fs_scan_event(
            {
                "event_id": self._id_generator.new_id(),
                "job_id": state.job.job_id,
                "case_id": state.evidence.case_id,
                "evidence_id": state.evidence.evidence_id,
                "node_id": issue.node_id,
                "severity": issue.severity,
                "code": issue.code,
                "message_key": issue.message_key,
                "developer_message": issue.developer_message,
                "path": issue.path,
                "details": issue.details,
                "created_at": to_json_timestamp(self._clock.now()),
            }
        )

    def _sync_progress(self, state: _RunState) -> None:
        elapsed = max(0.0, time.monotonic() - state.run_started)
        state.coverage.elapsed_seconds = elapsed
        state.coverage.throughput_items_per_second = (
            state.indexed_this_run / elapsed if elapsed > 0 and state.indexed_this_run > 0 else None
        )
        state.coverage.estimated_remaining_seconds = None
        state.coverage.eta_confidence = "UNKNOWN"
        state.job.progress.current = state.coverage.discovered_items
        state.job.progress.total = None
        state.job.progress.processed_items = state.coverage.processed_items
        state.job.progress.estimated_total_items = None
        state.job.progress.progress_percent = None
        state.job.progress.throughput_items_per_second = state.coverage.throughput_items_per_second
        state.job.progress.elapsed_seconds = elapsed
        state.job.progress.estimated_remaining_seconds = None
        state.job.progress.estimate_confidence = "UNKNOWN"
        state.job.progress.partial_results_available = state.coverage.discovered_items > 0
        state.job.progress.discovered_items = state.coverage.discovered_items
        state.job.progress.skipped_items = state.coverage.skipped_items
        state.job.progress.warning_count = state.coverage.warning_count
        state.job.progress.error_count = state.coverage.error_count
        state.job.progress.current_path = state.coverage.current_path
        self._repository.upsert_fs_coverage(state.coverage)
        self._repository.update_job(state.job)

    def _emit_progress(self, state: _RunState) -> None:
        if state.progress_callback is None:
            return
        try:
            state.progress_callback(state.job)
        except Exception as error:
            self._record_issue(
                state,
                ProviderScanIssue(
                    severity="WARNING",
                    code="PROGRESS_CALLBACK_ERROR",
                    message_key="warning.fs.progress_callback_error",
                    developer_message=(
                        "Progress callback raised; indexing continued without touching evidence."
                    ),
                    details={"error": str(error)},
                ),
            )

    def _update_latest_coverage_status(self, job: Job, status: IndexCoverageStatus) -> None:
        if job.evidence_id is None:
            return
        coverage = self._repository.latest_fs_coverage(job.evidence_id)
        if coverage is None:
            return
        coverage.status = status
        coverage.updated_at = self._clock.now()
        self._repository.upsert_fs_coverage(coverage)

    def _final_coverage_status(self, state: _RunState) -> IndexCoverageStatus:
        if state.options.profile_type is AnalysisProfileType.QUICK_TRIAGE:
            return IndexCoverageStatus.PARTIAL
        if state.coverage.skipped_items > 0 or state.coverage.error_count > 0:
            return IndexCoverageStatus.PARTIAL
        return IndexCoverageStatus.COMPLETE

    def _cancel_requested(self, state: _RunState) -> bool:
        return bool(state.cancellation_token is not None and state.cancellation_token.is_cancelled)

    def _pause_requested(self, state: _RunState) -> bool:
        return bool(state.pause_token is not None and state.pause_token.is_pause_requested)

    def _budget_reached(self, state: _RunState) -> bool:
        return (
            state.options.item_budget is not None
            and state.indexed_this_run >= state.options.item_budget
        )

    def _can_traverse(self, depth: int, options: IndexOptions) -> bool:
        return options.max_depth is None or depth < options.max_depth

    def _included(self, node: FileSystemNode, options: IndexOptions) -> bool:
        path = node.original_relative_path
        if options.include_patterns and not any(
            fnmatch.fnmatch(path, pattern) for pattern in options.include_patterns
        ):
            return False
        return not any(fnmatch.fnmatch(path, pattern) for pattern in options.exclude_patterns)

    def _enqueue(
        self,
        job_id: str,
        node_id: str,
        *,
        priority: int,
        depth: int,
        reason: str,
        state_sequence: int,
    ) -> None:
        self._repository.enqueue_fs_queue_item(
            queue_id=self._id_generator.new_id(),
            job_id=job_id,
            node_id=node_id,
            priority=priority,
            depth=depth,
            sequence=state_sequence,
            reason=reason,
        )

    @staticmethod
    def _next_sequence(state: _RunState) -> int:
        state.sequence += 1
        return state.sequence

    def _get_evidence_for_case(self, case_id: str, evidence_id: str) -> Evidence:
        if self._case_repository.get_case(case_id) is None:
            raise NotFoundError("CASE_NOT_FOUND", f"Case not found: {case_id}", target="case_id")
        evidence = self._ensure_evidence_exists(evidence_id)
        if evidence.case_id != case_id:
            raise ValidationError(
                "Evidence does not belong to the requested case.", target="evidence_id"
            )
        return evidence

    def _ensure_evidence_exists(self, evidence_id: str) -> Evidence:
        evidence = self._evidence_repository.get_evidence(evidence_id)
        if evidence is None:
            raise NotFoundError(
                "EVIDENCE_NOT_FOUND", f"Evidence not found: {evidence_id}", target="evidence_id"
            )
        return evidence

    def _get_job(self, job_id: str) -> Job:
        job = self._repository.get_job(job_id)
        if job is None or job.job_type is not JobType.INDEX:
            raise NotFoundError(
                "INDEX_JOB_NOT_FOUND", f"Index job not found: {job_id}", target="job_id"
            )
        return job

    def _get_fs_job(self, job_id: str) -> dict[str, Any]:
        metadata = self._repository.get_fs_index_job(job_id)
        if metadata is None:
            raise NotFoundError(
                "INDEX_JOB_NOT_FOUND", f"Index job not found: {job_id}", target="job_id"
            )
        return metadata

    def _options(
        self,
        *,
        profile_type: AnalysisProfileType,
        max_depth: int | None,
        item_budget: int | None,
        batch_size: int,
        selected_paths: tuple[str, ...],
        selected_node_ids: tuple[str, ...],
        include_patterns: tuple[str, ...],
        exclude_patterns: tuple[str, ...],
        max_queue_size: int = 100_000,
    ) -> IndexOptions:
        if batch_size < 1 or batch_size > 10_000:
            raise ValidationError("batch_size must be between 1 and 10000.", target="batch_size")
        if item_budget is not None and item_budget < 1:
            raise ValidationError(
                "item_budget must be positive when provided.", target="item_budget"
            )
        if max_depth is not None and max_depth < 0:
            raise ValidationError(
                "max_depth must be non-negative when provided.", target="max_depth"
            )
        if profile_type is AnalysisProfileType.QUICK_TRIAGE and max_depth is None:
            max_depth = 1
        if (
            profile_type is AnalysisProfileType.SELECTED_SCOPE
            and not selected_paths
            and not selected_node_ids
        ):
            raise ValidationError(
                "SELECTED_SCOPE requires at least one selected path or node.",
                target="selected_scope",
            )
        return IndexOptions(
            profile_type=profile_type,
            max_depth=max_depth,
            item_budget=item_budget,
            batch_size=batch_size,
            selected_paths=selected_paths,
            selected_node_ids=selected_node_ids,
            include_patterns=include_patterns,
            exclude_patterns=exclude_patterns,
            max_queue_size=max_queue_size,
        )

    @staticmethod
    def _options_from_dict(data: dict[str, Any]) -> IndexOptions:
        return IndexOptions(
            profile_type=AnalysisProfileType(str(data["profile_type"])),
            max_depth=data.get("max_depth"),
            item_budget=data.get("item_budget"),
            batch_size=int(data["batch_size"]),
            follow_link_policy=FollowLinkPolicy(
                str(data.get("follow_link_policy", FollowLinkPolicy.NEVER.value))
            ),
            include_patterns=tuple(str(item) for item in data.get("include_patterns", [])),
            exclude_patterns=tuple(str(item) for item in data.get("exclude_patterns", [])),
            selected_paths=tuple(str(item) for item in data.get("selected_paths", [])),
            selected_node_ids=tuple(str(item) for item in data.get("selected_node_ids", [])),
            max_queue_size=int(data.get("max_queue_size", 100_000)),
        )

    @staticmethod
    def _clean_relative_path(path: str) -> str:
        pure = PurePosixPath(path.replace("\\", "/"))
        if pure.is_absolute() or any(part == ".." for part in pure.parts):
            raise ValidationError("Selected scope escapes evidence root.", target="selected_paths")
        cleaned = str(pure)
        return "" if cleaned == "." else cleaned

    @staticmethod
    def _ancestor_paths(relative_path: str) -> list[str]:
        if relative_path == "":
            return [""]
        parts = PurePosixPath(relative_path).parts
        paths = [""]
        current = ""
        for part in parts:
            current = part if current == "" else f"{current}/{part}"
            paths.append(current)
        return paths

    @staticmethod
    def _comparison_text(value: str | None) -> str | None:
        return None if value is None else unicodedata.normalize("NFC", value).casefold()

    def _query_fingerprint(
        self,
        *,
        evidence_id: str,
        parent_node_id: str | None,
        all_nodes: bool,
        directories_only: bool,
        files_only: bool,
        extension: str | None,
        name_or_path: str | None,
    ) -> str:
        return canonical_sha256(
            {
                "evidence_id": evidence_id,
                "parent_node_id": parent_node_id,
                "all_nodes": all_nodes,
                "directories_only": directories_only,
                "files_only": files_only,
                "extension": None if extension is None else extension.casefold().lstrip("."),
                "name_or_path": self._comparison_text(name_or_path),
                "sort": ["comparison_path", "node_id"],
            }
        )

    @staticmethod
    def _encode_cursor(query_key: str, comparison_path: str, node_id: str) -> str:
        payload = json.dumps(
            {"version": 1, "query": query_key, "after": [comparison_path, node_id]},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")

    @staticmethod
    def _decode_cursor(cursor: str, query_key: str) -> tuple[str, str]:
        try:
            padded = cursor + "=" * (-len(cursor) % 4)
            payload = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8"))
        except (ValueError, json.JSONDecodeError) as error:
            raise ValidationError("Invalid cursor.", target="cursor") from error
        if payload.get("version") != 1 or payload.get("query") != query_key:
            raise ValidationError("Cursor does not match query options.", target="cursor")
        after = payload.get("after")
        if not isinstance(after, list) or len(after) != 2:
            raise ValidationError("Invalid cursor payload.", target="cursor")
        return str(after[0]), str(after[1])
