"""Filesystem indexing repository port."""

from __future__ import annotations

from typing import Any, Protocol

from apex_forensic.domain.models import FileSystemNode, IndexCoverage, Job


class FileSystemIndexRepository(Protocol):
    """Persistence operations required by the filesystem index coordinator."""

    def save_job(self, job: Job) -> None: ...
    def update_job(self, job: Job) -> None: ...
    def get_job(self, job_id: str) -> Job | None: ...
    def save_fs_provider(
        self,
        provider_id: str,
        provider_version: str,
        capabilities: list[str],
        metadata: dict[str, Any],
    ) -> None: ...
    def next_index_revision(
        self, evidence_id: str, provider_id: str, provider_version: str
    ) -> int: ...
    def upsert_fs_node(self, node: FileSystemNode) -> FileSystemNode: ...
    def save_fs_nodes(self, nodes: list[FileSystemNode]) -> None: ...
    def get_fs_node(self, node_id: str) -> FileSystemNode | None: ...
    def get_fs_node_by_relative_path(
        self,
        evidence_id: str,
        provider_id: str,
        provider_version: str,
        relative_path: str,
    ) -> FileSystemNode | None: ...
    def list_fs_roots(self, evidence_id: str) -> list[FileSystemNode]: ...
    def list_fs_nodes_for_evidence(self, evidence_id: str) -> list[FileSystemNode]: ...
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
    ) -> None: ...
    def update_fs_index_job_status(
        self,
        job_id: str,
        status: str,
        *,
        pause_requested: bool | None = None,
    ) -> None: ...
    def get_fs_index_job(self, job_id: str) -> dict[str, Any] | None: ...
    def list_fs_index_jobs_for_evidence(self, evidence_id: str) -> list[dict[str, Any]]: ...
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
    ) -> None: ...
    def next_fs_queue_item(self, job_id: str) -> dict[str, Any] | None: ...
    def reset_interrupted_fs_queue(self, job_id: str) -> None: ...
    def update_fs_queue_cursor(self, queue_id: str, cursor_key: str | None) -> None: ...
    def mark_fs_queue_done(self, queue_id: str) -> None: ...
    def count_pending_fs_queue(self, job_id: str) -> int: ...
    def save_fs_checkpoint(
        self,
        *,
        job_id: str,
        current_node_id: str | None,
        current_path: str | None,
        pending_queue_count: int,
        processed_items: int,
        discovered_items: int,
    ) -> None: ...
    def upsert_fs_coverage(self, coverage: IndexCoverage) -> IndexCoverage: ...
    def get_fs_coverage(
        self,
        evidence_id: str,
        provider_id: str,
        provider_version: str,
        profile_type: str,
        option_fingerprint: str,
    ) -> IndexCoverage | None: ...
    def latest_fs_coverage(self, evidence_id: str) -> IndexCoverage | None: ...
    def save_fs_scan_event(self, event: dict[str, Any]) -> None: ...
    def list_fs_scan_events(self, job_id: str) -> list[dict[str, Any]]: ...
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
    ) -> list[FileSystemNode]: ...
