"""Artifact analysis repository port."""

from __future__ import annotations

from typing import Any, Protocol

from apex_forensic.domain.models import (
    ArtifactCapability,
    ArtifactCoverage,
    ArtifactQuery,
    ArtifactRecord,
    ArtifactSource,
    Job,
)


class ArtifactRepository(Protocol):
    """Persistence operations required by the artifact analysis coordinator."""

    def save_job(self, job: Job) -> None: ...
    def update_job(self, job: Job) -> None: ...
    def get_job(self, job_id: str) -> Job | None: ...
    def save_artifact_analyzer(self, capability: ArtifactCapability) -> None: ...
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
    ) -> None: ...
    def update_artifact_analysis_job_status(
        self,
        job_id: str,
        status: str,
        *,
        pause_requested: bool | None = None,
    ) -> None: ...
    def get_artifact_analysis_job(self, job_id: str) -> dict[str, Any] | None: ...
    def save_analyzer_option_fingerprint(
        self,
        *,
        option_fingerprint: str,
        analyzer_id: str,
        analyzer_version: str,
        options: dict[str, Any],
        created_at: str,
    ) -> None: ...
    def next_artifact_index_revision(self, evidence_id: str) -> int: ...
    def save_artifact_sources(self, sources: list[ArtifactSource]) -> None: ...
    def next_artifact_source(self, job_id: str) -> ArtifactSource | None: ...
    def reset_interrupted_artifact_sources(self, job_id: str) -> None: ...
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
        source_checkpoint: dict[str, Any] | None = None,
        inspected_count: int | None = None,
        source_fingerprint: str | None = None,
    ) -> None: ...
    def count_pending_artifact_sources(self, job_id: str) -> int: ...
    def has_completed_artifact_source(
        self,
        *,
        evidence_id: str,
        source_file_node_id: str,
        analyzer_id: str,
        analyzer_version: str,
        option_fingerprint: str,
        source_fingerprint: str | None = None,
    ) -> bool: ...
    def save_artifacts(self, artifacts: list[ArtifactRecord]) -> int: ...
    def save_cache_entries(self, entries: list[dict[str, Any]]) -> int: ...
    def get_artifact(self, artifact_id: str) -> ArtifactRecord | None: ...
    def query_artifacts(
        self,
        *,
        query: ArtifactQuery,
        after: tuple[str, str] | None,
        limit: int,
    ) -> list[ArtifactRecord]: ...
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
    ) -> None: ...
    def list_artifact_warnings(
        self,
        *,
        job_id: str | None = None,
        artifact_id: str | None = None,
        evidence_id: str | None = None,
    ) -> list[dict[str, Any]]: ...
    def upsert_artifact_coverage(self, coverage: ArtifactCoverage) -> ArtifactCoverage: ...
    def get_artifact_coverage(self, job_id: str) -> ArtifactCoverage | None: ...
    def latest_artifact_coverage(self, evidence_id: str) -> ArtifactCoverage | None: ...
    def save_artifact_checkpoint(
        self,
        *,
        job_id: str,
        current_source_id: str | None,
        current_source_path: str | None,
        pending_source_count: int,
        processed_sources: int,
        artifact_count: int,
    ) -> None: ...
