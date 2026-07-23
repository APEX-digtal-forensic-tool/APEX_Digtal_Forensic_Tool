"""Timeline repository port."""

from __future__ import annotations

from typing import Any, Protocol

from apex_forensic.domain.models import Job, TimelineBuildCoverage, TimelineEvent, TimelineQuery


class TimelineRepository(Protocol):
    """Persistence operations required by the timeline generator and query service."""

    def save_job(self, job: Job) -> None: ...
    def update_job(self, job: Job) -> None: ...
    def get_job(self, job_id: str) -> Job | None: ...
    def next_timeline_revision(self, case_id: str) -> int: ...
    def create_timeline_job(
        self,
        *,
        job_id: str,
        case_id: str,
        evidence_id: str | None,
        profile_type: str,
        options: dict[str, Any],
        option_fingerprint: str,
        timeline_revision: int,
        status: str,
        created_at: str,
    ) -> None: ...
    def update_timeline_job_status(
        self,
        job_id: str,
        status: str,
        *,
        pause_requested: bool | None = None,
    ) -> None: ...
    def get_timeline_job(self, job_id: str) -> dict[str, Any] | None: ...
    def save_timeline_checkpoint(
        self,
        *,
        job_id: str,
        current_source_type: str | None,
        current_source_id: str | None,
        processed_items: int,
        event_count: int,
        skipped_items: int,
    ) -> None: ...
    def get_timeline_checkpoint(self, job_id: str) -> dict[str, Any] | None: ...
    def iter_timeline_source_rows(
        self,
        *,
        case_id: str,
        evidence_id: str | None,
        source_types: tuple[str, ...],
        after_source: tuple[str, str] | None,
        limit: int,
    ) -> list[dict[str, Any]]: ...
    def save_timeline_events(self, events: list[TimelineEvent]) -> int: ...
    def get_timeline_event(self, timeline_event_id: str) -> TimelineEvent | None: ...
    def query_timeline_events(self, query: TimelineQuery) -> list[TimelineEvent]: ...
    def upsert_timeline_coverage(self, coverage: TimelineBuildCoverage) -> None: ...
    def get_timeline_coverage(self, job_id: str) -> TimelineBuildCoverage | None: ...
