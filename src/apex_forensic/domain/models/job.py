"""Job and progress domain models."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from apex_forensic._time import to_json_timestamp
from apex_forensic.domain.enums import JobStatus, JobType, ProgressUnit


@dataclass(slots=True)
class JobProgress:
    """Serializable job progress state."""

    current: int = 0
    total: int | None = None
    unit: ProgressUnit = ProgressUnit.UNKNOWN
    processed_items: int = 0
    estimated_total_items: int | None = None
    progress_percent: float | None = None
    throughput_items_per_second: float | None = None
    elapsed_seconds: float = 0.0
    estimated_remaining_seconds: float | None = None
    estimate_confidence: str = "UNKNOWN"
    current_analyzer: str | None = None
    worker_count: int = 0
    cache_hits: int = 0
    cache_misses: int = 0
    partial_results_available: bool = False

    def to_schema_dict(self, status: JobStatus) -> dict[str, Any]:
        """Return a JSON Schema-compatible progress DTO."""

        return {
            "current": self.current,
            "total": self.total,
            "unit": self.unit.value,
            "percent": self.progress_percent,
            "processed_items": self.processed_items,
            "estimated_total_items": self.estimated_total_items,
            "progress_percent": self.progress_percent,
            "throughput_items_per_second": self.throughput_items_per_second,
            "elapsed_seconds": self.elapsed_seconds,
            "estimated_remaining_seconds": self.estimated_remaining_seconds,
            "estimate_confidence": self.estimate_confidence,
            "current_analyzer": self.current_analyzer,
            "worker_count": self.worker_count,
            "cache_hits": self.cache_hits,
            "cache_misses": self.cache_misses,
            "partial_results_available": self.partial_results_available,
            "status": status.value,
        }


@dataclass(slots=True)
class Job:
    """A Phase 1 hash or verification job."""

    job_id: str
    case_id: str
    evidence_id: str | None
    job_type: JobType
    status: JobStatus
    progress: JobProgress
    queued_at: datetime
    started_at: datetime | None = None
    finished_at: datetime | None = None
    cancel_requested_at: datetime | None = None
    warnings: list[dict[str, Any]] = field(default_factory=list)
    errors: list[dict[str, Any]] = field(default_factory=list)
    profile_id: str | None = None
    priority: int = 100
    checkpoint_available: bool = False

    def to_schema_dict(self) -> dict[str, Any]:
        """Return a JSON Schema-compatible Job DTO."""

        as_of = self.finished_at or self.started_at or self.queued_at
        return {
            "id": self.job_id,
            "case_id": self.case_id,
            "evidence_id": self.evidence_id,
            "job_type": "HASH",
            "status": self.status.value,
            "progress": self.progress.to_schema_dict(self.status),
            "queued_at": to_json_timestamp(self.queued_at),
            "started_at": None if self.started_at is None else to_json_timestamp(self.started_at),
            "finished_at": (
                None if self.finished_at is None else to_json_timestamp(self.finished_at)
            ),
            "cancel_requested_at": (
                None
                if self.cancel_requested_at is None
                else to_json_timestamp(self.cancel_requested_at)
            ),
            "warnings": self.warnings,
            "errors": self.errors,
            "profile_id": self.profile_id,
            "priority": self.priority,
            "checkpoint_available": self.checkpoint_available,
            "result_completeness": {
                "is_partial": False,
                "as_of": to_json_timestamp(as_of),
                "completed_scopes": ["EVIDENCE"],
                "pending_scopes": [],
                "available_item_count": 1 if self.evidence_id is not None else 0,
                "warning": None,
            },
        }
