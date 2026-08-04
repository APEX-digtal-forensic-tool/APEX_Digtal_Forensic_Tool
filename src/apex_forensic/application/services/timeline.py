"""Timeline generation, timestamp normalization, and query service."""

from __future__ import annotations

import base64
import json
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from apex_forensic._time import parse_timestamp, to_json_timestamp
from apex_forensic.domain.enums import (
    AnalysisProfileType,
    ArtifactType,
    JobStatus,
    JobType,
    ProgressUnit,
    TimelineEventType,
    TimelineSourceType,
    TimestampPrecision,
    TimezoneConfidence,
    TimezoneSource,
)
from apex_forensic.domain.errors import NotFoundError, StateConflictError, ValidationError
from apex_forensic.domain.models import (
    CursorPage,
    Job,
    JobProgress,
    TimelineBuildCoverage,
    TimelineEvent,
    TimelinePage,
    TimelineQuery,
    TimestampNormalization,
)
from apex_forensic.domain.services.canonical import canonical_sha256
from apex_forensic.jobs import CancellationToken, PauseToken
from apex_forensic.ports.case_repository import CaseRepository
from apex_forensic.ports.clock import Clock
from apex_forensic.ports.id_generator import IdGenerator
from apex_forensic.ports.timeline_repository import TimelineRepository

MAX_TIMELINE_LIMIT = 1000

_FS_TIMESTAMP_EVENTS = {
    "created": TimelineEventType.FILE_CREATED,
    "modified": TimelineEventType.FILE_MODIFIED,
    "accessed": TimelineEventType.FILE_ACCESSED,
    "changed": TimelineEventType.FILE_METADATA_CHANGED,
}

_EVENT_ID_TYPES = {
    4624: TimelineEventType.LOGON,
    4634: TimelineEventType.LOGOFF,
    4647: TimelineEventType.LOGOFF,
    4688: TimelineEventType.PROCESS_CREATED,
    7045: TimelineEventType.SERVICE_INSTALLED,
    1102: TimelineEventType.EVENT_LOG_CLEARED,
    3: TimelineEventType.NETWORK_CONNECTION,
    11: TimelineEventType.FILE_CREATED_BY_PROCESS,
    12: TimelineEventType.REGISTRY_MODIFIED,
    13: TimelineEventType.REGISTRY_MODIFIED,
    22: TimelineEventType.DNS_QUERY,
}


@dataclass(frozen=True, slots=True)
class TimelineBuildOptions:
    """Serializable timeline build options."""

    profile_type: AnalysisProfileType
    evidence_id: str | None
    source_types: tuple[TimelineSourceType, ...]
    item_budget: int | None
    batch_size: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "profile_type": self.profile_type.value,
            "evidence_id": self.evidence_id,
            "source_types": [item.value for item in self.source_types],
            "item_budget": self.item_budget,
            "batch_size": self.batch_size,
            "reads_file_body": False,
            "background_daemon": False,
        }


@dataclass(slots=True)
class _TimelineRunState:
    job: Job
    options: TimelineBuildOptions
    option_fingerprint: str
    timeline_revision: int
    case_timezone: str
    cancellation_token: CancellationToken | None
    pause_token: PauseToken | None
    progress_callback: Callable[[Job], None] | None
    run_started: float = field(default_factory=time.monotonic)
    processed_items: int = 0
    event_count: int = 0
    skipped_items: int = 0
    warning_count: int = 0
    error_count: int = 0
    current_source: tuple[str, str] | None = None


class TimelineService:
    """Build and query unified timeline events."""

    def __init__(
        self,
        *,
        case_repository: CaseRepository,
        timeline_repository: TimelineRepository,
        clock: Clock,
        id_generator: IdGenerator,
    ) -> None:
        self._case_repository = case_repository
        self._timeline_repository = timeline_repository
        self._clock = clock
        self._id_generator = id_generator

    def build(
        self,
        *,
        case_id: str,
        evidence_id: str | None = None,
        source_types: list[TimelineSourceType] | None = None,
        profile_type: AnalysisProfileType = AnalysisProfileType.QUICK_TRIAGE,
        item_budget: int | None = None,
        batch_size: int = 100,
        cancellation_token: CancellationToken | None = None,
        pause_token: PauseToken | None = None,
        progress_callback: Callable[[Job], None] | None = None,
    ) -> tuple[Job, TimelineBuildCoverage]:
        """Project filesystem nodes and Windows artifacts into timeline events."""

        case = self._require_case(case_id)
        _validate_batch_size(batch_size)
        options = TimelineBuildOptions(
            profile_type=profile_type,
            evidence_id=evidence_id,
            source_types=tuple(
                source_types
                or (
                    TimelineSourceType.FILE_SYSTEM_NODE,
                    TimelineSourceType.REGISTRY_ARTIFACT,
                    TimelineSourceType.EVENT_LOG_ARTIFACT,
                    TimelineSourceType.PREFETCH_ARTIFACT,
                    TimelineSourceType.MEDIA_ARTIFACT,
                    TimelineSourceType.BROWSER_ARTIFACT,
                    TimelineSourceType.COMMUNICATION_ARTIFACT,
                )
            ),
            item_budget=item_budget,
            batch_size=batch_size,
        )
        option_fingerprint = canonical_sha256(options.to_dict())
        timeline_revision = self._timeline_repository.next_timeline_revision(case_id)
        now = self._clock.now()
        job = Job(
            job_id=self._id_generator.new_id(),
            case_id=case_id,
            evidence_id=evidence_id,
            job_type=JobType.TIMELINE,
            status=JobStatus.QUEUED,
            progress=JobProgress(unit=ProgressUnit.FILES, current_analyzer="timeline.build"),
            queued_at=now,
            priority=25 if profile_type is AnalysisProfileType.SELECTED_SCOPE else 50,
            checkpoint_available=True,
            index_revision=timeline_revision,
        )
        self._timeline_repository.save_job(job)
        self._timeline_repository.create_timeline_job(
            job_id=job.job_id,
            case_id=case_id,
            evidence_id=evidence_id,
            profile_type=profile_type.value,
            options=options.to_dict(),
            option_fingerprint=option_fingerprint,
            timeline_revision=timeline_revision,
            status=job.status.value,
            created_at=to_json_timestamp(now),
        )
        state = _TimelineRunState(
            job=job,
            options=options,
            option_fingerprint=option_fingerprint,
            timeline_revision=timeline_revision,
            case_timezone=case.timezone,
            cancellation_token=cancellation_token,
            pause_token=pause_token,
            progress_callback=progress_callback,
        )
        return self._run_build(state, after_source=None)

    def resume_build_job(
        self,
        job_id: str,
        *,
        item_budget: int | None = None,
        cancellation_token: CancellationToken | None = None,
        pause_token: PauseToken | None = None,
        progress_callback: Callable[[Job], None] | None = None,
    ) -> tuple[Job, TimelineBuildCoverage]:
        """Resume an interrupted timeline build job."""

        job = self._get_job(job_id)
        if job.status is JobStatus.SUCCEEDED:
            raise StateConflictError("Completed timeline jobs cannot be resumed.", target="job_id")
        metadata = self._get_timeline_job(job_id)
        case = self._require_case(str(metadata["case_id"]))
        options = self._options_from_dict(metadata["options"])
        options = TimelineBuildOptions(
            profile_type=options.profile_type,
            evidence_id=options.evidence_id,
            source_types=options.source_types,
            item_budget=item_budget,
            batch_size=options.batch_size,
        )
        checkpoint = self._timeline_repository.get_timeline_checkpoint(job_id)
        after_source = None
        if checkpoint is not None and checkpoint.get("current_source_type") is not None:
            after_source = (
                str(checkpoint["current_source_type"]),
                str(checkpoint["current_source_id"]),
            )
        job.status = JobStatus.RESUMING
        job.finished_at = None
        job.job_revision += 1
        self._timeline_repository.update_job(job)
        self._timeline_repository.update_timeline_job_status(
            job_id,
            job.status.value,
            pause_requested=False,
        )
        state = _TimelineRunState(
            job=job,
            options=options,
            option_fingerprint=str(metadata["option_fingerprint"]),
            timeline_revision=int(metadata["timeline_revision"]),
            case_timezone=case.timezone,
            cancellation_token=cancellation_token,
            pause_token=pause_token,
            progress_callback=progress_callback,
            processed_items=int((checkpoint or {}).get("processed_items", 0)),
            event_count=int((checkpoint or {}).get("event_count", 0)),
            skipped_items=int((checkpoint or {}).get("skipped_items", 0)),
        )
        return self._run_build(state, after_source=after_source)

    def cancel_build_job(self, job_id: str) -> Job:
        """Persist a cooperative cancellation request/result for CLI contexts."""

        job = self._get_job(job_id)
        if job.status in {JobStatus.SUCCEEDED, JobStatus.CANCELLED}:
            return job
        now = self._clock.now()
        job.status = JobStatus.CANCELLED
        job.cancel_requested_at = now
        job.finished_at = now
        job.job_revision += 1
        self._timeline_repository.update_job(job)
        self._timeline_repository.update_timeline_job_status(job_id, job.status.value)
        return job

    def status(self, job_id: str) -> dict[str, Any]:
        """Return timeline build job status with checkpoint and coverage."""

        job = self._get_job(job_id)
        coverage = self._timeline_repository.get_timeline_coverage(job_id)
        return {
            "job": job.to_schema_dict(),
            "timeline_job": self._get_timeline_job(job_id),
            "checkpoint": self._timeline_repository.get_timeline_checkpoint(job_id),
            "coverage": None if coverage is None else coverage.to_schema_dict(),
        }

    def get_event(self, timeline_event_id: str) -> TimelineEvent:
        """Return one timeline event."""

        event = self._timeline_repository.get_timeline_event(timeline_event_id)
        if event is None:
            raise NotFoundError(
                "TIMELINE_EVENT_NOT_FOUND",
                "Timeline event not found.",
                target="timeline_event_id",
            )
        return event

    def list_events(
        self,
        *,
        case_id: str,
        evidence_id: str | None = None,
        source_types: list[TimelineSourceType] | None = None,
        event_types: list[TimelineEventType] | None = None,
        analyzer_id: str | None = None,
        keyword: str | None = None,
        path: str | None = None,
        artifact_type: str | None = None,
        is_partial: bool | None = None,
        confidence: TimezoneConfidence | None = None,
        time_from: datetime | None = None,
        time_to: datetime | None = None,
        timezone: str | None = None,
        cursor: str | None = None,
        limit: int = 100,
        order: str = "ASC",
    ) -> TimelinePage:
        """Query case timeline using opaque stable cursor pagination."""

        case = self._require_case(case_id)
        limit = _validate_limit(limit)
        selected_timezone = timezone or case.timezone
        _validate_timezone(selected_timezone)
        query = TimelineQuery(
            case_id=case_id,
            evidence_id=evidence_id,
            source_types=tuple(source_types or ()),
            event_types=tuple(event_types or ()),
            analyzer_id=analyzer_id,
            keyword=keyword,
            path=path,
            artifact_type=artifact_type,
            is_partial=is_partial,
            confidence=confidence,
            time_from=time_from,
            time_to=time_to,
            timezone=selected_timezone,
            cursor=cursor,
            limit=limit + 1,
            order=order.upper(),
        )
        items = self._timeline_repository.query_timeline_events(query)
        has_more = len(items) > limit
        returned = items[:limit]
        next_cursor = (
            _encode_timeline_cursor(returned[-1], order.upper()) if has_more and returned else None
        )
        return TimelinePage(
            items=returned,
            page=CursorPage(next_cursor=next_cursor, has_more=has_more, returned=len(returned)),
            timezone=selected_timezone,
        )

    def _run_build(
        self,
        state: _TimelineRunState,
        *,
        after_source: tuple[str, str] | None,
    ) -> tuple[Job, TimelineBuildCoverage]:
        state.job.status = JobStatus.RUNNING
        state.job.started_at = state.job.started_at or self._clock.now()
        state.job.finished_at = None
        self._timeline_repository.update_job(state.job)
        self._timeline_repository.update_timeline_job_status(
            state.job.job_id,
            state.job.status.value,
            pause_requested=False,
        )
        next_after = after_source
        while True:
            if self._cancel_requested(state):
                return self._finish_build(state, JobStatus.CANCELLED)
            if self._pause_requested(state):
                return self._finish_build(state, JobStatus.PAUSED)
            if self._budget_reached(state):
                return self._finish_build(state, JobStatus.PARTIAL)
            rows = self._timeline_repository.iter_timeline_source_rows(
                case_id=state.job.case_id,
                evidence_id=state.options.evidence_id,
                source_types=tuple(item.value for item in state.options.source_types),
                after_source=next_after,
                limit=self._remaining_batch_limit(state),
            )
            if not rows:
                return self._finish_build(state, JobStatus.SUCCEEDED)
            events: list[TimelineEvent] = []
            for row in rows:
                source_key = (str(row["source_type"]), str(row["source_id"]))
                state.current_source = source_key
                next_after = source_key
                projected = self._events_from_source_row(row, state)
                if projected:
                    state.processed_items += 1
                    events.extend(projected)
                else:
                    state.skipped_items += 1
            if events:
                state.event_count += self._timeline_repository.save_timeline_events(events)
            self._save_checkpoint(state)
            self._update_progress(state)
            if state.progress_callback is not None:
                state.progress_callback(state.job)

    def _finish_build(
        self,
        state: _TimelineRunState,
        status: JobStatus,
    ) -> tuple[Job, TimelineBuildCoverage]:
        now = self._clock.now()
        state.job.status = status
        state.job.finished_at = now
        if status is JobStatus.CANCELLED:
            state.job.cancel_requested_at = now
        state.job.progress.partial_results_available = state.event_count > 0
        self._update_progress(state)
        self._timeline_repository.update_job(state.job)
        self._timeline_repository.update_timeline_job_status(state.job.job_id, status.value)
        self._save_checkpoint(state)
        coverage = TimelineBuildCoverage(
            job_id=state.job.job_id,
            case_id=state.job.case_id,
            evidence_id=state.options.evidence_id,
            status=status.value,
            discovered_items=state.processed_items + state.skipped_items,
            processed_items=state.processed_items,
            skipped_items=state.skipped_items,
            event_count=state.event_count,
            warning_count=state.warning_count,
            error_count=state.error_count,
            current_source=None
            if state.current_source is None
            else f"{state.current_source[0]}:{state.current_source[1]}",
            is_partial=status in {JobStatus.PARTIAL, JobStatus.PAUSED, JobStatus.CANCELLED},
            timeline_revision=state.timeline_revision,
            created_at=state.job.started_at,
            updated_at=now,
        )
        self._timeline_repository.upsert_timeline_coverage(coverage)
        return state.job, coverage

    def _events_from_source_row(
        self,
        row: dict[str, Any],
        state: _TimelineRunState,
    ) -> list[TimelineEvent]:
        source_type = TimelineSourceType(str(row["source_type"]))
        if source_type is TimelineSourceType.FILE_SYSTEM_NODE:
            return self._fs_events(row, state)
        return [self._artifact_event(row, state)]

    def _fs_events(self, row: dict[str, Any], state: _TimelineRunState) -> list[TimelineEvent]:
        raw_timestamps = dict(row.get("raw_timestamps") or {})
        utc_timestamps = dict(row.get("utc_timestamps") or {})
        timestamp_meanings = dict(row.get("timestamp_meanings") or {})
        timestamp_sources = dict(row.get("timestamp_sources") or {})
        events: list[TimelineEvent] = []
        for key, event_type in _FS_TIMESTAMP_EVENTS.items():
            utc_value = utc_timestamps.get(key)
            raw_value = raw_timestamps.get(key)
            if utc_value is None and raw_value is None:
                continue
            normalized = normalize_timestamp(
                raw_timestamp=None if raw_value is None else str(raw_value),
                raw_timezone="UTC" if utc_value is not None else None,
                case_timezone=state.case_timezone,
                timestamp_semantics=str(timestamp_meanings.get(key, key)),
                utc_source=utc_value
                if isinstance(utc_value, datetime)
                else None
                if utc_value is None
                else parse_timestamp(str(utc_value)),
                source_hint=(
                    TimezoneSource.UTC_SOURCE if utc_value is not None else TimezoneSource.UNKNOWN
                ),
            )
            events.append(
                self._make_event(
                    row=row,
                    state=state,
                    source_type=TimelineSourceType.FILE_SYSTEM_NODE,
                    event_type=event_type,
                    event_subtype=str(timestamp_sources.get(key, "os.stat")),
                    title=f"{event_type.value}: {row['title']}",
                    description=str(row.get("description") or row.get("path") or ""),
                    normalization=normalized,
                    analyzer_id=str(row.get("analyzer_id") or "filesystem.metadata"),
                    analyzer_version=row.get("analyzer_version"),
                    fields={
                        "timestamp_key": key,
                        "path": row.get("path"),
                        "node_type": row.get("node_type"),
                        "platform": row.get("platform"),
                    },
                )
            )
        return events

    def _artifact_event(
        self,
        row: dict[str, Any],
        state: _TimelineRunState,
    ) -> TimelineEvent:
        artifact_type = str(row.get("artifact_type") or "")
        fields = dict(row.get("fields") or {})
        event_type, subtype = _artifact_event_type(artifact_type, fields)
        normalized = normalize_timestamp(
            raw_timestamp=row.get("raw_timestamp"),
            raw_timezone=None,
            case_timezone=state.case_timezone,
            timestamp_semantics=str(row.get("timestamp_semantics") or "artifact_observed_at"),
            utc_source=row.get("normalized_utc")
            if isinstance(row.get("normalized_utc"), datetime)
            else None
            if row.get("normalized_utc") is None
            else parse_timestamp(str(row["normalized_utc"])),
            source_hint=TimezoneSource.UTC_SOURCE
            if row.get("normalized_utc") is not None
            else TimezoneSource.UNKNOWN,
        )
        source_type = _artifact_source_type(artifact_type)
        return self._make_event(
            row=row,
            state=state,
            source_type=source_type,
            event_type=event_type,
            event_subtype=subtype,
            title=str(row["title"]),
            description=str(row.get("description") or ""),
            normalization=normalized,
            analyzer_id=row.get("analyzer_id"),
            analyzer_version=row.get("analyzer_version"),
            fields=fields | {"artifact_type": artifact_type, "source_path": row.get("path")},
        )

    def _make_event(
        self,
        *,
        row: dict[str, Any],
        state: _TimelineRunState,
        source_type: TimelineSourceType,
        event_type: TimelineEventType,
        event_subtype: str,
        title: str,
        description: str,
        normalization: TimestampNormalization,
        analyzer_id: str | None,
        analyzer_version: str | None,
        fields: dict[str, Any],
    ) -> TimelineEvent:
        source_revision = int(row["source_revision"])
        source_id = str(row["source_id"])
        dedup_key = canonical_sha256(
            {
                "case_id": row["case_id"],
                "evidence_id": row["evidence_id"],
                "source_type": source_type.value,
                "source_id": source_id,
                "source_revision": source_revision,
                "event_type": event_type.value,
                "raw_timestamp": normalization.raw_timestamp,
                "normalized_utc": None
                if normalization.normalized_utc is None
                else to_json_timestamp(normalization.normalized_utc),
            }
        )
        return TimelineEvent(
            timeline_event_id="timeline-event-" + dedup_key,
            case_id=str(row["case_id"]),
            evidence_id=str(row["evidence_id"]),
            source_type=source_type,
            source_id=source_id,
            source_revision=source_revision,
            event_type=event_type,
            event_subtype=event_subtype,
            title=title,
            description=description,
            raw_timestamp=normalization.raw_timestamp,
            raw_timezone=normalization.raw_timezone,
            timestamp_semantics=normalization.timestamp_semantics,
            normalized_utc=normalization.normalized_utc,
            case_timezone=normalization.case_timezone,
            displayed_case_time=normalization.displayed_case_time,
            timezone_source=normalization.timezone_source,
            timezone_confidence=normalization.timezone_confidence,
            precision=normalization.precision,
            analyzer_id=analyzer_id,
            analyzer_version=analyzer_version,
            raw_locator=dict(row.get("raw_locator") or {}),
            citations=list(row.get("citations") or []),
            fields=fields,
            is_partial=bool(row.get("is_partial")),
            timeline_revision=state.timeline_revision,
            created_at=self._clock.now(),
            dedup_key=dedup_key,
        )

    def _get_job(self, job_id: str) -> Job:
        job = self._timeline_repository.get_job(job_id)
        if job is None:
            raise NotFoundError("JOB_NOT_FOUND", "Job not found.", target="job_id")
        if job.job_type is not JobType.TIMELINE:
            raise ValidationError("Job is not a timeline job.", target="job_id")
        return job

    def _get_timeline_job(self, job_id: str) -> dict[str, Any]:
        metadata = self._timeline_repository.get_timeline_job(job_id)
        if metadata is None:
            raise NotFoundError(
                "TIMELINE_JOB_NOT_FOUND",
                "Timeline job not found.",
                target="job_id",
            )
        return metadata

    def _options_from_dict(self, data: dict[str, Any]) -> TimelineBuildOptions:
        return TimelineBuildOptions(
            profile_type=AnalysisProfileType(str(data["profile_type"])),
            evidence_id=data.get("evidence_id"),
            source_types=tuple(
                TimelineSourceType(str(item))
                for item in data.get(
                    "source_types",
                    [
                        TimelineSourceType.FILE_SYSTEM_NODE.value,
                        TimelineSourceType.REGISTRY_ARTIFACT.value,
                        TimelineSourceType.EVENT_LOG_ARTIFACT.value,
                        TimelineSourceType.PREFETCH_ARTIFACT.value,
                        TimelineSourceType.MEDIA_ARTIFACT.value,
                        TimelineSourceType.BROWSER_ARTIFACT.value,
                    ],
                )
            ),
            item_budget=data.get("item_budget"),
            batch_size=int(data.get("batch_size", 100)),
        )

    def _require_case(self, case_id: str) -> Any:
        case = self._case_repository.get_case(case_id)
        if case is None:
            raise NotFoundError("CASE_NOT_FOUND", "Case not found.", target="case_id")
        return case

    def _remaining_batch_limit(self, state: _TimelineRunState) -> int:
        if state.options.item_budget is None:
            return state.options.batch_size
        remaining = max(state.options.item_budget - _inspected_items(state), 0)
        return max(1, min(state.options.batch_size, remaining))

    @staticmethod
    def _budget_reached(state: _TimelineRunState) -> bool:
        return (
            state.options.item_budget is not None
            and _inspected_items(state) >= state.options.item_budget
        )

    @staticmethod
    def _cancel_requested(state: _TimelineRunState) -> bool:
        return bool(state.cancellation_token is not None and state.cancellation_token.is_cancelled)

    @staticmethod
    def _pause_requested(state: _TimelineRunState) -> bool:
        return bool(state.pause_token is not None and state.pause_token.is_pause_requested)

    def _update_progress(self, state: _TimelineRunState) -> None:
        elapsed = max(time.monotonic() - state.run_started, 0.001)
        inspected_items = _inspected_items(state)
        state.job.progress.current = inspected_items
        state.job.progress.processed_items = state.processed_items
        state.job.progress.discovered_items = inspected_items
        state.job.progress.skipped_items = state.skipped_items
        state.job.progress.warning_count = state.warning_count
        state.job.progress.error_count = state.error_count
        state.job.progress.elapsed_seconds = elapsed
        state.job.progress.throughput_items_per_second = inspected_items / elapsed
        state.job.progress.estimate_confidence = "LOW"
        state.job.progress.current_analyzer = "timeline.build"
        if state.current_source is not None:
            state.job.progress.current_path = f"{state.current_source[0]}:{state.current_source[1]}"

    def _save_checkpoint(self, state: _TimelineRunState) -> None:
        self._timeline_repository.save_timeline_checkpoint(
            job_id=state.job.job_id,
            current_source_type=None if state.current_source is None else state.current_source[0],
            current_source_id=None if state.current_source is None else state.current_source[1],
            processed_items=state.processed_items,
            event_count=state.event_count,
            skipped_items=state.skipped_items,
        )


def _inspected_items(state: _TimelineRunState) -> int:
    return state.processed_items + state.skipped_items


def normalize_timestamp(
    *,
    raw_timestamp: str | None,
    raw_timezone: str | None,
    case_timezone: str,
    timestamp_semantics: str,
    utc_source: datetime | None = None,
    source_hint: TimezoneSource = TimezoneSource.UNKNOWN,
) -> TimestampNormalization:
    """Normalize timestamps without overwriting raw timestamp evidence."""

    _validate_timezone(case_timezone)
    warnings: list[dict[str, Any]] = []
    normalized: datetime | None = None
    timezone_source = source_hint
    confidence = TimezoneConfidence.UNKNOWN
    precision = _precision(raw_timestamp)
    if utc_source is not None:
        if utc_source.tzinfo is None:
            normalized = utc_source.replace(tzinfo=UTC)
        else:
            normalized = utc_source.astimezone(UTC)
        timezone_source = TimezoneSource.UTC_SOURCE
        confidence = TimezoneConfidence.HIGH
    elif raw_timestamp:
        parsed = _parse_raw_datetime(raw_timestamp)
        if parsed is not None and parsed.tzinfo is not None:
            normalized = parsed.astimezone(UTC)
            timezone_source = (
                TimezoneSource.UTC_SOURCE
                if normalized.utcoffset() == parsed.utcoffset()
                else TimezoneSource.EXPLICIT_OFFSET
            )
            confidence = TimezoneConfidence.HIGH
        elif parsed is not None and raw_timezone:
            try:
                zone = ZoneInfo(raw_timezone)
            except ZoneInfoNotFoundError:
                warnings.append(
                    {
                        "code": "UNKNOWN_TIMEZONE",
                        "developer_message": f"Unknown IANA timezone: {raw_timezone}",
                    }
                )
            else:
                local = parsed.replace(tzinfo=zone)
                normalized = local.astimezone(UTC)
                timezone_source = TimezoneSource.ARTIFACT_CONFIGURATION
                confidence = TimezoneConfidence.MEDIUM
                if _is_ambiguous(parsed, zone):
                    warnings.append(
                        {
                            "code": "AMBIGUOUS_LOCAL_TIME",
                            "developer_message": "Local timestamp is ambiguous in this timezone.",
                        }
                    )
        elif parsed is not None:
            warnings.append(
                {
                    "code": "NAIVE_TIMESTAMP_TIMEZONE_UNKNOWN",
                    "developer_message": "Naive timestamp was not assumed to be UTC.",
                }
            )
            timezone_source = TimezoneSource.UNKNOWN
            confidence = TimezoneConfidence.UNKNOWN
    displayed = None
    if normalized is not None:
        displayed = normalized.astimezone(ZoneInfo(case_timezone)).isoformat()
    return TimestampNormalization(
        raw_timestamp=raw_timestamp,
        raw_timezone=raw_timezone,
        timestamp_semantics=timestamp_semantics,
        normalized_utc=normalized,
        case_timezone=case_timezone,
        displayed_case_time=displayed,
        timezone_source=timezone_source,
        timezone_confidence=confidence,
        precision=precision,
        warnings=warnings,
    )


def _artifact_source_type(artifact_type: str) -> TimelineSourceType:
    if artifact_type in {
        ArtifactType.REGISTRY_KEY.value,
        ArtifactType.REGISTRY_VALUE.value,
        ArtifactType.REGISTRY_AUTORUN.value,
        ArtifactType.REGISTRY_USB_DEVICE.value,
        ArtifactType.REGISTRY_TIMEZONE.value,
        ArtifactType.REGISTRY_USERASSIST.value,
    }:
        return TimelineSourceType.REGISTRY_ARTIFACT
    if artifact_type == ArtifactType.EVENT_LOG_RECORD.value:
        return TimelineSourceType.EVENT_LOG_ARTIFACT
    if artifact_type == ArtifactType.PREFETCH_EXECUTION.value:
        return TimelineSourceType.PREFETCH_ARTIFACT
    if artifact_type in {
        ArtifactType.MEDIA_IMAGE.value,
        ArtifactType.MEDIA_VIDEO.value,
        ArtifactType.MEDIA_AUDIO.value,
    }:
        return TimelineSourceType.MEDIA_ARTIFACT
    if artifact_type in {
        ArtifactType.BROWSER_PROFILE.value,
        ArtifactType.BROWSER_VISIT.value,
        ArtifactType.BROWSER_SEARCH.value,
        ArtifactType.BROWSER_DOWNLOAD.value,
        ArtifactType.BROWSER_COOKIE.value,
        ArtifactType.BROWSER_CREDENTIAL.value,
        ArtifactType.BROWSER_CACHE_ENTRY.value,
        ArtifactType.BROWSER_DELETED_SQLITE_ROW.value,
        ArtifactType.BROWSER_PRIVATE_MODE_CANDIDATE.value,
    }:
        return TimelineSourceType.BROWSER_ARTIFACT
    if artifact_type in {
        ArtifactType.COMMUNICATION_PROFILE.value,
        ArtifactType.COMMUNICATION_ACCOUNT.value,
        ArtifactType.COMMUNICATION_CONVERSATION.value,
        ArtifactType.COMMUNICATION_MESSAGE.value,
        ArtifactType.COMMUNICATION_ATTACHMENT.value,
        ArtifactType.COMMUNICATION_UNSUPPORTED_STORE.value,
    }:
        return TimelineSourceType.COMMUNICATION_ARTIFACT
    return TimelineSourceType.REGISTRY_ARTIFACT


def _artifact_event_type(
    artifact_type: str,
    fields: dict[str, Any],
) -> tuple[TimelineEventType, str]:
    if artifact_type == ArtifactType.PREFETCH_EXECUTION.value:
        return TimelineEventType.PREFETCH_LAST_RUN, "PREFETCH_LAST_RUN_CANDIDATE"
    if artifact_type == ArtifactType.EVENT_LOG_RECORD.value:
        event_id = _int_or_none(fields.get("event_id"))
        subtype = (
            str(fields.get("event_subtype") or f"EVENT_ID_{event_id}")
            if event_id is not None
            else "EVENT_RECORD"
        )
        return _EVENT_ID_TYPES.get(event_id or -1, TimelineEventType.OTHER), subtype
    if artifact_type == ArtifactType.MEDIA_IMAGE.value:
        if fields.get("media_timestamps"):
            return TimelineEventType.MEDIA_CAPTURED_CANDIDATE, "MEDIA_IMAGE_CAPTURED_CANDIDATE"
        return TimelineEventType.MEDIA_MODIFIED, "MEDIA_IMAGE_MODIFIED"
    if artifact_type == ArtifactType.MEDIA_VIDEO.value:
        if fields.get("media_timestamps"):
            return TimelineEventType.MEDIA_METADATA_TIMESTAMP, "MEDIA_VIDEO_METADATA_TIMESTAMP"
        return TimelineEventType.MEDIA_MODIFIED, "MEDIA_VIDEO_MODIFIED"
    if artifact_type == ArtifactType.MEDIA_AUDIO.value:
        if fields.get("media_timestamps"):
            return TimelineEventType.MEDIA_METADATA_TIMESTAMP, "MEDIA_AUDIO_METADATA_TIMESTAMP"
        return TimelineEventType.MEDIA_MODIFIED, "MEDIA_AUDIO_MODIFIED"
    if artifact_type == ArtifactType.BROWSER_PROFILE.value:
        return TimelineEventType.BROWSER_PROFILE_OBSERVED, "BROWSER_PROFILE"
    if artifact_type == ArtifactType.BROWSER_VISIT.value:
        return TimelineEventType.BROWSER_VISIT, "BROWSER_VISIT"
    if artifact_type == ArtifactType.BROWSER_SEARCH.value:
        return TimelineEventType.BROWSER_SEARCH, "BROWSER_SEARCH"
    if artifact_type == ArtifactType.BROWSER_DOWNLOAD.value:
        status = str(fields.get("state_label") or fields.get("state") or "").upper()
        if status in {"COMPLETE", "COMPLETED", "1"}:
            return TimelineEventType.BROWSER_DOWNLOAD_COMPLETED, "BROWSER_DOWNLOAD_COMPLETED"
        if fields.get("end_time_utc") is None:
            return TimelineEventType.BROWSER_DOWNLOAD_STARTED, "BROWSER_DOWNLOAD_STARTED"
        return TimelineEventType.BROWSER_DOWNLOAD_OBSERVED, "BROWSER_DOWNLOAD_OBSERVED"
    if artifact_type == ArtifactType.BROWSER_COOKIE.value:
        return TimelineEventType.BROWSER_COOKIE_OBSERVED, "BROWSER_COOKIE_OBSERVED"
    if artifact_type == ArtifactType.BROWSER_CREDENTIAL.value:
        return TimelineEventType.BROWSER_CREDENTIAL_OBSERVED, "BROWSER_CREDENTIAL_OBSERVED"
    if artifact_type == ArtifactType.BROWSER_CACHE_ENTRY.value:
        return TimelineEventType.BROWSER_CACHE_ENTRY_OBSERVED, "BROWSER_CACHE_ENTRY_OBSERVED"
    if artifact_type == ArtifactType.BROWSER_DELETED_SQLITE_ROW.value:
        return (
            TimelineEventType.BROWSER_DELETED_SQLITE_ROW_CANDIDATE,
            "BROWSER_DELETED_SQLITE_ROW_CANDIDATE",
        )
    if artifact_type == ArtifactType.BROWSER_PRIVATE_MODE_CANDIDATE.value:
        return TimelineEventType.BROWSER_PRIVATE_MODE_CANDIDATE, "BROWSER_PRIVATE_MODE_CANDIDATE"
    if artifact_type == ArtifactType.COMMUNICATION_PROFILE.value:
        return TimelineEventType.COMMUNICATION_PROFILE_OBSERVED, "COMMUNICATION_PROFILE"
    if artifact_type == ArtifactType.COMMUNICATION_ACCOUNT.value:
        return TimelineEventType.COMMUNICATION_ACCOUNT_OBSERVED, "COMMUNICATION_ACCOUNT"
    if artifact_type == ArtifactType.COMMUNICATION_CONVERSATION.value:
        return (
            TimelineEventType.COMMUNICATION_CONVERSATION_OBSERVED,
            "COMMUNICATION_CONVERSATION",
        )
    if artifact_type == ArtifactType.COMMUNICATION_MESSAGE.value:
        return TimelineEventType.COMMUNICATION_MESSAGE, "COMMUNICATION_MESSAGE"
    if artifact_type == ArtifactType.COMMUNICATION_ATTACHMENT.value:
        return TimelineEventType.COMMUNICATION_ATTACHMENT, "COMMUNICATION_ATTACHMENT"
    if artifact_type == ArtifactType.COMMUNICATION_UNSUPPORTED_STORE.value:
        return TimelineEventType.COMMUNICATION_UNSUPPORTED_STORE, "COMMUNICATION_UNSUPPORTED_STORE"
    if artifact_type == ArtifactType.REGISTRY_KEY.value:
        return TimelineEventType.REGISTRY_KEY_LAST_WRITE, "REGISTRY_KEY"
    if artifact_type == ArtifactType.REGISTRY_USERASSIST.value:
        return TimelineEventType.PROCESS_EXECUTION, "USERASSIST_EXECUTION_CANDIDATE"
    if artifact_type == ArtifactType.REGISTRY_AUTORUN.value:
        return TimelineEventType.REGISTRY_VALUE_OBSERVED, "AUTORUN_ENTRY_CANDIDATE"
    if artifact_type == ArtifactType.REGISTRY_USB_DEVICE.value:
        return TimelineEventType.REGISTRY_VALUE_OBSERVED, "USB_DEVICE_CANDIDATE"
    if artifact_type == ArtifactType.REGISTRY_TIMEZONE.value:
        return TimelineEventType.REGISTRY_VALUE_OBSERVED, "TIMEZONE_CONFIGURATION"
    return TimelineEventType.REGISTRY_VALUE_OBSERVED, "REGISTRY_VALUE"


def _int_or_none(value: Any) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _parse_raw_datetime(value: str) -> datetime | None:
    try:
        return parse_timestamp(value) if value.endswith("Z") else datetime.fromisoformat(value)
    except ValueError:
        return None


def _precision(raw_timestamp: str | None) -> TimestampPrecision:
    if raw_timestamp is None:
        return TimestampPrecision.UNKNOWN
    if "T" not in raw_timestamp and len(raw_timestamp) == 10:
        return TimestampPrecision.DAY
    if "." in raw_timestamp:
        fraction = raw_timestamp.split(".", 1)[1].split("+", 1)[0].split("Z", 1)[0]
        if len(fraction) > 3:
            return TimestampPrecision.MICROSECOND
        return TimestampPrecision.MILLISECOND
    return TimestampPrecision.SECOND


def _is_ambiguous(value: datetime, zone: ZoneInfo) -> bool:
    fold_zero = value.replace(tzinfo=zone, fold=0).utcoffset()
    fold_one = value.replace(tzinfo=zone, fold=1).utcoffset()
    return fold_zero != fold_one


def _validate_timezone(timezone: str) -> None:
    try:
        ZoneInfo(timezone)
    except ZoneInfoNotFoundError as error:
        raise ValidationError("Invalid IANA timezone identifier.", target="timezone") from error


def _validate_batch_size(batch_size: int) -> None:
    if batch_size < 1 or batch_size > 5000:
        raise ValidationError("Batch size must be between 1 and 5000.", target="batch_size")


def _validate_limit(limit: int) -> int:
    if limit < 1 or limit > MAX_TIMELINE_LIMIT:
        raise ValidationError(
            f"Limit must be between 1 and {MAX_TIMELINE_LIMIT}.",
            target="limit",
        )
    return limit


def _encode_timeline_cursor(event: TimelineEvent, order: str) -> str:
    sort_value = None
    if event.normalized_utc is not None:
        sort_value = to_json_timestamp(event.normalized_utc)
    payload = {
        "sort": sort_value,
        "timeline_event_id": event.timeline_event_id,
        "order": order,
    }
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def decode_timeline_cursor(cursor: str | None) -> dict[str, Any] | None:
    """Decode a timeline cursor for repository implementations."""

    if cursor is None:
        return None
    try:
        padded = cursor + "=" * (-len(cursor) % 4)
        data = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8"))
        if not isinstance(data, dict) or "timeline_event_id" not in data:
            raise ValueError("missing timeline_event_id")
        return data
    except (ValueError, TypeError, json.JSONDecodeError) as error:
        raise ValidationError("Invalid timeline cursor.", target="cursor") from error
