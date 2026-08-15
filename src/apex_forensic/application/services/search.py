"""Search indexing, keyword-set, reproduction, and cache services."""

from __future__ import annotations

import base64
import json
import re
import time
import unicodedata
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from apex_forensic._time import parse_timestamp, to_json_timestamp
from apex_forensic.domain.enums import (
    AnalysisProfileType,
    JobStatus,
    JobType,
    KeywordMatchMode,
    KeywordSetStatus,
    KeywordType,
    ProgressUnit,
    SearchDocumentType,
    SearchQueryMode,
    SearchSourceType,
)
from apex_forensic.domain.errors import (
    NotFoundError,
    StateConflictError,
    UnsupportedCapabilityError,
    ValidationError,
)
from apex_forensic.domain.models import (
    CursorPage,
    Job,
    JobProgress,
    Keyword,
    KeywordSet,
    SearchCacheEntry,
    SearchDocument,
    SearchExecution,
    SearchIndexCapability,
    SearchQuery,
    SearchResult,
    SearchResultPage,
)
from apex_forensic.domain.services.canonical import canonical_sha256
from apex_forensic.jobs import CancellationToken, PauseToken
from apex_forensic.ports.case_repository import CaseRepository
from apex_forensic.ports.clock import Clock
from apex_forensic.ports.id_generator import IdGenerator
from apex_forensic.ports.search_index import SearchIndexProvider, SearchRepository

MAX_QUERY_LIMIT = 1000
MAX_QUERY_LENGTH = 4096
MAX_REGEX_LENGTH = 512
MAX_REGEX_BOUNDED_REPEAT = 1000
DEFAULT_SEARCH_CACHE_TTL_SECONDS: int | None = None
SEARCH_NORMALIZATION_VERSION = "apex-search-normalization-ko-v1"
SEARCH_TOKENIZER_VERSION = "sqlite-fts5-unicode61-apex-ko-v1"


@dataclass(frozen=True, slots=True)
class SearchIndexOptions:
    """Serializable options for a metadata/artifact search-index build."""

    profile_type: AnalysisProfileType
    evidence_ids: tuple[str, ...]
    source_types: tuple[SearchSourceType, ...]
    item_budget: int | None
    batch_size: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "profile_type": self.profile_type.value,
            "evidence_ids": list(self.evidence_ids),
            "source_types": [item.value for item in self.source_types],
            "item_budget": self.item_budget,
            "batch_size": self.batch_size,
            "reads_file_body": False,
            "background_daemon": False,
        }


@dataclass(slots=True)
class _SearchRunState:
    job: Job
    options: SearchIndexOptions
    option_fingerprint: str
    index_revision: int
    capability: SearchIndexCapability
    cancellation_token: CancellationToken | None
    pause_token: PauseToken | None
    progress_callback: Callable[[Job], None] | None
    run_started: float = field(default_factory=time.monotonic)
    processed_items: int = 0
    indexed_items: int = 0
    skipped_items: int = 0
    warning_count: int = 0
    error_count: int = 0
    current_source: tuple[str, str] | None = None


def _normalize_search_copy(value: str) -> str:
    normalized = unicodedata.normalize("NFC", value)
    normalized = normalized.replace("\\", "/")
    normalized = normalized.casefold()
    normalized = re.sub(r"/+", "/", normalized)
    normalized = re.sub(r"\s+", " ", normalized, flags=re.UNICODE)
    return normalized.strip()


def _normalized_structured_fields(row: dict[str, Any]) -> dict[str, Any]:
    original = str(row["searchable_text"])
    fields = dict(row.get("structured_fields") or {})
    fields["search_normalization"] = {
        "version": SEARCH_NORMALIZATION_VERSION,
        "tokenizer_version": SEARCH_TOKENIZER_VERSION,
        "unicode_normalization": "NFC",
        "case_folding": "casefold",
        "path_separator_normalization": "\\\\ -> /",
        "hangul_policy": "NFC_COMPOSED_JAMO_WHEN_CANONICAL",
        "morphological_analysis": False,
        "original_search_text_sha256": canonical_sha256(original),
    }
    return fields


class SearchService:
    """Coordinates Phase 4 search indexing, query reproduction, cache, and keywords."""

    def __init__(
        self,
        *,
        case_repository: CaseRepository,
        search_index: SearchIndexProvider,
        search_repository: SearchRepository,
        clock: Clock,
        id_generator: IdGenerator,
    ) -> None:
        self._case_repository = case_repository
        self._search_index = search_index
        self._search_repository = search_repository
        self._clock = clock
        self._id_generator = id_generator

    def capability(self) -> SearchIndexCapability:
        """Return runtime search backend capability."""

        return self._search_index.search_capability()

    def index(
        self,
        *,
        case_id: str,
        evidence_ids: list[str] | None = None,
        source_types: list[SearchSourceType] | None = None,
        profile_type: AnalysisProfileType = AnalysisProfileType.QUICK_TRIAGE,
        item_budget: int | None = None,
        batch_size: int = 100,
        cancellation_token: CancellationToken | None = None,
        pause_token: PauseToken | None = None,
        progress_callback: Callable[[Job], None] | None = None,
    ) -> tuple[Job, dict[str, Any]]:
        """Build the metadata/artifact search index synchronously."""

        self._require_case(case_id)
        self._validate_batch_size(batch_size)
        capability = self._require_available_capability()
        options = SearchIndexOptions(
            profile_type=profile_type,
            evidence_ids=tuple(evidence_ids or ()),
            source_types=tuple(
                source_types
                or (SearchSourceType.FILE_SYSTEM_NODE, SearchSourceType.WINDOWS_ARTIFACT)
            ),
            item_budget=item_budget,
            batch_size=batch_size,
        )
        option_fingerprint = canonical_sha256(options.to_dict())
        index_revision = self._search_index.next_search_index_revision(case_id)
        now = self._clock.now()
        job = Job(
            job_id=self._id_generator.new_id(),
            case_id=case_id,
            evidence_id=options.evidence_ids[0] if len(options.evidence_ids) == 1 else None,
            job_type=JobType.SEARCH_INDEX,
            status=JobStatus.QUEUED,
            progress=JobProgress(unit=ProgressUnit.FILES, current_analyzer="search.index"),
            queued_at=now,
            priority=25 if profile_type is AnalysisProfileType.SELECTED_SCOPE else 50,
            checkpoint_available=True,
            index_revision=index_revision,
        )
        self._search_repository.save_job(job)
        self._search_repository.create_search_job(
            job_id=job.job_id,
            case_id=case_id,
            evidence_id=job.evidence_id,
            profile_type=profile_type.value,
            options=options.to_dict(),
            option_fingerprint=option_fingerprint,
            index_revision=index_revision,
            status=job.status.value,
            created_at=to_json_timestamp(now),
        )
        state = _SearchRunState(
            job=job,
            options=options,
            option_fingerprint=option_fingerprint,
            index_revision=index_revision,
            capability=capability,
            cancellation_token=cancellation_token,
            pause_token=pause_token,
            progress_callback=progress_callback,
        )
        return self._run_index(state, after_source=None)

    def resume_index_job(
        self,
        job_id: str,
        *,
        item_budget: int | None = None,
        cancellation_token: CancellationToken | None = None,
        pause_token: PauseToken | None = None,
        progress_callback: Callable[[Job], None] | None = None,
    ) -> tuple[Job, dict[str, Any]]:
        """Resume a paused, cancelled, failed, or partial search index job."""

        self._require_available_capability()
        job = self._get_job(job_id)
        if job.status is JobStatus.SUCCEEDED:
            raise StateConflictError(
                "Completed search index jobs cannot be resumed.",
                target="job_id",
            )
        metadata = self._get_search_job(job_id)
        options = self._options_from_dict(metadata["options"])
        options = SearchIndexOptions(
            profile_type=options.profile_type,
            evidence_ids=options.evidence_ids,
            source_types=options.source_types,
            item_budget=item_budget,
            batch_size=options.batch_size,
        )
        checkpoint = self._search_repository.get_search_checkpoint(job_id)
        after_source = None
        if checkpoint is not None and checkpoint.get("current_source_type") is not None:
            after_source = (
                str(checkpoint["current_source_type"]),
                str(checkpoint["current_source_id"]),
            )
        job.status = JobStatus.RESUMING
        job.finished_at = None
        job.job_revision += 1
        self._search_repository.update_job(job)
        self._search_repository.update_search_job_status(
            job_id,
            job.status.value,
            pause_requested=False,
        )
        state = _SearchRunState(
            job=job,
            options=options,
            option_fingerprint=str(metadata["option_fingerprint"]),
            index_revision=int(metadata["index_revision"]),
            capability=self.capability(),
            cancellation_token=cancellation_token,
            pause_token=pause_token,
            progress_callback=progress_callback,
            processed_items=int((checkpoint or {}).get("processed_items", 0)),
            indexed_items=int((checkpoint or {}).get("indexed_items", 0)),
            skipped_items=int((checkpoint or {}).get("skipped_items", 0)),
        )
        return self._run_index(state, after_source=after_source)

    def cancel_index_job(self, job_id: str) -> Job:
        """Persist a cooperative cancellation request/result for CLI contexts."""

        job = self._get_job(job_id)
        if job.status in {JobStatus.SUCCEEDED, JobStatus.CANCELLED}:
            return job
        now = self._clock.now()
        job.status = JobStatus.CANCELLED
        job.cancel_requested_at = now
        job.finished_at = now
        job.job_revision += 1
        self._search_repository.update_job(job)
        self._search_repository.update_search_job_status(job_id, job.status.value)
        return job

    def index_status(self, job_id: str) -> dict[str, Any]:
        """Return search index job status with checkpoint metadata."""

        job = self._get_job(job_id)
        metadata = self._get_search_job(job_id)
        return {
            "job": job.to_schema_dict(),
            "search_job": metadata,
            "checkpoint": self._search_repository.get_search_checkpoint(job_id),
            "capability": self.capability().to_schema_dict(),
        }

    def rebuild(
        self,
        *,
        case_id: str | None = None,
    ) -> dict[str, Any]:
        """Rebuild the FTS table from persisted search documents."""

        self._require_available_capability()
        indexed = self._search_index.rebuild_search_index(case_id=case_id)
        self._search_repository.invalidate_search_cache(
            case_id=case_id,
            index_revision=None,
            source_revision_fingerprint=None,
            invalidated_at=to_json_timestamp(self._clock.now()),
        )
        return {"indexed_documents": indexed, "capability": self.capability().to_schema_dict()}

    def optimize(self) -> dict[str, Any]:
        """Optimize the search backend if supported."""

        self._require_available_capability()
        self._search_index.optimize_search_index()
        return {"optimized": True, "capability": self.capability().to_schema_dict()}

    def query(
        self,
        *,
        case_id: str,
        query_text: str,
        query_mode: SearchQueryMode = SearchQueryMode.TERM,
        evidence_ids: list[str] | None = None,
        source_types: list[SearchSourceType] | None = None,
        document_types: list[SearchDocumentType] | None = None,
        time_from: datetime | None = None,
        time_to: datetime | None = None,
        path_scope: str | None = None,
        filters: dict[str, Any] | None = None,
        keyword_set_id: str | None = None,
        keyword_set_version: int | None = None,
        case_sensitive: bool = False,
        cursor: str | None = None,
        limit: int = 100,
        sort: str = "rank",
        use_cache: bool = True,
    ) -> SearchResultPage:
        """Execute a metadata/artifact search and persist reproduction records."""

        self._require_case(case_id)
        capability = self._require_available_capability()
        self._validate_query(query_text, query_mode)
        limit = self._validate_limit(limit)
        after = _decode_search_cursor(cursor)
        keyword_set = None
        effective_keyword_set_version = keyword_set_version
        if keyword_set_id is not None:
            keyword_set = self._search_repository.get_keyword_set(
                keyword_set_id=keyword_set_id,
                version=keyword_set_version,
            )
            if keyword_set is None:
                raise NotFoundError("KEYWORD_SET_NOT_FOUND", "Keyword set not found.")
            effective_keyword_set_version = keyword_set.version
        raw_effective_query_text = self._effective_query_text(query_text, keyword_set)
        self._validate_query(raw_effective_query_text, query_mode)
        effective_query_text = (
            raw_effective_query_text
            if query_mode is SearchQueryMode.REGEX_METADATA
            else _normalize_search_copy(raw_effective_query_text)
        )
        index_revision = self._search_index.current_search_index_revision(case_id)
        source_revision_fingerprint = self._search_repository.search_source_revision_fingerprint(
            case_id=case_id,
            evidence_ids=tuple(evidence_ids or ()),
            source_types=tuple(item.value for item in (source_types or ())),
        )
        time_from_json = None if time_from is None else to_json_timestamp(time_from)
        time_to_json = None if time_to is None else to_json_timestamp(time_to)
        options = {
            "case_id": case_id,
            "query_text": effective_query_text,
            "original_query_text": query_text,
            "effective_query_text": effective_query_text,
            "raw_effective_query_text": raw_effective_query_text,
            "normalized_effective_query_text": effective_query_text,
            "normalization_version": SEARCH_NORMALIZATION_VERSION,
            "tokenizer_version": SEARCH_TOKENIZER_VERSION,
            "query_mode": query_mode.value,
            "evidence_ids": evidence_ids or [],
            "source_types": [item.value for item in (source_types or ())],
            "document_types": [item.value for item in (document_types or ())],
            "time_from": time_from_json,
            "time_to": time_to_json,
            "path_scope": path_scope,
            "filters": filters or {},
            "keyword_set_id": keyword_set_id,
            "keyword_set_version": effective_keyword_set_version,
            "case_sensitive": case_sensitive,
            "cursor": cursor,
            "limit": limit,
            "sort": sort,
            "cache_ttl_seconds": DEFAULT_SEARCH_CACHE_TTL_SECONDS,
        }
        fingerprint_options = {
            key: value
            for key, value in options.items()
            if key not in {"original_query_text", "raw_effective_query_text"}
        }
        options_fingerprint = canonical_sha256(fingerprint_options)
        cache_key = canonical_sha256(
            {
                "case_id": case_id,
                "evidence_scope": evidence_ids or [],
                "query_fingerprint": options_fingerprint,
                "keyword_set_version": effective_keyword_set_version,
                "index_revision": index_revision,
                "source_revision_fingerprint": source_revision_fingerprint,
                "time_range": {"from": options["time_from"], "to": options["time_to"]},
                "filters": filters or {},
                "cursor": cursor,
                "sort": sort,
            }
        )
        now = self._clock.now()
        query = SearchQuery(
            query_id=self._id_generator.new_id(),
            query_text=effective_query_text,
            query_mode=query_mode,
            case_id=case_id,
            evidence_ids=tuple(evidence_ids or ()),
            source_types=tuple(source_types or ()),
            document_types=tuple(document_types or ()),
            time_range={"from": time_from_json, "to": time_to_json},
            path_scope=path_scope,
            filters=filters or {},
            keyword_set_id=keyword_set_id,
            keyword_set_version=effective_keyword_set_version,
            index_revision=index_revision,
            options_fingerprint=options_fingerprint,
            created_at=now,
            sort=sort,
            limit=limit,
            case_sensitive=case_sensitive,
        )
        self._search_repository.save_search_query(query)
        execution = SearchExecution(
            execution_id=self._id_generator.new_id(),
            query_id=query.query_id,
            case_id=case_id,
            query_text=effective_query_text,
            query_mode=query_mode,
            keyword_set_id=keyword_set_id,
            keyword_set_version=effective_keyword_set_version,
            options=options,
            options_fingerprint=options_fingerprint,
            search_backend=capability.backend,
            search_backend_version=capability.backend_version,
            index_revision=index_revision,
            source_revision_fingerprint=source_revision_fingerprint,
            started_at=now,
            cache_key=cache_key,
        )
        self._search_repository.save_search_execution(execution)
        cache_entry = self._search_repository.get_search_cache(cache_key) if use_cache else None
        cache_results: list[SearchResult] = []
        if cache_entry is not None:
            self._search_repository.record_search_cache_hit(cache_key)
            results = [
                self._result_from_schema(item, query_id=query.query_id)
                for item in cache_entry.results[:limit]
            ]
            result_count = cache_entry.result_count
            cache_hit = True
            has_more = len(cache_entry.results) > limit
        else:
            rows = self._search_index.query_search_documents(
                query=query,
                after=after,
                limit=limit + 1,
            )
            has_more = len(rows) > limit
            cache_results = [self._result_from_row(row, query_id=query.query_id) for row in rows]
            results = cache_results[:limit]
            result_count = self._search_index.count_search_documents(query)
            cache_hit = False
            cache_entry = None
        self._search_repository.save_search_results(results)
        execution.completed_at = self._clock.now()
        execution.status = "SUCCEEDED"
        execution.result_count = result_count
        execution.cache_hit = cache_hit
        execution.is_partial = any(result.is_partial for result in results)
        if index_revision == 0:
            execution.warnings.append(
                {
                    "code": "SEARCH_INDEX_EMPTY",
                    "developer_message": "No search index revision exists for this case.",
                }
            )
        if keyword_set is not None and result_count == 0:
            execution.zero_result_keyword_ids = [
                keyword.keyword_id for keyword in keyword_set.keywords if keyword.enabled
            ]
        self._search_repository.update_search_execution(execution)
        if not cache_hit and use_cache:
            self._search_repository.save_search_cache(
                SearchCacheEntry(
                    cache_key=cache_key,
                    case_id=case_id,
                    query_fingerprint=options_fingerprint,
                    keyword_set_version=effective_keyword_set_version,
                    index_revision=index_revision,
                    source_revision_fingerprint=source_revision_fingerprint,
                    is_partial=execution.is_partial,
                    result_count=result_count,
                    results=[result.to_schema_dict() for result in cache_results],
                    created_at=self._clock.now(),
                )
            )
        next_cursor = _encode_search_cursor(results[-1]) if has_more and results else None
        return SearchResultPage(
            execution=execution,
            query=query,
            results=results,
            page=CursorPage(next_cursor=next_cursor, has_more=has_more, returned=len(results)),
            cache={
                "cache_key": cache_key,
                "hit": cache_hit,
                "ttl_seconds": DEFAULT_SEARCH_CACHE_TTL_SECONDS,
                "partial_cached": execution.is_partial,
            },
            capability=capability,
        )

    def rerun(self, execution_id: str, *, use_cache: bool = True) -> SearchResultPage:
        """Rerun a prior immutable search execution with the same user options."""

        execution = self._search_repository.get_search_execution(execution_id)
        if execution is None:
            raise NotFoundError("SEARCH_EXECUTION_NOT_FOUND", "Search execution not found.")
        query = self._search_repository.get_search_query(execution.query_id)
        if query is None:
            raise StateConflictError("Stored search query is missing.", target="execution_id")
        time_from = query.time_range.get("from")
        time_to = query.time_range.get("to")
        return self.query(
            case_id=query.case_id,
            query_text=execution.options.get("query_text", query.query_text),
            query_mode=query.query_mode,
            evidence_ids=list(query.evidence_ids),
            source_types=list(query.source_types),
            document_types=list(query.document_types),
            time_from=None if time_from is None else parse_timestamp(time_from),
            time_to=None if time_to is None else parse_timestamp(time_to),
            path_scope=query.path_scope,
            filters=query.filters,
            keyword_set_id=query.keyword_set_id,
            keyword_set_version=query.keyword_set_version,
            case_sensitive=query.case_sensitive,
            cursor=execution.options.get("cursor"),
            limit=query.limit,
            sort=query.sort,
            use_cache=use_cache,
        )

    def show_execution(self, execution_id: str, *, limit: int = 100) -> dict[str, Any]:
        """Return one execution and its persisted result page."""

        execution = self._search_repository.get_search_execution(execution_id)
        if execution is None:
            raise NotFoundError("SEARCH_EXECUTION_NOT_FOUND", "Search execution not found.")
        query = self._search_repository.get_search_query(execution.query_id)
        results = self._search_repository.list_search_results(
            query_id=execution.query_id,
            after=None,
            limit=self._validate_limit(limit),
        )
        return {
            "execution": execution.to_schema_dict(),
            "query": None if query is None else query.to_schema_dict(),
            "results": [item.to_schema_dict() for item in results],
        }

    def history(self, *, case_id: str, limit: int = 100) -> list[dict[str, Any]]:
        """Return recent immutable search executions for a case."""

        self._require_case(case_id)
        return [
            item.to_schema_dict()
            for item in self._search_repository.list_search_executions(
                case_id=case_id,
                limit=self._validate_limit(limit),
            )
        ]

    def cache_status(self, *, case_id: str) -> dict[str, Any]:
        """Return cache hit/miss and invalidation state."""

        self._require_case(case_id)
        return self._search_repository.search_cache_status(case_id)

    def create_keyword_set(
        self,
        *,
        case_id: str,
        name: str,
        description: str | None = None,
        created_by: str | None = None,
        keywords: list[dict[str, Any]] | None = None,
        default_options: dict[str, Any] | None = None,
    ) -> KeywordSet:
        """Create a draft keyword set version."""

        self._require_case(case_id)
        now = self._clock.now()
        keyword_set = KeywordSet(
            keyword_set_id=self._id_generator.new_id(),
            keyword_set_version_id=self._id_generator.new_id(),
            case_id=case_id,
            name=_require_non_empty(name, "name"),
            description=description,
            version=1,
            status=KeywordSetStatus.DRAFT,
            created_by=created_by,
            created_at=now,
            updated_at=now,
            keywords=[self._keyword_from_input(item, now) for item in (keywords or [])],
            default_options=default_options or {"case_sensitive": False},
        )
        self._validate_keyword_duplicates(keyword_set.keywords)
        self._search_repository.save_keyword_set(keyword_set)
        return keyword_set

    def list_keyword_sets(
        self,
        *,
        case_id: str,
        status: KeywordSetStatus | None = None,
    ) -> list[KeywordSet]:
        """List latest keyword-set versions for a case."""

        self._require_case(case_id)
        return self._search_repository.list_keyword_sets(
            case_id=case_id,
            status=None if status is None else status.value,
        )

    def get_keyword_set(self, keyword_set_id: str, *, version: int | None = None) -> KeywordSet:
        """Return a keyword set version."""

        keyword_set = self._search_repository.get_keyword_set(
            keyword_set_id=keyword_set_id,
            version=version,
        )
        if keyword_set is None:
            raise NotFoundError("KEYWORD_SET_NOT_FOUND", "Keyword set not found.")
        return keyword_set

    def add_keyword(
        self,
        keyword_set_id: str,
        *,
        term: str,
        keyword_type: KeywordType = KeywordType.OTHER,
        match_mode: KeywordMatchMode = KeywordMatchMode.TERM,
        case_sensitive: bool = False,
        enabled: bool = True,
        notes: str | None = None,
        source: str = "ANALYST",
    ) -> KeywordSet:
        """Add a keyword by creating a new keyword-set version."""

        keyword_set = self.get_keyword_set(keyword_set_id)
        now = self._clock.now()
        keyword = Keyword(
            keyword_id=self._id_generator.new_id(),
            term=_require_non_empty(term, "term"),
            keyword_type=keyword_type,
            match_mode=match_mode,
            case_sensitive=case_sensitive,
            enabled=enabled,
            notes=notes,
            source=source,
            created_at=now,
        )
        self._validate_keyword(keyword)
        return self._new_keyword_set_version(
            keyword_set,
            keywords=[*keyword_set.keywords, keyword],
            status=KeywordSetStatus.DRAFT,
        )

    def remove_keyword(self, keyword_set_id: str, *, keyword_id: str) -> KeywordSet:
        """Remove a keyword by creating a new keyword-set version."""

        keyword_set = self.get_keyword_set(keyword_set_id)
        keywords = [keyword for keyword in keyword_set.keywords if keyword.keyword_id != keyword_id]
        if len(keywords) == len(keyword_set.keywords):
            raise NotFoundError("KEYWORD_NOT_FOUND", "Keyword not found.", target="keyword_id")
        return self._new_keyword_set_version(
            keyword_set,
            keywords=keywords,
            status=KeywordSetStatus.DRAFT,
        )

    def activate_keyword_set(self, keyword_set_id: str) -> KeywordSet:
        """Create an active version of a keyword set."""

        keyword_set = self.get_keyword_set(keyword_set_id)
        if not keyword_set.keywords:
            raise ValidationError("Cannot activate an empty keyword set.", target="keyword_set_id")
        return self._new_keyword_set_version(
            keyword_set,
            keywords=keyword_set.keywords,
            status=KeywordSetStatus.ACTIVE,
        )

    def archive_keyword_set(self, keyword_set_id: str) -> KeywordSet:
        """Create an archived version of a keyword set."""

        keyword_set = self.get_keyword_set(keyword_set_id)
        return self._new_keyword_set_version(
            keyword_set,
            keywords=keyword_set.keywords,
            status=KeywordSetStatus.ARCHIVED,
        )

    def version_keyword_set(self, keyword_set_id: str) -> KeywordSet:
        """Create a new draft version preserving the current keywords."""

        keyword_set = self.get_keyword_set(keyword_set_id)
        return self._new_keyword_set_version(
            keyword_set,
            keywords=keyword_set.keywords,
            status=KeywordSetStatus.DRAFT,
        )

    def _run_index(
        self,
        state: _SearchRunState,
        *,
        after_source: tuple[str, str] | None,
    ) -> tuple[Job, dict[str, Any]]:
        state.job.status = JobStatus.RUNNING
        state.job.started_at = state.job.started_at or self._clock.now()
        state.job.finished_at = None
        self._search_repository.update_job(state.job)
        self._search_repository.update_search_job_status(
            state.job.job_id,
            state.job.status.value,
            pause_requested=False,
        )
        next_after = after_source
        while True:
            if self._cancel_requested(state):
                return self._finish_index(state, JobStatus.CANCELLED)
            if self._pause_requested(state):
                return self._finish_index(state, JobStatus.PAUSED)
            if self._budget_reached(state):
                return self._finish_index(state, JobStatus.PARTIAL)
            batch_limit = self._remaining_batch_limit(state)
            rows = self._search_repository.iter_search_source_rows(
                case_id=state.job.case_id,
                evidence_ids=state.options.evidence_ids,
                source_types=tuple(item.value for item in state.options.source_types),
                after_source=next_after,
                limit=batch_limit,
            )
            if not rows:
                return self._finish_index(state, JobStatus.SUCCEEDED)
            documents: list[SearchDocument] = []
            for row in rows:
                source_key = (str(row["source_type"]), str(row["source_id"]))
                state.current_source = source_key
                next_after = source_key
                document_type = str(row["document_type"])
                state.processed_items += 1
                if self._search_repository.search_document_exists_current(
                    case_id=str(row["case_id"]),
                    evidence_id=str(row["evidence_id"]),
                    source_type=str(row["source_type"]),
                    source_id=str(row["source_id"]),
                    source_revision=int(row["source_revision"]),
                    document_type=document_type,
                ):
                    state.skipped_items += 1
                    continue
                self._search_index.mark_search_source_stale(
                    case_id=str(row["case_id"]),
                    evidence_id=str(row["evidence_id"]),
                    source_type=str(row["source_type"]),
                    source_id=str(row["source_id"]),
                    current_source_revision=int(row["source_revision"]),
                )
                documents.append(self._document_from_source_row(row, state))
            if documents:
                state.indexed_items += self._search_index.batch_index_search_documents(documents)
            self._save_index_checkpoint(state)
            self._update_index_progress(state)
            if state.progress_callback is not None:
                state.progress_callback(state.job)

    def _finish_index(
        self,
        state: _SearchRunState,
        status: JobStatus,
    ) -> tuple[Job, dict[str, Any]]:
        now = self._clock.now()
        state.job.status = status
        state.job.finished_at = now
        if status is JobStatus.CANCELLED:
            state.job.cancel_requested_at = now
        state.job.progress.partial_results_available = state.indexed_items > 0
        self._update_index_progress(state)
        self._search_repository.update_job(state.job)
        self._search_repository.update_search_job_status(state.job.job_id, status.value)
        self._save_index_checkpoint(state)
        self._search_repository.invalidate_search_cache(
            case_id=state.job.case_id,
            index_revision=None,
            source_revision_fingerprint=None,
            invalidated_at=to_json_timestamp(now),
        )
        coverage = {
            "job_id": state.job.job_id,
            "case_id": state.job.case_id,
            "status": status.value,
            "profile_type": state.options.profile_type.value,
            "option_fingerprint": state.option_fingerprint,
            "index_revision": state.index_revision,
            "discovered_items": state.processed_items + state.skipped_items,
            "processed_items": state.processed_items,
            "indexed_items": state.indexed_items,
            "skipped_items": state.skipped_items,
            "warning_count": state.warning_count,
            "error_count": state.error_count,
            "current_source": None
            if state.current_source is None
            else {"source_type": state.current_source[0], "source_id": state.current_source[1]},
            "is_partial": status in {JobStatus.PARTIAL, JobStatus.PAUSED, JobStatus.CANCELLED},
            "capability": state.capability.to_schema_dict(),
        }
        return state.job, coverage

    def _document_from_source_row(
        self,
        row: dict[str, Any],
        state: _SearchRunState,
    ) -> SearchDocument:
        now = self._clock.now()
        observed_at = row.get("observed_at_utc")
        source_type = SearchSourceType(str(row["source_type"]))
        source_revision = int(row["source_revision"])
        document_type = SearchDocumentType(str(row["document_type"]))
        source_id = str(row["source_id"])
        document_id = "search-doc-" + canonical_sha256(
            {
                "case_id": row["case_id"],
                "evidence_id": row["evidence_id"],
                "source_type": source_type.value,
                "source_id": source_id,
                "source_revision": source_revision,
                "document_type": document_type.value,
            }
        )
        return SearchDocument(
            document_id=document_id,
            case_id=str(row["case_id"]),
            evidence_id=str(row["evidence_id"]),
            source_type=source_type,
            source_id=source_id,
            source_revision=source_revision,
            document_type=document_type,
            title=str(row["title"]),
            path=row.get("path"),
            normalized_path=None
            if row.get("normalized_path") is None
            else _normalize_search_copy(str(row["normalized_path"])),
            searchable_text=_normalize_search_copy(str(row["searchable_text"])),
            structured_fields=_normalized_structured_fields(row),
            observed_at_utc=None
            if observed_at is None
            else observed_at
            if isinstance(observed_at, datetime)
            else parse_timestamp(str(observed_at)),
            raw_locator=dict(row.get("raw_locator") or {}),
            citations=list(row.get("citations") or []),
            analyzer_id=row.get("analyzer_id"),
            analyzer_version=row.get("analyzer_version"),
            is_partial=bool(row.get("is_partial")),
            created_at=now,
            updated_at=now,
            index_revision=state.index_revision,
            search_backend=state.capability.backend,
            search_backend_version=state.capability.backend_version,
        )

    def _result_from_row(self, row: dict[str, Any], *, query_id: str) -> SearchResult:
        return SearchResult(
            result_id=self._id_generator.new_id(),
            query_id=query_id,
            document_id=str(row["document_id"]),
            source_type=SearchSourceType(str(row["source_type"])),
            source_id=str(row["source_id"]),
            rank=float(row["rank"]),
            matched_fields=list(row.get("matched_fields") or []),
            matched_terms=list(row.get("matched_terms") or []),
            snippet=str(row.get("snippet") or ""),
            raw_locator=dict(row.get("raw_locator") or {}),
            citations=list(row.get("citations") or []),
            is_partial=bool(row.get("is_partial")),
            index_revision=int(row["index_revision"]),
            created_at=self._clock.now(),
        )

    def _result_from_schema(self, data: dict[str, Any], *, query_id: str) -> SearchResult:
        return SearchResult(
            result_id=self._id_generator.new_id(),
            query_id=query_id,
            document_id=str(data["document_id"]),
            source_type=SearchSourceType(str(data["source_type"])),
            source_id=str(data["source_id"]),
            rank=float(data["rank"]),
            matched_fields=list(data.get("matched_fields") or []),
            matched_terms=list(data.get("matched_terms") or []),
            snippet=str(data.get("snippet") or ""),
            raw_locator=dict(data.get("raw_locator") or {}),
            citations=list(data.get("citations") or []),
            is_partial=bool(data.get("is_partial")),
            index_revision=int(data["index_revision"]),
            created_at=self._clock.now(),
        )

    def _new_keyword_set_version(
        self,
        current: KeywordSet,
        *,
        keywords: list[Keyword],
        status: KeywordSetStatus,
    ) -> KeywordSet:
        self._validate_keyword_duplicates(keywords)
        now = self._clock.now()
        keyword_set = KeywordSet(
            keyword_set_id=current.keyword_set_id,
            keyword_set_version_id=self._id_generator.new_id(),
            case_id=current.case_id,
            name=current.name,
            description=current.description,
            version=current.version + 1,
            status=status,
            created_by=current.created_by,
            created_at=current.created_at,
            updated_at=now,
            keywords=keywords,
            default_options=current.default_options,
            previous_version_id=current.keyword_set_version_id,
        )
        self._search_repository.save_keyword_set(keyword_set)
        return keyword_set

    def _keyword_from_input(self, data: dict[str, Any], now: datetime) -> Keyword:
        keyword = Keyword(
            keyword_id=str(data.get("keyword_id") or self._id_generator.new_id()),
            term=_require_non_empty(str(data.get("term") or ""), "term"),
            keyword_type=KeywordType(str(data.get("keyword_type", KeywordType.OTHER.value))),
            match_mode=KeywordMatchMode(str(data.get("match_mode", KeywordMatchMode.TERM.value))),
            case_sensitive=bool(data.get("case_sensitive", False)),
            enabled=bool(data.get("enabled", True)),
            notes=data.get("notes"),
            source=str(data.get("source", "ANALYST")),
            created_at=now,
        )
        self._validate_keyword(keyword)
        return keyword

    def _validate_keyword(self, keyword: Keyword) -> None:
        _require_non_empty(keyword.term, "term")
        if (
            keyword.keyword_type is KeywordType.REGEX
            or keyword.match_mode is KeywordMatchMode.REGEX_METADATA
        ):
            _validate_safe_regex(keyword.term)

    def _validate_keyword_duplicates(self, keywords: list[Keyword]) -> None:
        seen: set[tuple[str, str, bool]] = set()
        for keyword in keywords:
            self._validate_keyword(keyword)
            key = (
                keyword.term if keyword.case_sensitive else keyword.term.casefold(),
                keyword.match_mode.value,
                keyword.case_sensitive,
            )
            if key in seen:
                raise ValidationError("Duplicate keyword.", target="keywords")
            seen.add(key)

    def _effective_query_text(self, query_text: str, keyword_set: KeywordSet | None) -> str:
        text = query_text.strip()
        if keyword_set is None:
            return text
        enabled_terms = [keyword.term for keyword in keyword_set.keywords if keyword.enabled]
        if not text and enabled_terms:
            return " ".join(enabled_terms)
        if enabled_terms:
            return " ".join([text, *enabled_terms]).strip()
        return text

    def _options_from_dict(self, data: dict[str, Any]) -> SearchIndexOptions:
        return SearchIndexOptions(
            profile_type=AnalysisProfileType(str(data["profile_type"])),
            evidence_ids=tuple(str(item) for item in data.get("evidence_ids", [])),
            source_types=tuple(
                SearchSourceType(str(item))
                for item in data.get(
                    "source_types",
                    [
                        SearchSourceType.FILE_SYSTEM_NODE.value,
                        SearchSourceType.WINDOWS_ARTIFACT.value,
                    ],
                )
            ),
            item_budget=data.get("item_budget"),
            batch_size=int(data.get("batch_size", 100)),
        )

    def _get_search_job(self, job_id: str) -> dict[str, Any]:
        metadata = self._search_repository.get_search_job(job_id)
        if metadata is None:
            raise NotFoundError("SEARCH_JOB_NOT_FOUND", "Search job not found.", target="job_id")
        return metadata

    def _get_job(self, job_id: str) -> Job:
        job = self._search_repository.get_job(job_id)
        if job is None:
            raise NotFoundError("JOB_NOT_FOUND", "Job not found.", target="job_id")
        if job.job_type is not JobType.SEARCH_INDEX:
            raise ValidationError("Job is not a search index job.", target="job_id")
        return job

    def _require_case(self, case_id: str) -> None:
        if self._case_repository.get_case(case_id) is None:
            raise NotFoundError("CASE_NOT_FOUND", "Case not found.", target="case_id")

    def _require_available_capability(self) -> SearchIndexCapability:
        capability = self.capability()
        if not capability.is_available:
            raise UnsupportedCapabilityError(
                "SQLite FTS5 is not available; search cannot be executed.",
                required_capability="SQLITE_FTS5",
            )
        return capability

    def _validate_query(self, query_text: str, query_mode: SearchQueryMode) -> None:
        if not query_text.strip():
            raise ValidationError("Search query cannot be empty.", target="query")
        if len(query_text) > MAX_QUERY_LENGTH:
            raise ValidationError(
                f"Search query cannot exceed {MAX_QUERY_LENGTH} characters.",
                target="query",
            )
        if query_mode is SearchQueryMode.REGEX_METADATA:
            _validate_safe_regex(query_text)

    def _validate_limit(self, limit: int) -> int:
        if limit < 1 or limit > MAX_QUERY_LIMIT:
            raise ValidationError(
                f"Limit must be between 1 and {MAX_QUERY_LIMIT}.",
                target="limit",
            )
        return limit

    @staticmethod
    def _validate_batch_size(batch_size: int) -> None:
        if batch_size < 1 or batch_size > 5000:
            raise ValidationError("Batch size must be between 1 and 5000.", target="batch_size")

    def _remaining_batch_limit(self, state: _SearchRunState) -> int:
        if state.options.item_budget is None:
            return state.options.batch_size
        remaining = max(state.options.item_budget - state.processed_items, 0)
        return max(1, min(state.options.batch_size, remaining))

    @staticmethod
    def _budget_reached(state: _SearchRunState) -> bool:
        return (
            state.options.item_budget is not None
            and state.processed_items >= state.options.item_budget
        )

    @staticmethod
    def _cancel_requested(state: _SearchRunState) -> bool:
        return bool(state.cancellation_token is not None and state.cancellation_token.is_cancelled)

    @staticmethod
    def _pause_requested(state: _SearchRunState) -> bool:
        return bool(state.pause_token is not None and state.pause_token.is_pause_requested)

    def _update_index_progress(self, state: _SearchRunState) -> None:
        elapsed = max(time.monotonic() - state.run_started, 0.001)
        state.job.progress.current = state.processed_items
        state.job.progress.processed_items = state.processed_items
        state.job.progress.discovered_items = state.processed_items + state.skipped_items
        state.job.progress.skipped_items = state.skipped_items
        state.job.progress.warning_count = state.warning_count
        state.job.progress.error_count = state.error_count
        state.job.progress.elapsed_seconds = elapsed
        state.job.progress.throughput_items_per_second = state.processed_items / elapsed
        state.job.progress.estimate_confidence = "LOW"
        state.job.progress.current_analyzer = "search.index"
        if state.current_source is not None:
            state.job.progress.current_path = f"{state.current_source[0]}:{state.current_source[1]}"

    def _save_index_checkpoint(self, state: _SearchRunState) -> None:
        self._search_repository.save_search_checkpoint(
            job_id=state.job.job_id,
            current_source_type=None if state.current_source is None else state.current_source[0],
            current_source_id=None if state.current_source is None else state.current_source[1],
            processed_items=state.processed_items,
            indexed_items=state.indexed_items,
            skipped_items=state.skipped_items,
        )


def _encode_search_cursor(result: SearchResult) -> str:
    payload = {"rank": result.rank, "document_id": result.document_id}
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _decode_search_cursor(cursor: str | None) -> tuple[float, str] | None:
    if cursor is None:
        return None
    try:
        padded = cursor + "=" * (-len(cursor) % 4)
        data = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8"))
        return float(data["rank"]), str(data["document_id"])
    except (KeyError, ValueError, TypeError, json.JSONDecodeError) as error:
        raise ValidationError("Invalid search cursor.", target="cursor") from error


def _require_non_empty(value: str, target: str) -> str:
    stripped = value.strip()
    if not stripped:
        raise ValidationError("Value cannot be empty.", target=target)
    return stripped


def _validate_safe_regex(pattern: str) -> None:
    if len(pattern) > MAX_REGEX_LENGTH:
        raise ValidationError("Regex keyword is too long.", target="regex")
    try:
        re.compile(pattern)
    except re.error as error:
        raise ValidationError(
            "Invalid regex.",
            target="regex",
            details={"error": str(error)},
        ) from error
    lexical = _regex_lexical_tokens(pattern)
    if re.search(r"\\[1-9]", lexical) or "(?P=" in lexical:
        raise ValidationError("Regex backreferences are not allowed.", target="regex")
    if "(?" in lexical:
        raise ValidationError("Extended regex groups are not allowed.", target="regex")
    if "|" in lexical:
        raise ValidationError("Regex alternation is not allowed.", target="regex")
    if re.search(r"\)(?:[*+?]|\{\d+(?:,\d*)?\})", lexical):
        raise ValidationError("Quantified regex groups are not allowed.", target="regex")
    variable_quantifiers = len(re.findall(r"(?<!\\)[*+?]", lexical))
    variable_quantifiers += len(re.findall(r"(?<!\\)\{\d+,\d*\}", lexical))
    if variable_quantifiers > 1:
        raise ValidationError(
            "Regex may contain at most one variable quantifier.",
            target="regex",
        )
    for match in re.finditer(r"(?<!\\)\{(\d+)(?:,(\d*))?\}", lexical):
        upper_text = match.group(2)
        upper = int(upper_text) if upper_text else int(match.group(1))
        if upper > MAX_REGEX_BOUNDED_REPEAT:
            raise ValidationError("Regex bounded repeat is too large.", target="regex")


def _regex_lexical_tokens(pattern: str) -> str:
    """Mask character classes while retaining escaped backreference syntax."""

    output: list[str] = []
    in_class = False
    index = 0
    while index < len(pattern):
        character = pattern[index]
        if character == "\\" and index + 1 < len(pattern):
            escaped = pattern[index : index + 2]
            output.append(escaped if not in_class else "__")
            index += 2
            continue
        if character == "[" and not in_class:
            in_class = True
            output.append("_")
        elif character == "]" and in_class:
            in_class = False
            output.append("_")
        else:
            output.append("_" if in_class else character)
        index += 1
    return "".join(output)
