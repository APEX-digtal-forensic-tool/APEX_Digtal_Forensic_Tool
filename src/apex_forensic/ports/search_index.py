"""Provider-neutral search index and keyword repository ports."""

from __future__ import annotations

from typing import Any, Protocol

from apex_forensic.domain.models import (
    Job,
    Keyword,
    KeywordSet,
    SearchCacheEntry,
    SearchDocument,
    SearchExecution,
    SearchIndexCapability,
    SearchQuery,
    SearchResult,
)


class SearchIndexProvider(Protocol):
    """Search backend boundary used by the application layer."""

    def search_capability(self) -> SearchIndexCapability: ...
    def index_search_document(self, document: SearchDocument) -> None: ...
    def batch_index_search_documents(self, documents: list[SearchDocument]) -> int: ...
    def mark_search_source_stale(
        self,
        *,
        case_id: str,
        evidence_id: str,
        source_type: str,
        source_id: str,
        current_source_revision: int,
    ) -> None: ...
    def query_search_documents(
        self,
        *,
        query: SearchQuery,
        after: tuple[float, str] | None,
        limit: int,
    ) -> list[dict[str, Any]]: ...
    def count_search_documents(self, query: SearchQuery) -> int: ...
    def rebuild_search_index(self, *, case_id: str | None = None) -> int: ...
    def optimize_search_index(self) -> None: ...
    def next_search_index_revision(self, case_id: str) -> int: ...
    def current_search_index_revision(self, case_id: str) -> int: ...
    def search_backend_version(self) -> str: ...


class SearchRepository(Protocol):
    """Persistence operations for search jobs, reproduction, cache, and keyword sets."""

    def save_job(self, job: Job) -> None: ...
    def update_job(self, job: Job) -> None: ...
    def get_job(self, job_id: str) -> Job | None: ...
    def create_search_job(
        self,
        *,
        job_id: str,
        case_id: str,
        evidence_id: str | None,
        profile_type: str,
        options: dict[str, Any],
        option_fingerprint: str,
        index_revision: int,
        status: str,
        created_at: str,
    ) -> None: ...
    def update_search_job_status(
        self,
        job_id: str,
        status: str,
        *,
        pause_requested: bool | None = None,
    ) -> None: ...
    def get_search_job(self, job_id: str) -> dict[str, Any] | None: ...
    def save_search_checkpoint(
        self,
        *,
        job_id: str,
        current_source_type: str | None,
        current_source_id: str | None,
        processed_items: int,
        indexed_items: int,
        skipped_items: int,
    ) -> None: ...
    def get_search_checkpoint(self, job_id: str) -> dict[str, Any] | None: ...
    def iter_search_source_rows(
        self,
        *,
        case_id: str,
        evidence_ids: tuple[str, ...],
        source_types: tuple[str, ...],
        after_source: tuple[str, str] | None,
        limit: int,
    ) -> list[dict[str, Any]]: ...
    def search_document_exists_current(
        self,
        *,
        case_id: str,
        evidence_id: str,
        source_type: str,
        source_id: str,
        source_revision: int,
        document_type: str,
    ) -> bool: ...
    def search_source_revision_fingerprint(
        self,
        *,
        case_id: str,
        evidence_ids: tuple[str, ...],
        source_types: tuple[str, ...],
    ) -> str: ...
    def save_search_query(self, query: SearchQuery) -> None: ...
    def save_search_execution(self, execution: SearchExecution) -> None: ...
    def update_search_execution(self, execution: SearchExecution) -> None: ...
    def get_search_query(self, query_id: str) -> SearchQuery | None: ...
    def get_search_execution(self, execution_id: str) -> SearchExecution | None: ...
    def list_search_executions(
        self,
        *,
        case_id: str,
        limit: int,
    ) -> list[SearchExecution]: ...
    def save_search_results(self, results: list[SearchResult]) -> None: ...
    def list_search_results(
        self,
        *,
        query_id: str,
        after: tuple[float, str] | None,
        limit: int,
    ) -> list[SearchResult]: ...
    def get_search_cache(self, cache_key: str) -> SearchCacheEntry | None: ...
    def save_search_cache(self, entry: SearchCacheEntry) -> None: ...
    def record_search_cache_hit(self, cache_key: str) -> None: ...
    def invalidate_search_cache(
        self,
        *,
        case_id: str | None,
        index_revision: int | None,
        source_revision_fingerprint: str | None,
        invalidated_at: str,
    ) -> int: ...
    def search_cache_status(self, case_id: str) -> dict[str, Any]: ...
    def save_keyword_set(self, keyword_set: KeywordSet) -> None: ...
    def get_keyword_set(
        self,
        *,
        keyword_set_id: str,
        version: int | None = None,
    ) -> KeywordSet | None: ...
    def list_keyword_sets(
        self,
        *,
        case_id: str,
        status: str | None = None,
    ) -> list[KeywordSet]: ...
    def save_keywords_for_version(
        self,
        *,
        keyword_set_version_id: str,
        keywords: list[Keyword],
    ) -> None: ...
