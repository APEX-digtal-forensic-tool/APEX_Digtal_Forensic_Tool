"""Search and keyword-set domain models."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from apex_forensic._time import to_json_timestamp
from apex_forensic.domain.enums import (
    KeywordMatchMode,
    KeywordSetStatus,
    KeywordType,
    SearchDocumentType,
    SearchQueryMode,
    SearchSourceType,
)
from apex_forensic.domain.models.filesystem import CursorPage


def _nullable_timestamp(value: datetime | None) -> str | None:
    return None if value is None else to_json_timestamp(value)


@dataclass(slots=True)
class SearchIndexCapability:
    """Runtime capability statement for a search backend."""

    backend: str
    backend_version: str
    fts5_available: bool
    tokenizer: str
    capabilities: list[str] = field(default_factory=list)
    unavailable_capabilities: list[str] = field(default_factory=list)
    warnings: list[dict[str, Any]] = field(default_factory=list)

    @property
    def is_available(self) -> bool:
        return self.fts5_available and not self.unavailable_capabilities

    def to_schema_dict(self) -> dict[str, Any]:
        return {
            "backend": self.backend,
            "backend_version": self.backend_version,
            "fts5_available": self.fts5_available,
            "tokenizer": self.tokenizer,
            "capabilities": self.capabilities,
            "unavailable_capabilities": self.unavailable_capabilities,
            "warnings": self.warnings,
            "is_available": self.is_available,
        }


@dataclass(slots=True)
class SearchDocument:
    """A searchable projection of filesystem metadata, artifacts, or timeline events."""

    document_id: str
    case_id: str
    evidence_id: str
    source_type: SearchSourceType
    source_id: str
    source_revision: int
    document_type: SearchDocumentType
    title: str
    path: str | None
    normalized_path: str | None
    searchable_text: str
    structured_fields: dict[str, Any]
    observed_at_utc: datetime | None
    raw_locator: dict[str, Any]
    citations: list[dict[str, Any]]
    analyzer_id: str | None
    analyzer_version: str | None
    is_partial: bool
    created_at: datetime
    updated_at: datetime
    index_revision: int = 1
    search_backend: str = "sqlite-fts5"
    search_backend_version: str = "unknown"
    is_stale: bool = False

    def to_schema_dict(self) -> dict[str, Any]:
        return {
            "document_id": self.document_id,
            "case_id": self.case_id,
            "evidence_id": self.evidence_id,
            "source_type": self.source_type.value,
            "source_id": self.source_id,
            "source_revision": self.source_revision,
            "document_type": self.document_type.value,
            "title": self.title,
            "path": self.path,
            "normalized_path": self.normalized_path,
            "searchable_text": self.searchable_text,
            "structured_fields": self.structured_fields,
            "observed_at_utc": _nullable_timestamp(self.observed_at_utc),
            "raw_locator": self.raw_locator,
            "citations": self.citations,
            "analyzer_id": self.analyzer_id,
            "analyzer_version": self.analyzer_version,
            "is_partial": self.is_partial,
            "created_at": to_json_timestamp(self.created_at),
            "updated_at": to_json_timestamp(self.updated_at),
            "index_revision": self.index_revision,
            "search_backend": self.search_backend,
            "search_backend_version": self.search_backend_version,
            "is_stale": self.is_stale,
        }


@dataclass(frozen=True, slots=True)
class SearchQuery:
    """Immutable search query options used for reproduction."""

    query_id: str
    query_text: str
    query_mode: SearchQueryMode
    case_id: str
    evidence_ids: tuple[str, ...] = ()
    source_types: tuple[SearchSourceType, ...] = ()
    document_types: tuple[SearchDocumentType, ...] = ()
    time_range: dict[str, str | None] = field(default_factory=dict)
    path_scope: str | None = None
    filters: dict[str, Any] = field(default_factory=dict)
    keyword_set_id: str | None = None
    keyword_set_version: int | None = None
    index_revision: int | None = None
    options_fingerprint: str = ""
    created_at: datetime | None = None
    sort: str = "rank"
    limit: int = 100
    case_sensitive: bool = False

    def to_schema_dict(self) -> dict[str, Any]:
        return {
            "query_id": self.query_id,
            "query_text": self.query_text,
            "query_mode": self.query_mode.value,
            "case_id": self.case_id,
            "evidence_ids": list(self.evidence_ids),
            "source_types": [item.value for item in self.source_types],
            "document_types": [item.value for item in self.document_types],
            "time_range": self.time_range,
            "path_scope": self.path_scope,
            "filters": self.filters,
            "keyword_set_id": self.keyword_set_id,
            "keyword_set_version": self.keyword_set_version,
            "index_revision": self.index_revision,
            "options_fingerprint": self.options_fingerprint,
            "created_at": None if self.created_at is None else to_json_timestamp(self.created_at),
            "sort": self.sort,
            "limit": self.limit,
            "case_sensitive": self.case_sensitive,
        }


@dataclass(slots=True)
class SearchResult:
    """One persisted search result hit."""

    result_id: str
    query_id: str
    document_id: str
    source_type: SearchSourceType
    source_id: str
    rank: float
    matched_fields: list[str]
    matched_terms: list[str]
    snippet: str
    raw_locator: dict[str, Any]
    citations: list[dict[str, Any]]
    is_partial: bool
    index_revision: int
    created_at: datetime

    def to_schema_dict(self) -> dict[str, Any]:
        return {
            "result_id": self.result_id,
            "query_id": self.query_id,
            "document_id": self.document_id,
            "source_type": self.source_type.value,
            "source_id": self.source_id,
            "rank": self.rank,
            "matched_fields": self.matched_fields,
            "matched_terms": self.matched_terms,
            "snippet": self.snippet,
            "raw_locator": self.raw_locator,
            "citations": self.citations,
            "is_partial": self.is_partial,
            "index_revision": self.index_revision,
            "created_at": to_json_timestamp(self.created_at),
        }


@dataclass(slots=True)
class SearchExecution:
    """Immutable reproduction record for one search run."""

    execution_id: str
    query_id: str
    case_id: str
    query_text: str
    query_mode: SearchQueryMode
    keyword_set_id: str | None
    keyword_set_version: int | None
    options: dict[str, Any]
    options_fingerprint: str
    search_backend: str
    search_backend_version: str
    index_revision: int
    source_revision_fingerprint: str
    started_at: datetime
    completed_at: datetime | None = None
    status: str = "RUNNING"
    is_partial: bool = False
    result_count: int = 0
    warnings: list[dict[str, Any]] = field(default_factory=list)
    cache_key: str | None = None
    cache_hit: bool = False
    zero_result_keyword_ids: list[str] = field(default_factory=list)
    execution_revision: int = 1

    def to_schema_dict(self) -> dict[str, Any]:
        return {
            "execution_id": self.execution_id,
            "query_id": self.query_id,
            "case_id": self.case_id,
            "query_text": self.query_text,
            "query_mode": self.query_mode.value,
            "keyword_set_id": self.keyword_set_id,
            "keyword_set_version": self.keyword_set_version,
            "options": self.options,
            "options_fingerprint": self.options_fingerprint,
            "search_backend": self.search_backend,
            "search_backend_version": self.search_backend_version,
            "index_revision": self.index_revision,
            "source_revision_fingerprint": self.source_revision_fingerprint,
            "started_at": to_json_timestamp(self.started_at),
            "completed_at": _nullable_timestamp(self.completed_at),
            "status": self.status,
            "is_partial": self.is_partial,
            "result_count": self.result_count,
            "warnings": self.warnings,
            "cache_key": self.cache_key,
            "cache_hit": self.cache_hit,
            "zero_result_keyword_ids": self.zero_result_keyword_ids,
            "execution_revision": self.execution_revision,
        }


@dataclass(slots=True)
class SearchCacheEntry:
    """Cached page of search results keyed by immutable query and revision state."""

    cache_key: str
    case_id: str
    query_fingerprint: str
    keyword_set_version: int | None
    index_revision: int
    source_revision_fingerprint: str
    is_partial: bool
    result_count: int
    results: list[dict[str, Any]]
    created_at: datetime
    expires_at: datetime | None = None
    hit_count: int = 0
    invalidated_at: datetime | None = None

    def to_schema_dict(self) -> dict[str, Any]:
        return {
            "cache_key": self.cache_key,
            "case_id": self.case_id,
            "query_fingerprint": self.query_fingerprint,
            "keyword_set_version": self.keyword_set_version,
            "index_revision": self.index_revision,
            "source_revision_fingerprint": self.source_revision_fingerprint,
            "is_partial": self.is_partial,
            "result_count": self.result_count,
            "results": self.results,
            "created_at": to_json_timestamp(self.created_at),
            "expires_at": _nullable_timestamp(self.expires_at),
            "hit_count": self.hit_count,
            "invalidated_at": _nullable_timestamp(self.invalidated_at),
        }


@dataclass(slots=True)
class Keyword:
    """One manually managed keyword entry."""

    keyword_id: str
    term: str
    keyword_type: KeywordType
    match_mode: KeywordMatchMode
    case_sensitive: bool
    enabled: bool
    notes: str | None
    source: str
    created_at: datetime

    def to_schema_dict(self) -> dict[str, Any]:
        return {
            "keyword_id": self.keyword_id,
            "term": self.term,
            "keyword_type": self.keyword_type.value,
            "match_mode": self.match_mode.value,
            "case_sensitive": self.case_sensitive,
            "enabled": self.enabled,
            "notes": self.notes,
            "source": self.source,
            "created_at": to_json_timestamp(self.created_at),
        }


@dataclass(slots=True)
class KeywordSet:
    """Versioned manual keyword set."""

    keyword_set_id: str
    case_id: str
    name: str
    description: str | None
    version: int
    status: KeywordSetStatus
    created_by: str | None
    created_at: datetime
    updated_at: datetime
    keywords: list[Keyword]
    default_options: dict[str, Any]
    previous_version_id: str | None = None
    keyword_set_version_id: str | None = None

    def to_schema_dict(self) -> dict[str, Any]:
        return {
            "keyword_set_id": self.keyword_set_id,
            "case_id": self.case_id,
            "name": self.name,
            "description": self.description,
            "version": self.version,
            "status": self.status.value,
            "created_by": self.created_by,
            "created_at": to_json_timestamp(self.created_at),
            "updated_at": to_json_timestamp(self.updated_at),
            "keywords": [item.to_schema_dict() for item in self.keywords],
            "default_options": self.default_options,
            "previous_version_id": self.previous_version_id,
            "keyword_set_version_id": self.keyword_set_version_id,
        }


@dataclass(slots=True)
class SearchResultPage:
    """Search results plus reproduction, cache, and cursor metadata."""

    execution: SearchExecution
    query: SearchQuery
    results: list[SearchResult]
    page: CursorPage
    cache: dict[str, Any]
    capability: SearchIndexCapability

    def to_schema_dict(self) -> dict[str, Any]:
        return {
            "execution": self.execution.to_schema_dict(),
            "query": self.query.to_schema_dict(),
            "results": [item.to_schema_dict() for item in self.results],
            "page": self.page.to_schema_dict(),
            "cache": self.cache,
            "capability": self.capability.to_schema_dict(),
        }
