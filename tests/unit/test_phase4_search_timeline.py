from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from apex_forensic.application.services.timeline import normalize_timestamp
from apex_forensic.config import build_services
from apex_forensic.domain.enums import (
    AnalysisProfileType,
    FileSystemNodeType,
    KeywordMatchMode,
    KeywordType,
    SearchDocumentType,
    SearchQueryMode,
    SearchSourceType,
    TimelineEventType,
    TimelineSourceType,
    TimezoneSource,
)
from apex_forensic.domain.errors import ValidationError
from apex_forensic.domain.models import FileSystemNode
from apex_forensic.jobs import CancellationToken, PauseToken


def _indexed_case(services, root: Path):
    root.mkdir()
    (root / "한글-secret report.txt").write_text("body is not indexed", encoding="utf-8")
    (root / "notes.log").write_text("another body", encoding="utf-8")
    case = services.cases.create_case(name="Phase 4", investigator="analyst")
    evidence = services.evidence.register_evidence(case_id=case.case_id, source_path=root)
    services.fs.index_evidence(
        case_id=case.case_id,
        evidence_id=evidence.evidence_id,
        profile_type=AnalysisProfileType.FULL_ANALYSIS,
    )
    return case, evidence


def _indexed_search_case_with_names(services, root: Path, names: list[str]):
    root.mkdir()
    for name in names:
        (root / name).write_text("body is not indexed", encoding="utf-8")
    case = services.cases.create_case(name=f"Phase 4 {root.name}", investigator="analyst")
    evidence = services.evidence.register_evidence(case_id=case.case_id, source_path=root)
    services.fs.index_evidence(
        case_id=case.case_id,
        evidence_id=evidence.evidence_id,
        profile_type=AnalysisProfileType.FULL_ANALYSIS,
    )
    services.search.index(
        case_id=case.case_id,
        evidence_ids=[evidence.evidence_id],
        source_types=[SearchSourceType.FILE_SYSTEM_NODE],
    )
    return case, evidence


def _result_document_ids(page) -> list[str]:
    return [item.document_id for item in page.results]


def test_search_modes_cache_reproduction_and_schema(
    services,
    tmp_path: Path,
    schema_validator,
) -> None:
    case, evidence = _indexed_case(services, tmp_path / "evidence")
    job, coverage = services.search.index(
        case_id=case.case_id,
        evidence_ids=[evidence.evidence_id],
        source_types=[SearchSourceType.FILE_SYSTEM_NODE],
    )

    assert job.status == "SUCCEEDED"
    assert coverage["indexed_items"] >= 3
    assert services.search.capability().fts5_available is True

    term = services.search.query(case_id=case.case_id, query_text="한글", limit=10)
    phrase = services.search.query(
        case_id=case.case_id,
        query_text="secret report",
        query_mode=SearchQueryMode.PHRASE,
        limit=10,
    )
    prefix = services.search.query(
        case_id=case.case_id,
        query_text="sec",
        query_mode=SearchQueryMode.PREFIX,
        limit=10,
    )
    exact = services.search.query(
        case_id=case.case_id,
        query_text="한글-secret report.txt",
        query_mode=SearchQueryMode.EXACT,
        limit=10,
    )
    regex = services.search.query(
        case_id=case.case_id,
        query_text=r"secret.*txt",
        query_mode=SearchQueryMode.REGEX_METADATA,
        document_types=[SearchDocumentType.FILE],
        limit=10,
    )
    injection = services.search.query(
        case_id=case.case_id,
        query_text='" OR 1=1 --',
        limit=10,
    )
    cached = services.search.query(case_id=case.case_id, query_text="한글", limit=10)
    zero = services.search.query(case_id=case.case_id, query_text="missing-term", limit=10)

    assert term.execution.result_count == 1
    assert phrase.execution.result_count == 1
    assert prefix.execution.result_count == 1
    assert exact.execution.result_count == 1
    assert regex.execution.result_count == 1
    assert injection.execution.result_count == 0
    assert cached.execution.cache_hit is True
    assert zero.execution.result_count == 0
    shown = services.search.show_execution(zero.execution.execution_id)
    assert shown["execution"]["result_count"] == 0
    assert services.search.history(case_id=case.case_id, limit=20)

    before_reindex = services.search.cache_status(case_id=case.case_id)
    services.search.index(case_id=case.case_id, evidence_ids=[evidence.evidence_id])
    after_reindex = services.search.cache_status(case_id=case.case_id)
    fresh = services.search.query(case_id=case.case_id, query_text="한글", limit=10)

    assert before_reindex["active_entries"] >= 1
    assert after_reindex["invalidated_entries"] >= before_reindex["active_entries"]
    assert fresh.execution.cache_hit is False

    schema_validator.validate("search.schema.json", term.to_schema_dict())
    schema_validator.validate("search.schema.json", term.results[0].to_schema_dict())
    schema_validator.validate("search.schema.json", term.query.to_schema_dict())
    schema_validator.validate("search.schema.json", term.execution.to_schema_dict())


def test_search_cache_preserves_paginated_pages(services, tmp_path: Path) -> None:
    case, _ = _indexed_search_case_with_names(
        services,
        tmp_path / "search-pagination",
        [f"cacheterm-{index}.txt" for index in range(5)],
    )

    first = services.search.query(case_id=case.case_id, query_text="cacheterm", limit=2)
    cached_first = services.search.query(case_id=case.case_id, query_text="cacheterm", limit=2)
    second = services.search.query(
        case_id=case.case_id,
        query_text="cacheterm",
        cursor=first.page.next_cursor,
        limit=2,
    )
    cached_second = services.search.query(
        case_id=case.case_id,
        query_text="cacheterm",
        cursor=first.page.next_cursor,
        limit=2,
    )

    assert first.execution.result_count >= 5
    assert first.page.has_more is True
    assert first.page.next_cursor is not None
    assert cached_first.execution.cache_hit is True
    assert cached_first.page.has_more == first.page.has_more
    assert cached_first.page.next_cursor == first.page.next_cursor
    assert _result_document_ids(cached_first) == _result_document_ids(first)
    assert second.execution.cache_hit is False
    assert second.cache["cache_key"] != first.cache["cache_key"]
    assert set(_result_document_ids(first)).isdisjoint(_result_document_ids(second))
    assert cached_second.execution.cache_hit is True
    assert cached_second.page.has_more == second.page.has_more
    assert cached_second.page.next_cursor == second.page.next_cursor
    assert _result_document_ids(cached_second) == _result_document_ids(second)


def test_search_rebuild_invalidates_only_case_scope(services, tmp_path: Path) -> None:
    case_a, _ = _indexed_search_case_with_names(
        services,
        tmp_path / "case-scope-a",
        ["scope-alpha.txt"],
    )
    case_b, _ = _indexed_search_case_with_names(
        services,
        tmp_path / "case-scope-b",
        ["scope-beta.txt"],
    )
    services.search.query(case_id=case_a.case_id, query_text="scope", limit=10)
    services.search.query(case_id=case_b.case_id, query_text="scope", limit=10)

    services.search.rebuild(case_id=case_a.case_id)
    status_a = services.search.cache_status(case_id=case_a.case_id)
    status_b = services.search.cache_status(case_id=case_b.case_id)
    fresh_a = services.search.query(case_id=case_a.case_id, query_text="scope", limit=10)
    cached_b = services.search.query(case_id=case_b.case_id, query_text="scope", limit=10)

    assert status_a["active_entries"] == 0
    assert status_a["invalidated_entries"] >= 1
    assert status_b["active_entries"] == 1
    assert status_b["invalidated_entries"] == 0
    assert fresh_a.execution.cache_hit is False
    assert cached_b.execution.cache_hit is True


def test_search_rebuild_invalidates_global_cache_scope(services, tmp_path: Path) -> None:
    case_a, _ = _indexed_search_case_with_names(
        services,
        tmp_path / "global-scope-a",
        ["global-alpha.txt"],
    )
    case_b, _ = _indexed_search_case_with_names(
        services,
        tmp_path / "global-scope-b",
        ["global-beta.txt"],
    )
    services.search.query(case_id=case_a.case_id, query_text="global", limit=10)
    services.search.query(case_id=case_b.case_id, query_text="global", limit=10)

    services.search.rebuild()
    status_a = services.search.cache_status(case_id=case_a.case_id)
    status_b = services.search.cache_status(case_id=case_b.case_id)
    fresh_a = services.search.query(case_id=case_a.case_id, query_text="global", limit=10)
    fresh_b = services.search.query(case_id=case_b.case_id, query_text="global", limit=10)

    assert status_a["active_entries"] == 0
    assert status_a["invalidated_entries"] >= 1
    assert status_b["active_entries"] == 0
    assert status_b["invalidated_entries"] >= 1
    assert fresh_a.execution.cache_hit is False
    assert fresh_b.execution.cache_hit is False


def test_keyword_set_versioning_duplicate_and_regex_validation(services, tmp_path: Path) -> None:
    case, _ = _indexed_case(services, tmp_path / "kw-evidence")
    keyword_set = services.search.create_keyword_set(
        case_id=case.case_id,
        name="Manual Keywords",
        keywords=[{"term": "한글", "keyword_type": "DOCUMENT_TERM"}],
    )
    version_two = services.search.add_keyword(
        keyword_set.keyword_set_id,
        term="secret",
        keyword_type=KeywordType.FILE_NAME,
    )

    assert keyword_set.version == 1
    assert version_two.version == 2
    assert version_two.previous_version_id == keyword_set.keyword_set_version_id
    with pytest.raises(ValidationError):
        services.search.add_keyword(version_two.keyword_set_id, term="secret")
    with pytest.raises(ValidationError):
        services.search.add_keyword(
            version_two.keyword_set_id,
            term=r"(.*)+",
            keyword_type=KeywordType.REGEX,
            match_mode=KeywordMatchMode.REGEX_METADATA,
        )

    active = services.search.activate_keyword_set(version_two.keyword_set_id)

    assert active.version == 3
    assert active.status == "ACTIVE"
    assert services.search.get_keyword_set(active.keyword_set_id, version=1).version == 1


def test_timestamp_normalization_preserves_raw_and_rejects_naive_utc_assumption() -> None:
    explicit = normalize_timestamp(
        raw_timestamp="2024-01-02T03:04:05+09:00",
        raw_timezone=None,
        case_timezone="Asia/Seoul",
        timestamp_semantics="event_system_time",
    )
    naive = normalize_timestamp(
        raw_timestamp="2024-01-02T03:04:05",
        raw_timezone=None,
        case_timezone="Asia/Seoul",
        timestamp_semantics="unknown_local_time",
    )

    assert explicit.raw_timestamp == "2024-01-02T03:04:05+09:00"
    assert explicit.normalized_utc is not None
    assert explicit.displayed_case_time is not None
    assert explicit.timezone_source is TimezoneSource.EXPLICIT_OFFSET
    assert naive.normalized_utc is None
    assert naive.warnings[0]["code"] == "NAIVE_TIMESTAMP_TIMEZONE_UNKNOWN"


def test_timeline_build_query_cursor_and_schema(services, tmp_path: Path, schema_validator) -> None:
    case, evidence = _indexed_case(services, tmp_path / "timeline-evidence")
    job, coverage = services.timeline.build(case_id=case.case_id, evidence_id=evidence.evidence_id)
    first = services.timeline.list_events(
        case_id=case.case_id,
        evidence_id=evidence.evidence_id,
        limit=2,
    )
    second = services.timeline.list_events(
        case_id=case.case_id,
        evidence_id=evidence.evidence_id,
        cursor=first.page.next_cursor,
        limit=2,
    )
    modified = services.timeline.list_events(
        case_id=case.case_id,
        event_types=[TimelineEventType.FILE_MODIFIED],
        limit=10,
    )

    assert job.status == "SUCCEEDED"
    assert coverage.event_count >= 8
    assert first.page.has_more is True
    assert {item.timeline_event_id for item in first.items}.isdisjoint(
        {item.timeline_event_id for item in second.items}
    )
    assert modified.items
    assert all(item.raw_timestamp is not None for item in modified.items)
    assert all(item.case_timezone == "Asia/Seoul" for item in modified.items)
    assert all(item.displayed_case_time is not None for item in modified.items)

    schema_validator.validate("timeline-event.schema.json", first.to_schema_dict())
    schema_validator.validate("timeline-event.schema.json", first.items[0].to_schema_dict())


def test_timeline_coverage_counts_processed_and_skipped_rows_once(
    services,
    tmp_path: Path,
) -> None:
    root = tmp_path / "timeline-skipped"
    root.mkdir()
    case = services.cases.create_case(name="Timeline Skips", investigator="analyst")
    evidence = services.evidence.register_evidence(case_id=case.case_id, source_path=root)
    now = datetime(2024, 1, 2, 3, 4, 5, tzinfo=UTC)
    common = {
        "case_id": case.case_id,
        "evidence_id": evidence.evidence_id,
        "provider_id": "test-provider",
        "provider_version": "1.0",
        "parent_node_id": None,
        "node_type": FileSystemNodeType.FILE,
        "file_size": 0,
        "extension": ".txt",
        "mime_candidate": "text/plain",
        "mime_confidence": "LOW",
        "fs_metadata": {},
        "platform": "test",
        "is_deleted": False,
        "is_readable": True,
        "is_link": False,
        "is_traversed": True,
        "provider_metadata": {},
        "is_partial": False,
        "index_revision": 1,
        "created_at": now,
        "updated_at": now,
    }
    services.repository.upsert_fs_node(
        FileSystemNode(
            **common,
            node_id="processed-node",
            original_name="processed.txt",
            original_relative_path="processed.txt",
            display_path="/processed.txt",
            comparison_path="/processed.txt",
            timestamp_meanings={"modified": "modified"},
            raw_timestamps={"modified": "2024-01-02T03:04:05+00:00"},
            utc_timestamps={"modified": now},
            timestamp_sources={"modified": "test"},
            raw_locator={"path": "/processed.txt"},
        )
    )
    services.repository.upsert_fs_node(
        FileSystemNode(
            **common,
            node_id="skipped-node",
            original_name="skipped.txt",
            original_relative_path="skipped.txt",
            display_path="/skipped.txt",
            comparison_path="/skipped.txt",
            timestamp_meanings={},
            raw_timestamps={},
            utc_timestamps={},
            timestamp_sources={},
            raw_locator={"path": "/skipped.txt"},
        )
    )

    _, coverage = services.timeline.build(
        case_id=case.case_id,
        evidence_id=evidence.evidence_id,
        source_types=[TimelineSourceType.FILE_SYSTEM_NODE],
    )

    assert coverage.discovered_items == 2
    assert coverage.processed_items == 1
    assert coverage.skipped_items == 1
    assert coverage.event_count == 1


def test_phase4_reopen_resume_pause_and_cancel(tmp_path: Path) -> None:
    db_path = tmp_path / "phase4-resume.db"
    services = build_services(db_path)
    try:
        case, evidence = _indexed_case(services, tmp_path / "resume-evidence")
        search_partial, _ = services.search.index(
            case_id=case.case_id,
            evidence_ids=[evidence.evidence_id],
            item_budget=1,
        )
        timeline_partial, _ = services.timeline.build(
            case_id=case.case_id,
            evidence_id=evidence.evidence_id,
            item_budget=1,
        )
        assert search_partial.status == "PARTIAL"
        assert timeline_partial.status == "PARTIAL"
    finally:
        services.close()

    reopened = build_services(db_path)
    try:
        resumed_search, _ = reopened.search.resume_index_job(search_partial.job_id)
        resumed_timeline, _ = reopened.timeline.resume_build_job(timeline_partial.job_id)
        query = reopened.search.query(case_id=case.case_id, query_text="secret", limit=10)
        timeline_page = reopened.timeline.list_events(case_id=case.case_id, limit=10)

        assert resumed_search.status == "SUCCEEDED"
        assert resumed_timeline.status == "SUCCEEDED"
        assert query.execution.result_count >= 1
        assert timeline_page.items

        pause_token = PauseToken.new()
        pause_token.request_pause()
        paused_search, _ = reopened.search.index(
            case_id=case.case_id,
            evidence_ids=[evidence.evidence_id],
            pause_token=pause_token,
        )
        cancel_token = CancellationToken.new()
        cancel_token.cancel()
        cancelled_timeline, _ = reopened.timeline.build(
            case_id=case.case_id,
            evidence_id=evidence.evidence_id,
            cancellation_token=cancel_token,
        )

        assert paused_search.status == "PAUSED"
        assert cancelled_timeline.status == "CANCELLED"
    finally:
        reopened.close()
