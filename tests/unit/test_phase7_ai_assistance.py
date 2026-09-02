from __future__ import annotations

import copy
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest

from apex_forensic._time import to_json_timestamp
from apex_forensic.config import build_services
from apex_forensic.domain.enums import AnalysisContextPurpose, AnalysisProfileType
from apex_forensic.domain.errors import ApexError


def _snapshot_fixture(tmp_path: Path):
    root = tmp_path / "evidence"
    root.mkdir()
    (root / "한글-note.txt").write_text("alpha bravo charlie", encoding="utf-8")
    services = build_services(tmp_path / "apex.db")
    case = services.cases.create_case(name="Phase 7 Case")
    evidence = services.evidence.register_evidence(case_id=case.case_id, source_path=root)
    services.fs.index_evidence(
        case_id=case.case_id,
        evidence_id=evidence.evidence_id,
        profile_type=AnalysisProfileType.FULL_ANALYSIS,
    )
    node = next(
        item
        for item in services.repository.list_fs_nodes_for_evidence(evidence.evidence_id)
        if item.node_type.value == "FILE"
    )
    context = services.contexts.create(
        session_id="phase7-session",
        case_id=case.case_id,
        selected_file_node_ids=[node.node_id],
    )
    snapshot = services.contexts.build_from_session(
        context.session_context_id,
        purpose=AnalysisContextPurpose.AI_REQUEST,
        scopes=["filesystem"],
    )
    scope = services.contexts.list_scopes(snapshot.context_snapshot_id)[0]
    return services, case, evidence, node, snapshot, scope


def _citation(case_id: str, evidence_id: str, node_id: str, path: str) -> dict[str, object]:
    return {
        "id": str(uuid4()),
        "label": "CIT-001",
        "case_id": case_id,
        "evidence_id": evidence_id,
        "source_kind": "FILE",
        "source_id": node_id,
        "file_id": node_id,
        "artifact_id": None,
        "timeline_event_id": None,
        "search_result_id": None,
        "source_path": path,
        "source_offset": 0,
        "source_reference": "filesystem node",
        "excerpt": "alpha",
        "content_sha256": None,
        "created_at": to_json_timestamp(datetime(2024, 1, 1, tzinfo=UTC)),
        "source_length": 5,
        "encoding": "utf-8",
        "raw_locator": {
            "evidence_id": evidence_id,
            "source_kind": "FILE",
            "source_id": node_id,
            "source_path": path,
            "source_reference": "filesystem node",
            "locator_type": "LOGICAL_PATH",
            "offset": 0,
            "length": 5,
            "encoding": "utf-8",
            "view_types": ["TEXT"],
            "content_sha256": None,
            "limitations": [],
            "details": {},
        },
    }


def _keyword_payload(
    citation: dict[str, object], evidence_id: str, node_id: str
) -> dict[str, object]:
    return {
        "provider_id": "fake-ai",
        "provider_version": "1",
        "model_id": "synthetic",
        "external_request_id": "ext-1",
        "recommendations": [
            {
                "keyword_type": "DOCUMENT_TERM",
                "value": "한글키워드",
                "reason": "Term appears in selected scope.",
                "confidence": "MEDIUM",
                "recommended_scope": "filesystem",
                "evidence_ids": [evidence_id],
                "source_resource_ids": [node_id],
                "citations": [citation],
            },
            {
                "keyword_type": "DOCUMENT_TERM",
                "value": "한글키워드",
                "reason": "Duplicate should be deterministic.",
                "confidence": "LOW",
                "recommended_scope": "filesystem",
                "evidence_ids": [evidence_id],
                "source_resource_ids": [node_id],
                "citations": [citation],
            },
        ],
    }


def test_ai_request_fingerprint_ttl_and_repository_reopen(tmp_path: Path) -> None:
    services, case, evidence, node, snapshot, _ = _snapshot_fixture(tmp_path)
    db_path = services.repository.db_path
    try:
        first = services.ai.create_request_from_context_snapshot(
            case_id=case.case_id,
            context_snapshot_id=snapshot.context_snapshot_id,
            purpose="KEYWORD_RECOMMENDATION",
            requested_operations=["RECOMMEND_KEYWORDS"],
            requested_scopes=["filesystem"],
        )
        second = services.ai.create_request_from_context_snapshot(
            case_id=case.case_id,
            context_snapshot_id=snapshot.context_snapshot_id,
            purpose="KEYWORD_RECOMMENDATION",
            requested_operations=["RECOMMEND_KEYWORDS"],
            requested_scopes=["filesystem"],
        )
        assert second.assistance_request_id == first.assistance_request_id
        assert second.request_fingerprint == first.request_fingerprint

        services.ai.expire_request(first.assistance_request_id)
        with pytest.raises(ApexError) as expired:
            services.ai.ingest_keyword_batch(
                assistance_request_id=first.assistance_request_id,
                payload=_keyword_payload(
                    _citation(
                        case.case_id,
                        evidence.evidence_id,
                        node.node_id,
                        node.original_relative_path,
                    ),
                    evidence.evidence_id,
                    node.node_id,
                ),
            )
        assert expired.value.code == "AI_REQUEST_EXPIRED"
    finally:
        services.close()

    reopened = build_services(db_path)
    try:
        listed = reopened.ai.list_requests_by_case(case.case_id)
        assert listed[0].request_fingerprint == first.request_fingerprint
    finally:
        reopened.close()


def test_ai_revision_validation_propagates_unexpected_resolver_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    services, case, _evidence, _node, snapshot, _ = _snapshot_fixture(tmp_path)
    try:
        request = services.ai.create_request_from_context_snapshot(
            case_id=case.case_id,
            context_snapshot_id=snapshot.context_snapshot_id,
            purpose="KEYWORD_RECOMMENDATION",
            requested_operations=["RECOMMEND_KEYWORDS"],
            requested_scopes=["filesystem"],
        )

        def fail_resolve_resource(*_args: object, **_kwargs: object) -> dict[str, object]:
            raise RuntimeError("unexpected resolver failure")

        monkeypatch.setattr(services.contexts, "resolve_resource", fail_resolve_resource)
        with pytest.raises(RuntimeError, match="unexpected resolver failure"):
            services.ai.validate_current_revisions(request.assistance_request_id)
    finally:
        services.close()


def test_keyword_ingest_review_correction_and_immutability(tmp_path: Path) -> None:
    services, case, evidence, node, snapshot, _ = _snapshot_fixture(tmp_path)
    try:
        request = services.ai.create_request_from_context_snapshot(
            case_id=case.case_id,
            context_snapshot_id=snapshot.context_snapshot_id,
            purpose="KEYWORD_RECOMMENDATION",
            requested_operations=["RECOMMEND_KEYWORDS"],
            requested_scopes=["filesystem"],
        )
        citation = _citation(
            case.case_id, evidence.evidence_id, node.node_id, node.original_relative_path
        )
        result = services.ai.ingest_keyword_batch(
            assistance_request_id=request.assistance_request_id,
            payload=_keyword_payload(citation, evidence.evidence_id, node.node_id),
        )
        assert result["batch"]["recommendation_count"] == 1
        recommendation_id = result["recommendations"][0]["recommendation_id"]
        recommendation = services.ai.get_keyword_recommendation(recommendation_id)
        assert recommendation.value == "한글키워드"
        assert recommendation.review_status == "UNREVIEWED"
        assert recommendation.to_schema_dict()["observed_fact_status"] == "NOT_OBSERVED_FACT"

        event = services.ai.review_keyword_recommendation(
            recommendation_id=recommendation_id,
            action="CORRECT",
            actor_id="analyst-1",
            reason="Normalize spelling.",
            expected_review_revision=0,
            corrected_value="한글 키워드",
            corrected_reason="Spacing corrected.",
        )
        assert event.review_revision == 1
        corrected = services.ai.get_keyword_recommendation(recommendation_id)
        assert corrected.review_status == "CORRECTED"
        assert corrected.effective_value == "한글 키워드"

        with pytest.raises(ApexError) as conflict:
            services.ai.review_keyword_recommendation(
                recommendation_id=recommendation_id,
                action="ACCEPT",
                actor_id="analyst-2",
                reason="Outdated review.",
                expected_review_revision=0,
            )
        assert conflict.value.code == "AI_REVIEW_REVISION_CONFLICT"

        with pytest.raises(sqlite3.IntegrityError):
            services.repository.connection.execute(
                """
                UPDATE ai_keyword_recommendations
                SET value = ?
                WHERE recommendation_id = ?
                """,
                ("mutated", recommendation_id),
            )
    finally:
        services.close()


def test_cross_case_and_missing_citation_rejection(tmp_path: Path) -> None:
    services, case, evidence, node, snapshot, _ = _snapshot_fixture(tmp_path)
    try:
        other_case = services.cases.create_case(name="Other")
        other_evidence_root = tmp_path / "other-evidence"
        other_evidence_root.mkdir()
        (other_evidence_root / "other.txt").write_text("other", encoding="utf-8")
        other_evidence = services.evidence.register_evidence(
            case_id=case.case_id,
            source_path=other_evidence_root,
        )
        request = services.ai.create_request_from_context_snapshot(
            case_id=case.case_id,
            context_snapshot_id=snapshot.context_snapshot_id,
            purpose="KEYWORD_RECOMMENDATION",
            requested_operations=["RECOMMEND_KEYWORDS"],
            requested_scopes=["filesystem"],
        )
        citation = _citation(
            other_case.case_id, evidence.evidence_id, node.node_id, node.original_relative_path
        )
        with pytest.raises(ApexError) as mismatch:
            services.ai.ingest_keyword_batch(
                assistance_request_id=request.assistance_request_id,
                payload=_keyword_payload(citation, evidence.evidence_id, node.node_id),
            )
        assert mismatch.value.code == "AI_CITATION_CASE_MISMATCH"

        payload = _keyword_payload(
            _citation(
                case.case_id,
                evidence.evidence_id,
                node.node_id,
                node.original_relative_path,
            ),
            evidence.evidence_id,
            node.node_id,
        )
        payload["recommendations"][0]["citations"] = []
        with pytest.raises(ApexError) as missing:
            services.ai.ingest_keyword_batch(
                assistance_request_id=request.assistance_request_id,
                payload=payload,
            )
        assert missing.value.code == "AI_CITATION_REQUIRED"

        evidence_mismatch = _citation(
            case.case_id,
            other_evidence.evidence_id,
            node.node_id,
            node.original_relative_path,
        )
        with pytest.raises(ApexError) as cross_evidence:
            services.ai.ingest_keyword_batch(
                assistance_request_id=request.assistance_request_id,
                payload=_keyword_payload(
                    evidence_mismatch,
                    other_evidence.evidence_id,
                    node.node_id,
                ),
            )
        assert cross_evidence.value.code == "AI_CITATION_SCOPE_MISMATCH"

        invalid_hash = _keyword_payload(
            _citation(
                case.case_id,
                evidence.evidence_id,
                node.node_id,
                node.original_relative_path,
            ),
            evidence.evidence_id,
            node.node_id,
        )
        invalid_hash["recommendations"][0]["keyword_type"] = "HASH"
        invalid_hash["recommendations"][0]["value"] = "a" * 33
        with pytest.raises(ApexError) as bad_hash:
            services.ai.ingest_keyword_batch(
                assistance_request_id=request.assistance_request_id,
                payload=invalid_hash,
            )
        assert bad_hash.value.code == "VALIDATION_ERROR"
    finally:
        services.close()


def test_summary_ingest_review_and_content_limits(tmp_path: Path) -> None:
    services, case, evidence, node, snapshot, scope = _snapshot_fixture(tmp_path)
    try:
        request = services.ai.create_request_from_context_snapshot(
            case_id=case.case_id,
            context_snapshot_id=snapshot.context_snapshot_id,
            purpose="SCOPE_SUMMARY",
            requested_operations=["SUMMARIZE_SCOPE"],
            requested_scopes=["filesystem"],
        )
        citation = _citation(
            case.case_id, evidence.evidence_id, node.node_id, node.original_relative_path
        )
        summary = services.ai.ingest_scope_summary(
            assistance_request_id=request.assistance_request_id,
            payload={
                "provider_id": "fake-ai",
                "provider_version": "1",
                "model_id": "synthetic",
                "scope_context_id": scope.scope_context_id,
                "title": "Filesystem scope",
                "summary_text": "Selected filesystem scope contains one text file.",
                "key_points": ["One file was selected."],
                "referenced_resource_ids": [node.node_id],
                "citations": [citation],
            },
        )
        assert summary.scope_context_id == scope.scope_context_id
        event = services.ai.review_scope_summary(
            scope_summary_id=summary.scope_summary_id,
            action="ACCEPT",
            actor_id="analyst-1",
            reason="Summary matches cited source.",
            expected_review_revision=0,
        )
        assert event.new_status == "ACCEPTED"

        with pytest.raises(ApexError):
            services.ai.ingest_scope_summary(
                assistance_request_id=request.assistance_request_id,
                payload={
                    "scope_context_id": scope.scope_context_id,
                    "title": "Bad",
                    "summary_text": "<script>alert(1)</script>",
                    "key_points": [],
                    "referenced_resource_ids": [node.node_id],
                    "citations": [citation],
                },
            )
    finally:
        services.close()


def test_keyword_promotion_is_accepted_only_idempotent_and_does_not_search(
    tmp_path: Path,
) -> None:
    services, case, evidence, node, snapshot, _ = _snapshot_fixture(tmp_path)
    try:
        request = services.ai.create_request_from_context_snapshot(
            case_id=case.case_id,
            context_snapshot_id=snapshot.context_snapshot_id,
            purpose="KEYWORD_RECOMMENDATION",
            requested_operations=["RECOMMEND_KEYWORDS"],
            requested_scopes=["filesystem"],
        )
        citation = _citation(
            case.case_id, evidence.evidence_id, node.node_id, node.original_relative_path
        )
        result = services.ai.ingest_keyword_batch(
            assistance_request_id=request.assistance_request_id,
            payload=_keyword_payload(citation, evidence.evidence_id, node.node_id),
        )
        recommendation_id = result["recommendations"][0]["recommendation_id"]
        keyword_set = services.search.create_keyword_set(
            case_id=case.case_id,
            name="Promoted",
            created_by="analyst-1",
        )
        with pytest.raises(ApexError):
            services.ai.promote_accepted_keyword(
                recommendation_id=recommendation_id,
                keyword_set_id=keyword_set.keyword_set_id,
                actor_id="analyst-1",
                reason="Too early.",
            )

        services.ai.review_keyword_recommendation(
            recommendation_id=recommendation_id,
            action="ACCEPT",
            actor_id="analyst-1",
            reason="Useful term.",
            expected_review_revision=0,
        )
        before_count = services.repository.connection.execute(
            "SELECT COUNT(*) AS count FROM search_executions"
        ).fetchone()["count"]
        promotion = services.ai.promote_accepted_keyword(
            recommendation_id=recommendation_id,
            keyword_set_id=keyword_set.keyword_set_id,
            actor_id="analyst-1",
            reason="Promote for later manual search.",
            expected_review_revision=1,
        )
        replay = services.ai.promote_accepted_keyword(
            recommendation_id=recommendation_id,
            keyword_set_id=keyword_set.keyword_set_id,
            actor_id="analyst-1",
            reason="Promote for later manual search.",
            expected_review_revision=1,
        )
        after_count = services.repository.connection.execute(
            "SELECT COUNT(*) AS count FROM search_executions"
        ).fetchone()["count"]
        promoted_set = services.search.get_keyword_set(keyword_set.keyword_set_id)
        assert promotion.promotion_id == replay.promotion_id
        assert promotion.status == "PROMOTED"
        assert promoted_set.version == 2
        assert promoted_set.status.value == "DRAFT"
        assert before_count == after_count
    finally:
        services.close()


def test_provider_boundary_and_public_interface_descriptors(tmp_path: Path) -> None:
    services, case, _, _, snapshot, _ = _snapshot_fixture(tmp_path)
    try:
        request = services.ai.create_request_from_context_snapshot(
            case_id=case.case_id,
            context_snapshot_id=snapshot.context_snapshot_id,
            purpose="KEYWORD_RECOMMENDATION",
            requested_operations=["RECOMMEND_KEYWORDS"],
            requested_scopes=["filesystem"],
        )
        capability = services.ai.capabilities()
        assert capability["runtime_capability"]["is_available"] is False
        assert capability["runtime_capability"]["unavailable_reason"] == (
            "CAPABILITY_UNAVAILABLE"
        )
        with pytest.raises(ApexError) as unavailable:
            services.ai.generate_keyword_recommendations(
                assistance_request_id=request.assistance_request_id
            )
        assert unavailable.value.code == "CAPABILITY_UNAVAILABLE"

        ai_tools = [
            tool
            for tool in services.interface.tools()
            if tool.tool_name.startswith("ai.")
        ]
        assert {tool.tool_name for tool in ai_tools} >= {
            "ai.request.create",
            "ai.keyword-recommendation.review",
            "ai.keyword-recommendation.promote",
        }
        assert all(tool.tool_name in {tool.tool_name for tool in ai_tools} for tool in ai_tools)
        review_tool = next(
            tool for tool in ai_tools if tool.tool_name == "ai.keyword-recommendation.review"
        )
        assert review_tool.mutates_state is True
        assert review_tool.requires_confirmation is True

        envelope = services.interface.invoke_read(
            "ai.request.get",
            {},
            correlation_id="corr-1",
        )
        assert envelope["status"] == "ERROR"
        assert envelope["errors"][0]["code"] == "VALIDATION_ERROR"
    finally:
        services.close()


def test_ai_adapter_schema_boundaries_reject_before_persistence(tmp_path: Path) -> None:
    services, case, evidence, node, snapshot, _ = _snapshot_fixture(tmp_path)
    try:
        request_count = services.repository.connection.execute(
            "SELECT COUNT(*) AS count FROM ai_assistance_requests"
        ).fetchone()["count"]
        with pytest.raises(ApexError):
            services.ai.create_request_from_context_snapshot(
                case_id=case.case_id,
                context_snapshot_id=snapshot.context_snapshot_id,
                purpose="KEYWORD_RECOMMENDATION",
                requested_operations=["RECOMMEND_KEYWORDS"],
                requested_scopes=["filesystem"],
                correlation_id="",
            )
        assert services.repository.connection.execute(
            "SELECT COUNT(*) AS count FROM ai_assistance_requests"
        ).fetchone()["count"] == request_count

        with services.repository.connection:
            services.repository.connection.execute(
                """
                UPDATE analysis_scope_contexts
                SET result_count = ?
                WHERE context_snapshot_id = ?
                """,
                (10_000, snapshot.context_snapshot_id),
            )
        request = services.ai.create_request_from_context_snapshot(
            case_id=case.case_id,
            context_snapshot_id=snapshot.context_snapshot_id,
            purpose="KEYWORD_RECOMMENDATION",
            requested_operations=["RECOMMEND_KEYWORDS"],
            requested_scopes=["filesystem"],
            correlation_id="correlation-1",
        )
        assert request.resource_count == 10_000
        request_count = services.repository.connection.execute(
            "SELECT COUNT(*) AS count FROM ai_assistance_requests"
        ).fetchone()["count"]
        with services.repository.connection:
            services.repository.connection.execute(
                """
                UPDATE analysis_scope_contexts
                SET result_count = ?
                WHERE context_snapshot_id = ?
                """,
                (10_001, snapshot.context_snapshot_id),
            )
        with pytest.raises(ApexError):
            services.ai.create_request_from_context_snapshot(
                case_id=case.case_id,
                context_snapshot_id=snapshot.context_snapshot_id,
                purpose="KEYWORD_RECOMMENDATION",
                requested_operations=["RECOMMEND_KEYWORDS"],
                requested_scopes=["filesystem"],
                correlation_id="correlation-over-limit",
            )
        assert services.repository.connection.execute(
            "SELECT COUNT(*) AS count FROM ai_assistance_requests"
        ).fetchone()["count"] == request_count
        with services.repository.connection:
            services.repository.connection.execute(
                """
                UPDATE analysis_scope_contexts
                SET result_count = ?
                WHERE context_snapshot_id = ?
                """,
                (10_000, snapshot.context_snapshot_id),
            )
        citation = _citation(
            case.case_id,
            evidence.evidence_id,
            node.node_id,
            node.original_relative_path,
        )
        accepted_payload = _keyword_payload(citation, evidence.evidence_id, node.node_id)
        accepted_payload["recommendations"] = [accepted_payload["recommendations"][0]]
        accepted_payload["recommendations"][0]["display_value"] = "가" * 4096
        accepted_payload["recommendations"][0]["citations"] = [citation] * 200
        state_warning_count = int(request.is_partial) + int(request.is_stale)
        accepted_payload["warnings"] = [
            {"code": f"W{index:03d}"} for index in range(200 - state_warning_count)
        ]
        accepted = services.ai.ingest_keyword_batch(
            assistance_request_id=request.assistance_request_id,
            payload=accepted_payload,
        )
        assert len(accepted["recommendations"][0]["display_value"]) == 4096
        assert len(accepted["batch"]["warnings"]) == 200
        batch_count = services.repository.connection.execute(
            "SELECT COUNT(*) AS count FROM ai_keyword_recommendation_batches"
        ).fetchone()["count"]

        invalid_payloads = []
        too_long_display = copy.deepcopy(accepted_payload)
        too_long_display["recommendations"][0]["display_value"] = "가" * 4097
        invalid_payloads.append(too_long_display)
        too_many_warnings = copy.deepcopy(accepted_payload)
        too_many_warnings["warnings"] = [
            {"code": f"W{index:03d}"} for index in range(201)
        ]
        invalid_payloads.append(too_many_warnings)
        too_many_citations = copy.deepcopy(accepted_payload)
        too_many_citations["recommendations"][0]["citations"].append(citation)
        invalid_payloads.append(too_many_citations)
        empty_external_id = copy.deepcopy(accepted_payload)
        empty_external_id["external_request_id"] = ""
        invalid_payloads.append(empty_external_id)

        for payload in invalid_payloads:
            with pytest.raises(ApexError):
                services.ai.ingest_keyword_batch(
                    assistance_request_id=request.assistance_request_id,
                    payload=payload,
                )
            assert services.repository.connection.execute(
                "SELECT COUNT(*) AS count FROM ai_keyword_recommendation_batches"
            ).fetchone()["count"] == batch_count
    finally:
        services.close()


def test_ai_summary_review_and_promotion_schema_boundaries(tmp_path: Path) -> None:
    services, case, evidence, node, snapshot, scope = _snapshot_fixture(tmp_path)
    try:
        summary_request = services.ai.create_request_from_context_snapshot(
            case_id=case.case_id,
            context_snapshot_id=snapshot.context_snapshot_id,
            purpose="SCOPE_SUMMARY",
            requested_operations=["SUMMARIZE_SCOPE"],
            requested_scopes=["filesystem"],
        )
        citation = _citation(
            case.case_id,
            evidence.evidence_id,
            node.node_id,
            node.original_relative_path,
        )
        summary_payload = {
            "scope_context_id": scope.scope_context_id,
            "title": "가" * 300,
            "summary_text": "Bounded summary.",
            "key_points": ["가" * 500],
            "referenced_resource_ids": [node.node_id],
            "citations": [citation],
            "external_request_id": "summary-external-1",
        }
        summary = services.ai.ingest_scope_summary(
            assistance_request_id=summary_request.assistance_request_id,
            payload=summary_payload,
        )
        assert len(summary.title) == 300
        summary_count = services.repository.connection.execute(
            "SELECT COUNT(*) AS count FROM ai_scope_summaries"
        ).fetchone()["count"]
        invalid_summary = dict(summary_payload)
        invalid_summary["title"] = "가" * 301
        with pytest.raises(ApexError):
            services.ai.ingest_scope_summary(
                assistance_request_id=summary_request.assistance_request_id,
                payload=invalid_summary,
            )
        assert services.repository.connection.execute(
            "SELECT COUNT(*) AS count FROM ai_scope_summaries"
        ).fetchone()["count"] == summary_count

        keyword_request = services.ai.create_request_from_context_snapshot(
            case_id=case.case_id,
            context_snapshot_id=snapshot.context_snapshot_id,
            purpose="KEYWORD_RECOMMENDATION",
            requested_operations=["RECOMMEND_KEYWORDS"],
            requested_scopes=["filesystem"],
        )
        payload = _keyword_payload(citation, evidence.evidence_id, node.node_id)
        payload["recommendations"] = [payload["recommendations"][0]]
        result = services.ai.ingest_keyword_batch(
            assistance_request_id=keyword_request.assistance_request_id,
            payload=payload,
        )
        recommendation_id = result["recommendations"][0]["recommendation_id"]
        event = services.ai.review_keyword_recommendation(
            recommendation_id=recommendation_id,
            action="COMMENT",
            actor_id="r" * 256,
            reason="Boundary review.",
            expected_review_revision=0,
            corrected_reason="c" * 4000,
        )
        assert len(event.actor_id) == 256
        event_count = len(
            services.ai.review_history(
                target_type="KEYWORD_RECOMMENDATION",
                target_id=recommendation_id,
            )
        )
        with pytest.raises(ApexError):
            services.ai.review_keyword_recommendation(
                recommendation_id=recommendation_id,
                action="COMMENT",
                actor_id="r" * 257,
                reason="Rejected actor.",
                expected_review_revision=1,
            )
        with pytest.raises(ApexError):
            services.ai.review_keyword_recommendation(
                recommendation_id=recommendation_id,
                action="COMMENT",
                actor_id="reviewer",
                reason="Rejected correction.",
                expected_review_revision=1,
                corrected_reason="c" * 4001,
            )
        assert len(
            services.ai.review_history(
                target_type="KEYWORD_RECOMMENDATION",
                target_id=recommendation_id,
            )
        ) == event_count

        services.ai.review_keyword_recommendation(
            recommendation_id=recommendation_id,
            action="ACCEPT",
            actor_id="reviewer",
            reason="Accept.",
            expected_review_revision=1,
        )
        keyword_set = services.search.create_keyword_set(
            case_id=case.case_id,
            name="Boundary promotion",
            created_by="reviewer",
        )
        promotion = services.ai.promote_accepted_keyword(
            recommendation_id=recommendation_id,
            keyword_set_id=keyword_set.keyword_set_id,
            actor_id="p" * 256,
            reason="Promote.",
            expected_review_revision=2,
        )
        assert len(promotion.actor_id) == 256
        promotion_count = len(services.ai.promotion_history(recommendation_id=recommendation_id))
        with pytest.raises(ApexError):
            services.ai.promote_accepted_keyword(
                recommendation_id=recommendation_id,
                keyword_set_id=keyword_set.keyword_set_id,
                actor_id="p" * 257,
                reason="Rejected promoter.",
                expected_review_revision=2,
            )
        assert len(
            services.ai.promotion_history(recommendation_id=recommendation_id)
        ) == promotion_count
    finally:
        services.close()
