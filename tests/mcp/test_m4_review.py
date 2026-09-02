from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import uuid4

from apex_forensic._time import to_json_timestamp
from apex_forensic.config import build_services
from apex_forensic.domain.enums import AnalysisContextPurpose, AnalysisProfileType
from apex_mcp.config import McpConfig
from apex_mcp.confirmation import (
    ConfirmationGrant,
    ConfirmationRequest,
    InMemoryConfirmationProvider,
)
from apex_mcp.engine_adapter import EngineAdapter
from apex_mcp.m4_tools import M4_REVIEW_TOOL_NAMES, M4_TOOL_NAMES, m4_bindings
from apex_mcp.server import create_runtime
from apex_mcp.telemetry import request_fingerprint


def _citation(
    *,
    case_id: str,
    evidence_id: str,
    node_id: str,
    source_path: str,
) -> dict[str, Any]:
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
        "source_path": source_path,
        "source_offset": 0,
        "source_reference": "selected filesystem node",
        "excerpt": "alpha",
        "content_sha256": None,
        "created_at": to_json_timestamp(datetime(2026, 1, 1, tzinfo=UTC)),
        "source_length": 5,
        "encoding": "utf-8",
        "raw_locator": {
            "evidence_id": evidence_id,
            "source_kind": "FILE",
            "source_id": node_id,
            "source_path": source_path,
            "source_reference": "selected filesystem node",
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


def _seed(project_root: Path, tmp_path: Path) -> dict[str, Any]:
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    (evidence_root / "selected.txt").write_text("alpha bravo", encoding="utf-8")
    database_path = tmp_path / "m4.db"
    services = build_services(database_path)
    case = services.cases.create_case(name="MCP M4 Review")
    other_case = services.cases.create_case(name="MCP M4 Other Case")
    evidence = services.evidence.register_evidence(
        case_id=case.case_id,
        source_path=evidence_root,
    )
    services.fs.index_evidence(
        case_id=case.case_id,
        evidence_id=evidence.evidence_id,
        profile_type=AnalysisProfileType.FULL_ANALYSIS,
    )
    node = next(
        item
        for item in services.fs.list_nodes(
            evidence_id=evidence.evidence_id,
            all_nodes=True,
        ).items
        if item.node_type.value == "FILE"
    )
    context = services.contexts.create(
        session_id="mcp-m4-session",
        case_id=case.case_id,
        selected_file_node_ids=[node.node_id],
        active_context_scope="filesystem",
    )
    snapshot = services.contexts.build_from_session(
        context.session_context_id,
        purpose=AnalysisContextPurpose.AI_REQUEST,
        scopes=["filesystem"],
    )
    citation = _citation(
        case_id=case.case_id,
        evidence_id=evidence.evidence_id,
        node_id=node.node_id,
        source_path=node.original_relative_path,
    )
    keyword_request = services.ai.create_request_from_context_snapshot(
        case_id=case.case_id,
        context_snapshot_id=snapshot.context_snapshot_id,
        purpose="KEYWORD_RECOMMENDATION",
        requested_operations=["RECOMMEND_KEYWORDS"],
        requested_scopes=["filesystem"],
    )
    keyword_result = services.ai.ingest_keyword_batch(
        assistance_request_id=keyword_request.assistance_request_id,
        payload={
            "provider_id": "m4-fixture",
            "provider_version": "1.0.0",
            "model_id": "fixture-model",
            "recommendations": [
                {
                    "keyword_type": "DOCUMENT_TERM",
                    "value": "alpha",
                    "reason": "The cited selected file contains alpha.",
                    "confidence": "MEDIUM",
                    "recommended_scope": "filesystem",
                    "evidence_ids": [evidence.evidence_id],
                    "source_resource_ids": [node.node_id],
                    "citations": [citation],
                }
            ],
        },
    )
    recommendation_id = keyword_result["recommendations"][0]["recommendation_id"]
    summary_request = services.ai.create_request_from_context_snapshot(
        case_id=case.case_id,
        context_snapshot_id=snapshot.context_snapshot_id,
        purpose="SCOPE_SUMMARY",
        requested_operations=["SUMMARIZE_SCOPE"],
        requested_scopes=["filesystem"],
    )
    summary = services.ai.ingest_scope_summary(
        assistance_request_id=summary_request.assistance_request_id,
        payload={
            "provider_id": "m4-fixture",
            "provider_version": "1.0.0",
            "model_id": "fixture-model",
            "scope_context_id": summary_request.scope_context_ids[0],
            "title": "Selected filesystem scope",
            "summary_text": "The selected scope contains the cited alpha term.",
            "key_points": ["One selected text file contains alpha."],
            "referenced_resource_ids": [node.node_id],
            "citations": [citation],
        },
    )
    keyword_set = services.search.create_keyword_set(
        case_id=case.case_id,
        name="M4 promoted candidates",
        created_by="analyst-m4",
    )
    confirmation_provider = InMemoryConfirmationProvider()
    runtime = create_runtime(
        McpConfig(
            database_path=database_path,
            schema_dir=project_root / "schemas" / "v1",
            allowed_tools=M4_TOOL_NAMES,
        ),
        adapter=EngineAdapter(services),
        bindings=m4_bindings(),
        confirmation_provider=confirmation_provider,
    )
    return {
        "services": services,
        "runtime": runtime,
        "confirmation_provider": confirmation_provider,
        "case_id": case.case_id,
        "other_case_id": other_case.case_id,
        "recommendation_id": recommendation_id,
        "scope_summary_id": summary.scope_summary_id,
        "keyword_set_id": keyword_set.keyword_set_id,
    }


def _confirmation(
    *,
    grant_id: str,
    tool_name: str,
    arguments: dict[str, Any],
    target_ids: tuple[str, ...],
    actor_id: str = "analyst-m4",
    session_id: str = "frontend-m4",
) -> tuple[ConfirmationGrant, ConfirmationRequest]:
    fingerprint = request_fingerprint(arguments)
    values = {
        "grant_id": grant_id,
        "actor_id": actor_id,
        "session_id": session_id,
        "case_id": str(arguments["case_id"]),
        "tool_name": tool_name,
        "request_fingerprint": fingerprint,
        "target_ids": target_ids,
    }
    return (
        ConfirmationGrant(
            **values,
            expires_at=datetime.now(UTC) + timedelta(minutes=5),
        ),
        ConfirmationRequest(**values),
    )


def test_m4_default_deny_and_model_cannot_assert_actor(
    project_root: Path,
    tmp_path: Path,
) -> None:
    seeded = _seed(project_root, tmp_path)
    services = seeded["services"]
    runtime = seeded["runtime"]
    provider = seeded["confirmation_provider"]
    arguments = {
        "case_id": seeded["case_id"],
        "recommendation_id": seeded["recommendation_id"],
        "action": "ACCEPT",
        "reason": "The cited candidate is useful.",
        "expected_review_revision": 0,
    }
    try:
        tools = runtime.registry.list_tools()
        assert {tool.name for tool in tools} == M4_TOOL_NAMES
        assert {tool.name for tool in tools} >= M4_REVIEW_TOOL_NAMES
        promotion_tool = next(
            tool for tool in tools if tool.name == "ai.keyword-recommendation.promote"
        )
        assert promotion_tool.annotations is not None
        assert promotion_tool.annotations.destructive_hint is True

        denied = runtime.registry.call_tool(
            "ai.keyword-recommendation.review",
            arguments,
        )
        actor_spoof = runtime.registry.call_tool(
            "ai.keyword-recommendation.review",
            {**arguments, "actor_id": "model-claimed-analyst"},
        )
        correction_on_comment = runtime.registry.call_tool(
            "ai.keyword-recommendation.review",
            {
                **arguments,
                "action": "COMMENT",
                "corrected_value": "model-supplied mutation",
            },
        )
        missing_correction = runtime.registry.call_tool(
            "ai.keyword-recommendation.review",
            {**arguments, "action": "CORRECT"},
        )
        grant, confirmation = _confirmation(
            grant_id="anonymous-review",
            tool_name="ai.keyword-recommendation.review",
            arguments=arguments,
            target_ids=(seeded["recommendation_id"],),
            actor_id="UNAUTHENTICATED",
            session_id="stdio",
        )
        provider.issue(grant)
        anonymous = runtime.registry.call_tool(
            "ai.keyword-recommendation.review",
            arguments,
            confirmation=confirmation,
            trusted_actor_id="UNAUTHENTICATED",
            trusted_session_id="stdio",
        )

        assert denied.structured_content["errors"][0]["code"] == (
            "HUMAN_CONFIRMATION_REQUIRED"
        )
        assert actor_spoof.structured_content["errors"][0]["code"] == "VALIDATION_ERROR"
        assert correction_on_comment.structured_content["errors"][0]["code"] == (
            "VALIDATION_ERROR"
        )
        assert missing_correction.structured_content["errors"][0]["code"] == (
            "VALIDATION_ERROR"
        )
        assert anonymous.structured_content["errors"][0]["code"] == (
            "MCP_AUTHENTICATED_ACTOR_REQUIRED"
        )
        assert services.ai.get_keyword_recommendation(
            seeded["recommendation_id"]
        ).review_status == "UNREVIEWED"
    finally:
        runtime.close()
        services.close()


def test_m4_trusted_review_preview_and_promotion_workflow(
    project_root: Path,
    tmp_path: Path,
) -> None:
    seeded = _seed(project_root, tmp_path)
    services = seeded["services"]
    runtime = seeded["runtime"]
    provider = seeded["confirmation_provider"]
    recommendation_id = seeded["recommendation_id"]
    keyword_set_id = seeded["keyword_set_id"]
    actor_id = "analyst-m4"
    session_id = "frontend-m4"
    try:
        wrong_case_arguments = {
            "case_id": seeded["other_case_id"],
            "recommendation_id": recommendation_id,
            "action": "ACCEPT",
            "reason": "Wrong case must not authorize this target.",
            "expected_review_revision": 0,
        }
        wrong_grant, wrong_confirmation = _confirmation(
            grant_id="wrong-case-review",
            tool_name="ai.keyword-recommendation.review",
            arguments=wrong_case_arguments,
            target_ids=(recommendation_id,),
        )
        provider.issue(wrong_grant)
        wrong_case = runtime.registry.call_tool(
            "ai.keyword-recommendation.review",
            wrong_case_arguments,
            confirmation=wrong_confirmation,
            trusted_actor_id=actor_id,
            trusted_session_id=session_id,
        )
        assert wrong_case.structured_content["errors"][0]["code"] == (
            "AI_TARGET_CASE_MISMATCH"
        )

        review_arguments = {
            "case_id": seeded["case_id"],
            "recommendation_id": recommendation_id,
            "action": "ACCEPT",
            "reason": "The cited candidate is useful.",
            "expected_review_revision": 0,
        }
        review_grant, review_confirmation = _confirmation(
            grant_id="accept-review",
            tool_name="ai.keyword-recommendation.review",
            arguments=review_arguments,
            target_ids=(recommendation_id,),
        )
        provider.issue(review_grant)
        reviewed = runtime.registry.call_tool(
            "ai.keyword-recommendation.review",
            review_arguments,
            confirmation=review_confirmation,
            trusted_actor_id=actor_id,
            trusted_session_id=session_id,
        )
        assert reviewed.is_error is False
        event = reviewed.structured_content["data"]
        assert event["actor_id"] == actor_id
        assert event["new_status"] == "ACCEPTED"
        assert event["review_revision"] == 1

        history = runtime.registry.call_tool(
            "ai.verification.history",
            {
                "case_id": seeded["case_id"],
                "target_type": "KEYWORD_RECOMMENDATION",
                "target_id": recommendation_id,
            },
        )
        cross_case_history = runtime.registry.call_tool(
            "ai.verification.history",
            {
                "case_id": seeded["other_case_id"],
                "target_type": "KEYWORD_RECOMMENDATION",
                "target_id": recommendation_id,
            },
        )
        assert history.is_error is False
        assert history.structured_content["data"] == [event]
        assert cross_case_history.structured_content["errors"][0]["code"] == (
            "AI_TARGET_CASE_MISMATCH"
        )

        preview_arguments = {
            "case_id": seeded["case_id"],
            "recommendation_id": recommendation_id,
            "keyword_set_id": keyword_set_id,
            "regex_confirmed": False,
        }
        preview_grant, preview_confirmation = _confirmation(
            grant_id="promotion-preview",
            tool_name="ai.promotion.preview",
            arguments=preview_arguments,
            target_ids=(recommendation_id, keyword_set_id),
        )
        provider.issue(preview_grant)
        other_keyword_set = services.search.create_keyword_set(
            case_id=seeded["case_id"],
            name="M4 different target set",
            created_by=actor_id,
        )
        changed_target = runtime.registry.call_tool(
            "ai.promotion.preview",
            {
                **preview_arguments,
                "keyword_set_id": other_keyword_set.keyword_set_id,
            },
            confirmation=preview_confirmation,
            trusted_actor_id=actor_id,
            trusted_session_id=session_id,
        )
        preview = runtime.registry.call_tool(
            "ai.promotion.preview",
            preview_arguments,
            confirmation=preview_confirmation,
            trusted_actor_id=actor_id,
            trusted_session_id=session_id,
        )
        assert changed_target.structured_content["errors"][0]["code"] == (
            "HUMAN_CONFIRMATION_REQUIRED"
        )
        assert preview.is_error is False
        assert preview.structured_content["data"]["promotable"] is True
        assert preview.structured_content["data"]["will_run_search"] is False

        search_count_before = services.repository.connection.execute(
            "SELECT COUNT(*) AS count FROM search_executions"
        ).fetchone()["count"]
        promotion_arguments = {
            "case_id": seeded["case_id"],
            "recommendation_id": recommendation_id,
            "keyword_set_id": keyword_set_id,
            "reason": "Promote the accepted candidate for later manual search.",
            "expected_review_revision": 1,
            "regex_confirmed": False,
        }
        promotion_grant, promotion_confirmation = _confirmation(
            grant_id="promotion-1",
            tool_name="ai.keyword-recommendation.promote",
            arguments=promotion_arguments,
            target_ids=(recommendation_id, keyword_set_id),
        )
        provider.issue(promotion_grant)
        promoted = runtime.registry.call_tool(
            "ai.keyword-recommendation.promote",
            promotion_arguments,
            confirmation=promotion_confirmation,
            trusted_actor_id=actor_id,
            trusted_session_id=session_id,
        )
        reused = runtime.registry.call_tool(
            "ai.keyword-recommendation.promote",
            promotion_arguments,
            confirmation=promotion_confirmation,
            trusted_actor_id=actor_id,
            trusted_session_id=session_id,
        )

        assert promoted.is_error is False
        promotion = promoted.structured_content["data"]
        assert promotion["actor_id"] == actor_id
        assert promotion["status"] == "PROMOTED"
        confirmation_metadata = promotion["metadata"]["confirmation_metadata"]
        assert confirmation_metadata["grant_id"] == "promotion-1"
        assert confirmation_metadata["actor_id"] == actor_id
        assert confirmation_metadata["session_id"] == session_id
        assert reused.structured_content["errors"][0]["code"] == (
            "HUMAN_CONFIRMATION_REQUIRED"
        )
        search_count_after = services.repository.connection.execute(
            "SELECT COUNT(*) AS count FROM search_executions"
        ).fetchone()["count"]
        assert search_count_before == search_count_after
        assert services.search.get_keyword_set(keyword_set_id).status.value == "DRAFT"
    finally:
        runtime.close()
        services.close()


def test_m4_scope_summary_review_uses_trusted_actor(
    project_root: Path,
    tmp_path: Path,
) -> None:
    seeded = _seed(project_root, tmp_path)
    services = seeded["services"]
    runtime = seeded["runtime"]
    provider = seeded["confirmation_provider"]
    summary_id = seeded["scope_summary_id"]
    arguments = {
        "case_id": seeded["case_id"],
        "scope_summary_id": summary_id,
        "action": "ACCEPT",
        "reason": "The summary matches its citations.",
        "expected_review_revision": 0,
    }
    try:
        grant, confirmation = _confirmation(
            grant_id="summary-review",
            tool_name="ai.scope-summary.review",
            arguments=arguments,
            target_ids=(summary_id,),
            actor_id="summary-reviewer",
        )
        provider.issue(grant)
        result = runtime.registry.call_tool(
            "ai.scope-summary.review",
            arguments,
            confirmation=confirmation,
            trusted_actor_id="summary-reviewer",
            trusted_session_id="frontend-m4",
        )

        assert result.is_error is False
        assert result.structured_content["data"]["actor_id"] == "summary-reviewer"
        assert result.structured_content["data"]["new_status"] == "ACCEPTED"
    finally:
        runtime.close()
        services.close()
