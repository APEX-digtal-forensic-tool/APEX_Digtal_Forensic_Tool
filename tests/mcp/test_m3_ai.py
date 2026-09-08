from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, ClassVar
from uuid import uuid4

from mcp.client import Client

from apex_forensic._time import to_json_timestamp
from apex_forensic.config import build_services
from apex_forensic.domain.enums import AnalysisProfileType
from apex_forensic.domain.models import AiAssistanceRequest, AiProviderCapability
from apex_mcp.config import McpConfig
from apex_mcp.engine_adapter import EngineAdapter
from apex_mcp.m3_tools import M3_AI_TOOL_NAMES, M3_TOOL_NAMES, m3_bindings
from apex_mcp.server import create_runtime


class FakeAiProvider:
    provider_id = "fake-mcp-ai"
    provider_version = "1.0.0"
    supported_operations: ClassVar[list[str]] = [
        "RECOMMEND_KEYWORDS",
        "SUMMARIZE_SCOPE",
    ]
    max_request_items = 10_000
    max_result_items = 1000
    max_summary_length = 20_000

    def __init__(self) -> None:
        self.keyword_calls = 0
        self.summary_calls = 0
        self.keyword_payload: dict[str, Any] | None = None
        self.summary_payload: dict[str, Any] | None = None

    def capabilities(self) -> AiProviderCapability:
        return AiProviderCapability(
            provider_id=self.provider_id,
            provider_version=self.provider_version,
            supported_operations=list(self.supported_operations),
            max_request_items=self.max_request_items,
            max_result_items=self.max_result_items,
            max_summary_length=self.max_summary_length,
            is_available=True,
        )

    def generate_keyword_recommendations(
        self,
        request: AiAssistanceRequest,
        *,
        cancellation_requested: bool = False,
    ) -> dict[str, Any]:
        del request, cancellation_requested
        self.keyword_calls += 1
        assert self.keyword_payload is not None
        return self.keyword_payload

    def generate_scope_summary(
        self,
        request: AiAssistanceRequest,
        *,
        cancellation_requested: bool = False,
    ) -> dict[str, Any]:
        del cancellation_requested
        self.summary_calls += 1
        assert self.summary_payload is not None
        return {
            **self.summary_payload,
            "scope_context_id": request.scope_context_ids[0],
        }

    def generate_report_draft(
        self,
        request: AiAssistanceRequest,
        *,
        cancellation_requested: bool = False,
    ) -> dict[str, Any]:
        del request, cancellation_requested
        raise AssertionError("Report draft execution is outside the M3 public contract.")


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


def _fixture(
    project_root: Path,
    tmp_path: Path,
    *,
    configure_provider: bool = True,
) -> tuple[Any, FakeAiProvider, Any, Any]:
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    (evidence_root / "selected.txt").write_text("alpha bravo", encoding="utf-8")
    provider = FakeAiProvider()
    services = build_services(
        tmp_path / "m3.db",
        ai_provider=provider if configure_provider else None,
    )
    case = services.cases.create_case(name="MCP M3 AI")
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
        session_id="mcp-m3-session",
        case_id=case.case_id,
        actor_id="analyst-m3",
        selected_file_node_ids=[node.node_id],
        active_context_scope="filesystem",
    )
    provider.keyword_payload = {
        "provider_id": provider.provider_id,
        "provider_version": provider.provider_version,
        "model_id": "fake-model",
        "external_request_id": "fake-external-request",
        "recommendations": [
            {
                "keyword_type": "DOCUMENT_TERM",
                "value": "alpha",
                "reason": "The term appears in the selected snapshot scope.",
                "confidence": "MEDIUM",
                "recommended_scope": "filesystem",
                "evidence_ids": [evidence.evidence_id],
                "source_resource_ids": [node.node_id],
                "citations": [
                    _citation(
                        case_id=case.case_id,
                        evidence_id=evidence.evidence_id,
                        node_id=node.node_id,
                        source_path=node.original_relative_path,
                    )
                ],
            }
        ],
    }
    provider.summary_payload = {
        "provider_id": provider.provider_id,
        "provider_version": provider.provider_version,
        "model_id": "fake-model",
        "external_request_id": "fake-summary-request",
        "title": "Selected filesystem scope",
        "summary_text": "The selected snapshot scope contains the cited alpha term.",
        "key_points": ["One selected text file contains alpha."],
        "referenced_resource_ids": [node.node_id],
        "citations": [
            _citation(
                case_id=case.case_id,
                evidence_id=evidence.evidence_id,
                node_id=node.node_id,
                source_path=node.original_relative_path,
            )
        ],
    }
    runtime = create_runtime(
        McpConfig(
            database_path=tmp_path / "m3.db",
            schema_dir=project_root / "schemas" / "v1",
            allowed_tools=M3_TOOL_NAMES,
        ),
        adapter=EngineAdapter(services),
        bindings=m3_bindings(),
    )
    return services, provider, runtime, context


def test_m3_snapshot_first_ai_execute_and_replay(
    project_root: Path,
    tmp_path: Path,
) -> None:
    services, provider, runtime, context = _fixture(project_root, tmp_path)
    try:

        async def exercise() -> None:
            async with Client(runtime.server) as client:
                discovered = await client.list_tools(cache_mode="refresh")
                assert {tool.name for tool in discovered.tools} == M3_TOOL_NAMES
                assert {tool.name for tool in discovered.tools} >= M3_AI_TOOL_NAMES
                execute_tool = next(
                    tool for tool in discovered.tools if tool.name == "ai.request.execute"
                )
                assert execute_tool.annotations is not None
                assert execute_tool.annotations.read_only_hint is False
                assert execute_tool.annotations.idempotent_hint is True

                capabilities = await client.call_tool("ai.capabilities", {})
                assert capabilities.is_error is False
                assert capabilities.structured_content["data"]["runtime_capability"][
                    "is_available"
                ]

                snapshot_result = await client.call_tool(
                    "apex.context.snapshot",
                    {
                        "session_context_id": context.session_context_id,
                        "scopes": ["filesystem"],
                    },
                )
                snapshot = snapshot_result.structured_content["data"]
                request_result = await client.call_tool(
                    "ai.request.create",
                    {
                        "case_id": context.case_id,
                        "context_snapshot_id": snapshot["context_snapshot_id"],
                        "purpose": "KEYWORD_RECOMMENDATION",
                        "requested_operations": ["RECOMMEND_KEYWORDS"],
                        "requested_scopes": ["filesystem"],
                    },
                )
                assert request_result.is_error is False
                request = request_result.structured_content["data"]

                arguments = {
                    "assistance_request_id": request["assistance_request_id"],
                    "operation": "RECOMMEND_KEYWORDS",
                }
                first = await client.call_tool("ai.request.execute", arguments)
                assert first.is_error is False
                result = first.structured_content["data"]
                assert result["replayed"] is False
                assert result["observed_fact_status"] == "NOT_OBSERVED_FACT"
                assert result["source_revision_check"]["is_current"] is True
                assert result["result"]["batch"]["recommendation_count"] == 1
                assert result["result"]["recommendations"][0]["review_status"] == (
                    "UNREVIEWED"
                )

                replay = await client.call_tool("ai.request.execute", arguments)
                assert replay.is_error is False
                assert replay.structured_content["data"]["replayed"] is True
                assert replay.structured_content["data"]["result"] == result["result"]

                not_requested = await client.call_tool(
                    "ai.request.execute",
                    {
                        "assistance_request_id": request["assistance_request_id"],
                        "operation": "SUMMARIZE_SCOPE",
                    },
                )
                assert not_requested.is_error is True
                assert not_requested.structured_content["errors"][0]["code"] == (
                    "AI_OPERATION_NOT_REQUESTED"
                )

                summary_request_result = await client.call_tool(
                    "ai.request.create",
                    {
                        "case_id": context.case_id,
                        "context_snapshot_id": snapshot["context_snapshot_id"],
                        "purpose": "SCOPE_SUMMARY",
                        "requested_operations": ["SUMMARIZE_SCOPE"],
                        "requested_scopes": ["filesystem"],
                    },
                )
                assert summary_request_result.is_error is False
                summary_request = summary_request_result.structured_content["data"]
                summary_result = await client.call_tool(
                    "ai.request.execute",
                    {
                        "assistance_request_id": summary_request[
                            "assistance_request_id"
                        ],
                        "operation": "SUMMARIZE_SCOPE",
                    },
                )
                assert summary_result.is_error is False
                summary = summary_result.structured_content["data"]
                assert summary["result_kind"] == "AI_SUMMARY"
                assert summary["result"]["review_status"] == "UNREVIEWED"
                assert summary["result"]["observed_fact_status"] == (
                    "NOT_OBSERVED_FACT"
                )

                untrusted = await client.call_tool(
                    "ai.request.execute",
                    {**arguments, "api_key": "must-not-enter-the-contract"},
                )
                assert untrusted.is_error is True
                assert untrusted.structured_content["errors"][0]["code"] == (
                    "VALIDATION_ERROR"
                )

        asyncio.run(exercise())
        assert provider.keyword_calls == 1
        assert provider.summary_calls == 1
    finally:
        runtime.close()
        services.close()


def test_m3_rejects_changed_source_revision_before_provider_dispatch(
    project_root: Path,
    tmp_path: Path,
) -> None:
    services, provider, runtime, context = _fixture(project_root, tmp_path)
    try:
        snapshot = services.contexts.build_from_session(
            context.session_context_id,
            purpose="AI_REQUEST",
            scopes=["filesystem"],
        )
        request = services.ai.create_request_from_context_snapshot(
            case_id=context.case_id,
            context_snapshot_id=snapshot.context_snapshot_id,
            purpose="KEYWORD_RECOMMENDATION",
            requested_operations=["RECOMMEND_KEYWORDS"],
            requested_scopes=["filesystem"],
        )
        resource_id = snapshot.source_revisions[0].resource_id
        with services.repository.connection:
            services.repository.connection.execute(
                "UPDATE fs_nodes SET index_revision = index_revision + 1 WHERE node_id = ?",
                (resource_id,),
            )

        blocked = runtime.registry.call_tool(
            "ai.request.execute",
            {
                "assistance_request_id": request.assistance_request_id,
                "operation": "RECOMMEND_KEYWORDS",
            },
        )

        assert blocked.is_error is True
        assert blocked.structured_content["errors"][0]["code"] == (
            "AI_SOURCE_REVISION_STALE"
        )
        assert provider.keyword_calls == 0
    finally:
        runtime.close()
        services.close()


def test_m3_keeps_ai_tools_discoverable_but_execute_unavailable_without_provider(
    project_root: Path,
    tmp_path: Path,
) -> None:
    services, provider, runtime, context = _fixture(
        project_root,
        tmp_path,
        configure_provider=False,
    )
    try:
        snapshot = services.contexts.build_from_session(
            context.session_context_id,
            purpose="AI_REQUEST",
            scopes=["filesystem"],
        )
        request = services.ai.create_request_from_context_snapshot(
            case_id=context.case_id,
            context_snapshot_id=snapshot.context_snapshot_id,
            purpose="KEYWORD_RECOMMENDATION",
            requested_operations=["RECOMMEND_KEYWORDS"],
            requested_scopes=["filesystem"],
        )

        capabilities = runtime.registry.call_tool("ai.capabilities", {})
        unavailable = runtime.registry.call_tool(
            "ai.request.execute",
            {
                "assistance_request_id": request.assistance_request_id,
                "operation": "RECOMMEND_KEYWORDS",
            },
        )

        assert capabilities.is_error is False
        assert capabilities.structured_content["data"]["runtime_capability"][
            "is_available"
        ] is False
        assert unavailable.is_error is True
        assert unavailable.structured_content["errors"][0]["code"] == (
            "CAPABILITY_UNAVAILABLE"
        )
        assert provider.keyword_calls == 0
    finally:
        runtime.close()
        services.close()
