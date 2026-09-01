from __future__ import annotations

import asyncio
from pathlib import Path

from mcp.client import Client

from apex_forensic.config import build_services
from apex_forensic.domain.enums import AnalysisProfileType
from apex_mcp.config import McpConfig
from apex_mcp.engine_adapter import EngineAdapter
from apex_mcp.m1_tools import M1_TOOL_NAMES, m1_bindings
from apex_mcp.server import create_runtime


def test_m1_discovers_and_calls_all_context_view_tools(
    project_root: Path,
    tmp_path: Path,
) -> None:
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    for index in range(3):
        (evidence_root / f"item-{index}.txt").write_text(
            f"M1 item {index}",
            encoding="utf-8",
        )
    database_path = tmp_path / "m1.db"
    services = build_services(database_path)
    try:
        case = services.cases.create_case(name="MCP M1")
        evidence = services.evidence.register_evidence(
            case_id=case.case_id,
            source_path=evidence_root,
        )
        services.fs.index_evidence(
            case_id=case.case_id,
            evidence_id=evidence.evidence_id,
            profile_type=AnalysisProfileType.FULL_ANALYSIS,
        )
        nodes = [
            node
            for node in services.fs.list_nodes(
                evidence_id=evidence.evidence_id,
                all_nodes=True,
            ).items
            if node.node_type.value == "FILE"
        ]
        context = services.contexts.create(
            session_id="mcp-m1-session",
            case_id=case.case_id,
            actor_id="analyst-m1",
            selected_file_node_ids=[node.node_id for node in nodes],
            active_context_scope="filesystem",
        )
        runtime = create_runtime(
            McpConfig(
                database_path=database_path,
                schema_dir=project_root / "schemas" / "v1",
                allowed_tools=M1_TOOL_NAMES,
            ),
            adapter=EngineAdapter(services),
            bindings=m1_bindings(),
        )

        async def exercise() -> None:
            async with Client(runtime.server) as client:
                discovered = await client.list_tools(cache_mode="refresh")
                assert {tool.name for tool in discovered.tools} == M1_TOOL_NAMES
                assert "apex.view.raw_read" not in {tool.name for tool in discovered.tools}
                snapshot_tool = next(
                    tool for tool in discovered.tools if tool.name == "apex.context.snapshot"
                )
                assert snapshot_tool.annotations is not None
                assert snapshot_tool.annotations.read_only_hint is False
                assert snapshot_tool.annotations.destructive_hint is False

                context_result = await client.call_tool(
                    "apex.context.get",
                    {"session_context_id": context.session_context_id},
                )
                assert context_result.is_error is False
                assert context_result.structured_content["data"]["context_revision"] == 1

                rejected_purpose = await client.call_tool(
                    "apex.context.snapshot",
                    {
                        "session_context_id": context.session_context_id,
                        "purpose": "EXPORT",
                    },
                )
                assert rejected_purpose.is_error is True
                assert (
                    rejected_purpose.structured_content["errors"][0]["code"]
                    == "VALIDATION_ERROR"
                )

                snapshot_result = await client.call_tool(
                    "apex.context.snapshot",
                    {
                        "session_context_id": context.session_context_id,
                        "scopes": ["filesystem"],
                    },
                )
                assert snapshot_result.is_error is False
                snapshot = snapshot_result.structured_content["data"]
                assert snapshot["purpose"] == "MCP_REQUEST"
                assert snapshot["session_context_revision"] == context.context_revision
                assert isinstance(snapshot["partial_state"], dict)
                assert isinstance(snapshot["stale_state"], dict)
                assert isinstance(snapshot["citations"], list)

                shown = await client.call_tool(
                    "apex.context.snapshot_show",
                    {"context_snapshot_id": snapshot["context_snapshot_id"]},
                )
                assert shown.is_error is False
                assert shown.structured_content["data"] == snapshot

                first_page = await client.call_tool(
                    "apex.context.scope_page",
                    {
                        "context_snapshot_id": snapshot["context_snapshot_id"],
                        "scope": "filesystem",
                        "limit": 1,
                    },
                )
                assert first_page.is_error is False
                page_data = first_page.structured_content["data"]
                assert page_data["page"]["returned"] == 1
                assert page_data["page"]["has_more"] is True
                cursor = page_data["page"]["next_cursor"]
                assert isinstance(cursor, str)

                second_page = await client.call_tool(
                    "apex.context.scope_page",
                    {
                        "context_snapshot_id": snapshot["context_snapshot_id"],
                        "scope": "filesystem",
                        "cursor": cursor,
                        "limit": 1,
                    },
                )
                assert second_page.is_error is False
                assert second_page.structured_content["data"]["page"]["returned"] == 1

                pagination_loop = await client.call_tool(
                    "apex.context.scope_page",
                    {
                        "context_snapshot_id": snapshot["context_snapshot_id"],
                        "scope": "filesystem",
                        "cursor": cursor,
                        "limit": 1,
                    },
                )
                assert pagination_loop.is_error is True
                assert (
                    pagination_loop.structured_content["errors"][0]["code"]
                    == "MCP_PAGINATION_LOOP"
                )

                view_payload = {
                    "case_id": case.case_id,
                    "resource_type": "FILE_SYSTEM_NODE",
                    "resource_id": nodes[0].node_id,
                }
                for tool_name, mode in (
                    ("apex.view.simple", "SIMPLE"),
                    ("apex.view.detailed", "DETAILED"),
                    ("apex.view.raw", "RAW"),
                ):
                    projection_result = await client.call_tool(tool_name, view_payload)
                    assert projection_result.is_error is False
                    projection = projection_result.structured_content["data"]
                    assert projection["view_mode"] == mode
                    assert isinstance(projection["partial_state"], dict)
                    assert isinstance(projection["stale_state"], dict)
                    assert isinstance(projection["citations"], list)

                raw_read = await client.call_tool("apex.view.raw_read", view_payload)
                assert raw_read.is_error is True
                assert raw_read.structured_content["errors"][0]["code"] == "TOOL_NOT_FOUND"

        asyncio.run(exercise())
        runtime.close()
    finally:
        services.close()


def test_m1_rejects_expired_context(project_root: Path, tmp_path: Path) -> None:
    database_path = tmp_path / "expired.db"
    services = build_services(database_path)
    try:
        case = services.cases.create_case(name="Expired MCP Context")
        context = services.contexts.create(
            session_id="expired-mcp",
            case_id=case.case_id,
            expires_at="2000-01-01T00:00:00Z",
        )
        runtime = create_runtime(
            McpConfig(
                database_path=database_path,
                schema_dir=project_root / "schemas" / "v1",
                allowed_tools=M1_TOOL_NAMES,
            ),
            adapter=EngineAdapter(services),
            bindings=m1_bindings(),
        )

        result = runtime.registry.call_tool(
            "apex.context.get",
            {"session_context_id": context.session_context_id},
        )

        assert result.is_error is True
        assert result.structured_content["errors"][0]["code"] == "CONTEXT_EXPIRED"
        runtime.close()
    finally:
        services.close()
