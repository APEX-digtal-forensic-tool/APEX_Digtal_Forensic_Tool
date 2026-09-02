from __future__ import annotations

import asyncio
import sys
from pathlib import Path

from mcp.client import Client
from mcp.client.stdio import StdioServerParameters

from apex_forensic.config import build_services
from apex_mcp.config import McpConfig
from apex_mcp.engine_adapter import EngineAdapter
from apex_mcp.m7_tools import M7_TOOL_NAMES
from apex_mcp.server import create_runtime
from apex_mcp.tool_registry import ToolBinding

CONTEXT_GET_SCHEMA = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "object",
    "additionalProperties": False,
    "required": ["session_context_id"],
    "properties": {
        "session_context_id": {"type": "string", "minLength": 1},
    },
}


def test_mcp_2_in_process_discovery_and_context_call(project_root: Path, tmp_path: Path) -> None:
    services = build_services(tmp_path / "sdk.db")
    try:
        case = services.cases.create_case(name="MCP SDK Spike")
        context = services.contexts.create(
            session_id="sdk-spike",
            case_id=case.case_id,
            actor_id="analyst-1",
        )
        runtime = create_runtime(
            McpConfig(
                database_path=tmp_path / "sdk.db",
                schema_dir=project_root / "schemas" / "v1",
                allowed_tools=frozenset({"apex.context.get"}),
            ),
            adapter=EngineAdapter(services),
            bindings=(
                ToolBinding(
                    tool_name="apex.context.get",
                    operation="apex.context.get",
                    input_schema=CONTEXT_GET_SCHEMA,
                ),
            ),
        )

        async def exercise() -> None:
            async with Client(runtime.server) as client:
                tools = await client.list_tools(cache_mode="refresh")
                assert client.session.protocol_version == "2026-07-28"
                assert [tool.name for tool in tools.tools] == ["apex.context.get"]
                assert tools.tools[0].input_schema == CONTEXT_GET_SCHEMA
                result = await client.call_tool(
                    "apex.context.get",
                    {"session_context_id": context.session_context_id},
                )
                assert result.is_error is False
                assert result.structured_content["status"] == "OK"
                assert (
                    result.structured_content["data"]["session_context_id"]
                    == context.session_context_id
                )

        asyncio.run(exercise())
        runtime.close()
    finally:
        services.close()


def test_mcp_2_stdio_subprocess_negotiates_with_m7_tools(
    project_root: Path,
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "stdio.db"
    services = build_services(database_path)
    services.close()
    parameters = StdioServerParameters(
        command=sys.executable,
        args=[
            "-m",
            "apex_mcp",
            "--database",
            str(database_path),
            "--schema-dir",
            str(project_root / "schemas" / "v1"),
        ],
        cwd=project_root,
        env={"PYTHONPATH": str(project_root / "src")},
    )

    async def exercise() -> None:
        async with Client(parameters) as client:
            tools = await client.list_tools(cache_mode="refresh")
            assert client.session.protocol_version == "2026-07-28"
            assert {tool.name for tool in tools.tools} == M7_TOOL_NAMES
            raw_read = next(tool for tool in tools.tools if tool.name == "apex.view.raw_read")
            assert raw_read.meta is not None
            assert raw_read.meta["apex/requiresConfirmation"] is True
            denied = await client.call_tool(
                "apex.view.raw_read",
                {
                    "case_id": "case-id",
                    "resource_type": "FILE_SYSTEM_NODE",
                    "resource_id": "node-id",
                    "offset": 0,
                    "length": 16,
                },
            )
            assert denied.is_error is True
            assert denied.structured_content["errors"][0]["code"] == "HUMAN_CONFIRMATION_REQUIRED"
            review_denied = await client.call_tool(
                "ai.keyword-recommendation.review",
                {
                    "case_id": "case-id",
                    "recommendation_id": "recommendation-id",
                    "action": "ACCEPT",
                    "reason": "No trusted approval source is connected.",
                    "expected_review_revision": 0,
                },
            )
            assert review_denied.is_error is True
            assert review_denied.structured_content["errors"][0]["code"] == (
                "HUMAN_CONFIRMATION_REQUIRED"
            )
            approval_denied = await client.call_tool(
                "report.approve",
                {
                    "case_id": "case-id",
                    "report_version_id": "report-version-id",
                    "reason": "No trusted approval source is connected.",
                    "expected_review_revision": 1,
                    "expected_approval_revision": 0,
                },
            )
            assert approval_denied.is_error is True
            assert approval_denied.structured_content["errors"][0]["code"] == (
                "HUMAN_CONFIRMATION_REQUIRED"
            )

    asyncio.run(exercise())
