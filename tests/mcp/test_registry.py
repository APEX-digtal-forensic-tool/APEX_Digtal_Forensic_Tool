from __future__ import annotations

from pathlib import Path

import pytest

from apex_forensic.config import build_services
from apex_mcp.budget import ToolBudget
from apex_mcp.capability_gate import CapabilityGate
from apex_mcp.confirmation import ConfirmationGate
from apex_mcp.engine_adapter import EngineAdapter
from apex_mcp.errors import ToolRegistrationError
from apex_mcp.schema_catalog import SchemaCatalog
from apex_mcp.tool_registry import ToolBinding, ToolRegistry

CONTEXT_GET_SCHEMA = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "object",
    "additionalProperties": False,
    "required": ["session_context_id"],
    "properties": {
        "session_context_id": {"type": "string", "minLength": 1},
    },
}

RAW_READ_SCHEMA = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "object",
    "additionalProperties": False,
    "required": ["case_id", "resource_type", "resource_id", "length"],
    "properties": {
        "case_id": {"type": "string", "minLength": 1},
        "resource_type": {"type": "string", "minLength": 1},
        "resource_id": {"type": "string", "minLength": 1},
        "offset": {"type": "integer", "minimum": 0},
        "length": {"type": "integer", "minimum": 1, "maximum": 1048576},
    },
}


def _registry(
    project_root: Path,
    tmp_path: Path,
    *,
    allowed_tools: frozenset[str],
    budget: ToolBudget | None = None,
) -> tuple[object, ToolRegistry]:
    services = build_services(tmp_path / "registry.db")
    adapter = EngineAdapter(services)
    interface = adapter.get_interface()
    registry = ToolRegistry(
        adapter=adapter,
        catalog=SchemaCatalog(project_root / "schemas" / "v1"),
        capability_gate=CapabilityGate(interface),
        confirmation_gate=ConfirmationGate(),
        allowed_tools=allowed_tools,
        budget=budget,
    )
    return services, registry


def test_registry_requires_phase_allowlist(project_root: Path, tmp_path: Path) -> None:
    services, registry = _registry(project_root, tmp_path, allowed_tools=frozenset())
    try:
        with pytest.raises(ToolRegistrationError):
            registry.register(
                ToolBinding(
                    tool_name="apex.context.get",
                    operation="apex.context.get",
                    input_schema=CONTEXT_GET_SCHEMA,
                )
            )
    finally:
        services.close()  # type: ignore[attr-defined]


def test_registry_rejects_non_descriptor_tool(project_root: Path, tmp_path: Path) -> None:
    services, registry = _registry(
        project_root,
        tmp_path,
        allowed_tools=frozenset({"apex.fake.tool"}),
    )
    try:
        with pytest.raises(ToolRegistrationError):
            registry.register(
                ToolBinding(
                    tool_name="apex.fake.tool",
                    operation="apex.fake.tool",
                    input_schema={"type": "object"},
                )
            )
    finally:
        services.close()  # type: ignore[attr-defined]


def test_registry_blocks_confirmation_tool_before_core_call(
    project_root: Path,
    tmp_path: Path,
) -> None:
    services, registry = _registry(
        project_root,
        tmp_path,
        allowed_tools=frozenset({"apex.view.raw_read"}),
    )
    try:
        registry.register(
            ToolBinding(
                tool_name="apex.view.raw_read",
                operation="apex.view.raw_read",
                input_schema=RAW_READ_SCHEMA,
            )
        )

        result = registry.call_tool(
            "apex.view.raw_read",
            {
                "case_id": "case-id",
                "resource_type": "FILE_SYSTEM_NODE",
                "resource_id": "node-id",
                "length": 16,
            },
        )

        assert result.is_error is True
        assert result.structured_content["errors"][0]["code"] == "HUMAN_CONFIRMATION_REQUIRED"
    finally:
        services.close()  # type: ignore[attr-defined]


def test_registry_rejects_core_output_schema_mismatch(
    project_root: Path,
    tmp_path: Path,
) -> None:
    services, registry = _registry(
        project_root,
        tmp_path,
        allowed_tools=frozenset({"apex.context.get"}),
    )
    try:
        case = services.cases.create_case(name="Output Contract")  # type: ignore[attr-defined]
        context = services.contexts.create(  # type: ignore[attr-defined]
            session_id="output-contract",
            case_id=case.case_id,
        )
        registry.register(
            ToolBinding(
                tool_name="apex.context.get",
                operation="apex.context.get",
                input_schema=CONTEXT_GET_SCHEMA,
                output_schema_ref="view-projection.schema.json",
            )
        )

        result = registry.call_tool(
            "apex.context.get",
            {"session_context_id": context.session_context_id},
        )

        assert result.is_error is True
        assert (
            result.structured_content["errors"][0]["code"]
            == "MCP_OUTPUT_VALIDATION_FAILED"
        )
    finally:
        services.close()  # type: ignore[attr-defined]


def test_registry_enforces_rolling_call_budget(project_root: Path, tmp_path: Path) -> None:
    services, registry = _registry(
        project_root,
        tmp_path,
        allowed_tools=frozenset({"apex.context.get"}),
        budget=ToolBudget(max_calls=1),
    )
    try:
        case = services.cases.create_case(name="Call Budget")  # type: ignore[attr-defined]
        context = services.contexts.create(  # type: ignore[attr-defined]
            session_id="call-budget",
            case_id=case.case_id,
        )
        registry.register(
            ToolBinding(
                tool_name="apex.context.get",
                operation="apex.context.get",
                input_schema=CONTEXT_GET_SCHEMA,
            )
        )
        arguments = {"session_context_id": context.session_context_id}

        assert registry.call_tool("apex.context.get", arguments).is_error is False
        blocked = registry.call_tool("apex.context.get", arguments)

        assert blocked.is_error is True
        assert blocked.structured_content["errors"][0]["code"] == "MCP_BUDGET_EXCEEDED"
    finally:
        services.close()  # type: ignore[attr-defined]
