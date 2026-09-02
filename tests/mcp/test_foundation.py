from __future__ import annotations

from pathlib import Path

import pytest

from apex_forensic.config import build_services
from apex_mcp.capability_gate import CapabilityGate
from apex_mcp.config import McpConfig
from apex_mcp.confirmation import ConfirmationGate
from apex_mcp.context_bridge import ContextBridge
from apex_mcp.engine_adapter import EngineAdapter
from apex_mcp.error_mapper import ErrorMapper
from apex_mcp.errors import (
    CapabilityGateError,
    ConfirmationRequiredError,
    McpConfigurationError,
    McpFoundationError,
)
from apex_mcp.interface_guard import InterfaceGuard
from apex_mcp.redaction import Redactor
from apex_mcp.schema_catalog import SchemaCatalog


def test_schema_catalog_loads_all_canonical_contracts(project_root: Path) -> None:
    catalog = SchemaCatalog(project_root / "schemas" / "v1")

    assert catalog.count == 70
    assert catalog.has("engine-interface.schema.json")
    assert catalog.has("engine-tool-descriptor.schema.json")
    assert catalog.has("api-response.schema.json")


def test_config_requires_existing_database_by_default(project_root: Path, tmp_path: Path) -> None:
    with pytest.raises(McpConfigurationError):
        McpConfig(
            database_path=tmp_path / "missing.db",
            schema_dir=project_root / "schemas" / "v1",
        ).validate()


def test_config_from_env_requires_explicit_schema_directory(tmp_path: Path) -> None:
    database_path = tmp_path / "case.db"
    database_path.touch()

    with pytest.raises(McpConfigurationError) as captured:
        McpConfig.from_env({"APEX_MCP_DATABASE": str(database_path)})

    assert captured.value.target == "APEX_MCP_SCHEMA_DIR"


def test_config_from_env_keeps_ai_secret_out_of_configuration(
    project_root: Path,
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "case.db"
    database_path.touch()
    config = McpConfig.from_env(
        {
            "APEX_MCP_DATABASE": str(database_path),
            "APEX_MCP_SCHEMA_DIR": str(project_root / "schemas" / "v1"),
            "APEX_MCP_AI_PROVIDER_ID": "test-provider",
            "APEX_MCP_AI_BASE_URL": "https://provider.invalid/v1",
            "APEX_MCP_AI_MODEL": "test-model",
            "APEX_MCP_AI_API_KEY_ENV": "TEST_PROVIDER_API_KEY",
            "TEST_PROVIDER_API_KEY": "secret-value-must-not-be-copied",
        }
    )

    assert config.ai_provider is not None
    assert config.ai_provider.api_key_env == "TEST_PROVIDER_API_KEY"
    assert "secret-value-must-not-be-copied" not in repr(config)


def test_config_from_env_rejects_partial_ai_provider_settings(
    project_root: Path,
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "case.db"
    database_path.touch()

    with pytest.raises(McpConfigurationError):
        McpConfig.from_env(
            {
                "APEX_MCP_DATABASE": str(database_path),
                "APEX_MCP_SCHEMA_DIR": str(project_root / "schemas" / "v1"),
                "APEX_MCP_AI_PROVIDER_ID": "incomplete-provider",
            }
        )


def test_interface_guard_validates_current_core(project_root: Path, tmp_path: Path) -> None:
    services = build_services(tmp_path / "guard.db")
    try:
        adapter = EngineAdapter(services)
        interface, descriptors = InterfaceGuard(
            SchemaCatalog(project_root / "schemas" / "v1")
        ).validate(adapter)

        assert interface["interface_name"] == "apex.engine.public"
        assert interface["interface_version"] == "1.0.0"
        assert len(descriptors) >= 20
        assert {item["tool_name"] for item in descriptors} >= {
            "apex.context.get",
            "apex.view.raw_read",
            "ai.request.create",
            "ai.request.execute",
            "report.get",
        }
    finally:
        services.close()


def test_capability_gate_preserves_missing_capabilities() -> None:
    gate = CapabilityGate(
        {
            "capabilities": ["CONTEXT_SNAPSHOT"],
            "unavailable_capabilities": ["MCP_SERVER"],
        }
    )
    descriptor = {"required_capabilities": ["CONTEXT_SNAPSHOT", "MCP_SERVER"]}

    decision = gate.evaluate(descriptor)

    assert decision.allowed is False
    assert decision.missing == ("MCP_SERVER",)
    with pytest.raises(CapabilityGateError):
        gate.require(descriptor)


def test_confirmation_gate_is_default_deny() -> None:
    gate = ConfirmationGate()

    assert (
        gate.require(
            {"tool_name": "apex.context.get", "requires_confirmation": False},
            None,
        )
        is False
    )
    with pytest.raises(ConfirmationRequiredError):
        gate.require(
            {"tool_name": "apex.view.raw_read", "requires_confirmation": True},
            None,
        )


def test_redactor_removes_sensitive_fields_and_tokens() -> None:
    redacted = Redactor().redact(
        {
            "api_key": "sk-super-secret-value",
            "nested": {
                "authorization": "Bearer abc.def.ghi",
                "safe": "prefix sk-visible-secret suffix",
            },
            "payload": b"binary",
        }
    )

    assert redacted["api_key"] == "<redacted>"
    assert redacted["nested"]["authorization"] == "<redacted>"
    assert "sk-visible-secret" not in redacted["nested"]["safe"]
    assert redacted["payload"] == "<redacted>"


def test_error_mapper_never_exposes_unknown_exception_text() -> None:
    mapped = ErrorMapper().map_exception(RuntimeError("Bearer top-secret"))

    assert mapped["status"] == "ERROR"
    assert mapped["errors"][0]["code"] == "MCP_INTERNAL_ERROR"
    assert "top-secret" not in str(mapped)


def test_error_mapper_redacts_foundation_error_details() -> None:
    mapped = ErrorMapper().map_exception(
        McpFoundationError(
            "PROVIDER_FAILED",
            "Provider rejected the request.",
            details={"api_key": "sk-private-value"},
        )
    )

    assert mapped["errors"][0]["details"]["api_key"] == "<redacted>"


def test_context_bridge_rejects_depth_size_secret_and_binary_payloads() -> None:
    bridge = ContextBridge()
    nested: dict[str, object] = {"leaf": "value"}
    for _ in range(9):
        nested = {"nested": nested}

    for payload in (
        nested,
        {"safe": "x" * (64 * 1024)},
        {"api_key": "sk-private-value"},
        {"safe": b"raw"},
    ):
        with pytest.raises(McpFoundationError):
            bridge.prepare("apex.context.snapshot", payload)


def test_context_bridge_forces_mcp_request_snapshot_purpose() -> None:
    prepared = ContextBridge().prepare(
        "apex.context.snapshot",
        {"session_context_id": "context-1"},
    )

    assert prepared["purpose"] == "MCP_REQUEST"
