from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

from apex_forensic.config import build_services
from apex_forensic.domain.enums import AnalysisProfileType
from apex_mcp.config import McpConfig
from apex_mcp.confirmation import (
    ConfirmationGrant,
    ConfirmationRequest,
    InMemoryConfirmationProvider,
)
from apex_mcp.engine_adapter import EngineAdapter
from apex_mcp.m2_tools import M2_TOOL_NAMES, m2_bindings
from apex_mcp.server import create_runtime
from apex_mcp.telemetry import ToolTelemetryEvent, request_fingerprint


class RecordingTelemetry:
    def __init__(self) -> None:
        self.events: list[ToolTelemetryEvent] = []

    def emit(self, event: ToolTelemetryEvent) -> None:
        self.events.append(event)


def _grant(
    *,
    grant_id: str,
    arguments: dict[str, object],
    actor_id: str = "analyst-raw",
    session_id: str = "frontend-session-raw",
) -> tuple[ConfirmationGrant, ConfirmationRequest]:
    fingerprint = request_fingerprint(arguments)
    target_ids = (str(arguments["resource_id"]),)
    grant = ConfirmationGrant(
        grant_id=grant_id,
        actor_id=actor_id,
        session_id=session_id,
        case_id=str(arguments["case_id"]),
        tool_name="apex.view.raw_read",
        request_fingerprint=fingerprint,
        target_ids=target_ids,
        expires_at=datetime.now(UTC) + timedelta(minutes=5),
    )
    request = ConfirmationRequest(
        grant_id=grant_id,
        actor_id=actor_id,
        session_id=session_id,
        case_id=str(arguments["case_id"]),
        tool_name="apex.view.raw_read",
        request_fingerprint=fingerprint,
        target_ids=target_ids,
    )
    return grant, request


def test_m2_raw_read_is_default_deny_and_rejects_model_shortcuts(
    project_root: Path,
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "raw-deny.db"
    services = build_services(database_path)
    try:
        runtime = create_runtime(
            McpConfig(
                database_path=database_path,
                schema_dir=project_root / "schemas" / "v1",
                allowed_tools=M2_TOOL_NAMES,
            ),
            adapter=EngineAdapter(services),
            bindings=m2_bindings(),
        )
        arguments: dict[str, object] = {
            "case_id": "case-id",
            "resource_type": "FILE_SYSTEM_NODE",
            "resource_id": "node-id",
            "offset": 0,
            "length": 16,
        }

        denied = runtime.registry.call_tool("apex.view.raw_read", arguments)
        model_confirmation = runtime.registry.call_tool(
            "apex.view.raw_read",
            {**arguments, "confirmed": True},
        )
        model_token = runtime.registry.call_tool(
            "apex.view.raw_read",
            {**arguments, "confirmation_token": "model-controlled"},
        )
        too_large = runtime.registry.call_tool(
            "apex.view.raw_read",
            {**arguments, "length": 1024 * 1024 + 1},
        )
        arbitrary_path = runtime.registry.call_tool(
            "apex.view.raw_read",
            {**arguments, "path": "/etc/passwd"},
        )

        assert denied.structured_content["errors"][0]["code"] == "HUMAN_CONFIRMATION_REQUIRED"
        for rejected in (model_confirmation, model_token, too_large, arbitrary_path):
            assert rejected.is_error is True
            assert rejected.structured_content["errors"][0]["code"] == "VALIDATION_ERROR"
        runtime.close()
    finally:
        services.close()


def test_m2_exact_one_time_grant_allows_bounded_core_raw_read(
    project_root: Path,
    tmp_path: Path,
) -> None:
    evidence_root = tmp_path / "raw-evidence"
    evidence_root.mkdir()
    (evidence_root / "evidence.bin").write_bytes(b"APEX-M2-RAW" * 64)
    database_path = tmp_path / "raw-approved.db"
    services = build_services(database_path)
    provider = InMemoryConfirmationProvider()
    telemetry = RecordingTelemetry()
    try:
        case = services.cases.create_case(name="Approved Raw Read")
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
        runtime = create_runtime(
            McpConfig(
                database_path=database_path,
                schema_dir=project_root / "schemas" / "v1",
                allowed_tools=M2_TOOL_NAMES,
            ),
            adapter=EngineAdapter(services),
            bindings=m2_bindings(),
            confirmation_provider=provider,
            telemetry=telemetry,
        )
        arguments: dict[str, object] = {
            "case_id": case.case_id,
            "resource_type": "FILE_SYSTEM_NODE",
            "resource_id": node.node_id,
            "offset": 0,
            "length": 1024 * 1024,
        }
        grant, confirmation = _grant(grant_id="grant-1", arguments=arguments)
        provider.issue(grant)

        untrusted_claim = runtime.registry.call_tool(
            "apex.view.raw_read",
            arguments,
            confirmation=confirmation,
        )
        approved = runtime.registry.call_tool(
            "apex.view.raw_read",
            arguments,
            confirmation=confirmation,
            trusted_actor_id="analyst-raw",
            trusted_session_id="frontend-session-raw",
        )
        reused = runtime.registry.call_tool(
            "apex.view.raw_read",
            arguments,
            confirmation=confirmation,
            trusted_actor_id="analyst-raw",
            trusted_session_id="frontend-session-raw",
        )

        assert untrusted_claim.is_error is True
        assert (
            untrusted_claim.structured_content["errors"][0]["code"]
            == "HUMAN_CONFIRMATION_REQUIRED"
        )
        assert approved.is_error is False
        raw = approved.structured_content["data"]
        assert raw["requested_length"] == 1024 * 1024
        assert raw["returned_length"] == len(b"APEX-M2-RAW" * 64)
        assert raw["hex_preview"]
        assert reused.is_error is True
        assert reused.structured_content["errors"][0]["code"] == "HUMAN_CONFIRMATION_REQUIRED"
        approved_event = next(
            event for event in telemetry.events if event.confirmation_decision == "APPROVED"
        )
        assert approved_event.confirmation_actor_id == "analyst-raw"
        assert approved_event.confirmation_session_id == "frontend-session-raw"
        assert approved_event.correlation_id
        assert any(event.confirmation_decision == "DENIED" for event in telemetry.events)
        runtime.close()
    finally:
        services.close()


def test_m2_grant_cannot_cross_target_or_request_fingerprint(
    project_root: Path,
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "raw-binding.db"
    services = build_services(database_path)
    provider = InMemoryConfirmationProvider()
    try:
        runtime = create_runtime(
            McpConfig(
                database_path=database_path,
                schema_dir=project_root / "schemas" / "v1",
                allowed_tools=M2_TOOL_NAMES,
            ),
            adapter=EngineAdapter(services),
            bindings=m2_bindings(),
            confirmation_provider=provider,
        )
        arguments: dict[str, object] = {
            "case_id": "case-a",
            "resource_type": "FILE_SYSTEM_NODE",
            "resource_id": "node-a",
            "offset": 0,
            "length": 16,
        }

        target_grant, target_confirmation = _grant(
            grant_id="target-grant",
            arguments=arguments,
        )
        provider.issue(target_grant)
        wrong_target = runtime.registry.call_tool(
            "apex.view.raw_read",
            {**arguments, "resource_id": "node-b"},
            confirmation=target_confirmation,
            trusted_actor_id="analyst-raw",
            trusted_session_id="frontend-session-raw",
        )

        fingerprint_grant, fingerprint_confirmation = _grant(
            grant_id="fingerprint-grant",
            arguments=arguments,
        )
        provider.issue(fingerprint_grant)
        changed_offset = runtime.registry.call_tool(
            "apex.view.raw_read",
            {**arguments, "offset": 1},
            confirmation=fingerprint_confirmation,
            trusted_actor_id="analyst-raw",
            trusted_session_id="frontend-session-raw",
        )

        assert wrong_target.structured_content["errors"][0]["code"] == (
            "HUMAN_CONFIRMATION_REQUIRED"
        )
        assert changed_offset.structured_content["errors"][0]["code"] == (
            "HUMAN_CONFIRMATION_REQUIRED"
        )
        runtime.close()
    finally:
        services.close()
