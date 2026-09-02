from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from apex_forensic.config import build_services
from apex_forensic.domain.enums import AnalysisContextPurpose, AnalysisProfileType
from apex_mcp.config import McpConfig
from apex_mcp.confirmation import (
    ConfirmationGrant,
    ConfirmationRequest,
    InMemoryConfirmationProvider,
)
from apex_mcp.engine_adapter import EngineAdapter
from apex_mcp.m5_tools import M5_REPORT_TOOL_NAMES, M5_TOOL_NAMES, m5_bindings
from apex_mcp.server import create_runtime
from apex_mcp.telemetry import request_fingerprint


def _citation(seeded: dict[str, Any]) -> dict[str, Any]:
    return {
        "case_id": seeded["case_id"],
        "evidence_id": seeded["evidence_id"],
        "source_kind": "FILE",
        "source_id": seeded["node_id"],
        "file_id": seeded["node_id"],
        "source_path": seeded["source_path"],
        "excerpt": "alpha",
    }


def _section(seeded: dict[str, Any], *, content: str = "alpha observed") -> dict[str, Any]:
    return {
        "section_type": "KEY_FINDINGS",
        "title": "Key findings",
        "order": 1,
        "content": content,
        "source_resource_ids": [seeded["node_id"]],
        "context_snapshot_ids": [seeded["snapshot_id"]],
        "citations": [_citation(seeded)],
        "require_citation": True,
    }


def _version_arguments(
    seeded: dict[str, Any], *, content: str = "alpha observed"
) -> dict[str, Any]:
    return {
        "case_id": seeded["case_id"],
        "report_id": seeded["report_id"],
        "title": "M5 investigation report",
        "executive_summary": "The selected file contains the cited alpha term.",
        "sections": [_section(seeded, content=content)],
        "context_snapshot_ids": [seeded["snapshot_id"]],
        "evidence_ids": [seeded["evidence_id"]],
        "citations": [_citation(seeded)],
        "limitations": ["Synthetic MCP M5 fixture."],
        "analyzer_versions": {"fixture": "m5"},
    }


def _seed(project_root: Path, tmp_path: Path) -> dict[str, Any]:
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    (evidence_root / "selected.txt").write_text("alpha bravo", encoding="utf-8")
    database_path = tmp_path / "m5.db"
    services = build_services(database_path)
    case = services.cases.create_case(name="MCP M5 Report")
    other_case = services.cases.create_case(name="MCP M5 Other")
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
        session_id="mcp-m5-session",
        case_id=case.case_id,
        selected_file_node_ids=[node.node_id],
        active_context_scope="filesystem",
    )
    snapshot = services.contexts.build_from_session(
        context.session_context_id,
        purpose=AnalysisContextPurpose.REPORT_DRAFT,
        scopes=["filesystem"],
    )
    request = services.ai.create_request_from_context_snapshot(
        case_id=case.case_id,
        context_snapshot_id=snapshot.context_snapshot_id,
        purpose="REPORT_INPUT",
        requested_operations=["SUMMARIZE_SCOPE"],
        requested_scopes=["filesystem"],
    )
    report = services.reports.create_report(
        case_id=case.case_id,
        title="M5 seeded report",
        created_by="fixture-analyst",
    )
    other_report = services.reports.create_report(
        case_id=other_case.case_id,
        title="Other case report",
        created_by="fixture-analyst",
    )
    provider = InMemoryConfirmationProvider()
    runtime = create_runtime(
        McpConfig(
            database_path=database_path,
            schema_dir=project_root / "schemas" / "v1",
            allowed_tools=M5_TOOL_NAMES,
        ),
        adapter=EngineAdapter(services),
        bindings=m5_bindings(),
        confirmation_provider=provider,
    )
    return {
        "services": services,
        "runtime": runtime,
        "provider": provider,
        "case_id": case.case_id,
        "other_case_id": other_case.case_id,
        "report_id": report.report_id,
        "other_report_id": other_report.report_id,
        "evidence_id": evidence.evidence_id,
        "node_id": node.node_id,
        "source_path": node.original_relative_path,
        "snapshot_id": snapshot.context_snapshot_id,
        "assistance_request_id": request.assistance_request_id,
    }


def _confirmation(
    *,
    grant_id: str,
    tool_name: str,
    arguments: dict[str, Any],
    target_ids: tuple[str, ...],
    actor_id: str = "analyst-m5",
    session_id: str = "frontend-m5",
) -> tuple[ConfirmationGrant, ConfirmationRequest]:
    values = {
        "grant_id": grant_id,
        "actor_id": actor_id,
        "session_id": session_id,
        "case_id": str(arguments["case_id"]),
        "tool_name": tool_name,
        "request_fingerprint": request_fingerprint(arguments),
        "target_ids": target_ids,
    }
    return (
        ConfirmationGrant(
            **values,
            expires_at=datetime.now(UTC) + timedelta(minutes=5),
        ),
        ConfirmationRequest(**values),
    )


def _confirmed_call(
    seeded: dict[str, Any],
    *,
    grant_id: str,
    tool_name: str,
    arguments: dict[str, Any],
    target_ids: tuple[str, ...],
    actor_id: str = "analyst-m5",
    session_id: str = "frontend-m5",
) -> Any:
    grant, confirmation = _confirmation(
        grant_id=grant_id,
        tool_name=tool_name,
        arguments=arguments,
        target_ids=target_ids,
        actor_id=actor_id,
        session_id=session_id,
    )
    seeded["provider"].issue(grant)
    return seeded["runtime"].registry.call_tool(
        tool_name,
        arguments,
        confirmation=confirmation,
        trusted_actor_id=actor_id,
        trusted_session_id=session_id,
    )


def test_m5_discovery_case_binding_and_actor_spoofing(
    project_root: Path,
    tmp_path: Path,
) -> None:
    seeded = _seed(project_root, tmp_path)
    runtime = seeded["runtime"]
    services = seeded["services"]
    try:
        tools = runtime.registry.list_tools()
        assert {tool.name for tool in tools} == M5_TOOL_NAMES
        assert {tool.name for tool in tools} >= M5_REPORT_TOOL_NAMES
        assert len(tools) == 52
        assert "report.export.record-result" not in M5_TOOL_NAMES
        approval_tool = next(tool for tool in tools if tool.name == "report.approve")
        assert approval_tool.annotations is not None
        assert approval_tool.annotations.destructive_hint is True
        assert approval_tool.meta is not None
        assert approval_tool.meta["apex/requiresConfirmation"] is True

        create_arguments = {
            "case_id": seeded["case_id"],
            "title": "Created through M5",
        }
        unauthenticated = runtime.registry.call_tool("report.create", create_arguments)
        spoofed = runtime.registry.call_tool(
            "report.create",
            {**create_arguments, "created_by": "model-claimed-analyst"},
            trusted_actor_id="analyst-m5",
            trusted_session_id="frontend-m5",
        )
        created = runtime.registry.call_tool(
            "report.create",
            create_arguments,
            trusted_actor_id="analyst-m5",
            trusted_session_id="frontend-m5",
        )
        cross_case = runtime.registry.call_tool(
            "report.get",
            {
                "case_id": seeded["other_case_id"],
                "report_id": seeded["report_id"],
            },
        )
        host_only = runtime.registry.call_tool(
            "report.export.record-result",
            {
                "case_id": seeded["case_id"],
                "export_manifest_id": "not-a-manifest",
            },
        )

        assert unauthenticated.structured_content["errors"][0]["code"] == (
            "MCP_AUTHENTICATED_ACTOR_REQUIRED"
        )
        assert spoofed.structured_content["errors"][0]["code"] == "VALIDATION_ERROR"
        assert created.is_error is False
        assert created.structured_content["data"]["created_by"] == "analyst-m5"
        assert cross_case.structured_content["errors"][0]["code"] == (
            "REPORT_REFERENCE_CASE_MISMATCH"
        )
        assert host_only.structured_content["errors"][0]["code"] == "TOOL_NOT_FOUND"
        assert len(services.reports.list_reports(case_id=seeded["case_id"])["items"]) == 2
    finally:
        runtime.close()
        services.close()


def test_m5_ai_draft_ingest_never_auto_approves(
    project_root: Path,
    tmp_path: Path,
) -> None:
    seeded = _seed(project_root, tmp_path)
    runtime = seeded["runtime"]
    services = seeded["services"]
    arguments = {
        "case_id": seeded["case_id"],
        "report_id": seeded["report_id"],
        "assistance_request_id": seeded["assistance_request_id"],
        "context_snapshot_ids": [seeded["snapshot_id"]],
        "ai_result_ids": [],
        "provider_id": "m5-fixture",
        "provider_version": "1.0.0",
        "model_id": "fixture-model",
        "external_request_id": "m5-ai-draft-1",
        "title": "AI-generated draft",
        "executive_summary": "External AI draft requiring human review.",
        "sections": [_section(seeded)],
        "citations": [_citation(seeded)],
        "generated_at": None,
        "response_hash": "1" * 64,
        "correlation_id": "m5-correlation",
        "limitations": ["AI-generated content requires human verification."],
    }
    try:
        ingested = runtime.registry.call_tool("report.ai-draft.ingest", arguments)
        replay = runtime.registry.call_tool("report.ai-draft.ingest", arguments)
        approval = runtime.registry.call_tool(
            "report.approval.get",
            {
                "case_id": seeded["case_id"],
                "report_version_id": ingested.structured_content["data"]["report_version_id"],
            },
        )
        actor_spoof = runtime.registry.call_tool(
            "report.ai-draft.ingest",
            {**arguments, "approver_id": "model"},
        )

        assert ingested.is_error is False
        version = ingested.structured_content["data"]
        assert (
            replay.structured_content["data"]["report_version_id"] == (version["report_version_id"])
        )
        assert version["source_kind"] == "AI_DRAFT"
        assert version["created_by"] == "mcp-ai-layer"
        assert version["review_state"]["status"] == "DRAFT"
        assert version["approval_state"]["decision"] is None
        assert approval.is_error is False
        assert approval.structured_content["data"] is None
        assert actor_spoof.structured_content["errors"][0]["code"] == "VALIDATION_ERROR"
        assert services.reports.get_approval(version["report_version_id"]) is None
    finally:
        runtime.close()
        services.close()


def test_m5_human_review_approval_and_bound_export(
    project_root: Path,
    tmp_path: Path,
) -> None:
    seeded = _seed(project_root, tmp_path)
    runtime = seeded["runtime"]
    services = seeded["services"]
    actor_id = "analyst-m5"
    session_id = "frontend-m5"
    try:
        version_arguments = _version_arguments(seeded)
        version_result = runtime.registry.call_tool(
            "report.version.create",
            version_arguments,
            trusted_actor_id=actor_id,
            trusted_session_id=session_id,
        )
        assert version_result.is_error is False
        version = version_result.structured_content["data"]
        version_id = version["report_version_id"]
        section_id = version["sections"][0]["section_id"]
        assert version["created_by"] == actor_id

        count_before = len(services.reports.list_versions(seeded["report_id"]))
        wrong_case = runtime.registry.call_tool(
            "report.version.create",
            {
                **_version_arguments(seeded, content="must not persist"),
                "case_id": seeded["other_case_id"],
            },
            trusted_actor_id=actor_id,
            trusted_session_id=session_id,
        )
        assert wrong_case.structured_content["errors"][0]["code"] == (
            "REPORT_REFERENCE_CASE_MISMATCH"
        )
        assert len(services.reports.list_versions(seeded["report_id"])) == count_before

        submit_arguments = {
            "case_id": seeded["case_id"],
            "report_version_id": version_id,
            "reason": "Submit for review.",
            "expected_review_revision": 0,
        }
        denied = runtime.registry.call_tool("report.review.submit", submit_arguments)
        spoofed = runtime.registry.call_tool(
            "report.review.submit",
            {**submit_arguments, "actor_id": "model"},
        )
        machine = _confirmed_call(
            seeded,
            grant_id="machine-submit",
            tool_name="report.review.submit",
            arguments=submit_arguments,
            target_ids=(version_id,),
            actor_id="ai-agent",
            session_id=session_id,
        )
        assert denied.structured_content["errors"][0]["code"] == ("HUMAN_CONFIRMATION_REQUIRED")
        assert spoofed.structured_content["errors"][0]["code"] == "VALIDATION_ERROR"
        assert machine.structured_content["errors"][0]["code"] == (
            "MCP_AUTHENTICATED_ACTOR_REQUIRED"
        )
        assert services.reports.review_history(version_id) == []

        submitted = _confirmed_call(
            seeded,
            grant_id="human-submit",
            tool_name="report.review.submit",
            arguments=submit_arguments,
            target_ids=(version_id,),
        )
        assert submitted.is_error is False
        assert submitted.structured_content["data"]["actor_id"] == actor_id

        accept_arguments = {
            "case_id": seeded["case_id"],
            "report_version_id": version_id,
            "section_id": section_id,
            "reason": "Citation and content verified.",
            "expected_review_revision": 1,
        }
        accepted = _confirmed_call(
            seeded,
            grant_id="accept-section",
            tool_name="report.review.accept-section",
            arguments=accept_arguments,
            target_ids=(version_id, section_id),
        )
        assert accepted.is_error is False

        complete_arguments = {
            "case_id": seeded["case_id"],
            "report_version_id": version_id,
            "reason": "All required sections are verified.",
            "expected_review_revision": 2,
        }
        completed = _confirmed_call(
            seeded,
            grant_id="complete-review",
            tool_name="report.review.complete",
            arguments=complete_arguments,
            target_ids=(version_id,),
        )
        assert completed.is_error is False

        unapproved_export_arguments = {
            "case_id": seeded["case_id"],
            "report_version_id": version_id,
            "format": "HTML",
            "filename": "unapproved.html",
            "expected_content_fingerprint": version["content_fingerprint"],
            "expected_approval_id": "approval-not-created",
            "expected_custody_snapshot_id": "custody-not-created",
        }
        unapproved = _confirmed_call(
            seeded,
            grant_id="unapproved-export",
            tool_name="report.export.prepare",
            arguments=unapproved_export_arguments,
            target_ids=(version_id, "custody-not-created", "approval-not-created"),
        )
        assert unapproved.structured_content["errors"][0]["code"] == (
            "REPORT_APPROVAL_TRANSITION_INVALID"
        )

        approve_arguments = {
            "case_id": seeded["case_id"],
            "report_version_id": version_id,
            "reason": "Human approval after completed review.",
            "expected_review_revision": 3,
            "expected_approval_revision": 0,
        }
        approved = _confirmed_call(
            seeded,
            grant_id="approve-report",
            tool_name="report.approve",
            arguments=approve_arguments,
            target_ids=(version_id,),
        )
        assert approved.is_error is False
        approval = approved.structured_content["data"]
        assert approval["approver_id"] == actor_id
        assert approval["decision"] == "APPROVED"
        assert approval["content_fingerprint"] == version["content_fingerprint"]
        assert approval["custody_snapshot_id"] is not None

        manifest_count_before = services.repository.connection.execute(
            "SELECT COUNT(*) AS count FROM report_export_manifests"
        ).fetchone()["count"]
        stale_export_arguments = {
            "case_id": seeded["case_id"],
            "report_version_id": version_id,
            "format": "HTML",
            "filename": "stale-approval.html",
            "expected_content_fingerprint": "0" * 64,
            "expected_approval_id": approval["approval_id"],
            "expected_custody_snapshot_id": approval["custody_snapshot_id"],
        }
        stale_export = _confirmed_call(
            seeded,
            grant_id="stale-export",
            tool_name="report.export.prepare",
            arguments=stale_export_arguments,
            target_ids=(
                version_id,
                approval["custody_snapshot_id"],
                approval["approval_id"],
            ),
        )
        assert stale_export.structured_content["errors"][0]["code"] == (
            "REPORT_APPROVAL_FINGERPRINT_MISMATCH"
        )
        assert (
            services.repository.connection.execute(
                "SELECT COUNT(*) AS count FROM report_export_manifests"
            ).fetchone()["count"]
            == manifest_count_before
        )

        export_arguments = {
            "case_id": seeded["case_id"],
            "report_version_id": version_id,
            "format": "HTML",
            "filename": "m5-report.html",
            "include_citations": True,
            "include_custody": True,
            "include_technical_appendix": True,
            "stale_confirmed": False,
            "expected_content_fingerprint": version["content_fingerprint"],
            "expected_approval_id": approval["approval_id"],
            "expected_custody_snapshot_id": approval["custody_snapshot_id"],
        }
        grant, confirmation = _confirmation(
            grant_id="prepare-export",
            tool_name="report.export.prepare",
            arguments=export_arguments,
            target_ids=(
                version_id,
                approval["custody_snapshot_id"],
                approval["approval_id"],
            ),
        )
        seeded["provider"].issue(grant)
        exported = runtime.registry.call_tool(
            "report.export.prepare",
            export_arguments,
            confirmation=confirmation,
            trusted_actor_id=actor_id,
            trusted_session_id=session_id,
        )
        reused = runtime.registry.call_tool(
            "report.export.prepare",
            export_arguments,
            confirmation=confirmation,
            trusted_actor_id=actor_id,
            trusted_session_id=session_id,
        )
        assert exported.is_error is False
        manifest = exported.structured_content["data"]
        assert manifest["approval_id"] == approval["approval_id"]
        assert manifest["custody_snapshot_id"] == approval["custody_snapshot_id"]
        assert manifest["content_fingerprint"] == version["content_fingerprint"]
        assert manifest["created_by"] == actor_id
        assert reused.structured_content["errors"][0]["code"] == ("HUMAN_CONFIRMATION_REQUIRED")

        package = runtime.registry.call_tool(
            "report.render-package.get",
            {
                "case_id": seeded["case_id"],
                "package_id": manifest["render_package_id"],
            },
        )
        status = runtime.registry.call_tool(
            "report.export-status",
            {
                "case_id": seeded["case_id"],
                "export_manifest_id": manifest["export_manifest_id"],
            },
        )
        cross_case = runtime.registry.call_tool(
            "report.export-manifest.get",
            {
                "case_id": seeded["other_case_id"],
                "export_manifest_id": manifest["export_manifest_id"],
            },
        )
        assert package.is_error is False
        assert package.structured_content["data"]["citations"]
        assert (
            package.structured_content["data"]["custody_snapshot_id"]
            == (approval["custody_snapshot_id"])
        )
        assert status.is_error is False
        assert (
            status.structured_content["data"]["manifest"]["approval_id"]
            == (approval["approval_id"])
        )
        assert cross_case.structured_content["errors"][0]["code"] == (
            "REPORT_REFERENCE_CASE_MISMATCH"
        )
        assert (
            services.reports.get_version(version_id).content_fingerprint
            == (version["content_fingerprint"])
        )
    finally:
        runtime.close()
        services.close()
