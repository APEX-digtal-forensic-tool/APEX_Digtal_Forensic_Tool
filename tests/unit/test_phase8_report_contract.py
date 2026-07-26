from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any, ClassVar

import pytest

from apex_forensic.config import build_services
from apex_forensic.domain.enums import AnalysisContextPurpose, AnalysisProfileType
from apex_forensic.domain.errors import ApexError, ReportError
from apex_forensic.domain.models import ReportRendererCapability, ReportRenderPackage


class FakeReportRenderer:
    renderer_id = "fake.renderer"
    renderer_version = "1.0.0"
    supported_formats: ClassVar[list[str]] = ["PDF", "HTML"]

    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail

    def capabilities(self) -> ReportRendererCapability:
        return ReportRendererCapability(
            renderer_id=self.renderer_id,
            renderer_version=self.renderer_version,
            supported_formats=self.supported_formats,
            is_available=True,
            unavailable_reason=None,
            warnings=[],
        )

    def validate_package(self, package: ReportRenderPackage) -> None:
        if not package.sections:
            raise ReportError("REPORT_PACKAGE_INVALID", "Package has no sections.")

    def render(
        self,
        package: ReportRenderPackage,
        *,
        export_manifest_id: str,
        requested_filename: str,
    ) -> dict[str, Any]:
        del package, export_manifest_id
        if self.fail:
            raise ReportError("REPORT_RENDER_FAILED", "Synthetic renderer failure.")
        return {
            "status": "COMPLETED",
            "output_reference": f"derived://apex-derived-default/{requested_filename}",
            "filename": requested_filename,
            "mime_type": "application/pdf" if requested_filename.endswith(".pdf") else "text/html",
            "size_bytes": 9,
            "sha256": "0" * 64,
            "renderer_id": self.renderer_id,
            "renderer_version": self.renderer_version,
            "warnings": [],
        }

    def cancel(self, export_manifest_id: str) -> dict[str, Any]:
        del export_manifest_id
        return {"status": "CANCELLED"}

    def verify_output(self, result: dict[str, Any]) -> None:
        if len(str(result.get("sha256", ""))) != 64:
            raise ReportError("REPORT_OUTPUT_INVALID", "Synthetic hash invalid.")


def _base_fixture(services: Any, tmp_path: Path) -> dict[str, Any]:
    root = tmp_path / "evidence"
    root.mkdir()
    (root / "한글-note.txt").write_text("alpha bravo charlie", encoding="utf-8")
    case = services.cases.create_case(name="Phase 8 Case", locale="ko-KR")
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
        session_id="phase8-session",
        case_id=case.case_id,
        selected_file_node_ids=[node.node_id],
    )
    snapshot = services.contexts.build_from_session(
        context.session_context_id,
        purpose=AnalysisContextPurpose.REPORT_DRAFT,
        scopes=["filesystem"],
    )
    report = services.reports.create_report(
        case_id=case.case_id,
        title="Investigation Report",
        created_by="analyst-1",
    )
    return {
        "case": case,
        "evidence": evidence,
        "node": node,
        "snapshot": snapshot,
        "report": report,
    }


def _citation(case_id: str, evidence_id: str, node_id: str) -> dict[str, str]:
    return {
        "case_id": case_id,
        "evidence_id": evidence_id,
        "source_kind": "FILE",
        "source_id": node_id,
    }


def _version_payload(base: dict[str, Any], *, content: str = "alpha observed") -> dict[str, Any]:
    case = base["case"]
    evidence = base["evidence"]
    node = base["node"]
    snapshot = base["snapshot"]
    citation = _citation(case.case_id, evidence.evidence_id, node.node_id)
    return {
        "title": "Investigation Report",
        "executive_summary": "External analyst summary.",
        "sections": [
            {
                "section_type": "KEY_FINDINGS",
                "title": "Key Findings",
                "order": 1,
                "content": content,
                "source_resource_ids": [node.node_id],
                "context_snapshot_ids": [snapshot.context_snapshot_id],
                "citations": [citation],
            }
        ],
        "context_snapshot_ids": [snapshot.context_snapshot_id],
        "evidence_ids": [evidence.evidence_id],
        "citations": [citation],
        "limitations": ["Directory evidence hashing is policy-limited in this fixture."],
        "analyzer_versions": {"fixture": "1"},
    }


def _create_version(services: Any, base: dict[str, Any], **overrides: Any):
    payload = _version_payload(base, **overrides)
    return services.reports.create_version(
        report_id=base["report"].report_id,
        source_kind="ANALYST_DRAFT",
        created_by="analyst-1",
        **payload,
    )


def _review_and_approve(services: Any, version: Any):
    services.reports.submit_review(
        report_version_id=version.report_version_id,
        actor_id="reviewer-1",
        reason="Submit.",
    )
    services.reports.accept_section(
        report_version_id=version.report_version_id,
        section_id=version.sections[0].section_id,
        actor_id="reviewer-1",
        reason="Accepted.",
        expected_review_revision=1,
    )
    with pytest.raises(ApexError) as conflict:
        services.reports.complete_review(
            report_version_id=version.report_version_id,
            actor_id="reviewer-1",
            reason="Outdated.",
            expected_review_revision=1,
        )
    assert conflict.value.code == "REPORT_REVIEW_REVISION_CONFLICT"
    services.reports.complete_review(
        report_version_id=version.report_version_id,
        actor_id="reviewer-1",
        reason="Complete.",
        expected_review_revision=2,
    )
    return services.reports.approve(
        report_version_id=version.report_version_id,
        approver_id="approver-1",
        reason="Approved.",
        expected_review_revision=3,
    )


def test_report_version_review_approval_and_repository_reopen(tmp_path: Path) -> None:
    services = build_services(tmp_path / "apex.db")
    try:
        base = _base_fixture(services, tmp_path)
        version = _create_version(services, base)
        replay = _create_version(services, base)
        assert replay.report_version_id == version.report_version_id
        assert version.version_number == 1
        assert version.previous_version_id is None
        assert version.sections[0].source_kind == "ANALYST_DRAFT"

        with pytest.raises(ApexError) as incomplete:
            services.reports.approve(
                report_version_id=version.report_version_id,
                approver_id="approver-1",
                reason="Too early.",
            )
        assert incomplete.value.code == "REPORT_APPROVAL_REVIEW_INCOMPLETE"

        with pytest.raises(ApexError) as missing_section:
            services.reports.complete_review(
                report_version_id=version.report_version_id,
                actor_id="reviewer-1",
                reason="No submit.",
            )
        assert missing_section.value.code == "REPORT_REVIEW_TRANSITION_INVALID"

        approval = _review_and_approve(services, version)
        assert approval.decision == "APPROVED"
        assert approval.content_fingerprint == version.content_fingerprint
        assert approval.custody_snapshot_id is not None

        second = _create_version(services, base, content="changed analyst draft")
        assert second.version_number == 2
        assert second.previous_version_id == version.report_version_id
        assert second.previous_content_fingerprint == version.content_fingerprint
        second_state = services.reports.get_version(second.report_version_id).approval_state
        assert second_state["decision"] is None
        assert services.reports.get_report(base["report"].report_id).status == "REVIEW_REQUIRED"

        revoked = services.reports.revoke_approval(
            report_version_id=version.report_version_id,
            actor_id="approver-1",
            reason="Reopened by policy.",
            expected_approval_revision=1,
        )
        assert revoked.decision == "REVOKED"
        assert revoked.previous_approval_hash == approval.approval_hash

        with pytest.raises(sqlite3.IntegrityError):
            services.repository.connection.execute(
                "UPDATE report_versions SET source_kind = ? WHERE report_version_id = ?",
                ("OTHER", version.report_version_id),
            )
        with pytest.raises(sqlite3.IntegrityError):
            services.repository.connection.execute(
                "DELETE FROM report_review_events WHERE report_version_id = ?",
                (version.report_version_id,),
            )
    finally:
        services.close()

    reopened = build_services(tmp_path / "apex.db")
    try:
        versions = reopened.reports.list_versions(base["report"].report_id)
        assert [item.version_number for item in versions] == [1, 2]
        assert reopened.reports.get_approval(version.report_version_id).decision == "REVOKED"
    finally:
        reopened.close()


def test_cross_case_payload_security_and_ai_draft_ingest(services: Any, tmp_path: Path) -> None:
    base = _base_fixture(services, tmp_path)
    other_case = services.cases.create_case(name="Other Case")
    other_report = services.reports.create_report(
        case_id=other_case.case_id,
        title="Other",
        created_by="analyst-2",
    )

    payload = _version_payload(base)
    with pytest.raises(ApexError) as cross_case_evidence:
        services.reports.create_version(
            report_id=other_report.report_id,
            source_kind="ANALYST_DRAFT",
            created_by="analyst-2",
            **payload,
        )
    assert cross_case_evidence.value.code == "REPORT_REFERENCE_CASE_MISMATCH"

    malicious = _version_payload(base)
    malicious["sections"][0]["content"] = "<script>alert(1)</script>"
    with pytest.raises(ApexError):
        services.reports.create_version(
            report_id=base["report"].report_id,
            source_kind="ANALYST_DRAFT",
            created_by="analyst-1",
            **malicious,
        )

    raw_payload = _version_payload(base)
    raw_payload["analyzer_versions"] = {"raw_response": "provider body"}
    with pytest.raises(ApexError):
        services.reports.create_version(
            report_id=base["report"].report_id,
            source_kind="ANALYST_DRAFT",
            created_by="analyst-1",
            **raw_payload,
        )

    request = services.ai.create_request_from_context_snapshot(
        case_id=base["case"].case_id,
        context_snapshot_id=base["snapshot"].context_snapshot_id,
        purpose="REPORT_INPUT",
        requested_operations=["SUMMARIZE_SCOPE"],
        requested_scopes=["filesystem"],
    )
    ai_payload = {
        "case_id": base["case"].case_id,
        "assistance_request_id": request.assistance_request_id,
        "context_snapshot_ids": [base["snapshot"].context_snapshot_id],
        "ai_result_ids": [],
        "provider_id": "fake-ai",
        "provider_version": "1",
        "model_id": "synthetic",
        "external_request_id": "ai-report-1",
        "title": "AI Draft",
        "executive_summary": "External AI draft summary.",
        "sections": _version_payload(base)["sections"],
        "citations": _version_payload(base)["citations"],
        "generated_at": None,
        "response_hash": "1" * 64,
        "correlation_id": "corr-1",
        "limitations": ["AI draft requires human review."],
    }
    ai_version = services.reports.ingest_ai_draft(
        payload=ai_payload,
        report_id=base["report"].report_id,
    )
    replay = services.reports.ingest_ai_draft(
        payload=ai_payload,
        report_id=base["report"].report_id,
    )
    assert replay.report_version_id == ai_version.report_version_id
    assert ai_version.source_kind == "AI_DRAFT"
    assert ai_version.sections[0].source_kind == "AI_DRAFT"
    serialized = json.dumps(ai_version.to_schema_dict(), ensure_ascii=False).casefold()
    assert "prompt" not in serialized
    assert "raw_response" not in serialized

    bad_ai_payload = dict(ai_payload)
    bad_ai_payload["prompt"] = "do not persist"
    with pytest.raises(ApexError):
        services.reports.ingest_ai_draft(
            payload=bad_ai_payload,
            report_id=base["report"].report_id,
        )


def test_custody_export_renderer_and_audit_contract(
    services: Any, tmp_path: Path, schema_validator: Any
) -> None:
    base = _base_fixture(services, tmp_path)
    version = _create_version(services, base)
    schema_validator.validate("report-record.schema.json", base["report"].to_schema_dict())
    schema_validator.validate("report-version.schema.json", version.to_schema_dict())
    schema_validator.validate("report-section.schema.json", version.sections[0].to_schema_dict())
    with pytest.raises(ApexError):
        services.reports.prepare_export(
            report_version_id=version.report_version_id,
            format="PDF",
            filename="report.pdf",
            created_by="analyst-1",
        )

    approval = _review_and_approve(services, version)
    schema_validator.validate("report-approval-record.schema.json", approval.to_schema_dict())
    snapshot = services.reports.get_custody_snapshot(approval.custody_snapshot_id)
    assert snapshot.verification_status == "VERIFIED"
    schema_validator.validate("custody-snapshot.schema.json", snapshot.to_schema_dict())
    package = services.reports.create_render_package(
        report_version_id=version.report_version_id,
        created_by="analyst-1",
        for_export=True,
    )
    assert package.custody_snapshot_id == snapshot.custody_snapshot_id
    schema_validator.validate("report-render-package.schema.json", package.to_schema_dict())
    assert package.package_fingerprint == services.reports.create_render_package(
        report_version_id=version.report_version_id,
        created_by="analyst-2",
        for_export=True,
    ).package_fingerprint

    with pytest.raises(ApexError):
        services.reports.prepare_export(
            report_version_id=version.report_version_id,
            format="PDF",
            filename="../report.pdf",
            created_by="analyst-1",
        )
    with pytest.raises(ApexError):
        services.reports.prepare_export(
            report_version_id=version.report_version_id,
            format="PDF",
            filename="/tmp/report.pdf",
            created_by="analyst-1",
        )
    with pytest.raises(ApexError):
        services.reports.prepare_export(
            report_version_id=version.report_version_id,
            format="PDF",
            filename="report.pdf",
            created_by="analyst-1",
            overwrite_policy="OVERWRITE",
        )

    unavailable = services.reports.prepare_export(
        report_version_id=version.report_version_id,
        format="PDF",
        filename="report.pdf",
        created_by="analyst-1",
    )
    assert unavailable.status == "CAPABILITY_UNAVAILABLE"
    schema_validator.validate("report-export-manifest.schema.json", unavailable.to_schema_dict())
    assert services.reports.renderer_capabilities().is_available is False
    schema_validator.validate(
        "report-renderer-capability.schema.json",
        services.reports.renderer_capabilities().to_schema_dict(),
    )

    fake = FakeReportRenderer()
    manifest = services.reports.prepare_export(
        report_version_id=version.report_version_id,
        format="PDF",
        filename="fake.pdf",
        created_by="analyst-1",
        renderer=fake,
    )
    completed = services.reports.render_export(
        export_manifest_id=manifest.export_manifest_id,
        renderer=fake,
    )
    assert completed.status == "COMPLETED"
    status = services.reports.export_status(manifest.export_manifest_id)
    assert status["artifacts"][0]["sha256"] == "0" * 64
    assert status["artifacts"][0]["output_reference"].startswith("derived://apex-derived-default/")
    schema_validator.validate("rendered-report-artifact.schema.json", status["artifacts"][0])

    with pytest.raises(ApexError):
        services.reports.record_export_result(
            export_manifest_id=manifest.export_manifest_id,
            payload={
                "status": "COMPLETED",
                "output_reference": "derived://other-root/report.pdf",
                "filename": "report.pdf",
                "mime_type": "application/pdf",
                "size_bytes": 1,
                "sha256": "0" * 64,
            },
        )

    failed_manifest = services.reports.prepare_export(
        report_version_id=version.report_version_id,
        format="PDF",
        filename="fail.pdf",
        created_by="analyst-1",
        renderer=fake,
    )
    failed = services.reports.render_export(
        export_manifest_id=failed_manifest.export_manifest_id,
        renderer=FakeReportRenderer(fail=True),
    )
    assert failed.status == "FAILED"
    cancel_manifest = services.reports.prepare_export(
        report_version_id=version.report_version_id,
        format="HTML",
        filename="cancel.html",
        created_by="analyst-1",
        renderer=fake,
    )
    cancelled = services.reports.record_export_result(
        export_manifest_id=cancel_manifest.export_manifest_id,
        payload={"status": "CANCELLED", "warnings": [{"code": "REPORT_RENDER_CANCELLED"}]},
    )
    assert cancelled.status == "CANCELLED"

    with pytest.raises(sqlite3.IntegrityError):
        services.repository.connection.execute(
            "UPDATE rendered_report_artifacts SET size_bytes = 2 WHERE export_manifest_id = ?",
            (manifest.export_manifest_id,),
        )
    with pytest.raises(sqlite3.IntegrityError):
        services.repository.connection.execute(
            "DELETE FROM report_export_audit_events WHERE export_manifest_id = ?",
            (manifest.export_manifest_id,),
        )


def test_public_interface_report_descriptors_and_errors(services: Any, tmp_path: Path) -> None:
    base = _base_fixture(services, tmp_path)
    version = _create_version(services, base)
    tools = {item.tool_name: item for item in services.interface.tools()}
    for name in (
        "report.get",
        "report.version.create",
        "report.review.submit",
        "report.approve",
        "report.export.prepare",
        "report.export.record-result",
    ):
        assert name in tools
    assert tools["report.approve"].requires_confirmation is True
    assert tools["report.export.prepare"].mutates_state is True

    response = services.interface.invoke_read(
        "report.version.get",
        {"report_version_id": version.report_version_id},
    )
    assert response["status"] == "OK"
    assert response["data"]["report_version_id"] == version.report_version_id

    invalid = services.interface.invoke_read(
        "report.list",
        {"case_id": base["case"].case_id, "limit": "bad"},
    )
    assert invalid["status"] == "ERROR"
    assert invalid["errors"][0]["code"] == "VALIDATION_ERROR"
