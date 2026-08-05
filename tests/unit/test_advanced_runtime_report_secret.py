from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from apex_forensic.adapters.report import RuntimeReportRenderer
from apex_forensic.config import build_services
from apex_forensic.domain.enums import AnalysisProfileType
from apex_forensic.domain.errors import ApexError
from apex_forensic.domain.models import (
    ReportRenderPackage,
    SecretDerivationInput,
    SecretMaterial,
    SecretReference,
)


def _package() -> ReportRenderPackage:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    return ReportRenderPackage(
        package_id="pkg-1",
        report_id="rpt-1",
        report_version_id="rv-1",
        case_id="case-1",
        locale="ko-KR",
        timezone="Asia/Seoul",
        report_metadata={
            "title": "한국어 Report",
            "executive_summary": "Summary <b>escaped</b>",
            "version_number": 1,
            "approval_state": {"decision": "APPROVED"},
        },
        sections=[
            {
                "section_id": "sec-1",
                "section_type": "KEY_FINDINGS",
                "title": "Findings",
                "order": 1,
                "content": "한국어 <script>alert(1)</script>",
                "structured_data": {"path": "C:/Evidence/긴 경로.txt"},
                "citations": [{"case_id": "case-1", "source_kind": "FILE", "source_id": "node-1"}],
                "is_partial": True,
                "stale_reasons": ["fixture"],
            }
        ],
        evidence_manifest=[
            {
                "evidence_id": "ev-1",
                "display_name": "Synthetic Evidence",
                "format": "DIRECTORY",
                "hashes": [{"algorithm": "SHA256", "value": "0" * 64}],
            }
        ],
        hash_integrity_summary={"evidence_count": 1, "hash_record_count": 1},
        custody_snapshot_id="custody-1",
        context_snapshot_ids=[],
        citations=[{"case_id": "case-1", "source_kind": "FILE", "source_id": "node-1"}],
        partial_state={"is_partial": True},
        stale_state={"is_stale": False},
        coverage_summary={},
        limitations=["Synthetic fixture."],
        renderer_requirements={"formats": ["HTML", "PDF"]},
        package_fingerprint="a" * 64,
        created_at=now,
    )


def test_secret_material_redacts_default_output_and_blocks_cross_case() -> None:
    reference = SecretReference(
        secret_id="sec-1",
        case_id="case-1",
        evidence_id="ev-1",
        key_source_kind="USER_PASSWORD",
        provider_id="test-provider",
        source_kind="EXTERNAL_KEY",
    )
    material = SecretMaterial(reference=reference, value=b"correct horse battery staple")

    public = material.to_schema_dict()
    assert "secret_b64" not in public
    assert "correct" not in str(public)
    assert public["redacted"]["length"] == len(b"correct horse battery staple")

    explicit = material.to_schema_dict(include_secret=True)
    assert explicit["secret_b64"]

    derivation = SecretDerivationInput(
        case_id="other-case",
        evidence_id="ev-1",
        key_source_kind="USER_PASSWORD",
        references=[reference],
    )
    with pytest.raises(ApexError) as mismatch:
        derivation.assert_references_same_case()
    assert mismatch.value.code == "SOURCE_MISMATCH"


def test_runtime_html_renderer_writes_sanitized_utf8_output(tmp_path: Path) -> None:
    renderer = RuntimeReportRenderer(output_root=tmp_path)
    package = _package()

    result = renderer.render(
        package,
        export_manifest_id="manifest-1",
        requested_filename="report.html",
    )
    renderer.verify_output(result)

    output = (tmp_path / "report.html").read_text(encoding="utf-8")
    assert result["status"] == "COMPLETED"
    assert result["output_reference"] == "derived://apex-derived-default/report.html"
    assert "한국어 Report" in output
    assert "<script>" not in output
    assert "&lt;script&gt;" in output


def test_runtime_renderer_requires_approved_package(tmp_path: Path) -> None:
    renderer = RuntimeReportRenderer(output_root=tmp_path)
    package = _package()
    package.report_metadata["approval_state"] = {"decision": "DRAFT"}

    with pytest.raises(ApexError) as error:
        renderer.validate_package(package)

    assert error.value.code == "REPORT_APPROVAL_REQUIRED"


def test_runtime_pdf_renderer_writes_real_pdf_when_dependency_available(tmp_path: Path) -> None:
    pytest.importorskip("reportlab", reason="report-renderer optional dependency is not installed")
    renderer = RuntimeReportRenderer(output_root=tmp_path)

    result = renderer.render(
        _package(),
        export_manifest_id="manifest-1",
        requested_filename="report.pdf",
    )
    renderer.verify_output(result)

    assert (tmp_path / "report.pdf").read_bytes().startswith(b"%PDF-")
    assert result["mime_type"] == "application/pdf"


def test_report_service_renders_html_with_runtime_adapter(services: Any, tmp_path: Path) -> None:
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    (evidence_dir / "note.txt").write_text("alpha 한국어", encoding="utf-8")
    case = services.cases.create_case(name="Runtime Render Case", locale="ko-KR")
    evidence = services.evidence.register_evidence(case_id=case.case_id, source_path=evidence_dir)
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
    report = services.reports.create_report(
        case_id=case.case_id,
        title="Runtime HTML",
        created_by="analyst",
    )
    citation = {
        "case_id": case.case_id,
        "evidence_id": evidence.evidence_id,
        "source_kind": "FILE",
        "source_id": node.node_id,
    }
    version = services.reports.create_version(
        report_id=report.report_id,
        source_kind="ANALYST_DRAFT",
        created_by="analyst",
        title="Runtime HTML",
        executive_summary="Synthetic summary.",
        sections=[
            {
                "section_type": "KEY_FINDINGS",
                "title": "Finding",
                "order": 1,
                "content": "Observed alpha 한국어.",
                "source_resource_ids": [node.node_id],
                "citations": [citation],
            }
        ],
        evidence_ids=[evidence.evidence_id],
        citations=[citation],
        limitations=["Synthetic runtime rendering fixture."],
    )
    services.reports.submit_review(
        report_version_id=version.report_version_id,
        actor_id="reviewer",
        reason="Submit.",
    )
    services.reports.accept_section(
        report_version_id=version.report_version_id,
        section_id=version.sections[0].section_id,
        actor_id="reviewer",
        reason="Accept.",
        expected_review_revision=1,
    )
    services.reports.complete_review(
        report_version_id=version.report_version_id,
        actor_id="reviewer",
        reason="Complete.",
        expected_review_revision=2,
    )
    services.reports.approve(
        report_version_id=version.report_version_id,
        approver_id="approver",
        reason="Approve.",
        expected_review_revision=3,
    )
    renderer = RuntimeReportRenderer(output_root=tmp_path / "derived")
    manifest = services.reports.prepare_export(
        report_version_id=version.report_version_id,
        format="HTML",
        filename="runtime.html",
        created_by="analyst",
        renderer=renderer,
    )

    rendered = services.reports.render_export(
        export_manifest_id=manifest.export_manifest_id,
        renderer=renderer,
    )

    assert rendered.status == "COMPLETED"
    assert (tmp_path / "derived" / "runtime.html").is_file()
    status = services.reports.export_status(manifest.export_manifest_id)
    assert status["artifacts"][0]["sha256"]
    reopened = build_services(tmp_path / "apex.db")
    try:
        reopened_status = reopened.reports.export_status(manifest.export_manifest_id)
    finally:
        reopened.close()
    assert reopened_status["manifest"]["status"] == "COMPLETED"
    assert reopened_status["artifacts"][0]["sha256"] == status["artifacts"][0]["sha256"]
