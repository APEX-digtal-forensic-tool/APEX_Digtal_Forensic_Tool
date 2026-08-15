from __future__ import annotations

import json
import os
import stat
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from apex_forensic.adapters.report import RuntimeReportRenderer
from apex_forensic.adapters.report import runtime as report_runtime
from apex_forensic.config import build_services
from apex_forensic.domain.enums import AnalysisProfileType
from apex_forensic.domain.errors import ApexError
from apex_forensic.domain.models import (
    DecryptionAttempt,
    DecryptionResult,
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
    assert "secret_b64" not in explicit
    assert "correct" not in str(explicit)

    derivation = SecretDerivationInput(
        case_id="other-case",
        evidence_id="ev-1",
        key_source_kind="USER_PASSWORD",
        references=[reference],
    )
    with pytest.raises(ApexError) as mismatch:
        derivation.assert_references_same_case()
    assert mismatch.value.code == "SOURCE_MISMATCH"


def test_secret_serializers_recursively_redact_stable_secret_field_names() -> None:
    markers = {
        name: f"synthetic-marker-{name}"
        for name in (
            "db_key_hex",
            "db_iv_hex",
            "pragma_key",
            "user_nonce",
            "nt_hash_hex",
            "masterkey_hex",
        )
    }
    reference = SecretReference(
        secret_id="sec-redaction",
        case_id="case-redaction",
        evidence_id="evidence-redaction",
        key_source_kind="SYNTHETIC",
        provider_id="test-provider",
        source_kind="SYNTHETIC",
        raw_locator={
            "details": [
                dict(markers),
                ({"db_iv_hex": markers["db_iv_hex"]},),
            ],
            "source_id": "source-safe",
            "source_path": "evidence/safe.db",
            "offset": 42,
            "secret_values_emitted": False,
            "raw_key_material_emitted": False,
        },
    )
    derivation = SecretDerivationInput(
        case_id=reference.case_id,
        evidence_id=reference.evidence_id,
        key_source_kind=reference.key_source_kind,
        references=[reference],
        parameters={
            "nested": [
                {"pragma_key": markers["pragma_key"]},
                ({"user_nonce": markers["user_nonce"]},),
            ]
        },
    )
    now = datetime(2026, 1, 1, tzinfo=UTC)
    attempt = DecryptionAttempt(
        attempt_id="attempt-redaction",
        case_id=reference.case_id,
        evidence_id=reference.evidence_id,
        provider_id="test-provider",
        provider_version="1",
        algorithm="SYNTHETIC",
        key_source_kind=reference.key_source_kind,
        status="FAILED",
        started_at=now,
        warnings=[{"details": {"nt_hash_hex": markers["nt_hash_hex"]}}],
    )
    result = DecryptionResult(
        attempt=attempt,
        status="FAILED",
        citations=[{"details": {"masterkey_hex": markers["masterkey_hex"]}}],
        metadata={
            "secret_values_emitted": False,
            "raw_key_material_emitted": False,
        },
    )

    serialized = {
        "reference": reference.to_schema_dict(),
        "derivation": derivation.to_schema_dict(),
        "result": result.to_schema_dict(),
    }
    encoded = json.dumps(serialized, ensure_ascii=False)

    assert not any(marker in encoded for marker in markers.values())
    assert serialized["reference"]["raw_locator"]["source_id"] == "source-safe"
    assert serialized["reference"]["raw_locator"]["source_path"] == "evidence/safe.db"
    assert serialized["reference"]["raw_locator"]["offset"] == 42
    assert serialized["reference"]["raw_locator"]["secret_values_emitted"] is False
    assert serialized["result"]["metadata"]["raw_key_material_emitted"] is False


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
    if hasattr(os, "fchmod"):
        assert stat.S_IMODE((tmp_path / "report.html").stat().st_mode) == 0o600


def test_runtime_html_renderer_handles_windows_fchmod_boundary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delattr(report_runtime.os, "fchmod", raising=False)
    monkeypatch.setattr(report_runtime, "_is_windows_platform", lambda: True)
    renderer = RuntimeReportRenderer(output_root=tmp_path)

    result = renderer.render(
        _package(),
        export_manifest_id="manifest-1",
        requested_filename="windows.html",
    )
    renderer.verify_output(result)

    assert result["status"] == "COMPLETED"
    assert (tmp_path / "windows.html").is_file()


def test_runtime_renderer_closes_file_before_cleanup_on_write_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    renderer = RuntimeReportRenderer(output_root=tmp_path)
    real_close = report_runtime.os.close
    real_unlink = report_runtime.Path.unlink
    events: list[str] = []
    handle_box: dict[str, Any] = {}

    class FailingHandle:
        def __init__(self, fd: int) -> None:
            self.fd = fd
            self.closed = False

        def __enter__(self) -> FailingHandle:
            return self

        def __exit__(self, *args: object) -> None:
            self.close()

        def write(self, data: bytes) -> None:
            del data
            raise OSError("synthetic write failure")

        def close(self) -> None:
            if not self.closed:
                self.closed = True
                events.append("close")
                real_close(self.fd)

    def fake_fdopen(fd: int, mode: str) -> FailingHandle:
        assert mode == "wb"
        handle = FailingHandle(fd)
        handle_box["handle"] = handle
        return handle

    def fake_unlink(path: Path) -> None:
        handle = handle_box["handle"]
        events.append("unlink_after_close" if handle.closed else "unlink_before_close")
        real_unlink(path)

    monkeypatch.setattr(report_runtime.os, "fdopen", fake_fdopen)
    monkeypatch.setattr(report_runtime.Path, "unlink", fake_unlink)

    with pytest.raises(ApexError) as error:
        renderer.render(
            _package(),
            export_manifest_id="manifest-1",
            requested_filename="write-failure.html",
        )

    assert error.value.code == "REPORT_OUTPUT_WRITE_FAILED"
    assert events == ["close", "unlink_after_close"]
    assert not list(tmp_path.glob(".write-failure.html.*.tmp"))


def test_runtime_renderer_closes_fd_before_cleanup_on_chmod_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    renderer = RuntimeReportRenderer(output_root=tmp_path)
    real_close = report_runtime.os.close
    real_unlink = report_runtime.Path.unlink
    events: list[str] = []

    def failing_fchmod(fd: int, mode: int) -> None:
        del fd, mode
        events.append("chmod")
        raise OSError("synthetic chmod failure")

    def tracked_close(fd: int) -> None:
        events.append("close")
        real_close(fd)

    def tracked_unlink(path: Path) -> None:
        events.append("unlink")
        assert "close" in events
        real_unlink(path)

    monkeypatch.setattr(report_runtime.os, "fchmod", failing_fchmod, raising=False)
    monkeypatch.setattr(report_runtime.os, "close", tracked_close)
    monkeypatch.setattr(report_runtime.Path, "unlink", tracked_unlink)

    with pytest.raises(ApexError) as error:
        renderer.render(
            _package(),
            export_manifest_id="manifest-1",
            requested_filename="chmod-failure.html",
        )

    assert error.value.code == "REPORT_OUTPUT_PERMISSION_FAILED"
    assert events == ["chmod", "close", "unlink"]
    assert not list(tmp_path.glob(".chmod-failure.html.*.tmp"))


def test_runtime_renderer_cleans_up_temp_file_on_replace_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    renderer = RuntimeReportRenderer(output_root=tmp_path)
    replace_calls: list[tuple[Path, Path]] = []

    def failing_replace(source: Path, destination: Path) -> None:
        replace_calls.append((source, destination))
        raise OSError("synthetic replace failure")

    monkeypatch.setattr(report_runtime.os, "replace", failing_replace)

    with pytest.raises(ApexError) as error:
        renderer.render(
            _package(),
            export_manifest_id="manifest-1",
            requested_filename="replace-failure.html",
        )

    assert error.value.code == "REPORT_OUTPUT_WRITE_FAILED"
    assert error.value.details["error_type"] == "OSError"
    assert replace_calls
    assert not (tmp_path / "replace-failure.html").exists()
    assert not list(tmp_path.glob(".replace-failure.html.*.tmp"))


def test_runtime_renderer_reports_cleanup_failure_after_replace_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    renderer = RuntimeReportRenderer(output_root=tmp_path)

    def failing_replace(source: Path, destination: Path) -> None:
        del source, destination
        raise OSError("synthetic replace failure")

    def failing_unlink(path: Path) -> None:
        del path
        raise OSError("synthetic cleanup failure")

    monkeypatch.setattr(report_runtime.os, "replace", failing_replace)
    monkeypatch.setattr(report_runtime.Path, "unlink", failing_unlink)

    with pytest.raises(ApexError) as error:
        renderer.render(
            _package(),
            export_manifest_id="manifest-1",
            requested_filename="cleanup-failure.html",
        )

    assert error.value.code == "REPORT_OUTPUT_CLEANUP_FAILED"
    assert error.value.details["cleanup_error_type"] == "OSError"
    assert error.value.details["original_error_type"] == "OSError"
    assert list(tmp_path.glob(".cleanup-failure.html.*.tmp"))


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
