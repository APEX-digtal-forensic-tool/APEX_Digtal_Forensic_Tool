"""Verify runtime HTML/PDF report rendering with synthetic data.

The script creates a temporary case, approved report version, and derived output root. It never
prints secrets or reads user evidence. PDF returns CAPABILITY_UNAVAILABLE when ReportLab is absent.
"""

from __future__ import annotations

# ruff: noqa: E402, I001

import argparse
import json
import tempfile
from pathlib import Path
from typing import Any

from verification_common import ensure_source_tree_importable

ensure_source_tree_importable(__file__)

from apex_forensic.adapters.report import RuntimeReportRenderer
from apex_forensic.config import build_services
from apex_forensic.domain.enums import AnalysisProfileType


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify APEX report renderer runtimes.")
    parser.add_argument("--require-pdf", action="store_true")
    parser.add_argument("--keep-output", action="store_true")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="apex-report-render-") as temp:
        root = Path(temp)
        result = _verify(root, require_pdf=args.require_pdf)
        if args.keep_output:
            result["output_root"] = str(root / "derived")
        print(json.dumps(result, ensure_ascii=False, indent=2))
        if result["html"]["status"] != "COMPLETED":
            return 1
        if args.require_pdf and result["pdf"]["status"] != "COMPLETED":
            return 1
    return 0


def _verify(root: Path, *, require_pdf: bool) -> dict[str, Any]:
    db_path = root / "apex.db"
    evidence_dir = root / "evidence"
    evidence_dir.mkdir()
    (evidence_dir / "synthetic.txt").write_text(
        "Synthetic 한국어 report evidence.",
        encoding="utf-8",
    )
    services = build_services(db_path)
    try:
        case = services.cases.create_case(name="Renderer Verification", locale="ko-KR")
        evidence = services.evidence.register_evidence(
            case_id=case.case_id,
            source_path=evidence_dir,
        )
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
            title="Synthetic Renderer Verification",
            created_by="verifier",
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
            created_by="verifier",
            title="Synthetic Renderer Verification",
            executive_summary="Synthetic 한국어 summary.",
            sections=[
                {
                    "section_type": "KEY_FINDINGS",
                    "title": "Findings",
                    "order": 1,
                    "content": "Synthetic 한국어 report body.",
                    "source_resource_ids": [node.node_id],
                    "citations": [citation],
                }
            ],
            evidence_ids=[evidence.evidence_id],
            citations=[citation],
            limitations=["Synthetic runtime renderer verification fixture."],
        )
        _approve(services, version.report_version_id, version.sections[0].section_id)
        renderer = RuntimeReportRenderer(output_root=root / "derived")
        return {
            "html": _render_one(
                services,
                renderer,
                version.report_version_id,
                "HTML",
                "verify.html",
            ),
            "pdf": _render_one(services, renderer, version.report_version_id, "PDF", "verify.pdf"),
            "require_pdf": require_pdf,
        }
    finally:
        services.close()


def _approve(services: Any, report_version_id: str, section_id: str) -> None:
    services.reports.submit_review(
        report_version_id=report_version_id,
        actor_id="reviewer",
        reason="Verify.",
    )
    services.reports.accept_section(
        report_version_id=report_version_id,
        section_id=section_id,
        actor_id="reviewer",
        reason="Verify.",
        expected_review_revision=1,
    )
    services.reports.complete_review(
        report_version_id=report_version_id,
        actor_id="reviewer",
        reason="Verify.",
        expected_review_revision=2,
    )
    services.reports.approve(
        report_version_id=report_version_id,
        approver_id="approver",
        reason="Verify.",
        expected_review_revision=3,
    )


def _render_one(
    services: Any,
    renderer: RuntimeReportRenderer,
    report_version_id: str,
    format_value: str,
    filename: str,
) -> dict[str, Any]:
    manifest = services.reports.prepare_export(
        report_version_id=report_version_id,
        format=format_value,
        filename=filename,
        created_by="verifier",
        renderer=renderer,
    )
    if manifest.status == "PREPARED":
        services.reports.render_export(
            export_manifest_id=manifest.export_manifest_id,
            renderer=renderer,
        )
    status = services.reports.export_status(manifest.export_manifest_id)
    return status["manifest"] | {"artifacts": status["artifacts"]}


if __name__ == "__main__":
    raise SystemExit(main())
