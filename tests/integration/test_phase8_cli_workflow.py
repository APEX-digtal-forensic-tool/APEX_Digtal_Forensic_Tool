from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


def run_cli(args: list[str], env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "apex_forensic", *args],
        check=False,
        text=True,
        capture_output=True,
        env=env,
    )


def _json_cli(args: list[str], env: dict[str, str]) -> dict[str, object]:
    result = run_cli(args, env)
    assert result.returncode == 0, result.stderr
    return dict(json.loads(result.stdout))


def test_phase8_cli_report_review_approval_custody_export_e2e(
    tmp_path: Path, cli_env: dict[str, str]
) -> None:
    db_path = tmp_path / "phase8-cli.db"
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    (evidence_root / "cli-report-note.txt").write_text("phase eight cli", encoding="utf-8")

    case = _json_cli(
        ["--db", str(db_path), "case", "create", "--name", "Phase 8 CLI", "--json"],
        cli_env,
    )
    evidence = _json_cli(
        [
            "--db",
            str(db_path),
            "evidence",
            "add",
            "--case-id",
            str(case["id"]),
            "--path",
            str(evidence_root),
            "--json",
        ],
        cli_env,
    )
    indexed = run_cli(
        [
            "--db",
            str(db_path),
            "evidence",
            "index",
            "--case-id",
            str(case["id"]),
            "--evidence-id",
            str(evidence["id"]),
            "--profile",
            "FULL_ANALYSIS",
            "--json",
        ],
        cli_env,
    )
    assert indexed.returncode == 0, indexed.stderr

    nodes = _json_cli(
        [
            "--db",
            str(db_path),
            "fs",
            "list",
            "--evidence-id",
            str(evidence["id"]),
            "--all",
            "--files-only",
            "--json",
        ],
        cli_env,
    )
    node = dict(nodes["items"][0])
    context = _json_cli(
        [
            "--db",
            str(db_path),
            "context",
            "create",
            "--case-id",
            str(case["id"]),
            "--session-id",
            "phase8-cli-session",
            "--file-node-id",
            str(node["id"]),
            "--json",
        ],
        cli_env,
    )
    snapshot = _json_cli(
        [
            "--db",
            str(db_path),
            "context",
            "snapshot",
            "--session-context-id",
            str(context["session_context_id"]),
            "--purpose",
            "REPORT_DRAFT",
            "--scope",
            "filesystem",
            "--json",
        ],
        cli_env,
    )
    report = _json_cli(
        [
            "--db",
            str(db_path),
            "report",
            "create",
            "--case-id",
            str(case["id"]),
            "--title",
            "CLI Report 한글",
            "--created-by",
            "analyst-cli",
            "--json",
        ],
        cli_env,
    )
    citation = {
        "case_id": str(case["id"]),
        "evidence_id": str(evidence["id"]),
        "source_kind": "FILE",
        "source_id": str(node["id"]),
    }
    version_input = {
        "title": "CLI Report 한글",
        "executive_summary": "Analyst supplied report text.",
        "sections": [
            {
                "section_type": "KEY_FINDINGS",
                "title": "Findings",
                "order": 1,
                "content": "phase eight cli",
                "source_resource_ids": [str(node["id"])],
                "context_snapshot_ids": [str(snapshot["context_snapshot_id"])],
                "citations": [citation],
            }
        ],
        "context_snapshot_ids": [str(snapshot["context_snapshot_id"])],
        "evidence_ids": [str(evidence["id"])],
        "citations": [citation],
        "limitations": ["CLI fixture limitation."],
    }
    version = _json_cli(
        [
            "--db",
            str(db_path),
            "report",
            "version-create",
            "--report-id",
            str(report["report_id"]),
            "--created-by",
            "analyst-cli",
            "--input-json",
            json.dumps(version_input, ensure_ascii=False),
            "--json",
        ],
        cli_env,
    )
    section_id = str(version["sections"][0]["section_id"])

    for args in (
        [
            "review-submit",
            "--actor-id",
            "reviewer-cli",
            "--reason",
            "Submit.",
            "--expected-review-revision",
            "0",
        ],
        [
            "review-accept-section",
            "--actor-id",
            "reviewer-cli",
            "--reason",
            "Accept.",
            "--section-id",
            section_id,
            "--expected-review-revision",
            "1",
        ],
        [
            "review-complete",
            "--actor-id",
            "reviewer-cli",
            "--reason",
            "Complete.",
            "--expected-review-revision",
            "2",
        ],
    ):
        result = run_cli(
            [
                "--db",
                str(db_path),
                "report",
                *args,
                "--report-version-id",
                str(version["report_version_id"]),
                "--json",
            ],
            cli_env,
        )
        assert result.returncode == 0, result.stderr

    approval = _json_cli(
        [
            "--db",
            str(db_path),
            "report",
            "approve",
            "--report-version-id",
            str(version["report_version_id"]),
            "--approver-id",
            "approver-cli",
            "--reason",
            "Approve.",
            "--expected-review-revision",
            "3",
            "--json",
        ],
        cli_env,
    )
    assert approval["decision"] == "APPROVED"
    custody_snapshot = _json_cli(
        [
            "--db",
            str(db_path),
            "report",
            "custody-snapshot-show",
            "--custody-snapshot-id",
            str(approval["custody_snapshot_id"]),
            "--json",
        ],
        cli_env,
    )
    assert custody_snapshot["verification_status"] == "VERIFIED"

    package = _json_cli(
        [
            "--db",
            str(db_path),
            "report",
            "package-create",
            "--report-version-id",
            str(version["report_version_id"]),
            "--created-by",
            "analyst-cli",
            "--for-export",
            "--json",
        ],
        cli_env,
    )
    assert package["custody_snapshot_id"] == approval["custody_snapshot_id"]

    pdf_manifest = _json_cli(
        [
            "--db",
            str(db_path),
            "report",
            "export-prepare",
            "--report-version-id",
            str(version["report_version_id"]),
            "--format",
            "PDF",
            "--filename",
            "보고서.pdf",
            "--created-by",
            "analyst-cli",
            "--json",
        ],
        cli_env,
    )
    assert pdf_manifest["status"] == "CAPABILITY_UNAVAILABLE"
    html_manifest = _json_cli(
        [
            "--db",
            str(db_path),
            "report",
            "export-prepare",
            "--report-version-id",
            str(version["report_version_id"]),
            "--format",
            "HTML",
            "--filename",
            "report.html",
            "--created-by",
            "analyst-cli",
            "--json",
        ],
        cli_env,
    )
    assert html_manifest["format"] == "HTML"

    cancelled = _json_cli(
        [
            "--db",
            str(db_path),
            "report",
            "export-record-result",
            "--export-manifest-id",
            str(pdf_manifest["export_manifest_id"]),
            "--input-json",
            json.dumps({"status": "CANCELLED", "warnings": [{"code": "REPORT_RENDER_CANCELLED"}]}),
            "--json",
        ],
        cli_env,
    )
    assert cancelled["status"] == "CANCELLED"
    export_status = _json_cli(
        [
            "--db",
            str(db_path),
            "report",
            "export-status",
            "--export-manifest-id",
            str(pdf_manifest["export_manifest_id"]),
            "--json",
        ],
        cli_env,
    )
    assert dict(export_status["manifest"])["status"] == "CANCELLED"

    capabilities = _json_cli(
        ["--db", str(db_path), "report", "export-capabilities", "--json"],
        cli_env,
    )
    assert capabilities["is_available"] is False
    assert capabilities["unavailable_reason"] == "CAPABILITY_UNAVAILABLE"

    invoked = _json_cli(
        [
            "--db",
            str(db_path),
            "interface",
            "invoke-read",
            "--operation",
            "report.version.get",
            "--payload-json",
            json.dumps({"report_version_id": version["report_version_id"]}),
            "--json",
        ],
        cli_env,
    )
    assert invoked["status"] == "OK"
    assert dict(invoked["data"])["report_version_id"] == version["report_version_id"]
