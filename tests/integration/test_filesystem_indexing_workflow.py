from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from apex_forensic.config import build_services
from apex_forensic.domain.enums import AnalysisProfileType


def _run_cli(args: list[str], env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "apex_forensic", *args],
        check=False,
        text=True,
        capture_output=True,
        env=env,
    )


def test_sqlite_reopen_partial_resume_and_unicode_round_trip(tmp_path: Path) -> None:
    db_path = tmp_path / "fs.db"
    evidence_dir = tmp_path / "한글 Evidence"
    nested = evidence_dir / "하위 디렉터리"
    nested.mkdir(parents=True)
    (nested / "파일 (최종).txt").write_text("내용", encoding="utf-8")

    services = build_services(db_path)
    case = services.cases.create_case(name="FS 통합")
    evidence = services.evidence.register_evidence(case_id=case.case_id, source_path=evidence_dir)
    job, _ = services.fs.index_evidence(
        case_id=case.case_id,
        evidence_id=evidence.evidence_id,
        profile_type=AnalysisProfileType.FULL_ANALYSIS,
        item_budget=1,
    )
    services.close()

    reopened = build_services(db_path)
    try:
        resumed, coverage = reopened.fs.resume_index_job(job.job_id)
        nodes = reopened.fs.list_nodes(evidence_id=evidence.evidence_id, all_nodes=True).items
        assert resumed.status == "SUCCEEDED"
        assert coverage.status == "COMPLETE"
        assert "/하위 디렉터리/파일 (최종).txt" in {node.display_path for node in nodes}
    finally:
        reopened.close()


def test_large_pagination_has_no_duplicates_or_omissions(tmp_path: Path) -> None:
    db_path = tmp_path / "large.db"
    evidence_dir = tmp_path / "large"
    evidence_dir.mkdir()
    for index in range(1005):
        (evidence_dir / f"file-{index:04d}.txt").write_text("x", encoding="utf-8")
    services = build_services(db_path)
    try:
        case = services.cases.create_case(name="Large")
        evidence = services.evidence.register_evidence(
            case_id=case.case_id, source_path=evidence_dir
        )
        services.fs.index_evidence(
            case_id=case.case_id,
            evidence_id=evidence.evidence_id,
            profile_type=AnalysisProfileType.FULL_ANALYSIS,
            batch_size=128,
        )
        cursor = None
        paths: list[str] = []
        while True:
            page = services.fs.list_nodes(
                evidence_id=evidence.evidence_id,
                all_nodes=True,
                cursor=cursor,
                limit=200,
            )
            paths.extend(node.display_path for node in page.items)
            if not page.page.has_more:
                break
            cursor = page.page.next_cursor
        assert len(paths) == len(set(paths)) == 1006
    finally:
        services.close()


def test_cli_quick_full_resume_and_tree_queries(tmp_path: Path, cli_env: dict[str, str]) -> None:
    db_path = tmp_path / "cli-fs.db"
    evidence_dir = tmp_path / "cli evidence"
    nested = evidence_dir / "selected"
    nested.mkdir(parents=True)
    (nested / "한글.txt").write_text("x", encoding="utf-8")
    (evidence_dir / "root.txt").write_text("root", encoding="utf-8")

    assert _run_cli(["init", "--db", str(db_path), "--json"], cli_env).returncode == 0
    case_result = _run_cli(
        ["--db", str(db_path), "case", "create", "--name", "CLI FS", "--json"],
        cli_env,
    )
    assert case_result.returncode == 0, case_result.stderr
    case = json.loads(case_result.stdout)
    evidence_result = _run_cli(
        [
            "--db",
            str(db_path),
            "evidence",
            "add",
            "--case-id",
            case["id"],
            "--path",
            str(evidence_dir),
            "--json",
        ],
        cli_env,
    )
    assert evidence_result.returncode == 0, evidence_result.stderr
    evidence = json.loads(evidence_result.stdout)

    quick = _run_cli(
        [
            "--db",
            str(db_path),
            "evidence",
            "index",
            "--case-id",
            case["id"],
            "--evidence-id",
            evidence["id"],
            "--profile",
            "QUICK_TRIAGE",
            "--json",
        ],
        cli_env,
    )
    assert quick.returncode == 0, quick.stderr
    assert json.loads(quick.stdout)["coverage"]["status"] == "PARTIAL"

    partial = _run_cli(
        [
            "--db",
            str(db_path),
            "evidence",
            "index",
            "--case-id",
            case["id"],
            "--evidence-id",
            evidence["id"],
            "--profile",
            "FULL_ANALYSIS",
            "--item-budget",
            "1",
            "--json",
        ],
        cli_env,
    )
    assert partial.returncode == 0, partial.stderr
    partial_job = json.loads(partial.stdout)["job"]
    resume = _run_cli(
        [
            "--db",
            str(db_path),
            "evidence",
            "index-resume",
            "--job-id",
            partial_job["id"],
            "--json",
        ],
        cli_env,
    )
    assert resume.returncode == 0, resume.stderr
    assert json.loads(resume.stdout)["coverage"]["status"] == "COMPLETE"

    roots = _run_cli(
        ["--db", str(db_path), "fs", "roots", "--evidence-id", evidence["id"], "--json"],
        cli_env,
    )
    assert roots.returncode == 0, roots.stderr
    root_id = json.loads(roots.stdout)[0]["id"]
    listed = _run_cli(
        [
            "--db",
            str(db_path),
            "fs",
            "list",
            "--evidence-id",
            evidence["id"],
            "--parent-node-id",
            root_id,
            "--json",
        ],
        cli_env,
    )
    assert listed.returncode == 0, listed.stderr
    assert "/selected" in {item["display_path"] for item in json.loads(listed.stdout)["items"]}

    shown = _run_cli(
        ["--db", str(db_path), "fs", "show", "--node-id", root_id, "--json"],
        cli_env,
    )
    assert shown.returncode == 0, shown.stderr
    assert json.loads(shown.stdout)["node_type"] == "ROOT"
