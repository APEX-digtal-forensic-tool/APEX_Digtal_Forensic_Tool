from __future__ import annotations

import json
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from apex_forensic._time import to_json_timestamp


def run_cli(args: list[str], env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "apex_forensic", *args],
        check=False,
        text=True,
        capture_output=True,
        env=env,
    )


def _citation(case_id: str, evidence_id: str, node: dict[str, object]) -> dict[str, object]:
    path = str(node["original_relative_path"])
    node_id = str(node["id"])
    return {
        "id": str(uuid4()),
        "label": "CIT-001",
        "case_id": case_id,
        "evidence_id": evidence_id,
        "source_kind": "FILE",
        "source_id": node_id,
        "file_id": node_id,
        "artifact_id": None,
        "timeline_event_id": None,
        "search_result_id": None,
        "source_path": path,
        "source_offset": 0,
        "source_reference": "filesystem node",
        "excerpt": "cli",
        "content_sha256": None,
        "created_at": to_json_timestamp(datetime(2024, 1, 1, tzinfo=UTC)),
        "source_length": 3,
        "encoding": "utf-8",
        "raw_locator": {
            "evidence_id": evidence_id,
            "source_kind": "FILE",
            "source_id": node_id,
            "source_path": path,
            "source_reference": "filesystem node",
            "locator_type": "LOGICAL_PATH",
            "offset": 0,
            "length": 3,
            "encoding": "utf-8",
            "view_types": ["TEXT"],
            "content_sha256": None,
            "limitations": [],
            "details": {},
        },
    }


def test_phase7_cli_ai_keyword_and_summary_workflow(
    tmp_path: Path, cli_env: dict[str, str]
) -> None:
    db_path = tmp_path / "phase7-cli.db"
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    (evidence_root / "cli-note.txt").write_text("cli phase seven", encoding="utf-8")

    assert run_cli(["init", "--db", str(db_path), "--json"], cli_env).returncode == 0
    case = json.loads(
        run_cli(
            ["--db", str(db_path), "case", "create", "--name", "Phase 7 CLI", "--json"],
            cli_env,
        ).stdout
    )
    evidence = json.loads(
        run_cli(
            [
                "--db",
                str(db_path),
                "evidence",
                "add",
                "--case-id",
                case["id"],
                "--path",
                str(evidence_root),
                "--json",
            ],
            cli_env,
        ).stdout
    )
    indexed = run_cli(
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
            "--json",
        ],
        cli_env,
    )
    assert indexed.returncode == 0, indexed.stderr
    fs_page = json.loads(
        run_cli(
            [
                "--db",
                str(db_path),
                "fs",
                "list",
                "--evidence-id",
                evidence["id"],
                "--all",
                "--json",
            ],
            cli_env,
        ).stdout
    )
    node = next(item for item in fs_page["items"] if item["node_type"] == "FILE")
    context = json.loads(
        run_cli(
            [
                "--db",
                str(db_path),
                "context",
                "create",
                "--case-id",
                case["id"],
                "--session-id",
                "phase7-cli-session",
                "--file-node-id",
                node["id"],
                "--json",
            ],
            cli_env,
        ).stdout
    )
    snapshot = json.loads(
        run_cli(
            [
                "--db",
                str(db_path),
                "context",
                "snapshot",
                "--session-context-id",
                context["session_context_id"],
                "--purpose",
                "AI_REQUEST",
                "--scope",
                "filesystem",
                "--json",
            ],
            cli_env,
        ).stdout
    )
    request = json.loads(
        run_cli(
            [
                "--db",
                str(db_path),
                "ai",
                "request-create",
                "--case-id",
                case["id"],
                "--context-snapshot-id",
                snapshot["context_snapshot_id"],
                "--purpose",
                "KEYWORD_RECOMMENDATION",
                "--operation",
                "RECOMMEND_KEYWORDS",
                "--scope",
                "filesystem",
                "--json",
            ],
            cli_env,
        ).stdout
    )
    citation = _citation(case["id"], evidence["id"], node)
    keyword_batch = json.loads(
        run_cli(
            [
                "--db",
                str(db_path),
                "ai",
                "keyword-ingest",
                "--assistance-request-id",
                request["assistance_request_id"],
                "--input-json",
                json.dumps(
                    {
                        "provider_id": "fake-ai",
                        "provider_version": "1",
                        "model_id": "synthetic",
                        "recommendations": [
                            {
                                "keyword_type": "DOCUMENT_TERM",
                                "value": "cli",
                                "reason": "Term appears in the selected file.",
                                "confidence": "HIGH",
                                "recommended_scope": "filesystem",
                                "evidence_ids": [evidence["id"]],
                                "source_resource_ids": [node["id"]],
                                "citations": [citation],
                            }
                        ],
                    }
                ),
                "--json",
            ],
            cli_env,
        ).stdout
    )
    recommendation_id = keyword_batch["recommendations"][0]["recommendation_id"]
    reviewed = run_cli(
        [
            "--db",
            str(db_path),
            "ai",
            "keyword-review",
            "--recommendation-id",
            recommendation_id,
            "--action",
            "ACCEPT",
            "--actor-id",
            "analyst-cli",
            "--reason",
            "CLI review accepted.",
            "--expected-review-revision",
            "0",
            "--json",
        ],
        cli_env,
    )
    assert reviewed.returncode == 0, reviewed.stderr
    keyword_set = json.loads(
        run_cli(
            [
                "--db",
                str(db_path),
                "keyword-set",
                "create",
                "--case-id",
                case["id"],
                "--name",
                "CLI AI Terms",
                "--created-by",
                "analyst-cli",
                "--json",
            ],
            cli_env,
        ).stdout
    )
    promoted = json.loads(
        run_cli(
            [
                "--db",
                str(db_path),
                "ai",
                "keyword-promote",
                "--recommendation-id",
                recommendation_id,
                "--keyword-set-id",
                keyword_set["keyword_set_id"],
                "--actor-id",
                "analyst-cli",
                "--reason",
                "Promote after review.",
                "--expected-review-revision",
                "1",
                "--json",
            ],
            cli_env,
        ).stdout
    )
    assert promoted["status"] == "PROMOTED"

    summary_request = json.loads(
        run_cli(
            [
                "--db",
                str(db_path),
                "ai",
                "request-create",
                "--case-id",
                case["id"],
                "--context-snapshot-id",
                snapshot["context_snapshot_id"],
                "--purpose",
                "SCOPE_SUMMARY",
                "--operation",
                "SUMMARIZE_SCOPE",
                "--scope",
                "filesystem",
                "--json",
            ],
            cli_env,
        ).stdout
    )
    summary = json.loads(
        run_cli(
            [
                "--db",
                str(db_path),
                "ai",
                "summary-ingest",
                "--assistance-request-id",
                summary_request["assistance_request_id"],
                "--input-json",
                json.dumps(
                    {
                        "scope_context_id": summary_request["scope_context_ids"][0],
                        "provider_id": "fake-ai",
                        "provider_version": "1",
                        "model_id": "synthetic",
                        "title": "CLI filesystem summary",
                        "summary_text": "The selected file contains CLI workflow text.",
                        "key_points": ["One selected text file is cited."],
                        "referenced_resource_ids": [node["id"]],
                        "citations": [citation],
                    }
                ),
                "--json",
            ],
            cli_env,
        ).stdout
    )
    summary_review = run_cli(
        [
            "--db",
            str(db_path),
            "ai",
            "summary-review",
            "--scope-summary-id",
            summary["scope_summary_id"],
            "--action",
            "ACCEPT",
            "--actor-id",
            "analyst-cli",
            "--reason",
            "Summary reviewed.",
            "--expected-review-revision",
            "0",
            "--json",
        ],
        cli_env,
    )
    assert summary_review.returncode == 0, summary_review.stderr
