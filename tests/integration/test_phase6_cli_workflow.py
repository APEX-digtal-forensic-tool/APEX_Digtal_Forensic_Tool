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


def test_cli_context_view_and_interface_e2e(tmp_path: Path, cli_env: dict[str, str]) -> None:
    db_path = tmp_path / "phase6-cli.db"
    root = tmp_path / "evidence"
    root.mkdir()
    (root / "note.txt").write_text("phase6 cli raw", encoding="utf-8")

    case_result = run_cli(
        ["--db", str(db_path), "case", "create", "--name", "Phase 6 CLI", "--json"],
        cli_env,
    )
    assert case_result.returncode == 0, case_result.stderr
    case = json.loads(case_result.stdout)

    evidence_result = run_cli(
        [
            "--db",
            str(db_path),
            "evidence",
            "add",
            "--case-id",
            case["id"],
            "--path",
            str(root),
            "--json",
        ],
        cli_env,
    )
    assert evidence_result.returncode == 0, evidence_result.stderr
    evidence = json.loads(evidence_result.stdout)

    index_result = run_cli(
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
    assert index_result.returncode == 0, index_result.stderr

    nodes_result = run_cli(
        [
            "--db",
            str(db_path),
            "fs",
            "list",
            "--evidence-id",
            evidence["id"],
            "--all",
            "--files-only",
            "--json",
        ],
        cli_env,
    )
    assert nodes_result.returncode == 0, nodes_result.stderr
    node = json.loads(nodes_result.stdout)["items"][0]

    context_result = run_cli(
        [
            "--db",
            str(db_path),
            "context",
            "create",
            "--case-id",
            case["id"],
            "--session-id",
            "session-cli",
            "--file-node-id",
            node["id"],
            "--json",
        ],
        cli_env,
    )
    assert context_result.returncode == 0, context_result.stderr
    context = json.loads(context_result.stdout)
    assert context["context_revision"] == 1

    snapshot_result = run_cli(
        [
            "--db",
            str(db_path),
            "context",
            "snapshot",
            "--session-context-id",
            context["session_context_id"],
            "--purpose",
            "MCP_REQUEST",
            "--scope",
            "filesystem",
            "--json",
        ],
        cli_env,
    )
    assert snapshot_result.returncode == 0, snapshot_result.stderr
    snapshot = json.loads(snapshot_result.stdout)
    assert snapshot["included_resource_ids"]["FILE_SYSTEM_NODE"] == [node["id"]]

    raw_result = run_cli(
        [
            "--db",
            str(db_path),
            "view",
            "raw-read",
            "--case-id",
            case["id"],
            "--resource-type",
            "FILE_SYSTEM_NODE",
            "--resource-id",
            node["id"],
            "--offset",
            "0",
            "--length",
            "6",
            "--json",
        ],
        cli_env,
    )
    assert raw_result.returncode == 0, raw_result.stderr
    assert json.loads(raw_result.stdout)["text_preview"] == "phase6"

    tools_result = run_cli(
        ["--db", str(db_path), "interface", "tools", "--json"],
        cli_env,
    )
    assert tools_result.returncode == 0, tools_result.stderr
    tool_names = {item["tool_name"] for item in json.loads(tools_result.stdout)}
    assert "apex.view.raw_read" in tool_names
