from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


def test_synthetic_benchmark_reports_real_metrics_and_read_only_invariant(
    project_root: Path,
    cli_env: dict[str, str],
) -> None:
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "apex_forensic",
            "benchmark",
            "--profile",
            "BOTH",
            "--search-iterations",
            "3",
            "--json",
        ],
        check=False,
        capture_output=True,
        text=True,
        cwd=project_root,
        env=cli_env,
    )

    assert completed.returncode == 0, completed.stderr
    payload = json.loads(completed.stdout)
    assert payload["status"] == "COMPLETED"
    assert payload["fixture"]["id"] == "apex-benchmark-synthetic-v1"
    assert len(payload["fixture"]["sha256"]) == 64
    assert payload["read_only_invariant"]["evidence_unchanged"] is True
    assert payload["read_only_invariant"]["writes_to_evidence"] is False
    assert {item["profile"] for item in payload["results"]} == {
        "QUICK_TRIAGE",
        "FULL_ANALYSIS",
    }
    for result in payload["results"]:
        assert result["elapsed_wall_seconds"] > 0
        assert result["index"]["discovered_files"] > 0
        assert result["index"]["indexed_files"] > 0
        assert result["artifacts"]["artifact_count"] > 0
        assert result["search"]["cold_cache"]["samples"] == 3
        assert result["search"]["warm_cache"]["samples"] == 3
        assert result["search"]["warm_cache"]["p50_ms"] is not None
        assert result["search"]["warm_cache"]["p95_ms"] is not None
        assert result["resources"]["sqlite_db_size_bytes"] > 0
    assert payload["comparative_superiority_claimed"] is False


def test_user_evidence_benchmark_does_not_modify_input(
    project_root: Path,
    cli_env: dict[str, str],
    tmp_path: Path,
) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    source = evidence / "apex-source.txt"
    source.write_text("한글 APEX benchmark", encoding="utf-8")
    before = (source.read_bytes(), source.stat().st_mtime_ns)

    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "apex_forensic",
            "benchmark",
            "--evidence",
            str(evidence),
            "--profile",
            "FULL_ANALYSIS",
            "--search-iterations",
            "1",
            "--json",
        ],
        check=False,
        capture_output=True,
        text=True,
        cwd=project_root,
        env=cli_env,
    )

    assert completed.returncode == 0, completed.stderr
    payload = json.loads(completed.stdout)
    assert payload["status"] == "COMPLETED"
    assert payload["fixture"]["kind"] == "USER_PROVIDED_READ_ONLY"
    assert payload["read_only_invariant"]["evidence_unchanged"] is True
    assert (source.read_bytes(), source.stat().st_mtime_ns) == before
