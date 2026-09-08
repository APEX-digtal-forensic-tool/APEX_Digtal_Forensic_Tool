from __future__ import annotations

import json
import os
import subprocess
import sys
import tomllib
from pathlib import Path

from apex_mcp.m7_tools import m7_bindings


def test_m8_entrypoint_extras_and_lock_are_reproducible(project_root: Path) -> None:
    project = tomllib.loads((project_root / "pyproject.toml").read_text(encoding="utf-8"))
    lock = tomllib.loads((project_root / "uv.lock").read_text(encoding="utf-8"))
    packages = {
        item["name"]: item
        for item in lock["package"]
        if item.get("source", {}).get("registry") == "https://pypi.org/simple"
    }

    assert project["project"]["scripts"]["apex-mcp"] == "apex_mcp.__main__:main"
    assert project["project"]["optional-dependencies"]["mcp-server"] == [
        "mcp==2.1.1",
        "uvicorn==0.52.4",
    ]
    assert "setuptools>=78.1.1,<81" in project["build-system"]["requires"]
    assert packages["mcp"]["version"] == "2.1.1"
    assert packages["uvicorn"]["version"] == "0.52.4"
    assert packages["mcp"]["wheels"]
    assert all("hash" in wheel for wheel in packages["mcp"]["wheels"])


def test_m8_mcp_sdk_imports_stay_outside_core(project_root: Path) -> None:
    violations = []
    for path in (project_root / "src" / "apex_forensic").rglob("*.py"):
        content = path.read_text(encoding="utf-8")
        if "import mcp" in content or "from mcp" in content:
            violations.append(path.relative_to(project_root).as_posix())

    assert violations == []


def test_m8_tool_inputs_avoid_known_inspector_portability_errors() -> None:
    type_arrays: list[tuple[str, str]] = []
    for binding in m7_bindings():
        pending: list[tuple[str, object]] = [("inputSchema", binding.input_schema)]
        while pending:
            path, value = pending.pop()
            if isinstance(value, dict):
                type_value = value.get("type")
                if isinstance(type_value, list):
                    type_arrays.append((binding.tool_name, f"{path}.type"))
                pending.extend((f"{path}.{key}", item) for key, item in value.items())
            elif isinstance(value, list):
                pending.extend(
                    (f"{path}[{index}]", item) for index, item in enumerate(value)
                )

        if binding.tool_name in {
            "ai.keyword-recommendation.review",
            "ai.scope-summary.review",
        }:
            forbidden = binding.input_schema["allOf"][0]["else"]["properties"]
            assert forbidden["corrected_value"] == {"not": {}}
            assert forbidden["corrected_reason"] == {"not": {}}

    assert type_arrays == []


def test_m8_stdio_eof_unicode_and_security_contract(
    project_root: Path,
    tmp_path: Path,
) -> None:
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(project_root / "src")
    completed = subprocess.run(
        [
            sys.executable,
            str(project_root / "tools" / "verify_mcp_stdio.py"),
            "--module",
            "--schema-dir",
            str(project_root / "schemas" / "v1"),
            "--timeout",
            "30",
            "--json",
        ],
        cwd=tmp_path,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )
    report = json.loads(completed.stdout)

    assert completed.returncode == 0, completed.stderr
    assert report["status"] == "PASSED"
    assert report["protocol_version"] == "2026-07-28"
    assert report["tool_count"] == 52
    assert report["unicode_database_path_verified"] is True
    assert report["raw_read_default_deny"] is True
    assert report["secret_values_emitted"] is False
    assert report["eof_lifecycle"]["returncode"] == 0
    assert report["eof_lifecycle"]["stdout_protocol_only"] is True
