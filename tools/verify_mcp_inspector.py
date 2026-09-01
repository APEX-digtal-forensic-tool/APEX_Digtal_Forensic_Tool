#!/usr/bin/env python3
"""Run the pinned official MCP Inspector CLI against APEX stdio."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess  # nosec B404
import sys
import tempfile
from pathlib import Path
from typing import Any

from apex_forensic.config import build_services

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_INSPECTOR_PACKAGE = "@modelcontextprotocol/inspector@2.4.0"
DEFAULT_TIMEOUT_SECONDS = 180.0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    command_group = parser.add_mutually_exclusive_group()
    command_group.add_argument("--module", action="store_true")
    command_group.add_argument("--command", default="apex-mcp")
    parser.add_argument("--schema-dir", type=Path, default=ROOT / "schemas" / "v1")
    parser.add_argument("--package", default=DEFAULT_INSPECTOR_PACKAGE)
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT_SECONDS)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    if args.timeout <= 0:
        parser.error("--timeout must be positive")

    try:
        report = verify_inspector(
            module=args.module,
            command=args.command,
            schema_dir=args.schema_dir,
            inspector_package=args.package,
            timeout=args.timeout,
        )
    except Exception as error:
        report = {
            "schema_version": "1.0.0",
            "status": "FAILED",
            "reason": "MCP_INSPECTOR_VERIFICATION_FAILED",
            "error_type": type(error).__name__,
            "secret_values_emitted": False,
        }
    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    else:
        print(f"APEX MCP Inspector verification: {report['status']}")
    return 0 if report["status"] == "PASSED" else 1


def verify_inspector(
    *,
    module: bool,
    command: str,
    schema_dir: Path,
    inspector_package: str,
    timeout: float,
) -> dict[str, Any]:
    npx = shutil.which("npx")
    if npx is None:
        raise FileNotFoundError("npx")
    if module:
        server_command = sys.executable
        command_prefix = ["-m", "apex_mcp"]
    else:
        server_command = _resolve_executable(command)
        command_prefix = []
    canonical_schema_dir = schema_dir.expanduser().resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix="apex-mcp-inspector-한글-") as temporary_directory:
        temporary_root = Path(temporary_directory)
        database_path = temporary_root / "검사 사례.db"
        services = build_services(database_path)
        services.close()
        config_path = temporary_root / "mcp-inspector.json"
        server_config: dict[str, Any] = {
            "type": "stdio",
            "command": server_command,
            "args": [
                *command_prefix,
                "--database",
                str(database_path),
                "--schema-dir",
                str(canonical_schema_dir),
            ],
            "cwd": str(ROOT),
        }
        if module:
            server_config["env"] = {"PYTHONPATH": str(ROOT / "src")}
        config = {"mcpServers": {"apex": server_config}}
        config_path.write_text(
            json.dumps(config, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        completed = subprocess.run(  # nosec B603
            [
                npx,
                "--yes",
                inspector_package,
                "--cli",
                "--config",
                str(config_path),
                "--server",
                "apex",
                "--method",
                "tools/list",
                "--format",
                "json",
                "--strict",
            ],
            cwd=ROOT,
            env=_sanitized_environment(keep_pythonpath=module),
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    payload = _parse_json_output(completed.stdout)
    tools = _tool_items(payload)
    secret_emitted = "apex-m8-secret-marker-must-not-appear" in (
        completed.stdout + completed.stderr
    )
    diagnostics = [
        line.replace("apex-m8-secret-marker-must-not-appear", "<redacted>")
        for line in completed.stderr.splitlines()
        if line.strip()
    ]
    passed = completed.returncode == 0 and len(tools) == 52 and not secret_emitted
    return {
        "schema_version": "1.0.0",
        "status": "PASSED" if passed else "FAILED",
        "inspector_package": inspector_package,
        "method": "tools/list",
        "strict_schema_portability": completed.returncode == 0,
        "tool_count": len(tools),
        "secret_values_emitted": secret_emitted,
        "returncode": completed.returncode,
        "strict_diagnostics": diagnostics,
    }


def _resolve_executable(command: str) -> str:
    candidate = Path(command).expanduser()
    if candidate.is_absolute():
        return str(candidate.resolve(strict=True))
    resolved = shutil.which(command)
    if resolved is None:
        raise FileNotFoundError(command)
    return resolved


def _parse_json_output(stdout: str) -> dict[str, Any]:
    try:
        payload = json.loads(stdout)
    except json.JSONDecodeError:
        candidates = [line for line in stdout.splitlines() if line.lstrip().startswith("{")]
        if not candidates:
            raise
        payload = json.loads(candidates[-1])
    if not isinstance(payload, dict):
        raise ValueError("Inspector JSON root is not an object")
    return payload


def _tool_items(payload: dict[str, Any]) -> list[Any]:
    result = payload.get("result", payload)
    if not isinstance(result, dict):
        return []
    tools = result.get("tools")
    return tools if isinstance(tools, list) else []


def _sanitized_environment(*, keep_pythonpath: bool) -> dict[str, str]:
    environment = os.environ.copy()
    sensitive_parts = ("KEY", "TOKEN", "SECRET", "PASSWORD", "CREDENTIAL")
    for name in tuple(environment):
        if any(part in name.upper() for part in sensitive_parts):
            environment.pop(name, None)
    if keep_pythonpath:
        source_path = str(ROOT / "src")
        existing_path = environment.get("PYTHONPATH")
        environment["PYTHONPATH"] = (
            source_path + os.pathsep + existing_path if existing_path else source_path
        )
    else:
        environment.pop("PYTHONPATH", None)
    environment["APEX_MCP_SMOKE_SECRET"] = "apex-m8-secret-marker-must-not-appear"
    environment["PYTHONUTF8"] = "1"
    return environment


if __name__ == "__main__":
    raise SystemExit(main())
