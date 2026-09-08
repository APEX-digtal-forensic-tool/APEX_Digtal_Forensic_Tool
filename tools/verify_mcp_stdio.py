#!/usr/bin/env python3
"""Verify APEX MCP stdio negotiation, policy surface, and EOF lifecycle."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import platform
import shutil
import subprocess  # nosec B404
import sys
import tempfile
from pathlib import Path
from typing import Any

from mcp.client import Client
from mcp.client.stdio import StdioServerParameters

from apex_forensic.config import build_services
from apex_mcp.m7_tools import M7_TOOL_NAMES

ROOT = Path(__file__).resolve().parents[1]
SECRET_MARKER = "apex-m8-secret-marker-must-not-appear"
DEFAULT_TIMEOUT_SECONDS = 30.0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    command_group = parser.add_mutually_exclusive_group()
    command_group.add_argument(
        "--module",
        action="store_true",
        help="Start the source server as the current Python module.",
    )
    command_group.add_argument(
        "--command",
        default="apex-mcp",
        help="Installed apex-mcp console command or absolute executable path.",
    )
    parser.add_argument(
        "--schema-dir",
        type=Path,
        default=ROOT / "schemas" / "v1",
    )
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT_SECONDS)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    if args.timeout <= 0:
        parser.error("--timeout must be positive")

    try:
        report = asyncio.run(
            verify_stdio(
                module=args.module,
                command=args.command,
                schema_dir=args.schema_dir,
                timeout=args.timeout,
            )
        )
    except Exception as error:  # keep verifier failures structured and secret-free
        report = {
            "schema_version": "1.0.0",
            "status": "FAILED",
            "reason": "MCP_STDIO_VERIFICATION_FAILED",
            "error_type": type(error).__name__,
            "secret_values_emitted": False,
        }
    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    else:
        print(f"APEX MCP stdio verification: {report['status']}")
    return 0 if report["status"] == "PASSED" else 1


async def verify_stdio(
    *,
    module: bool,
    command: str,
    schema_dir: Path,
    timeout: float,
) -> dict[str, Any]:
    canonical_schema_dir = schema_dir.expanduser().resolve(strict=True)
    executable, command_prefix = _resolve_command(module=module, command=command)
    environment = _sanitized_environment(keep_pythonpath=module)
    with tempfile.TemporaryDirectory(prefix="apex-mcp-한글-") as temporary_directory:
        database_path = Path(temporary_directory) / "증거 사례.db"
        services = build_services(database_path)
        try:
            services.cases.create_case(name="M8 Windows stdio 한글")
        finally:
            services.close()
        server_args = [
            *command_prefix,
            "--database",
            str(database_path),
            "--schema-dir",
            str(canonical_schema_dir),
        ]
        eof = _verify_eof_lifecycle(
            executable,
            server_args,
            environment=environment,
            timeout=timeout,
        )
        if eof["status"] != "PASSED":
            return _report(status="FAILED", eof=eof)

        parameters = StdioServerParameters(
            command=executable,
            args=server_args,
            cwd=ROOT,
            env=environment,
        )
        async with Client(parameters, mode="2026-07-28") as client:
            protocol_version = client.session.protocol_version
            tools = await client.list_tools(cache_mode="refresh")
            tool_names = {tool.name for tool in tools.tools}
            denied = await client.call_tool(
                "apex.view.raw_read",
                {
                    "case_id": "case-id",
                    "resource_type": "FILE_SYSTEM_NODE",
                    "resource_id": "node-id",
                    "offset": 0,
                    "length": 16,
                },
            )

        denied_code = _error_code(denied.structured_content)
        passed = (
            protocol_version == "2026-07-28"
            and tool_names == M7_TOOL_NAMES
            and denied.is_error is True
            and denied_code == "HUMAN_CONFIRMATION_REQUIRED"
        )
        return _report(
            status="PASSED" if passed else "FAILED",
            eof=eof,
            protocol_version=protocol_version,
            tool_count=len(tool_names),
            tool_surface_matches=tool_names == M7_TOOL_NAMES,
            raw_read_default_deny=denied_code == "HUMAN_CONFIRMATION_REQUIRED",
        )


def _resolve_command(*, module: bool, command: str) -> tuple[str, list[str]]:
    if module:
        return sys.executable, ["-m", "apex_mcp"]
    candidate = Path(command).expanduser()
    if candidate.is_absolute():
        return str(candidate.resolve(strict=True)), []
    resolved = shutil.which(command)
    if resolved is None:
        raise FileNotFoundError(command)
    return resolved, []


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
    environment["APEX_MCP_SMOKE_SECRET"] = SECRET_MARKER
    environment["PYTHONUTF8"] = "1"
    return environment


def _verify_eof_lifecycle(
    executable: str,
    arguments: list[str],
    *,
    environment: dict[str, str],
    timeout: float,
) -> dict[str, Any]:
    process = subprocess.Popen(  # nosec B603
        [executable, *arguments],
        cwd=ROOT,
        env=environment,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        stdout, stderr = process.communicate(input=b"", timeout=timeout)
    except subprocess.TimeoutExpired:
        process.kill()
        stdout, stderr = process.communicate()
        return {
            "status": "FAILED",
            "reason": "EOF_EXIT_TIMEOUT",
            "returncode": process.returncode,
            "stdout_bytes": len(stdout),
            "stderr_bytes": len(stderr),
        }
    secret_emitted = SECRET_MARKER.encode() in stdout or SECRET_MARKER.encode() in stderr
    passed = process.returncode == 0 and stdout == b"" and not secret_emitted
    return {
        "status": "PASSED" if passed else "FAILED",
        "reason": None if passed else "EOF_OR_STDOUT_CONTRACT_VIOLATION",
        "returncode": process.returncode,
        "stdout_bytes": len(stdout),
        "stderr_bytes": len(stderr),
        "stdout_protocol_only": stdout == b"",
        "secret_values_emitted": secret_emitted,
    }


def _error_code(structured_content: Any) -> str | None:
    if not isinstance(structured_content, dict):
        return None
    errors = structured_content.get("errors")
    if not isinstance(errors, list) or not errors or not isinstance(errors[0], dict):
        return None
    code = errors[0].get("code")
    return code if isinstance(code, str) else None


def _report(*, status: str, eof: dict[str, Any], **details: Any) -> dict[str, Any]:
    return {
        "schema_version": "1.0.0",
        "status": status,
        "platform": platform.system(),
        "unicode_database_path_verified": True,
        "eof_lifecycle": eof,
        "secret_values_emitted": bool(eof.get("secret_values_emitted", False)),
        **details,
    }


if __name__ == "__main__":
    raise SystemExit(main())
