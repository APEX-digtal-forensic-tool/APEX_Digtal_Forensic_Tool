#!/usr/bin/env python3
"""Install a built APEX wheel from the lock into a clean venv and run MCP smoke."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess  # nosec B404
import sys
import tempfile
import tomllib
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_TIMEOUT_SECONDS = 300.0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    wheel_group = parser.add_mutually_exclusive_group(required=True)
    wheel_group.add_argument("--wheel", type=Path)
    wheel_group.add_argument("--wheel-dir", type=Path)
    parser.add_argument("--uv", default="uv")
    parser.add_argument("--schema-dir", type=Path, default=ROOT / "schemas" / "v1")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT_SECONDS)
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--inspector", action="store_true")
    parser.add_argument(
        "--inspector-package",
        default="@modelcontextprotocol/inspector@2.4.0",
    )
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    if args.timeout <= 0:
        parser.error("--timeout must be positive")

    try:
        wheel = _resolve_wheel(args.wheel, args.wheel_dir)
        report = verify_package(
            wheel=wheel,
            uv_command=args.uv,
            schema_dir=args.schema_dir,
            timeout=args.timeout,
            offline=args.offline,
            inspector=args.inspector,
            inspector_package=args.inspector_package,
        )
    except Exception as error:
        report = {
            "schema_version": "1.0.0",
            "status": "FAILED",
            "reason": "MCP_PACKAGE_VERIFICATION_FAILED",
            "error_type": type(error).__name__,
            "secret_values_emitted": False,
        }
    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    else:
        print(f"APEX MCP clean package verification: {report['status']}")
    return 0 if report["status"] == "PASSED" else 1


def verify_package(
    *,
    wheel: Path,
    uv_command: str,
    schema_dir: Path,
    timeout: float,
    offline: bool,
    inspector: bool,
    inspector_package: str,
) -> dict[str, Any]:
    uv_executable = shutil.which(uv_command)
    if uv_executable is None:
        raise FileNotFoundError(uv_command)
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    version = str(project["project"]["version"])
    with tempfile.TemporaryDirectory(prefix="apex-mcp-clean-한글-") as temporary_directory:
        temporary_root = Path(temporary_directory)
        environment_path = temporary_root / "venv"
        requirements_path = temporary_root / "mcp-requirements.lock"
        common = ["--offline"] if offline else []
        _run(
            [
                uv_executable,
                "export",
                "--locked",
                "--extra",
                "mcp-server",
                "--no-dev",
                "--no-emit-project",
                "--format",
                "requirements.txt",
                "--output-file",
                str(requirements_path),
                *common,
            ],
            timeout=timeout,
        )
        _run(
            [
                uv_executable,
                "venv",
                "--python",
                sys.executable,
                str(environment_path),
                *common,
            ],
            timeout=timeout,
        )
        clean_python, console = _venv_commands(environment_path)
        _run(
            [
                uv_executable,
                "pip",
                "install",
                "--python",
                str(clean_python),
                "--require-hashes",
                "--strict",
                "--requirements",
                str(requirements_path),
                *common,
            ],
            timeout=timeout,
        )
        _run(
            [
                uv_executable,
                "pip",
                "install",
                "--python",
                str(clean_python),
                "--no-deps",
                str(wheel),
            ],
            timeout=timeout,
        )
        _run(
            [uv_executable, "pip", "check", "--python", str(clean_python)],
            timeout=timeout,
        )
        smoke = _run(
            [
                str(clean_python),
                str(ROOT / "tools" / "verify_mcp_stdio.py"),
                "--command",
                str(console),
                "--schema-dir",
                str(schema_dir.expanduser().resolve(strict=True)),
                "--json",
            ],
            timeout=timeout,
        )
        smoke_report = json.loads(smoke.stdout)
        if not isinstance(smoke_report, dict):
            raise ValueError("stdio verifier JSON root is not an object")
        installed = _run(
            [
                str(clean_python),
                "-c",
                (
                    "import importlib.metadata as m; "
                    "print(m.version('apex-forensic'))"
                ),
            ],
            timeout=timeout,
        ).stdout.strip()
        inspector_report: dict[str, Any] | None = None
        if inspector:
            inspector_result = _run(
                [
                    str(clean_python),
                    str(ROOT / "tools" / "verify_mcp_inspector.py"),
                    "--command",
                    str(console),
                    "--schema-dir",
                    str(schema_dir.expanduser().resolve(strict=True)),
                    "--package",
                    inspector_package,
                    "--json",
                ],
                timeout=timeout,
            )
            inspector_report = json.loads(inspector_result.stdout)
            if not isinstance(inspector_report, dict):
                raise ValueError("Inspector verifier JSON root is not an object")
        passed = (
            smoke_report.get("status") == "PASSED"
            and installed == version
            and (inspector_report is None or inspector_report.get("status") == "PASSED")
        )
        return {
            "schema_version": "1.0.0",
            "status": "PASSED" if passed else "FAILED",
            "wheel_filename": wheel.name,
            "expected_version": version,
            "installed_version": installed,
            "dependency_lock_enforced": True,
            "dependency_hashes_enforced": True,
            "clean_environment": True,
            "stdio": smoke_report,
            "inspector": inspector_report,
            "secret_values_emitted": bool(
                smoke_report.get("secret_values_emitted", False)
            ),
        }


def _resolve_wheel(wheel: Path | None, wheel_dir: Path | None) -> Path:
    if wheel is not None:
        resolved = wheel.expanduser().resolve(strict=True)
        if resolved.suffix != ".whl":
            raise ValueError("--wheel must identify a wheel file")
        return resolved
    assert wheel_dir is not None
    candidates = sorted(wheel_dir.expanduser().resolve(strict=True).glob("apex_forensic-*.whl"))
    if len(candidates) != 1:
        raise ValueError("--wheel-dir must contain exactly one APEX wheel")
    return candidates[0]


def _venv_commands(environment_path: Path) -> tuple[Path, Path]:
    if os.name == "nt":
        return (
            environment_path / "Scripts" / "python.exe",
            environment_path / "Scripts" / "apex-mcp.exe",
        )
    return environment_path / "bin" / "python", environment_path / "bin" / "apex-mcp"


def _run(command: list[str], *, timeout: float) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(  # nosec B603
        command,
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
        env=_sanitized_environment(),
    )
    if completed.returncode != 0:
        raise RuntimeError(f"verification command failed with {completed.returncode}")
    return completed


def _sanitized_environment() -> dict[str, str]:
    environment = os.environ.copy()
    sensitive_parts = ("KEY", "TOKEN", "SECRET", "PASSWORD", "CREDENTIAL")
    for name in tuple(environment):
        if any(part in name.upper() for part in sensitive_parts):
            environment.pop(name, None)
    environment.pop("PYTHONPATH", None)
    environment["PYTHONUTF8"] = "1"
    return environment


if __name__ == "__main__":
    raise SystemExit(main())
