#!/usr/bin/env python3
"""Run advanced-runtime host verification probes without printing secret values."""

from __future__ import annotations

import argparse
import json
import os
import platform
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

MAX_CAPTURE_CHARS = 20_000


@dataclass(frozen=True, slots=True)
class Probe:
    name: str
    command: list[str]
    requires_windows: bool = False
    requires_secret: bool = False


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify advanced APEX runtimes on a Windows forensic host."
    )
    parser.add_argument("--python", default=sys.executable)
    parser.add_argument("--timeout", type=float, default=120.0)
    parser.add_argument(
        "--skip-execution",
        action="store_true",
        help="Only print the host/probe matrix; do not execute verifier scripts.",
    )
    args = parser.parse_args()

    root = Path(__file__).resolve().parents[1]
    is_windows = platform.system().casefold() == "windows"
    probes = _probes(root, args.python)

    results: list[dict[str, Any]] = []
    for probe in probes:
        if args.skip_execution:
            results.append(_skipped_probe(probe, "SKIPPED_BY_REQUEST"))
            continue
        if probe.requires_windows and not is_windows:
            results.append(_skipped_probe(probe, "WINDOWS_HOST_REQUIRED"))
            continue
        if probe.requires_secret and not _ai_env_ready():
            results.append(_skipped_probe(probe, "KEY_UNAVAILABLE"))
            continue
        results.append(_run_probe(probe, timeout=args.timeout, cwd=root))

    payload = {
        "host_platform": platform.platform(),
        "host_platform_status": "WINDOWS" if is_windows else "WINDOWS_HOST_REQUIRED",
        "python": args.python,
        "secret_values_emitted": False,
        "probes": results,
    }
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 1 if any(item["status"] == "FAILED" for item in results) else 0


def _probes(root: Path, python_executable: str) -> list[Probe]:
    def script(name: str) -> str:
        return str(root / "tools" / name)

    probes = [
        Probe("dpapi", [python_executable, script("verify_dpapi_runtime.py")], True),
        Probe("nss", [python_executable, script("verify_nss_runtime.py")]),
        Probe("kakaotalk", [python_executable, script("verify_kakaotalk_runtime.py")]),
        Probe("ocr", [python_executable, script("verify_ocr_runtime.py")]),
        Probe("stt", [python_executable, script("verify_stt_runtime.py")]),
        Probe("report-renderers", [python_executable, script("verify_report_renderers.py")]),
    ]
    ai_command = [
        python_executable,
        script("verify_ai_provider.py"),
        "--base-url",
        os.environ.get("APEX_AI_VERIFY_BASE_URL", ""),
        "--model",
        os.environ.get("APEX_AI_VERIFY_MODEL", ""),
        "--api-key-env",
        os.environ.get("APEX_AI_VERIFY_API_KEY_ENV", ""),
        "--operation",
        os.environ.get("APEX_AI_VERIFY_OPERATION", "capability"),
    ]
    probes.append(Probe("ai-provider", ai_command, requires_secret=True))
    return probes


def _ai_env_ready() -> bool:
    key_env = os.environ.get("APEX_AI_VERIFY_API_KEY_ENV")
    return bool(
        os.environ.get("APEX_AI_VERIFY_BASE_URL")
        and os.environ.get("APEX_AI_VERIFY_MODEL")
        and key_env
        and os.environ.get(key_env)
    )


def _skipped_probe(probe: Probe, reason: str) -> dict[str, Any]:
    return {
        "name": probe.name,
        "status": reason,
        "command": _redacted_command(probe.command),
        "returncode": None,
        "stdout": "",
        "stderr": "",
    }


def _run_probe(probe: Probe, *, timeout: float, cwd: Path) -> dict[str, Any]:
    try:
        completed = subprocess.run(
            probe.command,
            cwd=cwd,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as error:
        return {
            "name": probe.name,
            "status": "FAILED",
            "command": _redacted_command(probe.command),
            "returncode": None,
            "stdout": _truncate(error.stdout),
            "stderr": _truncate(error.stderr),
            "error_code": "TIMEOUT",
        }
    return {
        "name": probe.name,
        "status": "PASSED" if completed.returncode == 0 else "FAILED",
        "command": _redacted_command(probe.command),
        "returncode": completed.returncode,
        "stdout": _truncate(completed.stdout),
        "stderr": _truncate(completed.stderr),
    }


def _redacted_command(command: list[str]) -> list[str]:
    redacted: list[str] = []
    redact_next = False
    for item in command:
        if redact_next:
            redacted.append("<env-name>" if item.startswith("APEX_") else item)
            redact_next = False
            continue
        redacted.append(item)
        if item == "--api-key-env":
            redact_next = True
    return redacted


def _truncate(value: str | bytes | None) -> str:
    if value is None:
        return ""
    text = value.decode("utf-8", errors="replace") if isinstance(value, bytes) else value
    if len(text) <= MAX_CAPTURE_CHARS:
        return text
    return text[:MAX_CAPTURE_CHARS] + "...<truncated>"


if __name__ == "__main__":
    raise SystemExit(main())
