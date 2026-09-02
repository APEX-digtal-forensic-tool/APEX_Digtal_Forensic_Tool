#!/usr/bin/env python3
"""Run the reproducible APEX Core Engine release-hardening gate."""

from __future__ import annotations

import argparse
import json
import os
import subprocess  # nosec B404
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SECURITY_MANIFEST = ROOT / "tools" / "security_findings.json"
OUTPUT_LIMIT = 4_000
ALLOWED_STATUSES = {
    "PASSED",
    "SKIPPED_WITH_REASON",
    "CAPABILITY_UNAVAILABLE",
    "EXTERNAL_CONFIGURATION_REQUIRED",
    "HOST_VERIFICATION_REQUIRED",
    "FAILED",
}
ALLOWED_DISPOSITIONS = {
    "FIXED",
    "FALSE_POSITIVE_WITH_JUSTIFICATION",
    "ACCEPTED_RISK_WITH_JUSTIFICATION",
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="Emit structured JSON")
    parser.add_argument(
        "--skip-full-pytest",
        action="store_true",
        help="Skip only the full suite; focused gate tests still run.",
    )
    parser.add_argument(
        "--mcp-only",
        action="store_true",
        help="Run the portable MCP contract, source, design, and security subset.",
    )
    parser.add_argument("--timeout", type=float, default=900.0)
    parser.add_argument(
        "--fixture-manifest",
        help="Synthetic Windows runtime fixture manifest passed to the Windows semantic verifier.",
    )
    args = parser.parse_args()
    if args.timeout <= 0:
        parser.error("--timeout must be positive")

    report = run_release_gate(
        python_executable=sys.executable,
        timeout=args.timeout,
        skip_full_pytest=args.skip_full_pytest,
        fixture_manifest=args.fixture_manifest,
        mcp_only=args.mcp_only,
    )
    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    else:
        print(f"APEX Core Engine release gate: {report['status']}")
        for check in report["checks"]:
            reason = f" ({check['reason']})" if check.get("reason") else ""
            print(f"{check['name']}: {check['status']}{reason}")
    return 1 if report["status"] == "FAILED" else 0


def run_release_gate(
    *,
    python_executable: str,
    timeout: float,
    skip_full_pytest: bool,
    fixture_manifest: str | None = None,
    mcp_only: bool = False,
) -> dict[str, Any]:
    started = time.perf_counter()
    checks: list[dict[str, Any]] = []
    base_env = os.environ.copy()
    base_env["PYTHONPATH"] = str(ROOT / "src")

    if not mcp_only:
        if skip_full_pytest:
            checks.append(
                _check(
                    "pytest",
                    "SKIPPED_WITH_REASON",
                    reason="SKIPPED_BY_EXPLICIT_COMMAND_OPTION",
                )
            )
        else:
            checks.append(
                _run_command(
                    "pytest",
                    [python_executable, "-m", "pytest", "-q"],
                    timeout=timeout,
                    env=base_env,
                )
            )
    checks.append(
        _run_command(
            "mcp-contract",
            [python_executable, "-m", "pytest", "-q", "tests/mcp"],
            timeout=timeout,
            env=base_env,
        )
    )
    checks.append(
        _run_json_command(
            "mcp-stdio-lifecycle",
            [
                python_executable,
                "tools/verify_mcp_stdio.py",
                "--module",
                "--json",
            ],
            classifier=_classify_mcp_stdio,
            timeout=timeout,
            env=base_env,
        )
    )
    checks.append(
        _run_command(
            "ruff",
            [python_executable, "-m", "ruff", "check", "."],
            timeout=timeout,
            env=base_env,
        )
    )
    checks.append(
        _run_command(
            "mypy",
            [python_executable, "-m", "mypy", "src"],
            timeout=timeout,
            env=base_env,
        )
    )
    checks.append(
        _run_command(
            "git-diff-check",
            ["git", "diff", "--check"],
            timeout=timeout,
            env=base_env,
        )
    )

    design = _run_command(
        "design-schema-validation",
        ["bash", "tools/validate_design.sh"],
        timeout=timeout,
        env=base_env,
    )
    checks.append(design)
    checks.append(_strict_schema_status(design))

    if mcp_only:
        checks.append(_run_bandit(python_executable, timeout=timeout, env=base_env))
        return _release_report(checks, started=started, scope="MCP_ONLY")

    runtime_command = [
        python_executable,
        "tools/verify_windows_host_runtime.py",
    ]
    if fixture_manifest:
        runtime_command.extend(["--fixture-manifest", fixture_manifest])
    runtime_command.extend(["--exclude-probe", "kakaotalk"])

    runtime = _run_json_command(
        "runtime-semantic-verification",
        runtime_command,
        classifier=_classify_runtime_verifier,
        timeout=timeout,
        env=base_env,
    )
    checks.append(runtime)
    checks.append(
        _run_json_command(
            "provider-capabilities",
            [python_executable, "-m", "apex_forensic", "doctor", "--json"],
            classifier=_classify_doctor,
            timeout=timeout,
            env=base_env,
        )
    )
    checks.append(
        _run_command(
            "recovery-fault-injection",
            [
                python_executable,
                "-m",
                "pytest",
                "-q",
                "tests/unit/test_release_hardening_recovery.py",
                "tests/unit/test_file_system_indexing.py",
                "tests/unit/test_windows_artifacts.py",
            ],
            timeout=timeout,
            env=base_env,
        )
    )
    checks.append(_run_bandit(python_executable, timeout=timeout, env=base_env))

    benchmark = _run_json_command(
        "benchmark-smoke",
        [
            python_executable,
            "-m",
            "apex_forensic",
            "benchmark",
            "--runs",
            "1",
            "--search-iterations",
            "2",
            "--json",
        ],
        classifier=_classify_benchmark,
        timeout=timeout,
        env=base_env,
    )
    checks.append(benchmark)
    checks.append(_read_only_status(benchmark))
    checks.append(
        _run_command(
            "cli-smoke",
            [
                python_executable,
                "-m",
                "pytest",
                "-q",
                "tests/integration/test_cli_smoke.py",
            ],
            timeout=timeout,
            env=base_env,
        )
    )
    checks.append(
        _run_command(
            "unicode-korean-cli",
            [
                python_executable,
                "-m",
                "pytest",
                "-q",
                "tests/integration/test_cli_smoke.py::test_cli_case_to_evidence_verification_smoke",
                "tests/integration/test_phase8_cli_workflow.py",
            ],
            timeout=timeout,
            env=base_env,
        )
    )

    return _release_report(checks, started=started, scope="FULL_ENGINE")


def _release_report(
    checks: list[dict[str, Any]],
    *,
    started: float,
    scope: str,
) -> dict[str, Any]:
    failed = [check["name"] for check in checks if check["status"] == "FAILED"]
    limitations = [
        {"name": check["name"], "status": check["status"], "reason": check.get("reason")}
        for check in checks
        if check["status"] not in {"PASSED", "FAILED"}
    ]
    return {
        "schema_version": "1.0.0",
        "status": "FAILED" if failed else "PASSED_WITH_LIMITATIONS" if limitations else "PASSED",
        "release_ready_on_this_host": not failed and not limitations,
        "elapsed_wall_seconds": time.perf_counter() - started,
        "root": str(ROOT),
        "scope": scope,
        "failed_checks": failed,
        "limitations": limitations,
        "checks": checks,
    }


def _run_command(
    name: str,
    command: list[str],
    *,
    timeout: float,
    env: dict[str, str],
    preserve_stdout: bool = False,
) -> dict[str, Any]:
    started = time.perf_counter()
    try:
        completed = subprocess.run(  # nosec B603
            command,
            cwd=ROOT,
            env=env,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError as error:
        return _check(
            name,
            "CAPABILITY_UNAVAILABLE",
            reason="COMMAND_NOT_FOUND",
            command=command,
            details={"executable": error.filename},
        )
    except subprocess.TimeoutExpired as error:
        return _check(
            name,
            "FAILED",
            reason="COMMAND_TIMEOUT",
            command=command,
            elapsed_wall_seconds=time.perf_counter() - started,
            stdout=_truncate(error.stdout),
            stderr=_truncate(error.stderr),
        )
    return _check(
        name,
        "PASSED" if completed.returncode == 0 else "FAILED",
        reason=None if completed.returncode == 0 else "NONZERO_EXIT",
        command=command,
        returncode=completed.returncode,
        elapsed_wall_seconds=time.perf_counter() - started,
        stdout=completed.stdout if preserve_stdout else _truncate(completed.stdout),
        stderr=_truncate(completed.stderr),
    )


def _run_json_command(
    name: str,
    command: list[str],
    *,
    classifier: Any,
    timeout: float,
    env: dict[str, str],
) -> dict[str, Any]:
    result = _run_command(
        name,
        command,
        timeout=timeout,
        env=env,
        preserve_stdout=True,
    )
    if result["status"] == "CAPABILITY_UNAVAILABLE":
        return result
    try:
        payload = json.loads(result.get("stdout", ""))
    except (json.JSONDecodeError, TypeError) as error:
        result["status"] = "FAILED"
        result["reason"] = "INVALID_JSON_OUTPUT"
        result["details"] = {"error_type": type(error).__name__}
        return result
    if not isinstance(payload, dict):
        result["status"] = "FAILED"
        result["reason"] = "JSON_ROOT_NOT_OBJECT"
        return result
    status, reason, details = classifier(payload, result.get("returncode"))
    if status not in ALLOWED_STATUSES:
        raise ValueError(f"unsupported release-gate status: {status}")
    result["status"] = status
    result["reason"] = reason
    result["details"] = details
    result.pop("stdout", None)
    return result


def _strict_schema_status(design: dict[str, Any]) -> dict[str, Any]:
    if design["status"] == "FAILED":
        return _check(
            "strict-json-schema-validation",
            "FAILED",
            reason="DESIGN_VALIDATOR_FAILED",
        )
    output = f"{design.get('stdout', '')}\n{design.get('stderr', '')}"
    if "Ajv Draft 2020-12 strict validation passed." in output:
        return _check("strict-json-schema-validation", "PASSED")
    return _check(
        "strict-json-schema-validation",
        "CAPABILITY_UNAVAILABLE",
        reason="AJV_CLI_OR_FORMATS_NOT_INSTALLED",
    )


def _classify_runtime_verifier(
    payload: dict[str, Any],
    returncode: int | None,
) -> tuple[str, str | None, dict[str, Any]]:
    probes = [item for item in payload.get("probes", []) if isinstance(item, dict)]
    included = [item for item in probes if item.get("name") != "kakaotalk"]
    statuses = {str(item.get("status")) for item in included}
    details = {
        "host_platform_status": payload.get("host_platform_status"),
        "secret_values_emitted": payload.get("secret_values_emitted"),
        "windows_runtime_success_claimed": payload.get("windows_runtime_success_claimed"),
        "probes": [
            {
                "name": item.get("name"),
                "status": item.get("status"),
                "reason": item.get("reason"),
                "semantic_checks": item.get("semantic_checks"),
            }
            for item in probes
        ],
    }
    if returncode not in {0, None} or "FAILED" in statuses:
        return "FAILED", "RUNTIME_PROBE_FAILED", details
    if payload.get("secret_values_emitted") is not False:
        return "FAILED", "SECRET_OUTPUT_CONTRACT_VIOLATION", details
    if "CAPABILITY_UNAVAILABLE" in statuses:
        return "CAPABILITY_UNAVAILABLE", "OPTIONAL_RUNTIME_UNAVAILABLE", details
    if statuses & {"EXTERNAL_FIXTURE_NOT_CONFIGURED", "EXTERNAL_PROVIDER_NOT_CONFIGURED"}:
        return "EXTERNAL_CONFIGURATION_REQUIRED", "EXTERNAL_RUNTIME_INPUT_REQUIRED", details
    if "HOST_VERIFICATION_REQUIRED" in statuses:
        return "HOST_VERIFICATION_REQUIRED", "WINDOWS_RUNTIME_REQUIRES_WINDOWS_HOST", details
    return "PASSED", None, details


def _classify_doctor(
    payload: dict[str, Any],
    returncode: int | None,
) -> tuple[str, str | None, dict[str, Any]]:
    capabilities = [
        item for item in payload.get("capabilities", []) if isinstance(item, dict)
    ]
    statuses = {str(item.get("status")) for item in capabilities}
    details = {
        "summary": payload.get("summary"),
        "capabilities": [
            {
                "id": item.get("id"),
                "status": item.get("status"),
                "reason": item.get("reason"),
                "version": item.get("version"),
            }
            for item in capabilities
        ],
    }
    if returncode not in {0, None}:
        return "FAILED", "DOCTOR_NONZERO_EXIT", details
    summary = payload.get("summary")
    if not isinstance(summary, dict) or any(
        summary.get(flag) is not False
        for flag in (
            "secret_values_emitted",
            "environment_values_emitted",
            "environment_names_emitted",
        )
    ):
        return "FAILED", "DOCTOR_OUTPUT_CONTRACT_VIOLATION", details
    if "CAPABILITY_UNAVAILABLE" in statuses or "UNSUPPORTED_PLATFORM" in statuses:
        return "CAPABILITY_UNAVAILABLE", "ONE_OR_MORE_PROVIDERS_UNAVAILABLE", details
    if "EXTERNAL_CONFIGURATION_REQUIRED" in statuses:
        return (
            "EXTERNAL_CONFIGURATION_REQUIRED",
            "OPTIONAL_PROVIDER_CONFIGURATION_REQUIRED",
            details,
        )
    if "HOST_VERIFICATION_REQUIRED" in statuses:
        return "HOST_VERIFICATION_REQUIRED", "WINDOWS_PROVIDER_REQUIRES_WINDOWS_HOST", details
    return "PASSED", None, details


def _classify_mcp_stdio(
    payload: dict[str, Any],
    returncode: int | None,
) -> tuple[str, str | None, dict[str, Any]]:
    eof = payload.get("eof_lifecycle")
    details = {
        "protocol_version": payload.get("protocol_version"),
        "tool_count": payload.get("tool_count"),
        "tool_surface_matches": payload.get("tool_surface_matches"),
        "raw_read_default_deny": payload.get("raw_read_default_deny"),
        "unicode_database_path_verified": payload.get("unicode_database_path_verified"),
        "eof_lifecycle": eof if isinstance(eof, dict) else {},
        "secret_values_emitted": payload.get("secret_values_emitted"),
    }
    passed = (
        returncode in {0, None}
        and payload.get("status") == "PASSED"
        and payload.get("protocol_version") == "2026-07-28"
        and payload.get("tool_count") == 52
        and payload.get("tool_surface_matches") is True
        and payload.get("raw_read_default_deny") is True
        and payload.get("unicode_database_path_verified") is True
        and isinstance(eof, dict)
        and eof.get("status") == "PASSED"
        and eof.get("stdout_protocol_only") is True
        and payload.get("secret_values_emitted") is False
    )
    return (
        ("PASSED", None, details)
        if passed
        else ("FAILED", "MCP_STDIO_CONTRACT_VIOLATION", details)
    )


def _classify_benchmark(
    payload: dict[str, Any],
    returncode: int | None,
) -> tuple[str, str | None, dict[str, Any]]:
    details = {
        "benchmark_status": payload.get("status"),
        "fixture": payload.get("fixture"),
        "configuration": payload.get("configuration"),
        "read_only_invariant": payload.get("read_only_invariant"),
        "results": payload.get("results"),
        "comparative_superiority_claimed": payload.get("comparative_superiority_claimed"),
    }
    if payload.get("status") == "CAPABILITY_UNAVAILABLE":
        return "CAPABILITY_UNAVAILABLE", str(payload.get("reason")), details
    if (
        returncode == 0
        and payload.get("status") == "COMPLETED"
        and payload.get("comparative_superiority_claimed") is False
    ):
        return "PASSED", None, details
    return "FAILED", str(payload.get("reason") or "BENCHMARK_FAILED"), details


def _read_only_status(benchmark: dict[str, Any]) -> dict[str, Any]:
    invariant = benchmark.get("details", {}).get("read_only_invariant")
    if benchmark["status"] == "CAPABILITY_UNAVAILABLE":
        return _check(
            "read-only-evidence-invariant",
            "CAPABILITY_UNAVAILABLE",
            reason="BENCHMARK_RUNTIME_UNAVAILABLE",
        )
    if (
        isinstance(invariant, dict)
        and invariant.get("evidence_unchanged") is True
        and invariant.get("writes_to_evidence") is False
    ):
        return _check(
            "read-only-evidence-invariant",
            "PASSED",
            details=invariant,
        )
    return _check(
        "read-only-evidence-invariant",
        "FAILED",
        reason="EVIDENCE_MUTATION_DETECTED_OR_INVARIANT_MISSING",
        details=invariant if isinstance(invariant, dict) else {},
    )


def _run_bandit(
    python_executable: str,
    *,
    timeout: float,
    env: dict[str, str],
) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="apex-release-bandit-") as temporary_directory:
        report_path = Path(temporary_directory) / "bandit.json"
        command = [
            python_executable,
            "-m",
            "bandit",
            "-r",
            "src",
            "tools",
            "-f",
            "json",
            "-o",
            str(report_path),
        ]
        result = _run_command("security-bandit", command, timeout=timeout, env=env)
        if not report_path.is_file():
            if result["status"] == "FAILED" and "No module named bandit" in result.get(
                "stderr", ""
            ):
                result["status"] = "CAPABILITY_UNAVAILABLE"
                result["reason"] = "BANDIT_NOT_INSTALLED"
            else:
                result["status"] = "FAILED"
                result["reason"] = "BANDIT_REPORT_MISSING"
            return result
        try:
            report = json.loads(report_path.read_text(encoding="utf-8"))
            manifest = json.loads(SECURITY_MANIFEST.read_text(encoding="utf-8"))
            audit = audit_bandit_report(report, manifest)
        except (OSError, json.JSONDecodeError, TypeError, ValueError) as error:
            result["status"] = "FAILED"
            result["reason"] = "SECURITY_AUDIT_PARSE_FAILED"
            result["details"] = {"error_type": type(error).__name__}
            return result
        result["status"] = "PASSED" if audit["complete"] else "FAILED"
        result["reason"] = None if audit["complete"] else "UNCLASSIFIED_SECURITY_FINDINGS"
        result["details"] = audit
        return result


def audit_bandit_report(
    report: dict[str, Any],
    manifest: dict[str, Any],
) -> dict[str, Any]:
    current = {
        _finding_key(str(item["test_id"]), str(item["filename"]), int(item["line_number"]))
        for item in report.get("results", [])
        if item.get("issue_severity") in {"MEDIUM", "HIGH"}
    }
    classified: dict[str, dict[str, str]] = {}
    invalid: list[str] = []
    for group in manifest.get("classifications", []):
        if not isinstance(group, dict):
            invalid.append("classification entry is not an object")
            continue
        test_id = str(group.get("test_id", ""))
        disposition = str(group.get("disposition", ""))
        justification = str(group.get("justification", "")).strip()
        if disposition not in ALLOWED_DISPOSITIONS or not justification:
            invalid.append(f"invalid disposition or justification for {test_id or 'unknown'}")
            continue
        for location in group.get("locations", []):
            key = f"{test_id}|{location}"
            if key in classified:
                invalid.append(f"duplicate classification: {key}")
            classified[key] = {
                "disposition": disposition,
                "justification": justification,
            }
    classified_keys = set(classified)
    unclassified = sorted(current - classified_keys)
    stale = sorted(classified_keys - current)
    dispositions = {
        key: classified[key]
        for key in sorted(current & classified_keys)
    }
    totals = report.get("metrics", {}).get("_totals", {})
    return {
        "complete": not invalid and not unclassified and not stale,
        "scanner_exit_semantics": "Bandit may exit nonzero when classified findings remain.",
        "severity_counts": {
            "low": int(totals.get("SEVERITY.LOW", 0)),
            "medium": int(totals.get("SEVERITY.MEDIUM", 0)),
            "high": int(totals.get("SEVERITY.HIGH", 0)),
        },
        "medium_or_high_count": len(current),
        "classified_count": len(dispositions),
        "unclassified": unclassified,
        "stale_classifications": stale,
        "invalid_classifications": invalid,
        "dispositions": dispositions,
        "bandit_clean": len(current) == 0,
    }


def _finding_key(test_id: str, filename: str, line_number: int) -> str:
    path = Path(filename)
    resolved = path.resolve(strict=False)
    if resolved.is_relative_to(ROOT):
        path = resolved.relative_to(ROOT)
    return f"{test_id}|{path.as_posix()}:{line_number}"


def _check(
    name: str,
    status: str,
    *,
    reason: str | None = None,
    command: list[str] | None = None,
    returncode: int | None = None,
    elapsed_wall_seconds: float | None = None,
    stdout: str | None = None,
    stderr: str | None = None,
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if status not in ALLOWED_STATUSES:
        raise ValueError(f"unsupported release-gate status: {status}")
    result: dict[str, Any] = {"name": name, "status": status}
    if reason is not None:
        result["reason"] = reason
    if command is not None:
        result["command"] = command
    if returncode is not None:
        result["returncode"] = returncode
    if elapsed_wall_seconds is not None:
        result["elapsed_wall_seconds"] = elapsed_wall_seconds
    if stdout:
        result["stdout"] = stdout
    if stderr:
        result["stderr"] = stderr
    if details is not None:
        result["details"] = details
    return result


def _truncate(value: str | bytes | None) -> str:
    if value is None:
        return ""
    text = value.decode(errors="replace") if isinstance(value, bytes) else value
    return text if len(text) <= OUTPUT_LIMIT else text[-OUTPUT_LIMIT:]


if __name__ == "__main__":
    raise SystemExit(main())
