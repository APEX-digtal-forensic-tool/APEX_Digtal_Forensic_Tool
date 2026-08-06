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
_SECRET_ENV_FLAGS = {
    "--api-key-env",
    "--dpapi-password-env",
    "--dpapi-nt-hash-hex-env",
    "--dpapi-nt-hash-b64-env",
    "--dpapi-masterkey-hex-env",
    "--dpapi-masterkey-b64-env",
    "--dpapi-key-hex-env",
    "--dpapi-key-b64-env",
    "--nss-primary-password-env",
    "--kakaotalk-pragma-key-env",
    "--kakaotalk-user-nonce-env",
    "--kakaotalk-db-key-hex-env",
    "--kakaotalk-db-iv-hex-env",
}

_EPILOG = """
Windows fixture policy:
  Use synthetic or legally redistributable fixtures only. Do not pass paths from the
  current user's live DPAPI, browser, Firefox, or KakaoTalk profile. Child verifiers
  reject known live profile roots before reading fixture contents.

PowerShell setup outside the repository:
  py -3.11 -m venv "$env:TEMP\\apex-advanced-runtime-venv"
  & "$env:TEMP\\apex-advanced-runtime-venv\\Scripts\\python.exe" -m pip install -e `
    ".[advanced-secrets,browser-media,machine-extraction,report-renderer]"

PowerShell DPAPI/NSS host smoke:
  $py = "$env:TEMP\\apex-advanced-runtime-venv\\Scripts\\python.exe"
  $env:APEX_DPAPI_FIXTURE_PASSWORD = "<synthetic-fixture-password>"
  $env:APEX_NSS_PRIMARY_PASSWORD = "<synthetic-fixture-primary-password>"
  & $py tools\\verify_windows_host_runtime.py `
    --python $py `
    --dpapi-input-file C:\\apex-fixtures\\dpapi\\blob.bin `
    --dpapi-local-state-path "C:\\apex-fixtures\\dpapi\\Local State" `
    --dpapi-decrypt-local-state-key `
    --dpapi-sid S-1-5-21-1111111111-2222222222-3333333333-1001 `
    --dpapi-masterkey-path C:\\apex-fixtures\\dpapi\\Protect\\masterkey.bin `
    --dpapi-password-env APEX_DPAPI_FIXTURE_PASSWORD `
    --nss-root-path C:\\apex-fixtures\\firefox `
    --nss-profile-path C:\\apex-fixtures\\firefox\\Profiles\\verify.default `
    --nss-primary-password-env APEX_NSS_PRIMARY_PASSWORD

DPAPI fixture manifest fields:
  fixture_id, source, license, sid, masterkey_path, input_file, local_state_path,
  algorithm, expected_plaintext_sha256, expected_key_source, version.

NSS fixture manifest fields:
  fixture_id, source, license, profile_path, key4_db_path, logins_json_path,
  primary_password_required, expected_login_count, expected_plaintext_sha256, version.
"""


@dataclass(frozen=True, slots=True)
class Probe:
    name: str
    command: list[str]
    requires_windows: bool = False
    requires_secret: bool = False
    fixture_configured: bool = True


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify advanced APEX runtimes on a Windows forensic host.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=_EPILOG,
    )
    parser.add_argument("--python", default=sys.executable)
    parser.add_argument("--timeout", type=float, default=120.0)
    parser.add_argument(
        "--skip-execution",
        action="store_true",
        help="Only print the host/probe matrix; do not execute verifier scripts.",
    )
    parser.add_argument("--dpapi-input-file")
    parser.add_argument("--dpapi-local-state-path")
    parser.add_argument("--dpapi-decrypt-local-state-key", action="store_true")
    parser.add_argument("--dpapi-chromium-input-file")
    parser.add_argument("--dpapi-sid")
    parser.add_argument("--dpapi-masterkey-path")
    parser.add_argument("--dpapi-password-env")
    parser.add_argument("--dpapi-nt-hash-hex-env")
    parser.add_argument("--dpapi-nt-hash-b64-env")
    parser.add_argument("--dpapi-masterkey-hex-env")
    parser.add_argument("--dpapi-masterkey-b64-env")
    parser.add_argument("--dpapi-key-hex-env")
    parser.add_argument("--dpapi-key-b64-env")
    parser.add_argument("--nss-root-path")
    parser.add_argument("--nss-profile-path")
    parser.add_argument("--nss-primary-password-env")
    parser.add_argument("--kakaotalk-store-path")
    parser.add_argument("--kakaotalk-profile-root")
    parser.add_argument("--kakaotalk-pragma-key-env")
    parser.add_argument("--kakaotalk-user-nonce-env")
    parser.add_argument("--kakaotalk-db-key-hex-env")
    parser.add_argument("--kakaotalk-db-iv-hex-env")
    args = parser.parse_args()

    root = Path(__file__).resolve().parents[1]
    is_windows = platform.system().casefold() == "windows"
    probes = _probes(root, args.python, args)

    results: list[dict[str, Any]] = []
    for probe in probes:
        if args.skip_execution:
            results.append(_skipped_probe(probe, "SKIPPED_BY_REQUEST"))
            continue
        if probe.requires_windows and not is_windows:
            results.append(_skipped_probe(probe, "WINDOWS_HOST_REQUIRED"))
            continue
        if not probe.fixture_configured:
            results.append(_skipped_probe(probe, "EXTERNAL_FIXTURE_NOT_CONFIGURED"))
            continue
        if probe.requires_secret and not _ai_env_ready():
            results.append(_skipped_probe(probe, "EXTERNAL_PROVIDER_NOT_CONFIGURED"))
            continue
        results.append(_run_probe(probe, timeout=args.timeout, cwd=root))

    payload = {
        "host_platform": platform.platform(),
        "host_platform_status": "WINDOWS" if is_windows else "WINDOWS_HOST_REQUIRED",
        "python": args.python,
        "secret_values_emitted": False,
        "windows_runtime_success_claimed": is_windows
        and all(_probe_passed(results, name) for name in ("dpapi", "nss")),
        "windows_host_dpapi_nss_verified": is_windows
        and all(_probe_passed(results, name) for name in ("dpapi", "nss")),
        "probes": results,
    }
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 1 if any(item["status"] == "FAILED" for item in results) else 0


def _probes(root: Path, python_executable: str, args: argparse.Namespace) -> list[Probe]:
    def script(name: str) -> str:
        return str(root / "tools" / name)

    dpapi_command = [python_executable, script("verify_dpapi_runtime.py")]
    _append_option(dpapi_command, "--input-file", args.dpapi_input_file)
    _append_option(dpapi_command, "--local-state-path", args.dpapi_local_state_path)
    if args.dpapi_decrypt_local_state_key:
        dpapi_command.append("--decrypt-local-state-key")
    _append_option(dpapi_command, "--chromium-input-file", args.dpapi_chromium_input_file)
    _append_option(dpapi_command, "--sid", args.dpapi_sid)
    _append_option(dpapi_command, "--masterkey-path", args.dpapi_masterkey_path)
    _append_option(dpapi_command, "--password-env", args.dpapi_password_env)
    _append_option(dpapi_command, "--nt-hash-hex-env", args.dpapi_nt_hash_hex_env)
    _append_option(dpapi_command, "--nt-hash-b64-env", args.dpapi_nt_hash_b64_env)
    _append_option(dpapi_command, "--masterkey-hex-env", args.dpapi_masterkey_hex_env)
    _append_option(dpapi_command, "--masterkey-b64-env", args.dpapi_masterkey_b64_env)
    _append_option(dpapi_command, "--key-hex-env", args.dpapi_key_hex_env)
    _append_option(dpapi_command, "--key-b64-env", args.dpapi_key_b64_env)

    nss_command = [python_executable, script("verify_nss_runtime.py")]
    _append_option(nss_command, "--root-path", args.nss_root_path)
    _append_option(nss_command, "--profile-path", args.nss_profile_path)
    _append_option(nss_command, "--primary-password-env", args.nss_primary_password_env)

    kakaotalk_command = [python_executable, script("verify_kakaotalk_runtime.py")]
    _append_option(kakaotalk_command, "--store-path", args.kakaotalk_store_path)
    _append_option(kakaotalk_command, "--profile-root", args.kakaotalk_profile_root)
    _append_option(kakaotalk_command, "--pragma-key-env", args.kakaotalk_pragma_key_env)
    _append_option(kakaotalk_command, "--user-nonce-env", args.kakaotalk_user_nonce_env)
    _append_option(kakaotalk_command, "--db-key-hex-env", args.kakaotalk_db_key_hex_env)
    _append_option(kakaotalk_command, "--db-iv-hex-env", args.kakaotalk_db_iv_hex_env)

    probes = [
        Probe(
            "dpapi",
            dpapi_command,
            requires_windows=True,
            fixture_configured=_dpapi_fixture_configured(args),
        ),
        Probe(
            "nss",
            nss_command,
            requires_windows=True,
            fixture_configured=_nss_fixture_configured(args),
        ),
        Probe("kakaotalk", kakaotalk_command),
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


def _append_option(command: list[str], flag: str, value: str | None) -> None:
    if value:
        command.extend([flag, value])


def _dpapi_fixture_configured(args: argparse.Namespace) -> bool:
    return bool(
        args.dpapi_input_file
        or args.dpapi_local_state_path
        or args.dpapi_chromium_input_file
        or args.dpapi_masterkey_path
    )


def _nss_fixture_configured(args: argparse.Namespace) -> bool:
    return bool(args.nss_root_path or args.nss_profile_path)


def _ai_env_ready() -> bool:
    key_env = os.environ.get("APEX_AI_VERIFY_API_KEY_ENV")
    return bool(
        os.environ.get("APEX_AI_VERIFY_BASE_URL")
        and os.environ.get("APEX_AI_VERIFY_MODEL")
        and key_env
        and os.environ.get(key_env)
    )


def _probe_passed(results: list[dict[str, Any]], name: str) -> bool:
    return any(item["name"] == name and item["status"] == "PASSED" for item in results)


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
            redacted.append("<env-name>")
            redact_next = False
            continue
        redacted.append(item)
        if item in _SECRET_ENV_FLAGS:
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
