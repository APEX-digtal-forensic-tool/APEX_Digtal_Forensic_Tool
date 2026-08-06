from __future__ import annotations

import json
import os
import subprocess
import sys


def test_windows_host_runtime_verifier_dry_run_reports_probe_matrix(project_root) -> None:
    completed = subprocess.run(
        [
            sys.executable,
            str(project_root / "tools" / "verify_windows_host_runtime.py"),
            "--skip-execution",
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0
    payload = json.loads(completed.stdout)
    assert payload["secret_values_emitted"] is False
    assert {item["name"] for item in payload["probes"]} == {
        "ai-provider",
        "dpapi",
        "kakaotalk",
        "nss",
        "ocr",
        "report-renderers",
        "stt",
    }
    assert {item["status"] for item in payload["probes"]} == {"SKIPPED_BY_REQUEST"}
    assert payload["windows_runtime_success_claimed"] is False
    assert payload["windows_host_dpapi_nss_verified"] is False


def test_windows_host_runtime_help_documents_fixture_contract(project_root) -> None:
    completed = subprocess.run(
        [
            sys.executable,
            str(project_root / "tools" / "verify_windows_host_runtime.py"),
            "--help",
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0
    assert "Windows fixture policy" in completed.stdout
    assert "DPAPI fixture manifest fields" in completed.stdout
    assert "NSS fixture manifest fields" in completed.stdout


def test_ai_provider_verifier_reports_external_provider_not_configured(
    project_root,
    monkeypatch,
) -> None:
    monkeypatch.delenv("APEX_TEST_AI_PROVIDER_VERIFY_KEY", raising=False)

    completed = subprocess.run(
        [
            sys.executable,
            str(project_root / "tools" / "verify_ai_provider.py"),
            "--base-url",
            "http://127.0.0.1:9",
            "--model",
            "fixture-model",
            "--api-key-env",
            "APEX_TEST_AI_PROVIDER_VERIFY_KEY",
            "--operation",
            "keywords",
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0
    payload = json.loads(completed.stdout)
    assert payload["verification_status"] == "EXTERNAL_PROVIDER_NOT_CONFIGURED"
    assert payload["execution"]["status"] == "KEY_UNAVAILABLE"
    assert payload["execution"]["request_fingerprint"] == "c" * 64
    assert payload["execution"]["result_fingerprint"] is None
    assert payload["repository_reopen"]["status"] == "VERIFIED"
    assert payload["repository_reopen"]["api_key_value_stored"] is False
    assert "keywords" not in payload
    assert payload["secret_values_emitted"] is False


def test_dpapi_verifier_rejects_live_user_profile_paths(
    project_root,
    tmp_path,
    monkeypatch,
) -> None:
    appdata = tmp_path / "AppData" / "Roaming"
    live_masterkey = appdata / "Microsoft" / "Protect" / "S-1-5-21-live" / "masterkey"
    monkeypatch.setenv("APPDATA", str(appdata))
    env = os.environ.copy()

    completed = subprocess.run(
        [
            sys.executable,
            str(project_root / "tools" / "verify_dpapi_runtime.py"),
            "--masterkey-path",
            str(live_masterkey),
        ],
        check=False,
        capture_output=True,
        env=env,
        text=True,
    )

    assert completed.returncode == 1
    payload = json.loads(completed.stdout)
    policy = payload["verification"]["fixture_policy"]
    assert payload["verification"]["status"] == "LIVE_USER_PROFILE_REJECTED"
    assert policy["live_user_profile_allowed"] is False
    assert policy["rejected_paths"][0]["reason"] == "LIVE_USER_PROFILE_PATH"


def test_nss_verifier_rejects_live_user_profile_paths(
    project_root,
    tmp_path,
    monkeypatch,
) -> None:
    appdata = tmp_path / "AppData" / "Roaming"
    live_profile = appdata / "Mozilla" / "Firefox" / "Profiles" / "live.default"
    monkeypatch.setenv("APPDATA", str(appdata))
    env = os.environ.copy()

    completed = subprocess.run(
        [
            sys.executable,
            str(project_root / "tools" / "verify_nss_runtime.py"),
            "--profile-path",
            str(live_profile),
        ],
        check=False,
        capture_output=True,
        env=env,
        text=True,
    )

    assert completed.returncode == 1
    payload = json.loads(completed.stdout)
    policy = payload["verification"]["fixture_policy"]
    assert payload["verification"]["status"] == "LIVE_USER_PROFILE_REJECTED"
    assert policy["synthetic_or_redistributable_fixture_required"] is True
    assert policy["rejected_paths"][0]["input"] == "profile_path"
