from __future__ import annotations

import argparse
import ctypes.util
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest


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
    assert "Synthetic fixture generation" in completed.stdout
    assert "Linux-generated NSS fixtures" in completed.stdout
    assert "run_windows_runtime_verification.ps1" in completed.stdout
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


def test_windows_runtime_fixture_generator_reports_missing_nss_encrypt_symbol(
    project_root: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    spec = importlib.util.spec_from_file_location(
        "generate_windows_runtime_fixtures_missing_encrypt",
        project_root / "tools" / "generate_windows_runtime_fixtures.py",
    )
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)

    attrs = {
        name: object()
        for name in module._NSS_REQUIRED_SYMBOLS
        if name != module.NSS_ENCRYPT_SYMBOL
    }
    fake_nss = type("FakeNss", (), attrs)()
    fixture_root = tmp_path / "fixtures"
    manifest_path = fixture_root / "manifest.json"
    monkeypatch.setattr(module.ctypes, "CDLL", lambda path: fake_nss)
    monkeypatch.setattr(
        module,
        "_generate_dpapi_fixture",
        lambda output_dir: module._unavailable_fixture(
            fixture_id=module.DPAPI_FIXTURE_ID,
            status="CAPABILITY_UNAVAILABLE",
            warning_code="DPAPI_TEST_SKIPPED",
            message="DPAPI generation skipped by synthetic unit test.",
        ),
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "generate_windows_runtime_fixtures.py",
            "--output-dir",
            str(fixture_root),
            "--manifest-path",
            str(manifest_path),
            "--nss-library-path",
            "nss3.dll",
            "--require-nss",
            "--json",
        ],
    )

    assert module.main() == 1

    summary = json.loads(capsys.readouterr().out)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert summary["nss_status"] == "NSS_ENCRYPT_SYMBOL_UNAVAILABLE"
    assert manifest["nss"]["status"] == "NSS_ENCRYPT_SYMBOL_UNAVAILABLE"
    assert manifest["nss"]["warnings"][0]["code"] == "NSS_ENCRYPT_SYMBOL_UNAVAILABLE"
    assert module.NSS_ENCRYPT_SYMBOL in manifest["nss"]["warnings"][0]["details"][
        "missing_symbols"
    ]
    assert manifest["verification_flows"]["linux_generated_nss_windows_decrypt_supported"] is True
    assert not (fixture_root / "firefox").exists()


def test_windows_runtime_fixture_generator_creates_dpapi_fixture_and_manifest(
    project_root: Path,
    tmp_path: Path,
    cli_env: dict[str, str],
) -> None:
    pytest.importorskip("impacket.dpapi")
    pytest.importorskip("Cryptodome")
    pytest.importorskip("cryptography.hazmat.primitives.ciphers.aead")
    fixture_root = tmp_path / "fixtures"
    manifest_path = fixture_root / "manifest.json"

    generated = subprocess.run(
        [
            sys.executable,
            str(project_root / "tools" / "generate_windows_runtime_fixtures.py"),
            "--output-dir",
            str(fixture_root),
            "--manifest-path",
            str(manifest_path),
            "--require-dpapi",
            "--json",
        ],
        check=False,
        capture_output=True,
        env=cli_env,
        text=True,
    )

    assert generated.returncode == 0, generated.stderr
    summary = json.loads(generated.stdout)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert summary["dpapi_status"] == "GENERATED"
    assert manifest["secret_values_emitted"] is False
    assert manifest["dpapi"]["status"] == "GENERATED"
    assert manifest["dpapi"]["credential_env"] == "APEX_DPAPI_FIXTURE_PASSWORD"
    assert "apex synthetic dpapi fixture password v1" not in json.dumps(
        manifest,
        ensure_ascii=False,
    )

    env = cli_env | {"APEX_DPAPI_FIXTURE_PASSWORD": "apex synthetic dpapi fixture password v1"}
    verified = subprocess.run(
        [
            sys.executable,
            str(project_root / "tools" / "verify_dpapi_runtime.py"),
            "--input-file",
            manifest["dpapi"]["input_file"],
            "--local-state-path",
            manifest["dpapi"]["local_state_path"],
            "--decrypt-local-state-key",
            "--chromium-input-file",
            manifest["dpapi"]["chromium_input_file"],
            "--sid",
            manifest["dpapi"]["sid"],
            "--masterkey-path",
            manifest["dpapi"]["masterkey_path"],
            "--password-env",
            "APEX_DPAPI_FIXTURE_PASSWORD",
            "--require-available",
        ],
        check=False,
        capture_output=True,
        env=env,
        text=True,
    )

    assert verified.returncode == 0, verified.stderr
    payload = json.loads(verified.stdout)
    expected = manifest["dpapi"]["expected_redacted_result"]
    assert payload["decrypt"]["status"] == "DECRYPTED"
    assert payload["decrypt"]["content_sha256"] == expected["dpapi_blob"]["content_sha256"]
    assert payload["local_state_decrypt"]["content_sha256"] == (
        expected["chromium_local_state_key"]["content_sha256"]
    )
    assert payload["chromium_decrypt"]["content_sha256"] == (
        expected["chromium_secret"]["content_sha256"]
    )
    serialized = json.dumps(payload, ensure_ascii=False)
    assert "plaintext_b64" not in serialized
    assert "APEX synthetic DPAPI runtime secret" not in serialized


def test_windows_runtime_fixture_generator_creates_nss_fixture_when_nss_is_available(
    project_root: Path,
    tmp_path: Path,
    cli_env: dict[str, str],
) -> None:
    if ctypes.util.find_library("nss3") is None:
        pytest.skip("libnss3 is required for NSS runtime fixture generation")
    fixture_root = tmp_path / "fixtures"
    manifest_path = fixture_root / "manifest.json"

    generated = subprocess.run(
        [
            sys.executable,
            str(project_root / "tools" / "generate_windows_runtime_fixtures.py"),
            "--output-dir",
            str(fixture_root),
            "--manifest-path",
            str(manifest_path),
            "--require-nss",
            "--json",
        ],
        check=False,
        capture_output=True,
        env=cli_env,
        text=True,
    )

    assert generated.returncode == 0, generated.stderr
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["nss"]["status"] == "GENERATED"
    assert manifest["nss"]["primary_password_env"] == "APEX_NSS_PRIMARY_PASSWORD"
    assert manifest["nss"]["generation_method"] == "NSS_PK11SDR_ENCRYPT_SYMBOL"
    assert manifest["nss"]["profile_path_relative"] == "firefox/Profiles/verify.default"
    assert manifest["nss"]["linux_generated_windows_decrypt_supported"] is True
    assert "apex synthetic nss primary password v1" not in json.dumps(
        manifest,
        ensure_ascii=False,
    )

    env = cli_env | {"APEX_NSS_PRIMARY_PASSWORD": "apex synthetic nss primary password v1"}
    verified = subprocess.run(
        [
            sys.executable,
            str(project_root / "tools" / "verify_nss_runtime.py"),
            "--root-path",
            manifest["nss"]["root_path"],
            "--profile-path",
            manifest["nss"]["profile_path"],
            "--primary-password-env",
            "APEX_NSS_PRIMARY_PASSWORD",
            "--require-available",
        ],
        check=False,
        capture_output=True,
        env=env,
        text=True,
    )

    assert verified.returncode == 0, verified.stderr
    payload = json.loads(verified.stdout)
    assert payload["profiles"][0]["status"] == "PRIMARY_PASSWORD_REQUIRED"
    assert payload["decrypt"][0]["status"] == "NSS_DECRYPTED"
    assert len(payload["decrypt"]) == manifest["nss"]["expected_login_count"]
    serialized = json.dumps(payload, ensure_ascii=False)
    assert "plaintext_b64" not in serialized
    assert "APEX synthetic Firefox NSS login secret" not in serialized


def test_windows_host_manifest_prefers_manifest_relative_fixture_paths(
    project_root: Path,
    tmp_path: Path,
) -> None:
    spec = importlib.util.spec_from_file_location(
        "verify_windows_host_runtime_relative_manifest",
        project_root / "tools" / "verify_windows_host_runtime.py",
    )
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)

    fixture_root = tmp_path / "copied-fixtures"
    manifest_path = fixture_root / "manifest.json"
    fixture_root.mkdir()
    manifest_path.write_text(
        json.dumps(
            {
                "nss": {
                    "status": "GENERATED",
                    "root_path": "Z:/linux-generated/firefox",
                    "root_path_relative": "firefox",
                    "profile_path": "Z:/linux-generated/firefox/Profiles/verify.default",
                    "profile_path_relative": "firefox/Profiles/verify.default",
                    "primary_password_env": "APEX_NSS_PRIMARY_PASSWORD",
                }
            }
        ),
        encoding="utf-8",
    )
    args = argparse.Namespace(
        nss_root_path=None,
        nss_profile_path=None,
        nss_primary_password_env=None,
    )

    module._apply_fixture_manifest(args, manifest_path)

    assert args.nss_root_path == str((fixture_root / "firefox").resolve(strict=False))
    assert args.nss_profile_path == str(
        (fixture_root / "firefox" / "Profiles" / "verify.default").resolve(strict=False)
    )
    assert args.nss_primary_password_env == "APEX_NSS_PRIMARY_PASSWORD"


def test_windows_host_runtime_verifier_loads_generated_fixture_manifest(
    project_root: Path,
    tmp_path: Path,
    cli_env: dict[str, str],
) -> None:
    pytest.importorskip("impacket.dpapi")
    pytest.importorskip("Cryptodome")
    pytest.importorskip("cryptography.hazmat.primitives.ciphers.aead")
    fixture_root = tmp_path / "fixtures"
    manifest_path = fixture_root / "manifest.json"
    generated = subprocess.run(
        [
            sys.executable,
            str(project_root / "tools" / "generate_windows_runtime_fixtures.py"),
            "--output-dir",
            str(fixture_root),
            "--manifest-path",
            str(manifest_path),
            "--require-dpapi",
            "--json",
        ],
        check=False,
        capture_output=True,
        env=cli_env,
        text=True,
    )
    assert generated.returncode == 0, generated.stderr
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    completed = subprocess.run(
        [
            sys.executable,
            str(project_root / "tools" / "verify_windows_host_runtime.py"),
            "--fixture-manifest",
            str(manifest_path),
            "--skip-execution",
        ],
        check=False,
        capture_output=True,
        env=cli_env,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
    payload = json.loads(completed.stdout)
    dpapi_probe = next(item for item in payload["probes"] if item["name"] == "dpapi")
    assert manifest["dpapi"]["input_file"] in dpapi_probe["command"]
    assert manifest["dpapi"]["masterkey_path"] in dpapi_probe["command"]
    assert "<env-name>" in dpapi_probe["command"]
    assert "APEX_DPAPI_FIXTURE_PASSWORD" not in dpapi_probe["command"]
    assert payload["windows_runtime_success_claimed"] is False


def test_ai_provider_host_gate_requires_all_env_and_actual_key(
    project_root: Path,
    monkeypatch,
) -> None:
    spec = importlib.util.spec_from_file_location(
        "verify_windows_host_runtime",
        project_root / "tools" / "verify_windows_host_runtime.py",
    )
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)

    for name in (
        "APEX_AI_VERIFY_BASE_URL",
        "APEX_AI_VERIFY_MODEL",
        "APEX_AI_VERIFY_API_KEY_ENV",
        "APEX_TEST_AI_PROVIDER_VERIFY_KEY",
    ):
        monkeypatch.delenv(name, raising=False)
    assert module._ai_env_ready() is False

    monkeypatch.setenv("APEX_AI_VERIFY_BASE_URL", "http://127.0.0.1:9")
    monkeypatch.setenv("APEX_AI_VERIFY_MODEL", "fixture-model")
    monkeypatch.setenv("APEX_AI_VERIFY_API_KEY_ENV", "APEX_TEST_AI_PROVIDER_VERIFY_KEY")
    assert module._ai_env_ready() is False

    monkeypatch.setenv("APEX_TEST_AI_PROVIDER_VERIFY_KEY", "synthetic-api-key")
    assert module._ai_env_ready() is True


def test_windows_runtime_powershell_runner_is_static_redacted_flow(project_root: Path) -> None:
    script = (project_root / "tools" / "run_windows_runtime_verification.ps1").read_text(
        encoding="utf-8"
    )

    assert "generate_windows_runtime_fixtures.py" in script
    assert "verify_dpapi_runtime.py" in script
    assert "verify_nss_runtime.py" in script
    assert "verify_windows_host_runtime.py" in script
    assert "FixtureManifestPath" in script
    assert "PREGENERATED_MANIFEST" in script
    assert "Resolve-ApexManifestPath" in script
    assert "ConvertTo-Json -Depth 80" in script
    assert "Remove-Item -LiteralPath $FixtureRoot -Recurse -Force" in script
    assert "APEX_AI_VERIFY_BASE_URL" in script
    assert "EXTERNAL_PROVIDER_NOT_CONFIGURED" in script
    assert "Write-Output $ResultPath" in script
    assert "Write-Output $env:APEX_DPAPI_FIXTURE_PASSWORD" not in script
    assert "Write-Output $env:APEX_NSS_PRIMARY_PASSWORD" not in script
