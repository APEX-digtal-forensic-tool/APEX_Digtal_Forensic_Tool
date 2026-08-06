from __future__ import annotations

import json
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
    assert "keywords" not in payload
    assert payload["secret_values_emitted"] is False
