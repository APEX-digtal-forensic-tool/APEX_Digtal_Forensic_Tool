from __future__ import annotations

import json
import platform
import subprocess
import sys
from pathlib import Path

from apex_forensic.runtime.capabilities import AVAILABLE, capability_report


def test_doctor_reports_required_capability_matrix_without_secrets(
    project_root: Path,
    cli_env: dict[str, str],
) -> None:
    env = cli_env | {
        "APEX_AI_VERIFY_BASE_URL": "https://example.invalid/v1",
        "APEX_AI_VERIFY_MODEL": "fixture-model",
        "APEX_AI_VERIFY_API_KEY_ENV": "APEX_DOCTOR_PRIVATE_KEY_NAME",
        "APEX_DOCTOR_PRIVATE_KEY_NAME": "doctor-secret-value",
    }
    completed = subprocess.run(
        [sys.executable, "-m", "apex_forensic", "doctor", "--json"],
        check=False,
        capture_output=True,
        text=True,
        env=env,
        cwd=project_root,
    )

    assert completed.returncode == 0, completed.stderr
    payload = json.loads(completed.stdout)
    serialized = json.dumps(payload, ensure_ascii=False)
    capability_ids = {item["id"] for item in payload["capabilities"]}
    assert {
        "python",
        "sqlite",
        "sqlite-fts5",
        "pytsk3",
        "e01-libewf",
        "vhd-libvhdi",
        "vhdx-qemu-img",
        "registry-parser",
        "event-log-parser",
        "prefetch-parser",
        "prefetch-mam",
        "windows-event-message-renderer",
        "pillow",
        "ffmpeg",
        "ffprobe",
        "rapidocr",
        "onnx-runtime",
        "faster-whisper",
        "firefox-nss",
        "dpapi-impacket",
        "html-renderer",
        "pdf-renderer",
        "ai-provider-openai-compatible",
        "kakaotalk-existing",
    }.issubset(capability_ids)
    assert "doctor-secret-value" not in serialized
    assert "APEX_DOCTOR_PRIVATE_KEY_NAME" not in serialized
    assert payload["summary"]["secret_values_emitted"] is False
    assert payload["summary"]["environment_names_emitted"] is False


def test_doctor_performs_sqlite_and_fts5_runtime_queries() -> None:
    capabilities = {item["id"]: item for item in capability_report()["capabilities"]}

    assert capabilities["sqlite"]["status"] == AVAILABLE
    assert capabilities["sqlite"]["probe"] == "IN_MEMORY_QUERY"
    assert capabilities["sqlite-fts5"]["status"] == AVAILABLE
    assert capabilities["sqlite-fts5"]["probe"] == "IN_MEMORY_FTS5_QUERY"
    if platform.system() != "Windows":
        assert capabilities["windows-event-message-renderer"]["status"] == (
            "HOST_VERIFICATION_REQUIRED"
        )
