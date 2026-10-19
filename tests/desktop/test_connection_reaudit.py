"""Cross-layer regression cases found during the full workflow re-audit."""

import json
import re
from pathlib import Path
from types import SimpleNamespace

import pytest
from test_forensic_operations import registered
from test_local_api import TOKEN, call, wait
from test_local_api import client as api_client

from apex_desktop import machine
from apex_desktop.ai_content import redact_text
from apex_desktop.operations import MODELS
from apex_desktop.tasks import Tasks
from apex_forensic.adapters.machine_extraction.stt import local_model_available
from apex_forensic.domain.errors import ApexError

client = api_client


def test_electron_and_local_api_operation_contract():
    source = (Path(__file__).parents[2] / "frontend/electron/main.ts").read_text()
    block = source.split("const operations = new Set([", 1)[1].split("]);", 1)[0]
    assert set(re.findall(r'"([a-z.]+)"', block)) == set(MODELS)


def test_invalid_model_never_replaces_working_settings(tmp_path, monkeypatch):
    monkeypatch.delenv("APEX_DESKTOP_MACHINE_CONFIG", raising=False)
    settings = tmp_path / "machine-settings.json"
    settings.write_text('{"ocr_provider":"rapidocr"}')
    model = tmp_path / "incomplete"
    model.mkdir()
    (model / "model.bin").write_bytes(b"model")
    with pytest.raises(ApexError, match="STT_MODEL_INVALID"):
        machine.save_config(
            tmp_path, {"stt_provider": "faster-whisper", "stt_model_path": str(model)}
        )
    assert json.loads(settings.read_text()) == {"ocr_provider": "rapidocr"}
    (model / "config.json").write_text("{}")
    (model / "tokenizer.json").write_text("{}")
    (model / "vocabulary.json").mkdir()
    assert not local_model_available(model)
    (model / "vocabulary.json").rmdir()
    (model / "vocabulary.json").write_text('["word"]')
    assert local_model_available(model)
    (model / "tokenizer.json").write_text("invalid json")
    assert not local_model_available(model)


@pytest.mark.parametrize(
    "text,secret",
    [
        ('{"password": "SENSITIVE with spaces"}', "SENSITIVE"),
        ("{'api_key': 'SENSITIVE'}", "SENSITIVE"),
        ("Authorization: Bearer SENSITIVE", "SENSITIVE"),
        ("Authorization: Basic SENSITIVE", "SENSITIVE"),
        ('{"password": "SENSITIVE\\"hidden"}', "hidden"),
        ('{"refresh_token": "SENSITIVE', "SENSITIVE"),
    ],
)
def test_ai_excerpts_redact_quoted_secrets_headers_and_truncation(text, secret):
    assert secret not in redact_text(text)
    assert "[REDACTED]" in redact_text(text)


def test_safe_hash_field_is_not_treated_as_plaintext_secret():
    text = 'password_hash="safe-fingerprint"'
    assert redact_text(text) == text


def test_automatic_ocr_uses_available_korean_model(client, tmp_path, monkeypatch):
    source = tmp_path / "image.png"
    source.write_bytes(b"synthetic image")
    cid, eid = registered(client, source)
    node = call(client, "files.roots", case_id=cid, evidence_id=eid)[0]
    calls = []

    class Tesseract:
        def capabilities(self):
            return SimpleNamespace(metadata={"languages": ["eng"]})

        def analyze_image(self, *args, **kwargs):
            pytest.fail("English-only Tesseract must not receive Korean OCR")

    class Rapid:
        provider_id = "korean-fallback"
        provider_version = "1"

        def capabilities(self):
            return SimpleNamespace(is_available=True)

        def analyze_image(self, path, *, languages):
            calls.append(languages)
            return [{"text": "한글", "confidence": 0.9}]

    monkeypatch.setattr(machine, "providers", lambda root: (Tesseract(), None))
    monkeypatch.setattr(machine, "RapidOcrProvider", Rapid)
    result = wait(
        client,
        cid,
        call(
            client, "machine.run", case_id=cid, node_id=node["id"], kind="OCR", language="kor+eng"
        ),
    )
    assert result["result"]["candidate_count"] == 1
    assert calls == [["kor", "eng"]]


def test_output_receipt_survives_api_restart(client, tmp_path):
    from fastapi.testclient import TestClient

    from apex_desktop.app import create_app

    source = tmp_path / "source.dd"
    source.write_bytes(bytes(4096))
    cid, eid = registered(client, source)
    task = wait(
        client,
        cid,
        call(
            client,
            "evidence.carve",
            case_id=cid,
            evidence_id=eid,
            scope="IMAGE",
            formats=["PNG"],
            max_scan_bytes=512,
        ),
    )
    assert task["status"] == "PARTIAL"
    expected = task["result"]
    with TestClient(
        create_app(tmp_path / "data", TOKEN),
        base_url="http://127.0.0.1",
        headers={"Authorization": f"Bearer {TOKEN}"},
    ) as restarted:
        restored = next(
            t for t in call(restarted, "tasks.list", case_id=cid) if t["task_id"] == task["task_id"]
        )
        assert restored["result"]["next_offset"] == expected["next_offset"]
        assert restored["result"]["manifest_path"] == expected["manifest_path"]
        assert Path(restored["result"]["manifest_path"]).exists()


@pytest.mark.parametrize(
    "invalid", [b"\xff\xfe", b'[{"task_id":[],"case_id":"c","status":"RUNNING"}]']
)
def test_malformed_journal_cannot_prevent_startup(tmp_path, invalid):
    journal = tmp_path / "tasks.json"
    journal.write_bytes(invalid)
    tasks = Tasks(tmp_path / "apex.db", journal)
    assert tasks.journal_recovered
    assert tasks.records == {}
    tasks.close()


def test_interrupted_tasks_have_no_stale_cancel_button(tmp_path):
    journal = tmp_path / "tasks.json"
    journal.write_text(
        json.dumps(
            [
                {
                    "task_id": "t",
                    "case_id": "c",
                    "kind": "STT",
                    "status": "RUNNING",
                    "actions": ["CANCEL"],
                }
            ]
        )
    )
    tasks = Tasks(tmp_path / "apex.db", journal)
    assert tasks.list("c")[0]["status"] == "INTERRUPTED"
    assert tasks.list("c")[0]["actions"] == []
    tasks.close()
