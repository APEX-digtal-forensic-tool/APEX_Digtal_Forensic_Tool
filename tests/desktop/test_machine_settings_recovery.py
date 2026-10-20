"""Unusable machine-settings.json is diagnosed and recoverable without touching case data."""

import json
from time import monotonic, sleep

import pytest
from test_forensic_operations import registered
from test_local_api import call
from test_local_api import client as api_client

client = api_client
DEFAULTS = {
    "ocr_provider": "auto",
    "stt_provider": "faster-whisper",
    "stt_model_path": None,
    "tessdata_path": None,
}


@pytest.fixture(autouse=True)
def unmanaged(monkeypatch):
    monkeypatch.delenv("APEX_DESKTOP_MACHINE_CONFIG", raising=False)


@pytest.mark.parametrize(
    "content,reason,fields",
    [
        (b"{broken", "JSON_SYNTAX", []),
        (
            b'{"stt_provider": 7, "unexpected": true}',
            "INVALID_FIELDS",
            ["stt_provider", "unexpected"],
        ),
        ('{"ocr_provider": "자동"}'.encode("utf-16"), "ENCODING", []),
        (b"[]", "NOT_OBJECT", []),
        (b"", "EMPTY", []),
        (b"\xef\xbb\xbf", "EMPTY", []),
        (b"  \n", "EMPTY", []),
    ],
)
def test_invalid_settings_are_diagnosed_and_reset_preserves_them(
    client, tmp_path, content, reason, fields
):
    root = tmp_path / "data"
    settings = root / "machine-settings.json"
    settings.write_bytes(content)
    cases_before = call(client, "cases.list")

    capabilities = call(client, "machine.capabilities")
    assert capabilities["settings"] == DEFAULTS
    assert capabilities["settings_error"] == {
        "code": "MACHINE_SETTINGS_INVALID",
        "reason": reason,
        "source": "FILE",
        "fields": fields,
        "resettable": True,
    }
    assert capabilities["ocr"] is None and capabilities["stt"] is None

    reset = call(client, "machine.reset")
    assert reset["settings_error"] is None
    assert reset["settings"] == DEFAULTS
    backup = root / reset["preserved_settings_file"]
    assert backup.name.startswith("machine-settings.invalid-")
    assert backup.read_bytes() == content
    assert not settings.exists()
    assert call(client, "cases.list") == cases_before


def test_invalid_settings_block_extraction_instead_of_running_defaults(client, tmp_path):
    source = tmp_path / "image.png"
    source.write_bytes(b"synthetic")
    cid, eid = registered(client, source)
    node = call(client, "files.roots", case_id=cid, evidence_id=eid)[0]
    (tmp_path / "data/machine-settings.json").write_text("{broken")
    task = call(client, "machine.run", case_id=cid, node_id=node["id"], kind="OCR")
    deadline = monotonic() + 15
    while monotonic() < deadline:
        record = next(
            r for r in call(client, "tasks.list", case_id=cid) if r["task_id"] == task["task_id"]
        )
        if record["status"] not in {"QUEUED", "RUNNING", "CANCELLING"}:
            break
        sleep(0.02)
    assert record["status"] == "FAILED"
    assert "MACHINE_SETTINGS_INVALID" in json.dumps(record)


def test_saving_over_invalid_settings_keeps_a_copy(client, tmp_path):
    root = tmp_path / "data"
    (root / "machine-settings.json").write_text("{broken")
    saved = call(client, "machine.configure", ocr_provider="rapidocr")
    assert saved["settings_error"] is None
    assert saved["settings"]["ocr_provider"] == "rapidocr"
    assert (root / saved["preserved_settings_file"]).read_text() == "{broken"
    again = call(client, "machine.configure", ocr_provider="auto")
    assert again["preserved_settings_file"] is None


def test_valid_settings_reset_keeps_previous_copy(client, tmp_path):
    root = tmp_path / "data"
    call(client, "machine.configure", ocr_provider="rapidocr")
    reset = call(client, "machine.reset")
    assert reset["settings"] == DEFAULTS
    preserved = root / reset["preserved_settings_file"]
    assert preserved.name.startswith("machine-settings.previous-")
    assert json.loads(preserved.read_text())["ocr_provider"] == "rapidocr"


def test_managed_invalid_settings_are_not_reset_from_the_ui(client, monkeypatch):
    monkeypatch.setenv("APEX_DESKTOP_MACHINE_CONFIG", '{"stt_provider": "other"}')
    capabilities = call(client, "machine.capabilities")
    assert capabilities["managed"] is True
    assert capabilities["settings_error"]["source"] == "ENVIRONMENT"
    assert capabilities["settings_error"]["resettable"] is False
    response = client.post("/v1/operations/machine.reset", json={})
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "MACHINE_SETTINGS_MANAGED"


def test_missing_settings_control_uses_defaults(client, tmp_path):
    assert not (tmp_path / "data/machine-settings.json").exists()
    capabilities = call(client, "machine.capabilities")
    assert capabilities["settings"] == DEFAULTS
    assert capabilities["settings_error"] is None


def test_concurrent_settings_saves_must_not_share_temporary_file(tmp_path, monkeypatch):
    import threading

    from apex_desktop import machine

    monkeypatch.setattr(machine, "capabilities", lambda root: {})
    real_mkstemp = machine.tempfile.mkstemp
    barrier = threading.Barrier(2)

    def overlapping(*args, **kwargs):
        result = real_mkstemp(*args, **kwargs)
        barrier.wait(timeout=5)  # both requests have created their temp file
        return result

    monkeypatch.setattr(machine.tempfile, "mkstemp", overlapping)
    errors = []

    def save(provider):
        try:
            machine.save_config(tmp_path, {**DEFAULTS, "ocr_provider": provider})
        except Exception as error:
            errors.append(error)

    threads = [threading.Thread(target=save, args=(p,)) for p in ("rapidocr", "tesseract")]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert errors == []
    stored = json.loads((tmp_path / "machine-settings.json").read_text())
    assert stored["ocr_provider"] in {"rapidocr", "tesseract"}
    assert list(tmp_path.glob("*.tmp")) == []
