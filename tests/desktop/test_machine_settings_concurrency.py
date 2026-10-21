"""Public settings remain consistent across simultaneous save/reset requests."""

import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier, Event

import pytest

from apex_desktop import machine

DEFAULTS = {
    "ocr_provider": "auto",
    "stt_provider": "faster-whisper",
    "stt_model_path": None,
    "tessdata_path": None,
}


@pytest.fixture(autouse=True)
def isolated(monkeypatch):
    monkeypatch.delenv("APEX_DESKTOP_MACHINE_CONFIG", raising=False)
    # Provider discovery is unrelated to filesystem transactions.
    monkeypatch.setattr(
        machine,
        "_capabilities",
        lambda root: {
            "settings": machine.config(root),
            "settings_error": None,
        },
    )


def test_missing_and_bom_json_are_valid(tmp_path):
    assert machine.load_settings(tmp_path) == (DEFAULTS, None)
    (tmp_path / machine.SETTINGS_FILE).write_bytes(b"\xef\xbb\xbf{}")
    assert machine.load_settings(tmp_path) == (DEFAULTS, None)


@pytest.mark.parametrize("raw", ["", " ", "\n\t"])
def test_blank_environment_is_diagnosed_and_cannot_be_overwritten(tmp_path, monkeypatch, raw):
    monkeypatch.setenv("APEX_DESKTOP_MACHINE_CONFIG", raw)
    error = machine.load_settings(tmp_path)[1]
    assert error["reason"] == "EMPTY"
    assert error["source"] == "ENVIRONMENT" and not error["resettable"]
    with pytest.raises(Exception, match="MACHINE_SETTINGS_MANAGED"):
        machine.save_config(tmp_path, DEFAULTS)


def test_simultaneous_saves_each_return_their_own_published_settings(tmp_path, monkeypatch):
    barrier = Barrier(2)
    actual_fsync = machine.os.fsync

    def sync(fd):
        actual_fsync(fd)
        barrier.wait(timeout=5)

    monkeypatch.setattr(machine.os, "fsync", sync)
    values = [{**DEFAULTS, "ocr_provider": name} for name in ("rapidocr", "tesseract")]
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(machine.save_config, tmp_path, value) for value in values]
        responses = [f.result(timeout=10) for f in futures]
    assert [r["settings"] for r in responses] == values
    assert json.loads((tmp_path / machine.SETTINGS_FILE).read_text()) in values
    assert not list(tmp_path.glob("*.tmp"))


def test_reset_waits_for_save_publication_and_preserves_its_bytes(tmp_path, monkeypatch):
    publishing, release, resetting = Event(), Event(), Event()
    actual_replace = Path.replace
    values = {**DEFAULTS, "ocr_provider": "rapidocr"}

    def replace(path, target):
        if path.suffix == ".tmp":
            publishing.set()
            assert release.wait(5)
        return actual_replace(path, target)

    def reset():
        resetting.set()
        return machine.reset_config(tmp_path)

    monkeypatch.setattr(Path, "replace", replace)
    with ThreadPoolExecutor(max_workers=2) as pool:
        saved = pool.submit(machine.save_config, tmp_path, values)
        try:
            assert publishing.wait(5)
            reset_future = pool.submit(reset)
            assert resetting.wait(5)
            assert not reset_future.done()
        finally:
            release.set()
        assert saved.result(timeout=5)["settings"] == values
        result = reset_future.result(timeout=5)
    assert result["settings"] == DEFAULTS
    assert json.loads((tmp_path / result["preserved_settings_file"]).read_text()) == values
    assert not (tmp_path / machine.SETTINGS_FILE).exists()


@pytest.mark.parametrize("existing", [b'{"ocr_provider":"auto"}', b"{broken"])
def test_failed_publish_keeps_original_or_backup_and_cleans_own_temp(
    tmp_path, monkeypatch, existing
):
    path = tmp_path / machine.SETTINGS_FILE
    path.write_bytes(existing)
    actual_replace = Path.replace

    def fail_publish(source, target):
        if source.suffix == ".tmp":
            raise OSError("synthetic replace failure")
        return actual_replace(source, target)

    monkeypatch.setattr(Path, "replace", fail_publish)
    with pytest.raises(OSError, match="replace failure"):
        machine.save_config(tmp_path, DEFAULTS)
    assert path.read_bytes() == existing
    if existing == b"{broken":
        assert machine.load_settings(tmp_path)[1]["reason"] == "JSON_SYNTAX"
        assert next(tmp_path.glob("machine-settings.invalid-*.json")).read_bytes() == existing
    assert not list(tmp_path.glob("*.tmp"))
