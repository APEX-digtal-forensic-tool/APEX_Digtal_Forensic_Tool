"""Real offline media flow and pinned bundle safety regressions."""

import base64
import hashlib
import importlib.util
import json
import shutil
import subprocess
import zipfile
from pathlib import Path
from threading import Event

import httpx
import pytest
from test_forensic_operations import registered
from test_local_api import TOKEN, call
from test_local_api import client as api_client
from test_local_api import wait as wait_task

from apex_desktop import machine
from apex_forensic.config import build_services
from apex_forensic.runtime import assets

client = api_client


def test_reopening_services_is_read_only_even_with_another_writer(tmp_path):
    database = tmp_path / "case.db"
    initial = build_services(database)
    assert not initial.repository.connection.in_transaction
    assert initial.repository.list_engine_tool_descriptors()
    initial.repository.connection.execute("BEGIN IMMEDIATE")
    try:
        reader = build_services(database, initialize=False)
        try:
            assert not reader.repository.connection.in_transaction
            assert reader.repository.list_engine_tool_descriptors()
        finally:
            reader.close()
    finally:
        initial.repository.connection.rollback()
        initial.close()


def test_task_status_remains_readable_during_native_inference(client, tmp_path, monkeypatch):
    source = tmp_path / "audio.wav"
    source.write_bytes(b"synthetic audio; provider below does not decode it")
    cid, eid = registered(client, source)
    node = call(client, "files.roots", case_id=cid, evidence_id=eid)[0]
    entered, release = Event(), Event()

    def infer(services, **kwargs):
        assert not services.repository.connection.in_transaction
        entered.set()
        assert release.wait(timeout=15)
        return {"node_id": node["id"], "candidate_count": 0, "candidate_ids": []}

    monkeypatch.setattr(machine, "run", infer)
    task = call(client, "machine.run", case_id=cid, node_id=node["id"], kind="STT")
    try:
        assert entered.wait(timeout=10)
        rows = call(client, "tasks.list", case_id=cid)
        assert next(row for row in rows if row["task_id"] == task["task_id"])["status"] == "RUNNING"
        assert call(client, "cases.list")
    finally:
        release.set()
    wait_task(client, cid, task)


def builder():
    spec = importlib.util.spec_from_file_location(
        "prepare_assets", Path(__file__).parents[2] / "tools/prepare_desktop_assets.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_asset_integrity_failure_preserves_previous_file(tmp_path):
    destination = tmp_path / "model.bin"
    destination.write_bytes(b"old valid model")
    expected = {"size": 3, "sha256": hashlib.sha256(b"new").hexdigest()}
    transport = httpx.MockTransport(lambda _: httpx.Response(200, content=b"BAD"))
    with httpx.Client(transport=transport) as http, pytest.raises(ValueError, match="SHA-256"):
        builder().download(http, "https://example.test/model", destination, expected)
    assert destination.read_bytes() == b"old valid model"
    assert not destination.with_suffix(".bin.partial").exists()


def test_archive_traversal_is_rejected(tmp_path):
    archive = tmp_path / "archive.zip"
    with zipfile.ZipFile(archive, "w") as handle:
        handle.writestr("wrap/../../outside", b"bad")
    with pytest.raises(ValueError, match="Unsafe"):
        builder().extract_media(archive, tmp_path / "assets")
    assert not (tmp_path / "outside").exists()


def test_builtin_tools_win_over_path_and_are_not_downloaded(tmp_path, monkeypatch):
    monkeypatch.setattr(assets, "assets_root", lambda: tmp_path)
    monkeypatch.setattr(assets.sys, "platform", "win32")
    binary = tmp_path / "media/bin/ffmpeg.exe"
    binary.parent.mkdir(parents=True)
    binary.write_bytes(b"synthetic executable; never run")
    monkeypatch.setattr(assets.shutil, "which", lambda _: "PATH-tool")
    assert assets.media_executable("ffmpeg") == str(binary)
    assert assets.media_executable("ffprobe") == "PATH-tool"


def test_builtin_model_is_default_and_explicit_model_is_preserved(tmp_path, monkeypatch):
    monkeypatch.delenv("APEX_DESKTOP_MACHINE_CONFIG", raising=False)
    bundled = tmp_path / "bundled"
    custom = tmp_path / "custom"
    monkeypatch.setattr(machine, "bundled_stt_model", lambda: bundled)
    assert machine.providers(tmp_path)[1]._model_path == bundled
    (tmp_path / "machine-settings.json").write_text(json.dumps({"stt_model_path": str(custom)}))
    assert machine.providers(tmp_path)[1]._model_path == custom
    (tmp_path / "machine-settings.json").write_text('{"stt_provider":"whisper.cpp"}')
    assert machine.providers(tmp_path)[1]._model_path is None


def test_real_video_frame_http_case_boundary_and_original_hash(client, tmp_path):
    executable = assets.media_executable("ffmpeg")
    if not executable or not assets.media_executable("ffprobe"):
        pytest.skip("Media tools are verified by the Windows packaged runtime gate")
    source = tmp_path / "한국어 영상.mp4"
    subprocess.run(
        [
            executable,
            "-v",
            "error",
            "-f",
            "lavfi",
            "-i",
            "color=c=red:s=32x24:d=1:r=2",
            "-c:v",
            "mpeg4",
            str(source),
        ],
        check=True,
        timeout=20,
        capture_output=True,
    )
    before = hashlib.sha256(source.read_bytes()).hexdigest()
    cid, eid = registered(client, source)
    node = call(client, "files.roots", case_id=cid, evidence_id=eid)[0]
    args = {"case_id": cid, "resource_type": "FILE_SYSTEM_NODE", "resource_id": node["id"]}
    result = call(client, "media.video", **args, timestamp_seconds=0.5)
    assert result["source_sha256"] == before
    assert result["metadata"]["width"] == 32
    data = base64.b64decode(result["image_url"].split(",", 1)[1])
    assert data.startswith(b"\x89PNG")
    assert hashlib.sha256(data).hexdigest() == result["frame_sha256"]
    assert hashlib.sha256(source.read_bytes()).hexdigest() == before
    other = call(client, "cases.create", name="Other case")["id"]
    denied = client.post(
        "/v1/operations/media.video",
        json={**args, "case_id": other},
        headers={"Authorization": f"Bearer {TOKEN}"},
    ).json()
    assert not denied["ok"]
    beyond = client.post(
        "/v1/operations/media.video",
        json={**args, "timestamp_seconds": 100},
        headers={"Authorization": f"Bearer {TOKEN}"},
    ).json()
    assert not beyond["ok"]


def test_ffmpeg_rejects_evidence_playlists(tmp_path):
    if not shutil.which("ffmpeg"):
        pytest.skip("ffmpeg unavailable on this test host")
    from apex_forensic.adapters.artifacts.media import _ffmpeg_sample_frame

    playlist = tmp_path / "pretend.mp4"
    playlist.write_text("#EXTM3U\n#EXTINF:1,\nhttp://127.0.0.1:9/never-open\n")
    result = _ffmpeg_sample_frame(file_path=playlist, timestamp_seconds=0)
    assert result["status"] == "FAILED"
