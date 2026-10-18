"""Tests for A10: corrupt tasks.json causes graceful recovery, not crash."""

from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient

from apex_desktop.app import create_app
from apex_desktop.tasks import Tasks

TOKEN = "b" * 48  # min 32 chars


def _client(data_dir: Path) -> TestClient:
    return TestClient(
        create_app(data_dir, TOKEN),
        base_url="http://127.0.0.1",
        headers={"Authorization": f"Bearer {TOKEN}"},
    )


# ---------------------------------------------------------------------------
# create_app survives corrupt tasks.json
# ---------------------------------------------------------------------------


def test_corrupt_json_syntax_survives(tmp_path: Path) -> None:
    data = tmp_path / "data"
    data.mkdir()
    journal = data / "tasks.json"
    journal.write_text("{", encoding="utf-8")

    with _client(data) as client:
        resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["ok"] is True


def test_corrupt_json_non_list_survives(tmp_path: Path) -> None:
    data = tmp_path / "data"
    data.mkdir()
    journal = data / "tasks.json"
    journal.write_text('{"key": "value"}', encoding="utf-8")

    with _client(data) as client:
        resp = client.get("/health")
    assert resp.status_code == 200


def test_corrupt_item_missing_task_id_survives(tmp_path: Path) -> None:
    data = tmp_path / "data"
    data.mkdir()
    journal = data / "tasks.json"
    journal.write_text(
        json.dumps([{"status": "SUCCEEDED", "case_id": "x"}]),
        encoding="utf-8",
    )

    with _client(data) as client:
        resp = client.get("/health")
    assert resp.status_code == 200


def test_corrupt_item_non_dict_survives(tmp_path: Path) -> None:
    data = tmp_path / "data"
    data.mkdir()
    journal = data / "tasks.json"
    journal.write_text(json.dumps([1, 2, 3]), encoding="utf-8")

    with _client(data) as client:
        resp = client.get("/health")
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Corrupt file is preserved, not deleted
# ---------------------------------------------------------------------------


def test_corrupt_file_preserved_as_backup(tmp_path: Path) -> None:
    data = tmp_path / "data"
    data.mkdir()
    journal = data / "tasks.json"
    journal.write_text("{bad json", encoding="utf-8")

    with _client(data):
        pass

    # Original must be gone (renamed), a .corrupt-* backup must exist.
    assert not journal.exists()
    backups = list(data.glob("tasks.json.corrupt-*"))
    assert len(backups) == 1
    assert backups[0].read_text(encoding="utf-8") == "{bad json"


# ---------------------------------------------------------------------------
# Case DB accessible after corrupt journal recovery
# ---------------------------------------------------------------------------


def test_case_list_works_after_journal_recovery(tmp_path: Path) -> None:
    data = tmp_path / "data"
    data.mkdir()
    journal = data / "tasks.json"
    journal.write_text("{", encoding="utf-8")

    with _client(data) as client:
        resp = client.post(
            "/v1/operations/cases.list",
            json={},
        )
    assert resp.status_code == 200
    assert resp.json()["ok"] is True


# ---------------------------------------------------------------------------
# journal_recovered flag exposed on Tasks object
# ---------------------------------------------------------------------------


def test_tasks_journal_recovered_flag_set(tmp_path: Path) -> None:
    journal = tmp_path / "tasks.json"
    journal.write_text("[", encoding="utf-8")

    tasks = Tasks(tmp_path / "apex.db", journal)
    assert tasks.journal_recovered is True
    assert tasks.records == {}


def test_tasks_journal_recovered_flag_not_set_for_valid(tmp_path: Path) -> None:
    journal = tmp_path / "tasks.json"
    journal.write_text(
        json.dumps([
            {"task_id": "t1", "case_id": "c1", "kind": "FILES", "status": "SUCCEEDED",
             "job": None, "error": None, "actions": []}
        ]),
        encoding="utf-8",
    )

    tasks = Tasks(tmp_path / "apex.db", journal)
    assert tasks.journal_recovered is False
    assert "t1" in tasks.records


# ---------------------------------------------------------------------------
# In-progress tasks become INTERRUPTED on normal reload
# ---------------------------------------------------------------------------


def test_running_tasks_become_interrupted_on_reload(tmp_path: Path) -> None:
    journal = tmp_path / "tasks.json"
    journal.write_text(
        json.dumps([
            {"task_id": "r1", "case_id": "c1", "kind": "FILES", "status": "RUNNING",
             "job": None, "error": None, "actions": []},
            {"task_id": "q1", "case_id": "c1", "kind": "FILES", "status": "QUEUED",
             "job": None, "error": None, "actions": []},
            {"task_id": "s1", "case_id": "c1", "kind": "FILES", "status": "SUCCEEDED",
             "job": None, "error": None, "actions": []},
        ]),
        encoding="utf-8",
    )

    tasks = Tasks(tmp_path / "apex.db", journal)
    assert tasks.records["r1"]["status"] == "INTERRUPTED"
    assert tasks.records["q1"]["status"] == "INTERRUPTED"
    assert tasks.records["s1"]["status"] == "SUCCEEDED"
    assert tasks.journal_recovered is False


# ---------------------------------------------------------------------------
# case_id is a required field in journal items
# ---------------------------------------------------------------------------


def test_corrupt_item_missing_case_id_survives(tmp_path: Path) -> None:
    journal = tmp_path / "tasks.json"
    journal.write_text(
        json.dumps([{"task_id": "t1", "status": "SUCCEEDED"}]),
        encoding="utf-8",
    )

    tasks = Tasks(tmp_path / "apex.db", journal)
    assert tasks.journal_recovered is True
    assert tasks.records == {}


def test_corrupt_item_null_case_id_survives(tmp_path: Path) -> None:
    journal = tmp_path / "tasks.json"
    journal.write_text(
        json.dumps([{"task_id": "t1", "status": "SUCCEEDED", "case_id": None}]),
        encoding="utf-8",
    )

    tasks = Tasks(tmp_path / "apex.db", journal)
    assert tasks.journal_recovered is True


def test_corrupt_item_empty_case_id_survives(tmp_path: Path) -> None:
    journal = tmp_path / "tasks.json"
    journal.write_text(
        json.dumps([{"task_id": "t1", "status": "SUCCEEDED", "case_id": "   "}]),
        encoding="utf-8",
    )

    tasks = Tasks(tmp_path / "apex.db", journal)
    assert tasks.journal_recovered is True


# ---------------------------------------------------------------------------
# journal_recovered flag exposed in /health endpoint
# ---------------------------------------------------------------------------


def test_health_exposes_journal_recovered_false(tmp_path: Path) -> None:
    data = tmp_path / "data"
    data.mkdir()

    with _client(data) as client:
        resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["data"]["journal_recovered"] is False


def test_health_exposes_journal_recovered_true_after_corruption(tmp_path: Path) -> None:
    data = tmp_path / "data"
    data.mkdir()
    (data / "tasks.json").write_text("{bad json", encoding="utf-8")

    with _client(data) as client:
        resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["data"]["journal_recovered"] is True
