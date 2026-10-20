"""BE-02: a finished task whose receipt cannot be written must say so, then recover."""

import json
from pathlib import Path
from time import monotonic, sleep

from apex_desktop.tasks import Tasks
from apex_forensic.config import build_services


def wait_done(tasks: Tasks, case_id: str, task_id: str) -> dict:
    deadline = monotonic() + 15
    while monotonic() < deadline:
        record = next(r for r in tasks.list(case_id) if r["task_id"] == task_id)
        if record["status"] not in {"QUEUED", "RUNNING", "CANCELLING"} and not record["actions"]:
            return record
        sleep(0.02)
    raise AssertionError("task did not finish")


def test_completed_task_receipt_failure_must_be_visible(tmp_path, monkeypatch):
    database = tmp_path / "apex.db"
    build_services(database).close()
    journal = tmp_path / "tasks.json"
    tasks = Tasks(database, journal)
    output = tmp_path / "export.bin"
    output.write_bytes(b"derived")
    real_save = Tasks._save
    state = {"calls": 0, "fail": True}

    def flaky_save(self):
        state["calls"] += 1
        if state["calls"] >= 2 and state["fail"]:
            raise OSError(28, "No space left on device")
        return real_save(self)

    monkeypatch.setattr(Tasks, "_save", flaky_save)
    try:
        task = tasks.start("case", "STREAM_EXPORT", lambda _s, _t, _p: {"output_path": str(output)})
        record = wait_done(tasks, "case", task["task_id"])
        assert record["status"] == "SUCCEEDED"
        assert record["result"]["output_path"] == str(output)
        assert record["receipt_error"]["code"] == "TASK_RECEIPT_NOT_SAVED"
        assert json.loads(journal.read_text())[0]["status"] == "QUEUED"

        # Once the disk accepts writes again, listing persists the finished receipt.
        state["fail"] = False
        record = next(r for r in tasks.list("case") if r["task_id"] == task["task_id"])
        assert "receipt_error" not in record
        stored = json.loads(journal.read_text())[0]
        assert stored["status"] == "SUCCEEDED"
        assert stored["result"]["output_path"] == str(output)
        assert "receipt_error" not in stored
    finally:
        tasks.close()

    restarted = Tasks(database, journal)
    try:
        record = restarted.list("case")[0]
        assert record["status"] == "SUCCEEDED"
        assert Path(record["result"]["output_path"]) == output
    finally:
        restarted.close()
