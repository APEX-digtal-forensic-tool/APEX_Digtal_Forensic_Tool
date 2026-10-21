"""Receipt failure is visible independently from the real task outcome."""

import json
from unittest.mock import Mock

import pytest

from apex_desktop.tasks import Tasks
from apex_forensic.domain.errors import ApexError


@pytest.mark.parametrize("outcome", ["SUCCEEDED", "PARTIAL", "FAILED"])
def test_receipt_retry_never_reexecutes_work_and_survives_restart(
    tmp_path, services, monkeypatch, outcome
):
    journal = tmp_path / "tasks.json"
    tasks = Tasks(tmp_path / "apex.db", journal)
    actual_save = tasks._save
    writes = 0
    disk_full = True

    def save():
        nonlocal writes
        writes += 1
        if writes > 1 and disk_full:
            raise OSError("synthetic disk full")
        actual_save()

    def run(*_):
        if outcome == "FAILED":
            raise ApexError("SOURCE_FAILURE", "error.source_failure")
        return {"output_path": "derived.bin", "partial": outcome == "PARTIAL"}

    execute = Mock(side_effect=run)
    monkeypatch.setattr(tasks, "_save", save)
    tasks.start("case", "STREAM_EXPORT", execute)
    tasks.pool.shutdown(wait=True)
    try:
        row = tasks.list("case")[0]
        assert row["status"] == outcome
        assert row["receipt_error"]["code"] == "TASK_RECEIPT_NOT_SAVED"
        assert row["actions"] == [] and tasks.tokens == {}
        if outcome == "FAILED":
            assert row["error"]["code"] == "SOURCE_FAILURE"
        else:
            assert row["error"] is None and row["result"]["output_path"] == "derived.bin"
        for _ in range(5):
            tasks.list("case")
        tasks.list("other-case", retry_receipts=True)
        assert writes == 2  # polling and unrelated cases never retry writes
        failed_retry = tasks.list("case", retry_receipts=True)[0]
        assert failed_retry["receipt_error"] and writes == 3
        assert json.loads(journal.read_text())[0]["status"] == "QUEUED"
        disk_full = False
        repaired = tasks.list("case", retry_receipts=True)[0]
        assert "receipt_error" not in repaired
        assert repaired["status"] == outcome
        assert execute.call_count == 1
        restarted = Tasks(tmp_path / "apex.db", journal)
        try:
            loaded = restarted.list("case")[0]
            assert loaded["status"] == outcome and "receipt_error" not in loaded
            if outcome != "FAILED":
                assert loaded["result"]["output_path"] == "derived.bin"
        finally:
            restarted.close()
    finally:
        tasks.close()
