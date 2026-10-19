"""Task admission must not leave unexecutable work after persistence failure."""

import json

import pytest

from apex_desktop.tasks import Tasks


def test_journal_write_failure_does_not_fill_queue(tmp_path, monkeypatch):
    tasks = Tasks(tmp_path / "apex.db", tmp_path / "tasks.json")

    def fail_save():
        raise OSError("simulated disk full")

    monkeypatch.setattr(tasks, "_save", fail_save)
    try:
        for _ in range(17):
            with pytest.raises(OSError, match="disk full"):
                tasks.start("case", "OCR", lambda *_: pytest.fail("must not execute"))
            assert tasks.list("case") == []
            assert tasks.tokens == {}
    finally:
        tasks.close()


def test_closed_executor_does_not_leave_a_persisted_queued_task(tmp_path):
    journal = tmp_path / "tasks.json"
    tasks = Tasks(tmp_path / "apex.db", journal)
    tasks.close()
    with pytest.raises(RuntimeError):
        tasks.start("case", "OCR", lambda *_: pytest.fail("must not execute"))
    assert tasks.list("case") == []
    assert tasks.tokens == {}
    assert json.loads(journal.read_text()) == []
