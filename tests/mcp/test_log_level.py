"""Tests for Phase 14: --log-level wiring to Python logging module."""

from __future__ import annotations

import logging
from collections.abc import Iterator
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from apex_mcp.__main__ import main


@pytest.fixture
def _db(tmp_path: Path) -> Path:
    db = tmp_path / "test.db"
    db.touch()
    return db


@pytest.fixture(autouse=True)
def _restore_root_log_level() -> Iterator[None]:
    original = logging.root.level
    yield
    logging.root.setLevel(original)


def _run_main(db: Path, schema_dir: Path, log_level: str) -> int:
    mock_runtime = MagicMock()
    mock_runtime.run_stdio.return_value = None
    with patch("apex_mcp.__main__.create_runtime", return_value=mock_runtime):
        return main([
            "--database", str(db),
            "--schema-dir", str(schema_dir),
            "--log-level", log_level,
        ])


def test_log_level_debug_sets_root_logger(
    _db: Path, project_root: Path
) -> None:
    _run_main(_db, project_root / "schemas" / "v1", "DEBUG")
    assert logging.root.level == logging.DEBUG


def test_log_level_warning_sets_root_logger(
    _db: Path, project_root: Path
) -> None:
    _run_main(_db, project_root / "schemas" / "v1", "WARNING")
    assert logging.root.level == logging.WARNING


def test_log_level_debug_startup_log_captured(
    _db: Path, project_root: Path, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.DEBUG, logger="apex_mcp.__main__"):
        _run_main(_db, project_root / "schemas" / "v1", "DEBUG")

    assert any("apex-mcp starting" in r.message for r in caplog.records)


def test_log_level_warning_startup_log_hidden(
    _db: Path, project_root: Path, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.WARNING, logger="apex_mcp.__main__"):
        _run_main(_db, project_root / "schemas" / "v1", "WARNING")

    debug_records = [r for r in caplog.records if r.levelno == logging.DEBUG]
    assert len(debug_records) == 0
