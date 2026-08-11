from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from apex_forensic.config import build_services
from apex_forensic.domain.errors import PersistenceError


def test_corrupt_case_database_returns_structured_non_retryable_error(tmp_path: Path) -> None:
    database = tmp_path / "corrupt.db"
    database.write_bytes(b"not a sqlite database")

    with pytest.raises(PersistenceError) as raised:
        build_services(database)

    assert raised.value.code == "DATABASE_CORRUPT"
    assert raised.value.retryable is False
    serialized = raised.value.to_api_error()
    assert serialized["target"] == "database"
    assert str(database) not in str(serialized)


def test_writer_contention_returns_structured_retryable_error_without_sleep(
    tmp_path: Path,
) -> None:
    database = tmp_path / "contention.db"
    services = build_services(database)
    competing_writer = sqlite3.connect(database, isolation_level=None)
    try:
        services.repository.connection.commit()
        services.repository.connection.execute("PRAGMA busy_timeout = 0")
        competing_writer.execute("BEGIN IMMEDIATE")

        with pytest.raises(PersistenceError) as raised:
            services.cases.create_case(name="contended")

        assert raised.value.code == "DATABASE_LOCKED"
        assert raised.value.retryable is True
        assert raised.value.details["sqlite_error_name"] == "SQLITE_BUSY"
    finally:
        competing_writer.rollback()
        competing_writer.close()
        services.close()


def test_failed_contended_write_rolls_back_and_next_write_succeeds(tmp_path: Path) -> None:
    database = tmp_path / "contention-recovery.db"
    services = build_services(database)
    competing_writer = sqlite3.connect(database, isolation_level=None)
    try:
        services.repository.connection.commit()
        services.repository.connection.execute("PRAGMA busy_timeout = 0")
        competing_writer.execute("BEGIN IMMEDIATE")
        with pytest.raises(PersistenceError):
            services.cases.create_case(name="interrupted")
        competing_writer.rollback()

        recovered = services.cases.create_case(name="recovered")

        assert recovered.name == "recovered"
        assert [item.name for item in services.cases.list_cases()] == ["recovered"]
    finally:
        competing_writer.close()
        services.close()
