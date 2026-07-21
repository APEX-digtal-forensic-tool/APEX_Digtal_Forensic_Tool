from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path

import pytest

from apex_forensic.adapters.schema import JsonSchemaValidator
from apex_forensic.config import ServiceBundle, build_services


@pytest.fixture
def project_root() -> Path:
    return Path(__file__).resolve().parents[1]


@pytest.fixture
def schema_validator(project_root: Path) -> JsonSchemaValidator:
    return JsonSchemaValidator(project_root / "schemas" / "v1")


@pytest.fixture
def services(tmp_path: Path) -> Iterator[ServiceBundle]:
    bundle = build_services(tmp_path / "apex.db")
    try:
        yield bundle
    finally:
        bundle.close()


@pytest.fixture
def sample_file(tmp_path: Path) -> Path:
    path = tmp_path / "증거-파일.bin"
    path.write_bytes((b"apex-phase1\n" * 64) + "한글 경로".encode())
    return path


@pytest.fixture
def cli_env(project_root: Path) -> dict[str, str]:
    env = os.environ.copy()
    pythonpath = str(project_root / "src")
    if env.get("PYTHONPATH"):
        pythonpath = pythonpath + os.pathsep + env["PYTHONPATH"]
    env["PYTHONPATH"] = pythonpath
    return env
