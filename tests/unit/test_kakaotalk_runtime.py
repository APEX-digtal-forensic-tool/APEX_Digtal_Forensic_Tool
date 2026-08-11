from __future__ import annotations

import hashlib
import json
import sqlite3
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import padding as crypto_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from apex_forensic.adapters.decryption import kakaotalk as kakaotalk_runtime
from apex_forensic.adapters.decryption.kakaotalk import (
    MAX_KAKAOTALK_STORE_BYTES,
    KakaoTalkEncryptedStoreProvider,
)
from apex_forensic.domain.models import SecretDerivationInput


def _write_pe_version(path: Path, version: tuple[int, int, int, int]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    version_ms = (version[0] << 16) | version[1]
    version_ls = (version[2] << 16) | version[3]
    key = "VS_VERSION_INFO\x00".encode("utf-16-le")
    value_offset = (6 + len(key) + 3) & ~3
    version_blob = bytearray(value_offset + 52)
    struct.pack_into("<HHH", version_blob, 0, len(version_blob), 52, 0)
    version_blob[6 : 6 + len(key)] = key
    struct.pack_into(
        "<13I",
        version_blob,
        value_offset,
        0xFEEF04BD,
        0x00010000,
        version_ms,
        version_ls,
        version_ms,
        version_ls,
        0x3F,
        0,
        0x00040004,
        1,
        0,
        0,
        0,
    )

    data = bytearray(0x600)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\x00\x00"
    struct.pack_into("<HHIIIHH", data, 0x84, 0x14C, 1, 0, 0, 0, 224, 0x102)
    optional_offset = 0x98
    struct.pack_into("<H", data, optional_offset, 0x10B)
    struct.pack_into("<I", data, optional_offset + 92, 16)
    struct.pack_into("<II", data, optional_offset + 112, 0x1000, 0x400)
    section_offset = optional_offset + 224
    data[section_offset : section_offset + 8] = b".rsrc\x00\x00\x00"
    struct.pack_into("<IIII", data, section_offset + 8, 0x400, 0x1000, 0x400, 0x200)

    struct.pack_into("<IIHHHH", data, 0x200, 0, 0, 0, 0, 0, 1)
    struct.pack_into("<II", data, 0x210, 16, 0x80000020)
    struct.pack_into("<IIHHHH", data, 0x220, 0, 0, 0, 0, 0, 1)
    struct.pack_into("<II", data, 0x230, 1, 0x80000040)
    struct.pack_into("<IIHHHH", data, 0x240, 0, 0, 0, 0, 0, 1)
    struct.pack_into("<II", data, 0x250, 0x409, 0x60)
    struct.pack_into("<IIII", data, 0x260, 0x1080, len(version_blob), 0, 0)
    data[0x280 : 0x280 + len(version_blob)] = version_blob
    path.write_bytes(data)


def _write_encrypted_sqlite(
    tmp_path: Path,
    *,
    statements: tuple[str, ...],
) -> tuple[Path, bytes, bytes, bytes]:
    database = tmp_path / "plain.sqlite"
    with sqlite3.connect(database) as connection:
        for statement in statements:
            connection.execute(statement)
    plaintext = database.read_bytes()
    key = b"K" * 16
    iv = b"I" * 16
    padder = crypto_padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    store = tmp_path / "chatLogs_1.edb"
    store.write_bytes(encryptor.update(padded) + encryptor.finalize())
    return store, key, iv, plaintext


def _raw_derivation(key: bytes, iv: bytes, **overrides: str) -> SecretDerivationInput:
    parameters = {
        "platform": "WINDOWS_DESKTOP",
        "application_version": "2.0.8.990",
        "database_schema_version": "chatLogs",
        "db_key_hex": key.hex(),
        "db_iv_hex": iv.hex(),
        **overrides,
    }
    return SecretDerivationInput(
        case_id="case-1",
        evidence_id="ev-1",
        key_source_kind="KAKAOTALK_RAW_DB_KEY_IV",
        parameters=parameters,
    )


def test_kakaotalk_acquisition_requires_explicit_existing_root(tmp_path: Path) -> None:
    provider = KakaoTalkEncryptedStoreProvider()

    missing = provider.acquire_key_material(
        case_id="case-1", evidence_id="ev-1", profile_root=None
    )
    nonexistent = provider.acquire_key_material(
        case_id="case-1",
        evidence_id="ev-1",
        profile_root=str(tmp_path / "missing"),
    )
    empty = provider.acquire_key_material(
        case_id="case-1", evidence_id="ev-1", profile_root=str(tmp_path)
    )

    assert missing["status"] == "SOURCE_UNAVAILABLE"
    assert missing["reason"] == "KAKAOTALK_PROFILE_ROOT_REQUIRED"
    assert nonexistent["reason"] == "KAKAOTALK_PROFILE_ROOT_NOT_FOUND"
    assert empty["status"] == "SOURCE_UNAVAILABLE"
    assert empty["discovery_status"] == "EMPTY"
    assert empty["reason"] == "KAKAOTALK_ENCRYPTED_STORE_NOT_FOUND"


def test_kakaotalk_acquisition_rejects_unsupported_platform_before_discovery(
    tmp_path: Path,
) -> None:
    result = KakaoTalkEncryptedStoreProvider().acquire_key_material(
        case_id="case-1",
        evidence_id="ev-1",
        profile_root=str(tmp_path),
        platform="ANDROID",
    )

    assert result["status"] == "UNSUPPORTED_PLATFORM"
    assert result["discovery_status"] == "NOT_STARTED"


def test_kakaotalk_acquisition_verifies_supported_pe_but_remains_blocked(
    tmp_path: Path,
) -> None:
    _write_pe_version(tmp_path / "KakaoTalk.exe", (2, 0, 8, 990))
    (tmp_path / "chatLogs_7.edb").write_bytes(b"E" * 32)

    result = KakaoTalkEncryptedStoreProvider().acquire_key_material(
        case_id="case-1", evidence_id="ev-1", profile_root=str(tmp_path)
    )

    assert result["status"] == "BLOCKED_EXTERNAL_FIXTURE"
    assert result["version_status"] == "VERSION_VERIFIED"
    assert result["application_version"] == "2.0.8.990"
    assert result["key_material_status"] == "BLOCKED_EXTERNAL_FIXTURE"
    assert result["automatic_key_acquisition"] is False
    assert result["secret_values_emitted"] is False
    assert result["real_kakaotalk_fixture_verified"] is False


@pytest.mark.parametrize(
    ("version", "expected_status", "expected_reason"),
    [
        ((3, 0, 0, 0), "UNSUPPORTED_VERSION", "KAKAOTALK_UNSUPPORTED_VERSION"),
        (None, "VERSION_UNVERIFIED", "KAKAOTALK_VERSION_UNVERIFIED"),
    ],
)
def test_kakaotalk_acquisition_version_statuses(
    tmp_path: Path,
    version: tuple[int, int, int, int] | None,
    expected_status: str,
    expected_reason: str,
) -> None:
    executable = tmp_path / "KakaoTalk.exe"
    if version is None:
        executable.write_bytes(b"not-a-pe")
    else:
        _write_pe_version(executable, version)
    (tmp_path / "chatLogs_1.edb").write_bytes(b"E" * 16)

    result = KakaoTalkEncryptedStoreProvider().acquire_key_material(
        case_id="case-1", evidence_id="ev-1", profile_root=str(tmp_path)
    )

    assert result["status"] == expected_status
    assert result["reason"] == expected_reason


def test_kakaotalk_acquisition_rejects_ambiguous_versions(tmp_path: Path) -> None:
    _write_pe_version(tmp_path / "one" / "KakaoTalk.exe", (2, 0, 8, 990))
    _write_pe_version(tmp_path / "two" / "KakaoTalk.exe", (3, 0, 0, 0))
    (tmp_path / "chatLogs_1.edb").write_bytes(b"E" * 16)

    result = KakaoTalkEncryptedStoreProvider().acquire_key_material(
        case_id="case-1", evidence_id="ev-1", profile_root=str(tmp_path)
    )

    assert result["status"] == "VERSION_UNVERIFIED"
    assert result["reason"] == "KAKAOTALK_VERSION_AMBIGUOUS"


def test_kakaotalk_discovery_is_deterministic_and_does_not_mutate_evidence(
    tmp_path: Path,
) -> None:
    _write_pe_version(tmp_path / "install" / "KakaoTalk.exe", (2, 0, 8, 990))
    first = tmp_path / "users" / "b" / "chatLogs_2.edb"
    second = tmp_path / "users" / "a" / "chatLogs_1.edb"
    first.parent.mkdir(parents=True)
    second.parent.mkdir(parents=True)
    first.write_bytes(b"B" * 16)
    second.write_bytes(b"A" * 16)
    before = {
        path: (path.read_bytes(), path.stat().st_mtime_ns)
        for path in (first, second, tmp_path / "install" / "KakaoTalk.exe")
    }
    provider = KakaoTalkEncryptedStoreProvider()

    one = provider.acquire_key_material(
        case_id="case-1", evidence_id="ev-1", profile_root=str(tmp_path)
    )
    two = provider.acquire_key_material(
        case_id="case-1", evidence_id="ev-1", profile_root=str(tmp_path)
    )

    assert [item["relative_path"] for item in one["store_candidates"]] == [
        "users/a/chatLogs_1.edb",
        "users/b/chatLogs_2.edb",
    ]
    assert one["profile_fingerprint"] == two["profile_fingerprint"]
    for path, (contents, modified_ns) in before.items():
        assert path.read_bytes() == contents
        assert path.stat().st_mtime_ns == modified_ns


def test_kakaotalk_discovery_rejects_oversized_and_plaintext_candidates(
    tmp_path: Path,
) -> None:
    oversized = tmp_path / "chatLogs_large.edb"
    with oversized.open("wb") as handle:
        handle.truncate(MAX_KAKAOTALK_STORE_BYTES + 1)
    plaintext = tmp_path / "chatLogs_plain.edb"
    plaintext.write_bytes(b"SQLite format 3\x00" + (b"\x00" * 16))

    result = KakaoTalkEncryptedStoreProvider().acquire_key_material(
        case_id="case-1", evidence_id="ev-1", profile_root=str(tmp_path)
    )
    inspected = KakaoTalkEncryptedStoreProvider().inspect_store(
        case_id="case-1", evidence_id="ev-1", store_path=str(oversized)
    )

    statuses = {item["candidate_status"] for item in result["rejected_store_candidates"]}
    assert statuses == {"STORE_TOO_LARGE", "UNEXPECTED_PLAINTEXT_SQLITE"}
    assert result["reason"] == "KAKAOTALK_STORE_TOO_LARGE"
    assert inspected["status"] == "SOURCE_UNAVAILABLE"
    assert inspected["reason"] == "KAKAOTALK_STORE_TOO_LARGE"
    assert "store_sha256" not in inspected


def test_kakaotalk_discovery_enforces_cumulative_hash_budget(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(kakaotalk_runtime, "MAX_DISCOVERY_HASH_BYTES", 16)
    (tmp_path / "chatLogs_1.edb").write_bytes(b"A" * 16)
    (tmp_path / "chatLogs_2.edb").write_bytes(b"B" * 16)

    result = KakaoTalkEncryptedStoreProvider().acquire_key_material(
        case_id="case-1", evidence_id="ev-1", profile_root=str(tmp_path)
    )

    assert result["hash_bytes_examined"] == 16
    assert len(result["store_candidates"]) == 1
    assert result["rejected_store_candidates"][0]["candidate_status"] == (
        "DISCOVERY_HASH_BUDGET_EXCEEDED"
    )


def test_kakaotalk_discovery_skips_symlinks_and_enforces_containment(tmp_path: Path) -> None:
    root = tmp_path / "root"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    store = outside / "chatLogs_1.edb"
    store.write_bytes(b"E" * 16)
    try:
        (root / "linked").symlink_to(outside, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"symlink creation unavailable: {exc}")
    provider = KakaoTalkEncryptedStoreProvider()

    discovered = provider.acquire_key_material(
        case_id="case-1", evidence_id="ev-1", profile_root=str(root)
    )
    inspected = provider.inspect_store(
        case_id="case-1",
        evidence_id="ev-1",
        store_path=str(store),
        profile_root=str(root),
    )

    assert discovered["store_candidates"] == []
    assert discovered["skipped_entries"][0]["reason"] == "LINK_OR_REPARSE_SKIPPED"
    assert inspected["status"] == "SOURCE_UNAVAILABLE"
    assert inspected["reason"] == "KAKAOTALK_STORE_OUTSIDE_PROFILE_ROOT"


def test_kakaotalk_decrypt_rejects_malformed_ciphertext_and_wrong_iv(
    tmp_path: Path,
) -> None:
    malformed = tmp_path / "chatLogs_bad.edb"
    malformed.write_bytes(b"not-a-cbc-block")
    key = b"K" * 16
    iv = b"I" * 16
    malformed_result = KakaoTalkEncryptedStoreProvider().decrypt_store(
        _raw_derivation(key, iv), store_path=str(malformed)
    )
    store, _, _, _ = _write_encrypted_sqlite(
        tmp_path, statements=("CREATE TABLE chatLogs (logId INTEGER, message TEXT)",)
    )
    wrong_iv_result = KakaoTalkEncryptedStoreProvider().decrypt_store(
        _raw_derivation(key, b"J" * 16), store_path=str(store)
    )

    assert malformed_result.status == "CORRUPT_DB"
    assert malformed_result.plaintext is None
    assert wrong_iv_result.status == "AUTHENTICATION_FAILED"
    assert wrong_iv_result.plaintext is None


def test_kakaotalk_decrypt_requires_supported_platform_and_explicit_version(
    tmp_path: Path,
) -> None:
    store = tmp_path / "chatLogs_1.edb"
    store.write_bytes(b"E" * 16)
    unsupported_platform = SecretDerivationInput(
        case_id="case-1",
        evidence_id="ev-1",
        key_source_kind="EXTERNAL_OFFLINE_KEY_MATERIAL",
        parameters={"platform": "ANDROID", "application_version": "2.0.8.990"},
    )
    missing_version = SecretDerivationInput(
        case_id="case-1",
        evidence_id="ev-1",
        key_source_kind="EXTERNAL_OFFLINE_KEY_MATERIAL",
        parameters={"platform": "WINDOWS_DESKTOP"},
    )
    provider = KakaoTalkEncryptedStoreProvider()

    platform_result = provider.decrypt_store(unsupported_platform, store_path=str(store))
    version_result = provider.decrypt_store(missing_version, store_path=str(store))

    assert platform_result.status == "UNSUPPORTED_PLATFORM"
    assert version_result.status == "VERSION_UNVERIFIED"


@pytest.mark.parametrize(
    "statements",
    [
        ("CREATE TABLE unrelated (value TEXT)",),
        ("CREATE TABLE chatLogs (unknownValue TEXT)",),
    ],
)
def test_kakaotalk_decrypt_rejects_missing_or_wrong_chatlogs_schema(
    tmp_path: Path,
    statements: tuple[str, ...],
) -> None:
    store, key, iv, _ = _write_encrypted_sqlite(tmp_path, statements=statements)

    result = KakaoTalkEncryptedStoreProvider().decrypt_store(
        _raw_derivation(key, iv), store_path=str(store)
    )

    assert result.status == "UNSUPPORTED_SCHEMA"
    assert result.plaintext is None


def test_kakaotalk_temp_database_is_cleaned_after_schema_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    derived_root = tmp_path / "derived"
    derived_root.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(derived_root))
    store, key, iv, _ = _write_encrypted_sqlite(
        tmp_path, statements=("CREATE TABLE unrelated (value TEXT)",)
    )

    result = KakaoTalkEncryptedStoreProvider().decrypt_store(
        _raw_derivation(key, iv), store_path=str(store)
    )

    assert result.status == "UNSUPPORTED_SCHEMA"
    assert list(derived_root.iterdir()) == []


def test_kakaotalk_decrypt_extracts_only_present_columns_with_provenance(
    tmp_path: Path,
) -> None:
    store, key, iv, plaintext = _write_encrypted_sqlite(
        tmp_path,
        statements=(
            "CREATE TABLE chatLogs (logId INTEGER, message TEXT)",
            "INSERT INTO chatLogs (logId, message) VALUES (7, 'bounded message')",
        ),
    )

    result = KakaoTalkEncryptedStoreProvider().decrypt_store(
        _raw_derivation(key, iv), store_path=str(store)
    )
    schema = result.to_schema_dict()

    assert result.status == "KAKAOTALK_DECRYPTED"
    assert schema["metadata"]["chatlogs_columns_present"] == ["logId", "message"]
    message = schema["metadata"]["messages"][0]
    assert message["case_id"] == "case-1"
    assert message["evidence_id"] == "ev-1"
    assert message["source_path"] == str(store.resolve())
    assert message["source_database_sha256"] == hashlib.sha256(plaintext).hexdigest()
    assert message["provider_id"] == "apex.communication.kakaotalk"
    assert message["raw_locator"] == {"table": "chatLogs", "rowid": 1, "logId": 7}
    assert "plaintext_b64" not in schema
    serialized = json.dumps(schema, ensure_ascii=False, sort_keys=True)
    assert key.hex() not in serialized
    assert iv.hex() not in serialized
    assert plaintext.hex() not in serialized


@pytest.mark.parametrize(
    "parameters",
    [
        {"db_key_hex": (b"K" * 16).hex()},
        {"db_key_hex": "Z" * 32, "db_iv_hex": "1" * 32},
        {"pragma_key": "raw-pragma-must-not-leak"},
    ],
)
def test_kakaotalk_incomplete_key_material_is_redacted(
    tmp_path: Path,
    parameters: dict[str, str],
) -> None:
    store = tmp_path / "chatLogs_1.edb"
    store.write_bytes(b"E" * 16)
    derivation = SecretDerivationInput(
        case_id="case-1",
        evidence_id="ev-1",
        key_source_kind="EXTERNAL_OFFLINE_KEY_MATERIAL",
        parameters={
            "platform": "WINDOWS_DESKTOP",
            "application_version": "2.0.8.990",
            **parameters,
        },
    )

    schema = KakaoTalkEncryptedStoreProvider().decrypt_store(
        derivation, store_path=str(store)
    ).to_schema_dict()
    serialized = json.dumps(schema, sort_keys=True)

    assert schema["status"] == "KEY_UNAVAILABLE"
    assert all(value not in serialized for value in parameters.values())
    assert "plaintext_b64" not in serialized


def test_kakaotalk_cancellation_precedes_source_and_secret_access() -> None:
    result = KakaoTalkEncryptedStoreProvider().decrypt_store(
        SecretDerivationInput(
            case_id="case-1",
            evidence_id="ev-1",
            key_source_kind="EXTERNAL_OFFLINE_KEY_MATERIAL",
        ),
        store_path="does-not-exist.edb",
        cancellation_requested=True,
    )

    assert result.status == "FAILED"
    assert result.attempt.error_code == "OPERATION_CANCELLED"


@pytest.mark.parametrize("required_flag", ["--require-decrypted", "--require-real-fixture"])
def test_kakaotalk_verifier_require_flags_fail_without_fixture(
    project_root: Path,
    cli_env: dict[str, str],
    required_flag: str,
) -> None:
    completed = subprocess.run(
        [
            sys.executable,
            str(project_root / "tools" / "verify_kakaotalk_runtime.py"),
            required_flag,
        ],
        check=False,
        capture_output=True,
        env=cli_env,
        text=True,
    )

    assert completed.returncode == 1
    payload = json.loads(completed.stdout)
    assert payload["verification"]["real_kakaotalk_fixture_verified"] is False
    assert payload["verification"]["secret_leakage_check_passed"] is True
