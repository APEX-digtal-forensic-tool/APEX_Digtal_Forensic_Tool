from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime

import pytest

from apex_forensic.cli.commands import main
from apex_forensic.config import build_services
from apex_forensic.domain.errors import PersistenceError
from apex_forensic.domain.models import (
    DecryptionAttempt,
    DecryptionResult,
    HashVerification,
    SecretProviderCapability,
)


def test_secret_decryption_audit_persists_redacted_result(
    tmp_path,
    schema_validator,
) -> None:
    db_path = tmp_path / "advanced-runtime-audit.db"
    services = build_services(db_path)
    try:
        case = services.cases.create_case(name="Secret Audit", locale="ko-KR")
        generated_at = datetime(2026, 1, 1, tzinfo=UTC)
        capability = SecretProviderCapability(
            provider_id="apex.dpapi.offline",
            provider_version="0.1.0",
            capability_type="DPAPI_PROVIDER",
            runtime_status="CAPABILITY_UNAVAILABLE",
            supported_key_sources=["WINDOWS_USER_PASSWORD"],
            supported_algorithms=["DPAPI_BLOB"],
            warnings=[
                {
                    "code": "CAPABILITY_UNAVAILABLE",
                    "details": {"password_value": "do-not-store"},
                }
            ],
            generated_at=generated_at,
        )
        services.repository.save_secret_provider_capability(capability)

        attempt = DecryptionAttempt(
            attempt_id="attempt-1",
            case_id=case.case_id,
            evidence_id=None,
            provider_id="apex.dpapi.offline",
            provider_version="0.1.0",
            algorithm="DPAPI_BLOB",
            key_source_kind="WINDOWS_USER_PASSWORD",
            status="FAILED",
            started_at=generated_at,
            completed_at=generated_at,
            warnings=[
                {
                    "code": "INVALID_KEY",
                    "details": {"token": "do-not-store"},
                }
            ],
            error_code="INVALID_KEY",
            error_message="password secret token key=should-not-be-stored",
        )
        result = DecryptionResult(
            attempt=attempt,
            status="FAILED",
            plaintext=b"synthetic plaintext secret",
            output_kind="DPAPI_BLOB",
            citations=[{"case_id": case.case_id, "source_kind": "SYNTHETIC"}],
            partial=True,
            metadata={"password": "do-not-store", "ciphertext_length": 16},
        )
        services.repository.save_decryption_result(result)

        stored = services.repository.get_decryption_result("attempt-1")
        assert stored is not None
        assert stored["content_length"] == len(b"synthetic plaintext secret")
        assert stored["metadata"]["password"] == "<redacted>"
        assert stored["attempt"]["warnings"][0]["details"]["token"] == "<redacted>"
        assert stored["attempt"]["error_message"] == "Sensitive provider error redacted."
        assert "plaintext_b64" not in stored
        assert "synthetic plaintext secret" not in str(stored)
        schema_validator.validate("decryption-result.schema.json", stored)

        capabilities = services.repository.list_secret_provider_capabilities(
            capability_type="DPAPI_PROVIDER"
        )
        assert [item.runtime_status for item in capabilities] == ["CAPABILITY_UNAVAILABLE"]
        assert capabilities[0].warnings[0]["details"]["password_value"] == "<redacted>"
        schema_validator.validate(
            "secret-provider-capability.schema.json",
            capabilities[0].to_schema_dict(),
        )
    finally:
        services.close()

    reopened = build_services(db_path)
    try:
        results = reopened.repository.list_decryption_results(case_id=case.case_id)
        assert len(results) == 1
        raw = reopened.repository.connection.execute(
            """
            SELECT result_json, metadata_json FROM decryption_results
            WHERE attempt_id = ?
            """,
            ("attempt-1",),
        ).fetchone()
        raw_blob = f"{raw['result_json']} {raw['metadata_json']}"
        assert "plaintext_b64" not in raw_blob
        assert "synthetic plaintext secret" not in raw_blob
        assert "do-not-store" not in raw_blob

        migrations = {
            str(row["version"])
            for row in reopened.repository.connection.execute(
                "SELECT version FROM schema_migrations"
            ).fetchall()
        }
        assert "apex-engine-advanced-runtime-audit" in migrations

        with pytest.raises(sqlite3.IntegrityError):
            reopened.repository.connection.execute(
                "UPDATE decryption_results SET status = 'COMPLETED' WHERE attempt_id = ?",
                ("attempt-1",),
            )
    finally:
        reopened.close()


def test_hash_verification_case_scope_migrates_and_rejects_cross_case(
    tmp_path,
) -> None:
    db_path = tmp_path / "hash-case-migration.db"
    sample = tmp_path / "hash-source.bin"
    sample.write_bytes(b"hash verification case scope")
    services = build_services(db_path)
    case = services.cases.create_case(name="Hash case")
    other_case = services.cases.create_case(name="Other hash case")
    evidence = services.evidence.register_evidence(
        case_id=case.case_id,
        source_path=sample,
    )
    verification = HashVerification(
        {
            "id": "verification-migrated",
            "case_id": case.case_id,
            "evidence_id": evidence.evidence_id,
            "algorithm": "SHA256",
            "expected_digest": "0" * 64,
            "observed_digest": "0" * 64,
            "status": "MATCH",
            "verified_at": "2026-01-01T00:00:00Z",
            "tool_version": "test",
            "job_id": None,
            "custody_event_id": None,
            "error": None,
        }
    )
    services.repository.save_hash_verification(verification)
    services.close()

    legacy = sqlite3.connect(db_path)
    try:
        legacy.executescript(
            """
            CREATE TABLE hash_verifications_legacy (
                verification_id TEXT PRIMARY KEY,
                evidence_id TEXT NOT NULL REFERENCES evidence(evidence_id),
                algorithm TEXT NOT NULL,
                expected_digest TEXT NOT NULL,
                observed_digest TEXT,
                status TEXT NOT NULL,
                verified_at TEXT NOT NULL,
                tool_version TEXT NOT NULL,
                job_id TEXT REFERENCES jobs(job_id),
                custody_event_id TEXT,
                error_json TEXT
            );
            INSERT INTO hash_verifications_legacy
            SELECT verification_id, evidence_id, algorithm, expected_digest,
                   observed_digest, status, verified_at, tool_version, job_id,
                   custody_event_id, error_json
            FROM hash_verifications;
            DROP TABLE hash_verifications;
            ALTER TABLE hash_verifications_legacy RENAME TO hash_verifications;
            """
        )
        legacy.commit()
    finally:
        legacy.close()

    reopened = build_services(db_path)
    try:
        reopened.repository.initialize()
        columns = {
            row["name"]
            for row in reopened.repository.connection.execute(
                "PRAGMA table_info(hash_verifications)"
            )
        }
        stored = reopened.repository.connection.execute(
            "SELECT case_id FROM hash_verifications WHERE verification_id = ?",
            ("verification-migrated",),
        ).fetchone()
        reloaded = reopened.repository.list_hash_verifications(evidence.evidence_id)[0]
        assert "case_id" in columns
        assert stored["case_id"] == case.case_id
        assert reloaded.to_schema_dict()["case_id"] == case.case_id
        assert {
            key: reloaded.to_schema_dict()[key]
            for key in (
                "id",
                "evidence_id",
                "algorithm",
                "expected_digest",
                "observed_digest",
                "status",
                "verified_at",
                "tool_version",
            )
        } == {
            key: verification.to_schema_dict()[key]
            for key in (
                "id",
                "evidence_id",
                "algorithm",
                "expected_digest",
                "observed_digest",
                "status",
                "verified_at",
                "tool_version",
            )
        }

        cross_case = HashVerification(
            {
                **verification.to_schema_dict(),
                "id": "verification-cross-case",
                "case_id": other_case.case_id,
            }
        )
        before_count = reopened.repository.connection.execute(
            "SELECT COUNT(*) AS count FROM hash_verifications"
        ).fetchone()["count"]
        with pytest.raises(PersistenceError) as mismatch:
            reopened.repository.save_hash_verification(cross_case)
        assert mismatch.value.code == "CASE_SCOPE_MISMATCH"
        assert reopened.repository.connection.execute(
            "SELECT COUNT(*) AS count FROM hash_verifications"
        ).fetchone()["count"] == before_count
    finally:
        reopened.close()


def test_secret_cli_records_decryption_audit_for_registered_case(
    tmp_path,
    capsys,
    monkeypatch,
) -> None:
    db_path = tmp_path / "secret-cli-audit.db"
    blob = tmp_path / "dpapi.blob"
    blob.write_bytes(b"DPAPI synthetic ciphertext")
    crypto = pytest.importorskip("cryptography.hazmat.primitives.ciphers.aead")
    key = b"\x03" * 32
    nonce = b"\x04" * 12
    chromium_plaintext = b"synthetic chromium secret"
    chromium_blob = tmp_path / "chromium-secret.bin"
    chromium_blob.write_bytes(
        b"v10" + nonce + crypto.AESGCM(key).encrypt(nonce, chromium_plaintext, None)
    )
    monkeypatch.setenv("APEX_TEST_CHROMIUM_KEY_HEX", key.hex())
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    (evidence_root / "note.txt").write_text("synthetic", encoding="utf-8")

    assert (
        main(
            [
                "--db",
                str(db_path),
                "case",
                "create",
                "--name",
                "CLI Secret Audit",
                "--json",
            ]
        )
        == 0
    )
    case_payload = json.loads(capsys.readouterr().out)
    case_id = case_payload["id"]

    assert (
        main(
            [
                "--db",
                str(db_path),
                "evidence",
                "add",
                "--case-id",
                case_id,
                "--path",
                str(evidence_root),
                "--json",
            ]
        )
        == 0
    )
    evidence_payload = json.loads(capsys.readouterr().out)
    evidence_id = evidence_payload["id"]

    assert (
        main(
            [
                "--db",
                str(db_path),
                "secret",
                "decrypt-dpapi",
                "--case-id",
                case_id,
                "--evidence-id",
                evidence_id,
                "--input-file",
                str(blob),
                "--json",
            ]
        )
        == 0
    )
    output = json.loads(capsys.readouterr().out)
    assert output["status"] in {"CAPABILITY_UNAVAILABLE", "CORRUPT_KEY_MATERIAL"}

    assert (
        main(
            [
                "--db",
                str(db_path),
                "secret",
                "dpapi",
                "decrypt-chromium-secret",
                "--case-id",
                case_id,
                "--evidence-id",
                evidence_id,
                "--input-file",
                str(chromium_blob),
                "--key-hex-env",
                "APEX_TEST_CHROMIUM_KEY_HEX",
                "--json",
            ]
        )
        == 0
    )
    chromium_output = json.loads(capsys.readouterr().out)
    assert chromium_output["status"] == "DECRYPTED"
    assert chromium_output["content_length"] == len(chromium_plaintext)
    assert chromium_output["metadata"]["key_source"]["length"] == 32
    assert "plaintext_b64" not in chromium_output
    assert "synthetic chromium secret" not in json.dumps(chromium_output)

    services = build_services(db_path)
    try:
        results = services.repository.list_decryption_results(case_id=case_id)
        assert {item["status"] for item in results} in (
            {"CAPABILITY_UNAVAILABLE", "DECRYPTED"},
            {"CORRUPT_KEY_MATERIAL", "DECRYPTED"},
        )
        assert all("plaintext_b64" not in item for item in results)
    finally:
        services.close()
