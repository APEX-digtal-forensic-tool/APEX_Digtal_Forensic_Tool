"""Version-limited KakaoTalk encrypted store runtime."""

from __future__ import annotations

import base64
import hashlib
import os
import sqlite3
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from apex_forensic.constants import ENGINE_VERSION
from apex_forensic.domain.models import (
    DecryptionAttempt,
    DecryptionResult,
    SecretDerivationInput,
    SecretProviderCapability,
)

SUPPORTED_WINDOWS_VERSION = "2.0.8.990"
SUPPORTED_PLATFORM = "WINDOWS_DESKTOP"
SUPPORTED_SCHEMA = "chatLogs"
MAX_KAKAOTALK_STORE_BYTES = 512 * 1024 * 1024
SQLITE_HEADER = b"SQLite format 3\x00"
SENSITIVE_MESSAGE_MARKERS = ("password", "secret", "token", "cookie", "key=")
KAKAOTALK_RESEARCH_REFERENCE = {
    "title": (
        "Digital forensic analysis of encrypted database files in instant messaging "
        "applications on Windows operating systems"
    ),
    "doi": "10.1016/j.diin.2019.01.011",
    "validated_redistributable_fixture": False,
}
SUPPORT_MATRIX: tuple[dict[str, Any], ...] = (
    {
        "platform": SUPPORTED_PLATFORM,
        "application_version": SUPPORTED_WINDOWS_VERSION,
        "database_schema_version": SUPPORTED_SCHEMA,
        "encryption_scheme": "AES-128-CBC external-key contract",
        "key_source": "EXTERNAL_KPRAGMA_AND_SERVER_NONCE_OR_RAW_DB_KEY_IV",
        "fixture": None,
        "fixture_status": "BLOCKED_EXTERNAL_FIXTURE",
        "contract_fixture": "synthetic AES-CBC SQLite contract fixture; not a KakaoTalk DB",
        "status": "PARTIAL",
        "automatic_key_acquisition": False,
        "source": KAKAOTALK_RESEARCH_REFERENCE,
    },
    {
        "platform": "ANDROID",
        "application_version": "*",
        "database_schema_version": "*",
        "encryption_scheme": "not validated in this provider",
        "key_source": None,
        "fixture": None,
        "status": "UNSUPPORTED_PLATFORM",
    },
    {
        "platform": "IOS",
        "application_version": "*",
        "database_schema_version": "*",
        "encryption_scheme": "not validated in this provider",
        "key_source": None,
        "fixture": None,
        "status": "UNSUPPORTED_PLATFORM",
    },
)


class KakaoTalkCorruptStoreError(ValueError):
    """Encrypted store bytes are structurally corrupt before SQLite validation."""


class KakaoTalkCorruptDatabaseError(ValueError):
    """Decrypted bytes are not a valid SQLite database."""


class KakaoTalkUnsupportedSchemaError(ValueError):
    """Decrypted SQLite database is outside the version-limited schema."""


class KakaoTalkEncryptedStoreProvider:
    """KakaoTalk Windows 2.0.8.990 AES-CBC runtime with external key material."""

    provider_id = "apex.communication.kakaotalk"
    provider_version = ENGINE_VERSION

    def capabilities(self) -> SecretProviderCapability:
        return SecretProviderCapability(
            provider_id=self.provider_id,
            provider_version=self.provider_version,
            capability_type="KAKAOTALK_PROVIDER",
            runtime_status="AVAILABLE_WITH_EXTERNAL_KEY",
            supported_key_sources=[
                "KAKAOTALK_KPRAGMA_AND_SERVER_NONCE",
                "KAKAOTALK_RAW_DB_KEY_IV",
            ],
            supported_algorithms=["KAKAOTALK_WINDOWS_2_0_8_990_AES_128_CBC"],
            requires_host=False,
            requires_network=False,
            generated_at=datetime.now(UTC),
            warnings=[
                {
                    "code": "PARTIAL",
                    "developer_message": (
                        "KakaoTalk automatic key acquisition is unsupported; decryption only "
                        "runs with external KPRAGMA+nonce or raw DB key/IV for Windows "
                        "2.0.8.990 chatLogs stores."
                    ),
                    "details": {
                        "success_without_key": False,
                        "supported_matrix": list(SUPPORT_MATRIX),
                    },
                }
                ,
                {
                    "code": "BLOCKED_EXTERNAL_FIXTURE",
                    "developer_message": (
                        "No redistributable KakaoTalk Windows 2.0.8.990 encrypted database "
                        "fixture is bundled; synthetic AES contract tests are not reported as "
                        "real KakaoTalk fixture verification."
                    ),
                    "details": _runtime_evidence_metadata(),
                },
            ],
        )

    def acquire_key_material(
        self,
        *,
        case_id: str,
        evidence_id: str | None,
        profile_root: str | None = None,
    ) -> dict[str, object]:
        """Report the automatic key-acquisition boundary without using private secrets."""

        return {
            "schema_version": "1.0.0",
            "case_id": case_id,
            "evidence_id": evidence_id,
            "profile_root": profile_root,
            "status": "BLOCKED_EXTERNAL_FIXTURE",
            "reason": "KAKAOTALK_AUTOMATIC_KEY_ACQUISITION_UNVERIFIED",
            "automatic_key_acquisition": False,
            "secret_values_emitted": False,
            "required_evidence": [
                "redistributable Windows Desktop 2.0.8.990 encrypted chatLogs fixture",
                "validated key-material discovery path for the same client version",
                "version-specific KPRAGMA/nonce or equivalent derivation proof",
            ],
            **_runtime_evidence_metadata(),
        }

    def inspect_store(
        self,
        *,
        case_id: str,
        evidence_id: str | None,
        store_path: str,
    ) -> dict[str, object]:
        path = Path(store_path)
        if not path.is_file():
            return {
                "schema_version": "1.0.0",
                "case_id": case_id,
                "evidence_id": evidence_id,
                "store_path": store_path,
                "status": "SOURCE_UNAVAILABLE",
                "reason": "KAKAOTALK_STORE_NOT_FOUND",
                "success_without_key": False,
                "support_matrix": list(SUPPORT_MATRIX),
                **_runtime_evidence_metadata(),
            }
        data = path.read_bytes()
        return {
            "schema_version": "1.0.0",
            "case_id": case_id,
            "evidence_id": evidence_id,
            "store_path": store_path,
            "status": "KEY_UNAVAILABLE",
            "reason": "KAKAOTALK_KEY_PROVIDER_UNAVAILABLE",
            "encrypted_store_detected": not data.startswith(SQLITE_HEADER),
            "store_length": len(data),
            "store_sha256": hashlib.sha256(data).hexdigest(),
            "raw_store_emitted": False,
            "plaintext_emitted": False,
            "success_without_key": False,
            "support_matrix": list(SUPPORT_MATRIX),
            "supported_without_external_key": False,
            **_runtime_evidence_metadata(),
        }

    def decrypt_store(
        self,
        derivation_input: SecretDerivationInput,
        *,
        store_path: str,
        cancellation_requested: bool = False,
    ) -> DecryptionResult:
        derivation_input.assert_references_same_case()
        if cancellation_requested:
            return self._result(
                derivation_input,
                status="FAILED",
                store_path=store_path,
                reason="OPERATION_CANCELLED",
                error_message="KakaoTalk decryption was cancelled before dispatch.",
            )
        inspected = self.inspect_store(
            case_id=derivation_input.case_id,
            evidence_id=derivation_input.evidence_id,
            store_path=store_path,
        )
        if inspected["status"] == "SOURCE_UNAVAILABLE":
            return self._result(
                derivation_input,
                status="SOURCE_UNAVAILABLE",
                store_path=store_path,
                reason=str(inspected["reason"]),
                metadata=inspected,
                error_message="KakaoTalk encrypted store is unavailable.",
            )
        target_status = _validate_target(derivation_input.parameters)
        if target_status is not None:
            return self._result(
                derivation_input,
                status=target_status,
                store_path=store_path,
                reason=f"KAKAOTALK_{target_status}",
                metadata=inspected,
                error_message="KakaoTalk platform or version is outside the supported matrix.",
            )
        try:
            key, iv, key_metadata = _key_iv_from_parameters(derivation_input.parameters)
        except ValueError as exc:
            return self._result(
                derivation_input,
                status="KEY_UNAVAILABLE",
                store_path=store_path,
                reason="KAKAOTALK_KEY_MATERIAL_UNAVAILABLE",
                metadata=inspected,
                error_message=str(exc),
            )
        path = Path(store_path)
        if path.stat().st_size > MAX_KAKAOTALK_STORE_BYTES:
            return self._result(
                derivation_input,
                status="FAILED",
                store_path=store_path,
                reason="KAKAOTALK_STORE_TOO_LARGE",
                metadata=inspected,
                error_message="KakaoTalk store exceeds the configured size limit.",
            )
        ciphertext = path.read_bytes()
        try:
            plaintext = _aes_cbc_decrypt(ciphertext, key, iv)
            extracted = _extract_chatlogs(plaintext, source_path=store_path)
        except KakaoTalkUnsupportedSchemaError as exc:
            return self._result(
                derivation_input,
                status="UNSUPPORTED_VERSION",
                store_path=store_path,
                reason="KAKAOTALK_SCHEMA_UNSUPPORTED",
                metadata={**inspected, **key_metadata},
                error_message=str(exc),
            )
        except (KakaoTalkCorruptStoreError, KakaoTalkCorruptDatabaseError) as exc:
            return self._result(
                derivation_input,
                status="FAILED",
                store_path=store_path,
                reason="KAKAOTALK_CORRUPT_DB",
                metadata={**inspected, **key_metadata},
                error_message=str(exc),
            )
        except ValueError as exc:
            return self._result(
                derivation_input,
                status="AUTHENTICATION_FAILED",
                store_path=store_path,
                reason="KAKAOTALK_DECRYPTION_FAILED",
                metadata={**inspected, **key_metadata},
                error_message=str(exc),
            )
        metadata: dict[str, Any] = {
            **inspected,
            **key_metadata,
            **extracted,
            "status": "KAKAOTALK_DECRYPTED",
            "reason": "KAKAOTALK_WINDOWS_2_0_8_990_DECRYPTED",
            "plaintext_emitted": False,
            "success_without_key": False,
            "supported_matrix": list(SUPPORT_MATRIX),
        }
        citations = [
            {
                "source_path": store_path,
                "raw_locator": {
                    "table": "chatLogs",
                    "row_reference": item["row_reference"],
                },
            }
            for item in extracted["messages"]
        ]
        return self._result(
            derivation_input,
            status="KAKAOTALK_DECRYPTED",
            store_path=store_path,
            reason="KAKAOTALK_WINDOWS_2_0_8_990_DECRYPTED",
            metadata=metadata,
            plaintext=plaintext,
            content_sha256=hashlib.sha256(plaintext).hexdigest(),
            content_length=len(plaintext),
            citations=citations,
            partial=False,
        )

    def _result(
        self,
        derivation_input: SecretDerivationInput,
        *,
        status: str,
        store_path: str,
        reason: str,
        metadata: dict[str, Any] | dict[str, object] | None = None,
        error_message: str | None = None,
        plaintext: bytes | None = None,
        content_sha256: str | None = None,
        content_length: int | None = None,
        citations: list[dict[str, Any]] | None = None,
        partial: bool = True,
    ) -> DecryptionResult:
        now = datetime.now(UTC)
        safe_metadata: dict[str, Any] = {
            "schema_version": "1.0.0",
            "case_id": derivation_input.case_id,
            "evidence_id": derivation_input.evidence_id,
            "store_path": store_path,
            "status": status,
            "reason": reason,
            "raw_store_emitted": False,
            "plaintext_emitted": False,
            "success_without_key": False,
            "support_matrix": list(SUPPORT_MATRIX),
            **_runtime_evidence_metadata(),
        }
        if metadata:
            safe_metadata.update(dict(metadata))
            safe_metadata["status"] = status
            safe_metadata["reason"] = reason
            safe_metadata["raw_store_emitted"] = False
            safe_metadata["plaintext_emitted"] = False
            safe_metadata["success_without_key"] = False
        return DecryptionResult(
            attempt=DecryptionAttempt(
                attempt_id=f"kakaotalk-{uuid4()}",
                case_id=derivation_input.case_id,
                evidence_id=derivation_input.evidence_id,
                provider_id=self.provider_id,
                provider_version=self.provider_version,
                algorithm="KAKAOTALK_WINDOWS_2_0_8_990_AES_128_CBC",
                key_source_kind=derivation_input.key_source_kind,
                status=status,
                started_at=now,
                completed_at=now,
                warnings=[
                    {
                        "code": status,
                        "developer_message": (
                            "KakaoTalk runtime is limited to Windows 2.0.8.990 with "
                            "external key material."
                        ),
                    }
                ],
                error_code=None if status == "KAKAOTALK_DECRYPTED" else reason,
                error_message=error_message,
            ),
            status=status,
            plaintext=plaintext,
            output_kind="KAKAOTALK_SQLITE_PLAINTEXT",
            content_sha256=content_sha256,
            content_length=content_length,
            citations=citations or [],
            partial=partial,
            metadata=safe_metadata,
        )


def _validate_target(params: dict[str, Any]) -> str | None:
    platform = str(params.get("platform") or SUPPORTED_PLATFORM).upper().replace("-", "_")
    if platform not in {SUPPORTED_PLATFORM, "WINDOWS"}:
        return "UNSUPPORTED_PLATFORM"
    version = str(params.get("application_version") or SUPPORTED_WINDOWS_VERSION)
    if version != SUPPORTED_WINDOWS_VERSION:
        return "UNSUPPORTED_VERSION"
    schema = str(params.get("database_schema_version") or SUPPORTED_SCHEMA)
    if schema != SUPPORTED_SCHEMA:
        return "UNSUPPORTED_VERSION"
    return None


def _key_iv_from_parameters(params: dict[str, Any]) -> tuple[bytes, bytes, dict[str, Any]]:
    raw_key_hex = _optional_str(params.get("db_key_hex"))
    raw_iv_hex = _optional_str(params.get("db_iv_hex"))
    if raw_key_hex or raw_iv_hex:
        if not raw_key_hex or not raw_iv_hex:
            raise ValueError("Both db_key_hex and db_iv_hex are required.")
        key = bytes.fromhex(raw_key_hex)
        iv = bytes.fromhex(raw_iv_hex)
        _require_aes128_key_iv(key, iv)
        return (
            key,
            iv,
            {
                "key_source": "KAKAOTALK_RAW_DB_KEY_IV",
                "key_sha256": hashlib.sha256(key).hexdigest(),
                "iv_sha256": hashlib.sha256(iv).hexdigest(),
                "key_length": len(key),
                "iv_length": len(iv),
            },
        )
    pragma_key = _optional_str(params.get("pragma_key"))
    user_nonce = _optional_str(params.get("user_nonce"))
    if not pragma_key or not user_nonce:
        raise ValueError("KakaoTalk KPRAGMA and user_nonce are required.")
    repeated = (pragma_key + user_nonce).encode("utf-8")
    material = (repeated * ((512 // len(repeated)) + 1))[:512]
    key = hashlib.md5(material, usedforsecurity=False).digest()
    iv = hashlib.md5(base64.b64encode(key), usedforsecurity=False).digest()
    return (
        key,
        iv,
        {
            "key_source": "KAKAOTALK_KPRAGMA_AND_SERVER_NONCE",
            "key_sha256": hashlib.sha256(key).hexdigest(),
            "iv_sha256": hashlib.sha256(iv).hexdigest(),
            "key_length": len(key),
            "iv_length": len(iv),
            "pragma_key_hash": hashlib.sha256(pragma_key.encode("utf-8")).hexdigest(),
            "user_nonce_hash": hashlib.sha256(user_nonce.encode("utf-8")).hexdigest(),
        },
    )


def _require_aes128_key_iv(key: bytes, iv: bytes) -> None:
    if len(key) != 16:
        raise ValueError("KakaoTalk AES-128 key must be 16 bytes.")
    if len(iv) != 16:
        raise ValueError("KakaoTalk AES-CBC IV must be 16 bytes.")


def _aes_cbc_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    if len(ciphertext) == 0 or len(ciphertext) % 16 != 0:
        raise KakaoTalkCorruptStoreError(
            "KakaoTalk ciphertext length is invalid for AES-CBC."
        )
    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    try:
        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded) + unpadder.finalize()
    except ValueError as exc:
        raise ValueError("KakaoTalk AES-CBC padding validation failed.") from exc
    if not plaintext.startswith(SQLITE_HEADER):
        raise ValueError("KakaoTalk decrypted bytes are not a SQLite database.")
    return plaintext


def _extract_chatlogs(plaintext: bytes, *, source_path: str) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="apex-kakaotalk-") as temp_dir:
        sqlite_path = Path(temp_dir) / "chatlogs.sqlite"
        descriptor = os.open(sqlite_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(plaintext)
        with sqlite3.connect(f"file:{sqlite_path}?mode=ro", uri=True) as connection:
            connection.row_factory = sqlite3.Row
            try:
                integrity = str(connection.execute("PRAGMA integrity_check").fetchone()[0])
                if integrity != "ok":
                    raise KakaoTalkCorruptDatabaseError(
                        "KakaoTalk decrypted SQLite integrity check failed."
                    )
                tables = {
                    str(row["name"])
                    for row in connection.execute(
                        "SELECT name FROM sqlite_master WHERE type = 'table'"
                    )
                }
                if "chatLogs" not in tables:
                    raise KakaoTalkUnsupportedSchemaError(
                        "KakaoTalk chatLogs table is missing."
                    )
                columns = {
                    str(row["name"])
                    for row in connection.execute("PRAGMA table_info(chatLogs)")
                }
            except sqlite3.DatabaseError as exc:
                raise KakaoTalkCorruptDatabaseError(
                    "KakaoTalk decrypted SQLite database is corrupt."
                ) from exc
            missing_columns = {
                "logId",
                "authorId",
                "type",
                "sentAt",
                "message",
                "attachment",
                "deleted",
            } - columns
            if missing_columns:
                raise KakaoTalkUnsupportedSchemaError(
                    "KakaoTalk chatLogs schema is outside the supported version."
                )
            messages = _read_chatlog_messages(connection, columns)
    return {
        "sqlite_integrity_check": "ok",
        "database_schema_version": SUPPORTED_SCHEMA,
        "message_count": len(messages),
        "chatroom_count": 1 if messages else 0,
        "messages": messages,
        "search_projection_ready": True,
        "timeline_projection_ready": True,
        "source_path": source_path,
    }


def _read_chatlog_messages(
    connection: sqlite3.Connection,
    columns: set[str],
) -> list[dict[str, Any]]:
    del columns
    rows = connection.execute(
        """
        SELECT
            rowid AS rowid,
            logId,
            authorId,
            type,
            sentAt,
            message,
            attachment,
            deleted
        FROM chatLogs
        ORDER BY rowid
        LIMIT 5000
        """
    ).fetchall()
    messages: list[dict[str, Any]] = []
    for row in rows:
        message = "" if row["message"] is None else str(row["message"])
        attachment = None if row["attachment"] is None else str(row["attachment"])
        messages.append(
            {
                "row_reference": {
                    "rowid": row["rowid"],
                    "logId": row["logId"],
                },
                "sender_account_candidate": None
                if row["authorId"] is None
                else str(row["authorId"]),
                "message_type": row["type"],
                "timestamp": row["sentAt"],
                "message_text_sha256": hashlib.sha256(message.encode("utf-8")).hexdigest(),
                "message_preview": _safe_preview(message),
                "attachment_present": attachment is not None,
                "attachment_sha256": None
                if attachment is None
                else hashlib.sha256(attachment.encode("utf-8")).hexdigest(),
                "deleted_candidate": bool(row["deleted"]),
                "raw_locator": {
                    "table": "chatLogs",
                    "rowid": row["rowid"],
                    "logId": row["logId"],
                },
                "citation": {
                    "table": "chatLogs",
                    "rowid": row["rowid"],
                },
            }
        )
    return messages

def _safe_preview(message: str) -> str:
    if any(marker in message.casefold() for marker in SENSITIVE_MESSAGE_MARKERS):
        return "<redacted-sensitive-message>"
    return message[:80]


def _runtime_evidence_metadata() -> dict[str, Any]:
    return {
        "automatic_key_acquisition_status": "BLOCKED_EXTERNAL_FIXTURE",
        "redistributable_fixture_status": "BLOCKED_EXTERNAL_FIXTURE",
        "algorithm_contract_fixture_status": "CONTRACT_ONLY",
        "validated_redistributable_fixture": False,
        "real_kakaotalk_fixture_verified": False,
        "research_reference": dict(KAKAOTALK_RESEARCH_REFERENCE),
    }


def _optional_str(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None
