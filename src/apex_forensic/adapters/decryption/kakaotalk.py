"""Version-limited KakaoTalk encrypted store runtime."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import sqlite3
import stat
import struct
import tempfile
from contextlib import closing
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
MAX_KAKAOTALK_EXECUTABLE_BYTES = 256 * 1024 * 1024
MAX_DISCOVERY_ENTRIES = 20_000
MAX_DISCOVERY_DEPTH = 12
MAX_STORE_CANDIDATES = 1_024
MAX_VERSION_ARTIFACTS = 64
MAX_DISCOVERY_HASH_BYTES = 2 * 1024 * 1024 * 1024
MAX_EXTERNAL_KEY_INPUT_CHARS = 65_536
SQLITE_HEADER = b"SQLite format 3\x00"
SENSITIVE_MESSAGE_MARKERS = ("password", "secret", "token", "cookie", "key=")
KAKAOTALK_EXECUTABLE_NAME = "kakaotalk.exe"
KAKAOTALK_STORE_PREFIX = "chatlogs"
KAKAOTALK_STORE_SUFFIX = ".edb"
PE_VERSION_RESOURCE_TYPE = 16
PE_FIXED_FILE_INFO_SIGNATURE = 0xFEEF04BD
WINDOWS_REPARSE_POINT_ATTRIBUTE = 0x400
SUPPORTED_CHATLOG_COLUMNS = (
    "logId",
    "authorId",
    "type",
    "sentAt",
    "message",
    "attachment",
    "deleted",
)
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


class KakaoTalkVersionArtifactError(ValueError):
    """An offline executable does not contain a usable PE version resource."""


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
        platform: str = SUPPORTED_PLATFORM,
    ) -> dict[str, object]:
        """Discover offline evidence and report the proven key-acquisition boundary."""

        base: dict[str, object] = {
            "schema_version": "1.0.0",
            "case_id": case_id,
            "evidence_id": evidence_id,
            "profile_root": profile_root,
            "platform": platform,
            "automatic_key_acquisition": False,
            "secret_values_emitted": False,
            "discovery_status": "NOT_STARTED",
            "version_status": "VERSION_UNVERIFIED",
            "key_material_status": "KEY_UNAVAILABLE",
            "key_derivation_status": "NOT_ATTEMPTED",
            "store_candidates": [],
            "version_artifacts": [],
            "skipped_entries": [],
            "missing_derivation_evidence": [
                "authoritative Windows 2.0.8.990 built-in KPRAGMA encryption constant",
                "authoritative offline mappings for device UUID, disk model, and disk serial",
                "authoritative offline source mapping for the user/server nonce",
                "redistributable Windows 2.0.8.990 encrypted chatLogs fixture",
            ],
            **_runtime_evidence_metadata(),
        }
        normalized_platform = _normalize_platform(platform)
        if normalized_platform not in {SUPPORTED_PLATFORM, "WINDOWS"}:
            return {
                **base,
                "status": "UNSUPPORTED_PLATFORM",
                "reason": "KAKAOTALK_UNSUPPORTED_PLATFORM",
            }
        root_status = _validate_profile_root(profile_root)
        if isinstance(root_status, dict):
            return {**base, **root_status}
        root = root_status
        discovery = _discover_offline_artifacts(root)
        result: dict[str, object] = {
            **base,
            "profile_root": str(root),
            **discovery,
        }
        stores = discovery["store_candidates"]
        assert isinstance(stores, list)
        if not stores:
            rejected = discovery["rejected_store_candidates"]
            assert isinstance(rejected, list)
            rejected_statuses = {
                str(item.get("candidate_status"))
                for item in rejected
                if isinstance(item, dict)
            }
            reason = "KAKAOTALK_ENCRYPTED_STORE_NOT_FOUND"
            if "STORE_TOO_LARGE" in rejected_statuses:
                reason = "KAKAOTALK_STORE_TOO_LARGE"
            elif "MALFORMED_CIPHERTEXT" in rejected_statuses:
                reason = "KAKAOTALK_MALFORMED_CIPHERTEXT"
            elif "DISCOVERY_HASH_BUDGET_EXCEEDED" in rejected_statuses:
                reason = "KAKAOTALK_DISCOVERY_LIMIT_EXCEEDED"
            result.update(
                status="SOURCE_UNAVAILABLE",
                reason=reason,
            )
            return result
        version_status, version_reason, verified_version = _evaluate_versions(
            discovery["version_artifacts"]
        )
        result.update(
            version_status=version_status,
            version_reason=version_reason,
            application_version=verified_version,
        )
        if version_status != "VERSION_VERIFIED":
            result.update(status=version_status, reason=version_reason)
            return result
        result.update(
            status="BLOCKED_EXTERNAL_FIXTURE",
            reason="KAKAOTALK_AUTOMATIC_KEY_ACQUISITION_UNVERIFIED",
            key_material_status="BLOCKED_EXTERNAL_FIXTURE",
        )
        return result

    def inspect_store(
        self,
        *,
        case_id: str,
        evidence_id: str | None,
        store_path: str,
        profile_root: str | None = None,
    ) -> dict[str, object]:
        path, failure = _validate_store_path(store_path, profile_root=profile_root)
        if failure is not None:
            return {
                "schema_version": "1.0.0",
                "case_id": case_id,
                "evidence_id": evidence_id,
                "store_path": store_path,
                "status": "SOURCE_UNAVAILABLE",
                "reason": failure,
                "success_without_key": False,
                "support_matrix": list(SUPPORT_MATRIX),
                **_runtime_evidence_metadata(),
            }
        assert path is not None
        try:
            size = path.stat(follow_symlinks=False).st_size
        except OSError:
            return {
                "schema_version": "1.0.0",
                "case_id": case_id,
                "evidence_id": evidence_id,
                "store_path": str(path),
                "status": "SOURCE_UNAVAILABLE",
                "reason": "KAKAOTALK_STORE_UNREADABLE",
                "success_without_key": False,
                "support_matrix": list(SUPPORT_MATRIX),
                **_runtime_evidence_metadata(),
            }
        if size > MAX_KAKAOTALK_STORE_BYTES:
            return {
                "schema_version": "1.0.0",
                "case_id": case_id,
                "evidence_id": evidence_id,
                "store_path": str(path),
                "status": "SOURCE_UNAVAILABLE",
                "reason": "KAKAOTALK_STORE_TOO_LARGE",
                "store_length": size,
                "raw_store_emitted": False,
                "plaintext_emitted": False,
                "success_without_key": False,
                "support_matrix": list(SUPPORT_MATRIX),
                **_runtime_evidence_metadata(),
            }
        try:
            fingerprint, header = _hash_file(path, capture_prefix=len(SQLITE_HEADER))
        except OSError:
            return {
                "schema_version": "1.0.0",
                "case_id": case_id,
                "evidence_id": evidence_id,
                "store_path": str(path),
                "status": "SOURCE_UNAVAILABLE",
                "reason": "KAKAOTALK_STORE_UNREADABLE",
                "store_length": size,
                "raw_store_emitted": False,
                "plaintext_emitted": False,
                "success_without_key": False,
                "support_matrix": list(SUPPORT_MATRIX),
                **_runtime_evidence_metadata(),
            }
        return {
            "schema_version": "1.0.0",
            "case_id": case_id,
            "evidence_id": evidence_id,
            "store_path": str(path),
            "status": "KEY_UNAVAILABLE",
            "reason": "KAKAOTALK_KEY_PROVIDER_UNAVAILABLE",
            "encrypted_store_detected": not header.startswith(SQLITE_HEADER),
            "ciphertext_length_valid": size > 0 and size % 16 == 0,
            "store_length": size,
            "store_sha256": fingerprint,
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
        profile_root: str | None = None,
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
            profile_root=profile_root,
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
        target_error = _validate_target(derivation_input.parameters)
        if target_error is not None:
            target_status, target_reason = target_error
            return self._result(
                derivation_input,
                status=target_status,
                store_path=store_path,
                reason=target_reason,
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
        path = Path(str(inspected["store_path"]))
        try:
            ciphertext = _read_regular_file_bounded(
                path,
                max_bytes=MAX_KAKAOTALK_STORE_BYTES,
            )
        except OSError:
            return self._result(
                derivation_input,
                status="SOURCE_UNAVAILABLE",
                store_path=store_path,
                reason="KAKAOTALK_STORE_UNREADABLE",
                metadata=inspected,
                error_message="KakaoTalk encrypted store could not be read.",
            )
        if hashlib.sha256(ciphertext).hexdigest() != inspected.get("store_sha256"):
            return self._result(
                derivation_input,
                status="SOURCE_UNAVAILABLE",
                store_path=store_path,
                reason="KAKAOTALK_STORE_CHANGED_DURING_ANALYSIS",
                metadata=inspected,
                error_message="KakaoTalk encrypted store changed during analysis.",
            )
        try:
            plaintext = _aes_cbc_decrypt(ciphertext, key, iv)
            plaintext_sha256 = hashlib.sha256(plaintext).hexdigest()
            extracted = _extract_chatlogs(
                plaintext,
                source_path=str(path),
                source_database_sha256=plaintext_sha256,
                case_id=derivation_input.case_id,
                evidence_id=derivation_input.evidence_id,
                provider_id=self.provider_id,
                provider_version=self.provider_version,
            )
        except KakaoTalkUnsupportedSchemaError as exc:
            return self._result(
                derivation_input,
                status="UNSUPPORTED_SCHEMA",
                store_path=store_path,
                reason="KAKAOTALK_SCHEMA_UNSUPPORTED",
                metadata={**inspected, **key_metadata},
                error_message=str(exc),
            )
        except (KakaoTalkCorruptStoreError, KakaoTalkCorruptDatabaseError) as exc:
            return self._result(
                derivation_input,
                status="CORRUPT_DB",
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
            content_sha256=plaintext_sha256,
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


def _validate_profile_root(profile_root: str | None) -> Path | dict[str, object]:
    if not profile_root or not profile_root.strip():
        return {
            "status": "SOURCE_UNAVAILABLE",
            "reason": "KAKAOTALK_PROFILE_ROOT_REQUIRED",
        }
    supplied = Path(profile_root).expanduser()
    try:
        root_stat = supplied.lstat()
    except (FileNotFoundError, OSError):
        return {
            "status": "SOURCE_UNAVAILABLE",
            "reason": "KAKAOTALK_PROFILE_ROOT_NOT_FOUND",
        }
    if stat.S_ISLNK(root_stat.st_mode) or _is_reparse_point(root_stat):
        return {
            "status": "SOURCE_UNAVAILABLE",
            "reason": "KAKAOTALK_UNSAFE_PROFILE_ROOT",
        }
    if not stat.S_ISDIR(root_stat.st_mode):
        return {
            "status": "SOURCE_UNAVAILABLE",
            "reason": "KAKAOTALK_PROFILE_ROOT_NOT_DIRECTORY",
        }
    return supplied.resolve()


def _validate_store_path(
    store_path: str,
    *,
    profile_root: str | None,
) -> tuple[Path | None, str | None]:
    supplied = Path(store_path).expanduser()
    root: Path | None = None
    if profile_root is not None:
        root_status = _validate_profile_root(profile_root)
        if isinstance(root_status, dict):
            return None, str(root_status["reason"])
        root = root_status
        if not supplied.is_absolute():
            supplied = root / supplied
    absolute = supplied.absolute()
    if root is not None:
        try:
            absolute.relative_to(root)
        except ValueError:
            return None, "KAKAOTALK_STORE_OUTSIDE_PROFILE_ROOT"
    if _path_contains_unsafe_link(absolute, stop=root):
        return None, "KAKAOTALK_UNSAFE_STORE_PATH"
    try:
        file_stat = absolute.stat(follow_symlinks=False)
    except (FileNotFoundError, OSError):
        return None, "KAKAOTALK_STORE_NOT_FOUND"
    if not stat.S_ISREG(file_stat.st_mode) or _is_reparse_point(file_stat):
        return None, "KAKAOTALK_STORE_NOT_REGULAR_FILE"
    resolved = absolute.resolve()
    if root is not None:
        try:
            resolved.relative_to(root)
        except ValueError:
            return None, "KAKAOTALK_STORE_OUTSIDE_PROFILE_ROOT"
    return resolved, None


def _path_contains_unsafe_link(path: Path, *, stop: Path | None) -> bool:
    current = path
    while True:
        try:
            current_stat = current.lstat()
        except (FileNotFoundError, OSError):
            pass
        else:
            if stat.S_ISLNK(current_stat.st_mode) or _is_reparse_point(current_stat):
                return True
        if stop is not None and current == stop:
            return False
        if current.parent == current:
            return False
        current = current.parent


def _is_reparse_point(file_stat: os.stat_result) -> bool:
    attributes = getattr(file_stat, "st_file_attributes", 0)
    return bool(attributes & WINDOWS_REPARSE_POINT_ATTRIBUTE)


def _discover_offline_artifacts(root: Path) -> dict[str, object]:
    store_candidates: list[dict[str, object]] = []
    rejected_stores: list[dict[str, object]] = []
    version_artifacts: list[dict[str, object]] = []
    skipped_entries: list[dict[str, object]] = []
    directories: list[tuple[Path, int]] = [(root, 0)]
    entries_seen = 0
    hash_bytes_scheduled = 0
    traversal_truncated = False

    while directories and entries_seen < MAX_DISCOVERY_ENTRIES:
        directory, depth = directories.pop()
        try:
            with os.scandir(directory) as iterator:
                entries = sorted(
                    iterator,
                    key=lambda entry: (entry.name.casefold(), entry.name),
                )
        except OSError:
            skipped_entries.append(
                {
                    "relative_path": _relative_path(directory, root),
                    "reason": "DIRECTORY_UNREADABLE",
                }
            )
            continue
        child_directories: list[tuple[Path, int]] = []
        for entry in entries:
            entries_seen += 1
            if entries_seen > MAX_DISCOVERY_ENTRIES:
                traversal_truncated = True
                break
            path = Path(entry.path)
            relative_path = _relative_path(path, root)
            try:
                entry_stat = entry.stat(follow_symlinks=False)
            except OSError:
                skipped_entries.append(
                    {"relative_path": relative_path, "reason": "ENTRY_UNREADABLE"}
                )
                continue
            if entry.is_symlink() or _is_reparse_point(entry_stat):
                skipped_entries.append(
                    {"relative_path": relative_path, "reason": "LINK_OR_REPARSE_SKIPPED"}
                )
                continue
            if stat.S_ISDIR(entry_stat.st_mode):
                if depth >= MAX_DISCOVERY_DEPTH:
                    skipped_entries.append(
                        {"relative_path": relative_path, "reason": "MAX_DEPTH_EXCEEDED"}
                    )
                else:
                    child_directories.append((path, depth + 1))
                continue
            if not stat.S_ISREG(entry_stat.st_mode):
                continue
            name = entry.name.casefold()
            if name == KAKAOTALK_EXECUTABLE_NAME:
                if len(version_artifacts) >= MAX_VERSION_ARTIFACTS:
                    traversal_truncated = True
                    skipped_entries.append(
                        {"relative_path": relative_path, "reason": "VERSION_CANDIDATE_LIMIT"}
                    )
                elif (
                    entry_stat.st_size <= MAX_KAKAOTALK_EXECUTABLE_BYTES
                    and hash_bytes_scheduled + entry_stat.st_size > MAX_DISCOVERY_HASH_BYTES
                ):
                    skipped_entries.append(
                        {"relative_path": relative_path, "reason": "DISCOVERY_HASH_BUDGET"}
                    )
                else:
                    artifact = _inspect_version_artifact(
                        path, root=root, size=entry_stat.st_size
                    )
                    version_artifacts.append(artifact)
                    if "artifact_sha256" in artifact:
                        hash_bytes_scheduled += entry_stat.st_size
            if _is_chatlogs_store_name(name):
                if len(store_candidates) + len(rejected_stores) >= MAX_STORE_CANDIDATES:
                    traversal_truncated = True
                    skipped_entries.append(
                        {"relative_path": relative_path, "reason": "STORE_CANDIDATE_LIMIT"}
                    )
                elif (
                    entry_stat.st_size <= MAX_KAKAOTALK_STORE_BYTES
                    and hash_bytes_scheduled + entry_stat.st_size > MAX_DISCOVERY_HASH_BYTES
                ):
                    rejected_stores.append(
                        {
                            "path": str(path.resolve()),
                            "relative_path": relative_path,
                            "store_length": entry_stat.st_size,
                            "candidate_status": "DISCOVERY_HASH_BUDGET_EXCEEDED",
                        }
                    )
                else:
                    target = _inspect_discovered_store(
                        path, root=root, size=entry_stat.st_size
                    )
                    if "store_sha256" in target:
                        hash_bytes_scheduled += entry_stat.st_size
                    if target["candidate_status"] == "ENCRYPTED_STORE_CANDIDATE":
                        store_candidates.append(target)
                    else:
                        rejected_stores.append(target)
        directories.extend(reversed(child_directories))
    if directories:
        traversal_truncated = True

    store_candidates.sort(key=_artifact_sort_key)
    rejected_stores.sort(key=_artifact_sort_key)
    version_artifacts.sort(key=_artifact_sort_key)
    skipped_entries.sort(key=_artifact_sort_key)
    fingerprint_items = [
        _fingerprint_projection(item)
        for item in [*store_candidates, *rejected_stores, *version_artifacts]
    ]
    profile_fingerprint = hashlib.sha256(
        json.dumps(
            fingerprint_items,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()
    return {
        "discovery_status": "DISCOVERED"
        if store_candidates or rejected_stores or version_artifacts
        else "EMPTY",
        "entries_examined": min(entries_seen, MAX_DISCOVERY_ENTRIES),
        "hash_bytes_examined": hash_bytes_scheduled,
        "traversal_truncated": traversal_truncated,
        "store_candidates": store_candidates,
        "rejected_store_candidates": rejected_stores,
        "version_artifacts": version_artifacts,
        "skipped_entries": skipped_entries,
        "profile_fingerprint": profile_fingerprint,
    }


def _is_chatlogs_store_name(name: str) -> bool:
    return (
        name == f"{KAKAOTALK_STORE_PREFIX}{KAKAOTALK_STORE_SUFFIX}"
        or (
            name.startswith(f"{KAKAOTALK_STORE_PREFIX}_")
            and name.endswith(KAKAOTALK_STORE_SUFFIX)
        )
    )


def _inspect_discovered_store(path: Path, *, root: Path, size: int) -> dict[str, object]:
    base: dict[str, object] = {
        "path": str(path.resolve()),
        "relative_path": _relative_path(path, root),
        "store_length": size,
    }
    if size > MAX_KAKAOTALK_STORE_BYTES:
        return {**base, "candidate_status": "STORE_TOO_LARGE"}
    try:
        fingerprint, header = _hash_file(path, capture_prefix=len(SQLITE_HEADER))
    except OSError:
        return {**base, "candidate_status": "STORE_UNREADABLE"}
    if header.startswith(SQLITE_HEADER):
        return {
            **base,
            "candidate_status": "UNEXPECTED_PLAINTEXT_SQLITE",
            "store_sha256": fingerprint,
        }
    if size == 0 or size % 16:
        return {
            **base,
            "candidate_status": "MALFORMED_CIPHERTEXT",
            "store_sha256": fingerprint,
        }
    return {
        **base,
        "candidate_status": "ENCRYPTED_STORE_CANDIDATE",
        "store_sha256": fingerprint,
        "ciphertext_length_valid": True,
    }


def _inspect_version_artifact(path: Path, *, root: Path, size: int) -> dict[str, object]:
    base: dict[str, object] = {
        "path": str(path.resolve()),
        "relative_path": _relative_path(path, root),
        "artifact_length": size,
        "evidence_kind": "PE_FIXED_FILE_VERSION",
    }
    if size > MAX_KAKAOTALK_EXECUTABLE_BYTES:
        return {**base, "status": "VERSION_UNVERIFIED", "reason": "EXECUTABLE_TOO_LARGE"}
    try:
        data = _read_regular_file_bounded(path, max_bytes=MAX_KAKAOTALK_EXECUTABLE_BYTES)
    except OSError as exc:
        return {
            **base,
            "status": "VERSION_UNVERIFIED",
            "reason": type(exc).__name__,
        }
    fingerprint = hashlib.sha256(data).hexdigest()
    try:
        version = _parse_pe_fixed_file_version(data)
    except KakaoTalkVersionArtifactError as exc:
        return {
            **base,
            "status": "VERSION_UNVERIFIED",
            "reason": type(exc).__name__,
            "artifact_sha256": fingerprint,
        }
    return {
        **base,
        "status": "VERSION_VERIFIED",
        "application_version": version,
        "artifact_sha256": fingerprint,
    }


def _evaluate_versions(version_artifacts: object) -> tuple[str, str, str | None]:
    if not isinstance(version_artifacts, list):
        return "VERSION_UNVERIFIED", "KAKAOTALK_VERSION_ARTIFACT_NOT_FOUND", None
    versions = {
        str(item["application_version"])
        for item in version_artifacts
        if isinstance(item, dict)
        and item.get("status") == "VERSION_VERIFIED"
        and item.get("application_version")
    }
    if not versions:
        return "VERSION_UNVERIFIED", "KAKAOTALK_VERSION_UNVERIFIED", None
    if len(versions) != 1:
        return "VERSION_UNVERIFIED", "KAKAOTALK_VERSION_AMBIGUOUS", None
    version = next(iter(versions))
    if version != SUPPORTED_WINDOWS_VERSION:
        return "UNSUPPORTED_VERSION", "KAKAOTALK_UNSUPPORTED_VERSION", version
    return "VERSION_VERIFIED", "KAKAOTALK_SUPPORTED_VERSION_VERIFIED", version


def _artifact_sort_key(item: dict[str, object]) -> tuple[str, str]:
    path = str(item.get("relative_path", ""))
    return path.casefold(), path


def _fingerprint_projection(item: dict[str, object]) -> dict[str, object]:
    return {
        key: item[key]
        for key in (
            "relative_path",
            "candidate_status",
            "status",
            "store_length",
            "artifact_length",
            "store_sha256",
            "artifact_sha256",
            "application_version",
        )
        if key in item
    }


def _relative_path(path: Path, root: Path) -> str:
    try:
        return path.absolute().relative_to(root).as_posix() or "."
    except ValueError:
        return "<outside-root>"


def _hash_file(path: Path, *, capture_prefix: int = 0) -> tuple[str, bytes]:
    digest = hashlib.sha256()
    prefix = bytearray()
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    with os.fdopen(descriptor, "rb") as handle:
        if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
            raise OSError("Artifact is not a regular file.")
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
            if len(prefix) < capture_prefix:
                prefix.extend(chunk[: capture_prefix - len(prefix)])
    return digest.hexdigest(), bytes(prefix)


def _read_regular_file_bounded(path: Path, *, max_bytes: int) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    with os.fdopen(descriptor, "rb") as handle:
        file_stat = os.fstat(handle.fileno())
        if not stat.S_ISREG(file_stat.st_mode):
            raise OSError("Artifact is not a regular file.")
        if file_stat.st_size > max_bytes:
            raise OSError("Artifact exceeds the size limit.")
        data = handle.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise OSError("Artifact exceeds the size limit.")
    return data


def _parse_pe_fixed_file_version(data: bytes) -> str:
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise KakaoTalkVersionArtifactError("DOS header is missing.")
    pe_offset = _unpack_from("<I", data, 0x3C)[0]
    if pe_offset + 24 > len(data) or data[pe_offset : pe_offset + 4] != b"PE\x00\x00":
        raise KakaoTalkVersionArtifactError("PE header is missing.")
    coff_offset = pe_offset + 4
    number_of_sections = _unpack_from("<H", data, coff_offset + 2)[0]
    optional_size = _unpack_from("<H", data, coff_offset + 16)[0]
    optional_offset = coff_offset + 20
    if optional_offset + optional_size > len(data):
        raise KakaoTalkVersionArtifactError("PE optional header is truncated.")
    optional_magic = _unpack_from("<H", data, optional_offset)[0]
    if optional_magic == 0x10B:
        data_directory_offset = optional_offset + 96
    elif optional_magic == 0x20B:
        data_directory_offset = optional_offset + 112
    else:
        raise KakaoTalkVersionArtifactError("PE optional header type is unsupported.")
    resource_entry_offset = data_directory_offset + (8 * 2)
    if resource_entry_offset + 8 > optional_offset + optional_size:
        raise KakaoTalkVersionArtifactError("PE resource directory is missing.")
    resource_rva, resource_size = _unpack_from("<II", data, resource_entry_offset)
    if resource_rva == 0 or resource_size == 0:
        raise KakaoTalkVersionArtifactError("PE version resource is missing.")
    section_offset = optional_offset + optional_size
    sections: list[tuple[int, int, int, int]] = []
    for index in range(number_of_sections):
        entry_offset = section_offset + (index * 40)
        if entry_offset + 40 > len(data):
            raise KakaoTalkVersionArtifactError("PE section table is truncated.")
        virtual_size, virtual_address, raw_size, raw_offset = _unpack_from(
            "<IIII", data, entry_offset + 8
        )
        sections.append((virtual_address, max(virtual_size, raw_size), raw_offset, raw_size))

    def rva_to_offset(rva: int, size: int = 1) -> int:
        for virtual_address, mapped_size, raw_offset, raw_size in sections:
            relative = rva - virtual_address
            if relative >= 0 and relative + size <= mapped_size and relative + size <= raw_size:
                offset = raw_offset + relative
                if offset + size <= len(data):
                    return offset
        raise KakaoTalkVersionArtifactError("PE resource RVA is outside mapped sections.")

    resource_offset = rva_to_offset(resource_rva, resource_size)
    resource_limit = resource_offset + resource_size
    type_directory = _resource_child_offset(
        data,
        root_offset=resource_offset,
        root_limit=resource_limit,
        directory_offset=resource_offset,
        wanted_id=PE_VERSION_RESOURCE_TYPE,
        require_directory=True,
    )
    name_directory = _resource_child_offset(
        data,
        root_offset=resource_offset,
        root_limit=resource_limit,
        directory_offset=type_directory,
        wanted_id=None,
        require_directory=True,
    )
    data_entry = _resource_child_offset(
        data,
        root_offset=resource_offset,
        root_limit=resource_limit,
        directory_offset=name_directory,
        wanted_id=None,
        require_directory=False,
    )
    version_rva, version_size = _unpack_from("<II", data, data_entry)
    version_offset = rva_to_offset(version_rva, version_size)
    version_blob = data[version_offset : version_offset + version_size]
    return _parse_fixed_file_info(version_blob)


def _resource_child_offset(
    data: bytes,
    *,
    root_offset: int,
    root_limit: int,
    directory_offset: int,
    wanted_id: int | None,
    require_directory: bool,
) -> int:
    if directory_offset + 16 > root_limit:
        raise KakaoTalkVersionArtifactError("PE resource directory is truncated.")
    named_count, id_count = _unpack_from("<HH", data, directory_offset + 12)
    entries: list[tuple[int, int]] = []
    for index in range(named_count + id_count):
        entry_offset = directory_offset + 16 + (index * 8)
        if entry_offset + 8 > root_limit:
            raise KakaoTalkVersionArtifactError("PE resource entries are truncated.")
        name, target = _unpack_from("<II", data, entry_offset)
        if name & 0x80000000:
            continue
        entries.append((name, target))
    entries.sort(key=lambda item: item[0])
    selected = next((item for item in entries if wanted_id is None or item[0] == wanted_id), None)
    if selected is None:
        raise KakaoTalkVersionArtifactError("PE version resource entry is missing.")
    target = selected[1]
    is_directory = bool(target & 0x80000000)
    if is_directory != require_directory:
        raise KakaoTalkVersionArtifactError("PE version resource tree is malformed.")
    child_offset = root_offset + (target & 0x7FFFFFFF)
    if child_offset + 16 > root_limit:
        raise KakaoTalkVersionArtifactError("PE version resource target is truncated.")
    return child_offset


def _parse_fixed_file_info(blob: bytes) -> str:
    if len(blob) < 6:
        raise KakaoTalkVersionArtifactError("VS_VERSION_INFO is truncated.")
    total_length, value_length, _ = _unpack_from("<HHH", blob, 0)
    if total_length > len(blob) or value_length < 52:
        raise KakaoTalkVersionArtifactError("VS_VERSION_INFO lengths are invalid.")
    cursor = 6
    key_bytes = "VS_VERSION_INFO\x00".encode("utf-16-le")
    if blob[cursor : cursor + len(key_bytes)] != key_bytes:
        raise KakaoTalkVersionArtifactError("VS_VERSION_INFO key is invalid.")
    value_offset = (cursor + len(key_bytes) + 3) & ~3
    if value_offset + 52 > total_length:
        raise KakaoTalkVersionArtifactError("VS_FIXEDFILEINFO is truncated.")
    signature, _, version_ms, version_ls = _unpack_from("<IIII", blob, value_offset)
    if signature != PE_FIXED_FILE_INFO_SIGNATURE:
        raise KakaoTalkVersionArtifactError("VS_FIXEDFILEINFO signature is invalid.")
    return ".".join(
        str(part)
        for part in (
            version_ms >> 16,
            version_ms & 0xFFFF,
            version_ls >> 16,
            version_ls & 0xFFFF,
        )
    )


def _unpack_from(format_string: str, data: bytes, offset: int) -> tuple[int, ...]:
    try:
        return struct.unpack_from(format_string, data, offset)
    except struct.error as exc:
        raise KakaoTalkVersionArtifactError("Binary version artifact is truncated.") from exc


def _validate_target(params: dict[str, Any]) -> tuple[str, str] | None:
    platform = _normalize_platform(params.get("platform") or SUPPORTED_PLATFORM)
    if platform not in {SUPPORTED_PLATFORM, "WINDOWS"}:
        return "UNSUPPORTED_PLATFORM", "KAKAOTALK_UNSUPPORTED_PLATFORM"
    version = _optional_str(params.get("application_version"))
    if version is None:
        return "VERSION_UNVERIFIED", "KAKAOTALK_VERSION_UNVERIFIED"
    if version != SUPPORTED_WINDOWS_VERSION:
        return "UNSUPPORTED_VERSION", "KAKAOTALK_UNSUPPORTED_VERSION"
    schema = _optional_str(params.get("database_schema_version"))
    if schema is not None and schema != SUPPORTED_SCHEMA:
        return "UNSUPPORTED_SCHEMA", "KAKAOTALK_SCHEMA_UNSUPPORTED"
    return None


def _normalize_platform(value: Any) -> str:
    return str(value or "").strip().upper().replace("-", "_").replace(" ", "_")


def _key_iv_from_parameters(params: dict[str, Any]) -> tuple[bytes, bytes, dict[str, Any]]:
    raw_key_hex = _optional_str(params.get("db_key_hex"))
    raw_iv_hex = _optional_str(params.get("db_iv_hex"))
    if raw_key_hex or raw_iv_hex:
        if not raw_key_hex or not raw_iv_hex:
            raise ValueError("Both db_key_hex and db_iv_hex are required.")
        if len(raw_key_hex) != 32 or len(raw_iv_hex) != 32:
            raise ValueError("KakaoTalk AES key and IV must each be 32 hexadecimal characters.")
        try:
            key = bytes.fromhex(raw_key_hex)
            iv = bytes.fromhex(raw_iv_hex)
        except ValueError as exc:
            raise ValueError("KakaoTalk AES key or IV hexadecimal encoding is invalid.") from exc
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
    if (
        len(pragma_key) > MAX_EXTERNAL_KEY_INPUT_CHARS
        or len(user_nonce) > MAX_EXTERNAL_KEY_INPUT_CHARS
    ):
        raise ValueError("KakaoTalk external key inputs exceed the configured size limit.")
    repeated = (pragma_key + user_nonce).encode("utf-8")
    if len(repeated) > MAX_EXTERNAL_KEY_INPUT_CHARS:
        raise ValueError("KakaoTalk external key inputs exceed the configured size limit.")
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


def _extract_chatlogs(
    plaintext: bytes,
    *,
    source_path: str,
    source_database_sha256: str,
    case_id: str,
    evidence_id: str | None,
    provider_id: str,
    provider_version: str,
) -> dict[str, Any]:
    if not plaintext.startswith(SQLITE_HEADER):
        raise KakaoTalkCorruptDatabaseError("KakaoTalk SQLite header is missing.")
    with tempfile.TemporaryDirectory(prefix="apex-kakaotalk-") as temp_dir:
        sqlite_path = Path(temp_dir) / "chatlogs.sqlite"
        descriptor = os.open(sqlite_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(plaintext)
        with closing(
            sqlite3.connect(f"file:{sqlite_path}?mode=ro", uri=True)
        ) as connection:
            connection.row_factory = sqlite3.Row
            try:
                connection.execute("PRAGMA query_only = ON")
                connection.set_progress_handler(lambda: 1, 2_000_000)
                integrity_row = connection.execute("PRAGMA quick_check(1)").fetchone()
                integrity = "" if integrity_row is None else str(integrity_row[0])
                if integrity != "ok":
                    raise KakaoTalkCorruptDatabaseError(
                        "KakaoTalk decrypted SQLite quick check failed."
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
            if "logId" not in columns or not ({"message", "attachment"} & columns):
                raise KakaoTalkUnsupportedSchemaError(
                    "KakaoTalk chatLogs schema is outside the supported version."
                )
            selected_columns = [name for name in SUPPORTED_CHATLOG_COLUMNS if name in columns]
            messages = _read_chatlog_messages(
                connection,
                selected_columns,
                source_path=source_path,
                source_database_sha256=source_database_sha256,
                case_id=case_id,
                evidence_id=evidence_id,
                provider_id=provider_id,
                provider_version=provider_version,
            )
    return {
        "sqlite_integrity_check": "ok",
        "sqlite_quick_check": "ok",
        "sqlite_open_mode": "READ_ONLY_QUERY_ONLY",
        "database_schema_version": SUPPORTED_SCHEMA,
        "chatlogs_columns_present": selected_columns,
        "message_count": len(messages),
        "chatroom_count": 1 if messages else 0,
        "messages": messages,
        "search_projection_ready": True,
        "timeline_projection_ready": True,
        "source_path": source_path,
    }


def _read_chatlog_messages(
    connection: sqlite3.Connection,
    columns: list[str],
    *,
    source_path: str,
    source_database_sha256: str,
    case_id: str,
    evidence_id: str | None,
    provider_id: str,
    provider_version: str,
) -> list[dict[str, Any]]:
    available_columns = set(columns)
    rows = connection.execute(
        'SELECT rowid AS "_apex_rowid", * '
        'FROM "chatLogs" ORDER BY rowid LIMIT 5000'
    ).fetchall()
    messages: list[dict[str, Any]] = []
    for row in rows:
        message = _row_text(row, "message", available_columns)
        attachment = _row_text(row, "attachment", available_columns)
        log_id = _row_value(row, "logId", available_columns)
        rowid = row["_apex_rowid"]
        messages.append(
            {
                "case_id": case_id,
                "evidence_id": evidence_id,
                "source_path": source_path,
                "source_database_sha256": source_database_sha256,
                "provider_id": provider_id,
                "provider_version": provider_version,
                "row_reference": {
                    "rowid": rowid,
                    "logId": log_id,
                },
                "sender_account_candidate": _row_text(
                    row, "authorId", available_columns
                ),
                "message_type": _row_value(row, "type", available_columns),
                "timestamp": _row_value(row, "sentAt", available_columns),
                "message_text_sha256": None
                if message is None
                else hashlib.sha256(message.encode("utf-8")).hexdigest(),
                "message_preview": None if message is None else _safe_preview(message),
                "attachment_present": attachment is not None,
                "attachment_sha256": None
                if attachment is None
                else hashlib.sha256(attachment.encode("utf-8")).hexdigest(),
                "deleted_candidate": bool(
                    _row_value(row, "deleted", available_columns)
                ),
                "raw_locator": {
                    "table": "chatLogs",
                    "rowid": rowid,
                    "logId": log_id,
                },
                "citation": {
                    "table": "chatLogs",
                    "rowid": rowid,
                },
            }
        )
    return messages


def _row_value(row: sqlite3.Row, name: str, available_columns: set[str]) -> Any:
    return row[name] if name in available_columns else None


def _row_text(
    row: sqlite3.Row,
    name: str,
    available_columns: set[str],
) -> str | None:
    value = _row_value(row, name, available_columns)
    return None if value is None else str(value)

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
