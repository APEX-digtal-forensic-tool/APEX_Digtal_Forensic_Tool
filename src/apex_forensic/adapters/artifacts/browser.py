"""Browser communications artifact analyzer for Phase 5."""

from __future__ import annotations

import hashlib
import importlib
import shutil
import sqlite3
import tempfile
from collections.abc import Iterator
from contextlib import closing, contextmanager, suppress
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import urlparse

from apex_forensic._time import to_json_timestamp
from apex_forensic.adapters.artifacts.windows.common import (
    issue,
    make_artifact,
    make_raw_locator,
    source_shell,
)
from apex_forensic.constants import ENGINE_VERSION
from apex_forensic.domain.enums import (
    ArtifactParseStatus,
    ArtifactSourceKind,
    ArtifactType,
    FileSystemNodeType,
)
from apex_forensic.domain.models import (
    ArtifactAnalysisResult,
    ArtifactCapability,
    ArtifactIssue,
    ArtifactRecord,
    ArtifactSource,
    Evidence,
    FileSystemNode,
)
from apex_forensic.domain.services.canonical import canonical_sha256

_WEBKIT_EPOCH = datetime(1601, 1, 1, tzinfo=UTC)
_UNIX_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)
_BROWSER_NAMES = {
    "google/chrome": ("CHROMIUM", "GOOGLE_CHROME"),
    "google-chrome": ("CHROMIUM", "GOOGLE_CHROME"),
    "chrome": ("CHROMIUM", "GOOGLE_CHROME"),
    "microsoft/edge": ("CHROMIUM", "MICROSOFT_EDGE"),
    "edge": ("CHROMIUM", "MICROSOFT_EDGE"),
    "chromium": ("CHROMIUM", "CHROMIUM"),
    "bravesoftware/brave-browser": ("CHROMIUM", "BRAVE"),
    "brave": ("CHROMIUM", "BRAVE"),
    "opera": ("CHROMIUM", "OPERA"),
    "firefox": ("FIREFOX", "FIREFOX"),
}
_CHROMIUM_PROFILE_NAMES = {"default", "guest profile", "system profile"}
_BROWSER_SQLITE_BATCH_SIZE = 100
_BROWSER_CACHE_PREVIEW_MAX_BYTES = 16 * 1024 * 1024
_CHROMIUM_SECRET_PREFIXES = (b"v10", b"v11", b"v20")


@dataclass(frozen=True, slots=True)
class _BrowserSQLiteSnapshot:
    database_path: Path
    metadata: dict[str, Any]


@dataclass(frozen=True, slots=True)
class _BrowserExtractionPage:
    artifacts: tuple[ArtifactRecord, ...]
    checkpoint: dict[str, Any] | None
    source_complete: bool
    inspected_count: int


@dataclass(frozen=True, slots=True)
class _BrowserStreamPage:
    artifacts: tuple[ArtifactRecord, ...]
    last_row_id: int | None
    has_more: bool


class _BrowserSQLiteSnapshotCleanupError(OSError):
    """Snapshot cleanup failed after the copied database was analyzed."""

    def __init__(self, snapshot_directory: Path, original_error: OSError) -> None:
        super().__init__(str(original_error))
        self.snapshot_directory = snapshot_directory
        self.original_error = original_error


class BrowserHistoryAnalyzer:
    """Read-only analyzer for browser history SQLite databases."""

    analyzer_id = "browser.history"
    analyzer_version = ENGINE_VERSION

    @property
    def parser_backend(self) -> str:
        return "apex.browser_sqlite"

    @property
    def parser_backend_version(self) -> str:
        return ENGINE_VERSION

    def capabilities(self) -> ArtifactCapability:
        return ArtifactCapability(
            analyzer_id=self.analyzer_id,
            analyzer_version=self.analyzer_version,
            parser_backend=self.parser_backend,
            parser_backend_version=self.parser_backend_version,
            supported_source_kinds=(
                ArtifactSourceKind.BROWSER_SQLITE_DB,
                ArtifactSourceKind.BROWSER_CACHE_FILE,
            ),
            supported_artifact_types=(
                ArtifactType.BROWSER_PROFILE,
                ArtifactType.BROWSER_VISIT,
                ArtifactType.BROWSER_SEARCH,
                ArtifactType.BROWSER_DOWNLOAD,
                ArtifactType.BROWSER_COOKIE,
                ArtifactType.BROWSER_CREDENTIAL,
                ArtifactType.BROWSER_CACHE_ENTRY,
                ArtifactType.BROWSER_DELETED_SQLITE_ROW,
                ArtifactType.BROWSER_PRIVATE_MODE_CANDIDATE,
            ),
            capabilities=(
                "BROWSER_PROFILE",
                "CHROMIUM_HISTORY_VISITS",
                "CHROMIUM_SEARCH_TERMS",
                "CHROMIUM_DOWNLOADS",
                "CHROMIUM_COOKIE_METADATA_REDACTED",
                "CHROMIUM_LOGIN_METADATA_REDACTED",
                "FIREFOX_COOKIE_METADATA_REDACTED",
                "CHROMIUM_CACHE_FILE_CANDIDATE_METADATA",
                "FIREFOX_PLACES_VISITS",
                "FIREFOX_URLBAR_INPUT_HISTORY_CANDIDATE",
                "SQLITE_TABLE_ROW_PROVENANCE",
                "SQLITE_FREELIST_PRESENCE_CANDIDATE",
                "SQLITE_WAL_COMPONENT_PRESERVATION",
                "BROWSER_SECRET_HASH_ONLY",
                "INCOGNITO_CANDIDATE_ONLY_POLICY",
                "READ_ONLY_SQLITE_OPEN",
            ),
            unavailable_capabilities=(
                "EMAIL",
                "MESSENGER_PLUGINS",
                "LIVE_USER_CONTEXT_SECRET_EXTRACTION",
                "DPAPI_LIVE_USER_UNPROTECT",
                "FIREFOX_KEY4_DECRYPTION",
                "SQLITE_DELETED_ROW_CONTENT_RECOVERY",
                "CHROMIUM_CACHE_HTTP_HEADER_PARSE",
            ),
            warnings=(
                {
                    "code": "COMMUNICATION_PLUGINS_DEFERRED",
                    "message_key": "warning.browser.communication_plugins_deferred",
                    "developer_message": (
                        "Email and messenger analyzers are plugin scope and are not part of "
                        "the Phase 5 MVP."
                    ),
                },
                {
                    "code": "BROWSER_SECRET_VALUES_REDACTED",
                    "message_key": "warning.browser.secret_values_redacted",
                    "developer_message": (
                        "Cookie and credential values are not emitted as plaintext; records "
                        "store redacted metadata and hashes only unless an explicit protected "
                        "secret-decryption workflow is used."
                    ),
                },
            ),
            metadata={
                "supported_databases": [
                    "Chromium History",
                    "Chromium Cookies",
                    "Chromium Login Data",
                    "Firefox places.sqlite",
                    "Firefox cookies.sqlite",
                ],
                "cache_support": {
                    "status": "PARTIAL",
                    "supported": "Chromium opaque cache file candidates",
                    "body_offset_length": True,
                    "bounded_preview_max_bytes": _BROWSER_CACHE_PREVIEW_MAX_BYTES,
                },
                "secret_handling": _browser_secret_policy(),
                "decryption": {
                    "chromium_aes_gcm": {
                        "status": "AVAILABLE_WITH_EXTERNAL_KEY"
                        if _aes_gcm_available()
                        else "CAPABILITY_UNAVAILABLE",
                        "key_source": "EXPLICIT_EXTERNAL_KEY_ONLY",
                        "loads_evidence_libraries": False,
                        "live_user_context": False,
                    },
                    "dpapi": {
                        "status": "CAPABILITY_UNAVAILABLE",
                        "reason": "No live user-context unprotect operation is performed.",
                    },
                },
                "deleted_sqlite_records": {
                    "wal_components_preserved": True,
                    "freelist_presence_candidates": True,
                    "deleted_row_content_recovery": "CAPABILITY_UNAVAILABLE",
                    "candidate_records_are_not_confirmed_rows": True,
                },
                "incognito": _private_mode_policy(),
            },
        )

    def detect_source(self, node: FileSystemNode) -> ArtifactSource | None:
        if node.node_type is not FileSystemNodeType.FILE:
            return None
        if _profile_info(node) is not None:
            return source_shell(
                node=node,
                source_kind=ArtifactSourceKind.BROWSER_SQLITE_DB,
                analyzer_id=self.analyzer_id,
                analyzer_version=self.analyzer_version,
                parser_backend=self.parser_backend,
                parser_backend_version=self.parser_backend_version,
                priority=55,
            )
        if _cache_file_info(node) is not None:
            return source_shell(
                node=node,
                source_kind=ArtifactSourceKind.BROWSER_CACHE_FILE,
                analyzer_id=self.analyzer_id,
                analyzer_version=self.analyzer_version,
                parser_backend="apex.browser_cache_file",
                parser_backend_version=self.parser_backend_version,
                priority=45,
            )
        return None

    def supports_source(self, source: ArtifactSource) -> bool:
        return source.source_kind in {
            ArtifactSourceKind.BROWSER_SQLITE_DB,
            ArtifactSourceKind.BROWSER_CACHE_FILE,
        }

    def analyze(
        self,
        *,
        evidence: Evidence,
        node: FileSystemNode,
        source: ArtifactSource,
        file_path: Path,
        item_budget: int | None = None,
    ) -> ArtifactAnalysisResult:
        if source.source_kind is ArtifactSourceKind.BROWSER_CACHE_FILE:
            return _analyze_cache_file(
                evidence=evidence,
                node=node,
                source=source,
                file_path=file_path,
            )
        try:
            content_sha256 = _sha256_file(file_path)
        except OSError as error:
            return ArtifactAnalysisResult(
                errors=(
                    issue(
                        severity="ERROR",
                        code="BROWSER_DB_READ_FAILED",
                        message_key="error.browser.db_read_failed",
                        developer_message="Browser SQLite database could not be read.",
                        node=node,
                        details={"error": str(error)},
                    ),
                ),
                parse_status=ArtifactParseStatus.FAILED,
            )
        profile = _profile_info(node)
        if profile is None:
            return ArtifactAnalysisResult(
                warnings=(
                    issue(
                        severity="WARNING",
                        code="BROWSER_PROFILE_PATH_UNSUPPORTED",
                        message_key="warning.browser.profile_path_unsupported",
                        developer_message=(
                            "Browser database path did not match the Phase 5 allowlist."
                        ),
                        node=node,
                    ),
                ),
                parse_status=ArtifactParseStatus.UNSUPPORTED,
            )
        cleanup_warning: ArtifactIssue | None = None
        page: _BrowserExtractionPage | None = None
        db_kind = "UNKNOWN"
        try:
            with _browser_sqlite_snapshot(file_path) as snapshot:
                profile = profile | {"snapshot": snapshot.metadata}
                with closing(_connect_read_only(snapshot.database_path)) as connection:
                    connection.row_factory = sqlite3.Row
                    tables = _table_columns(connection)
                    db_kind = _database_kind(tables, profile)
                    if db_kind == "UNKNOWN":
                        artifact = _profile_artifact(
                            evidence=evidence,
                            node=node,
                            source=source,
                            content_sha256=content_sha256,
                            profile=profile,
                            db_kind=db_kind,
                            tables=tables,
                            parse_status=ArtifactParseStatus.UNSUPPORTED,
                            warnings=[
                                {
                                    "code": "BROWSER_DB_SCHEMA_UNSUPPORTED",
                                    "message_key": "warning.browser.schema_unsupported",
                                    "developer_message": (
                                        "SQLite database did not match supported browser schemas."
                                    ),
                                }
                            ],
                        )
                        return _result_with_warnings(
                            artifact,
                            node,
                            ArtifactParseStatus.UNSUPPORTED,
                        )
                    page = _browser_extraction_page(
                        connection=connection,
                        evidence=evidence,
                        node=node,
                        source=source,
                        content_sha256=content_sha256,
                        profile=profile,
                        db_kind=db_kind,
                        tables=tables,
                        item_budget=item_budget,
                    )
        except _BrowserSQLiteSnapshotCleanupError as error:
            if page is None:
                return ArtifactAnalysisResult(
                    errors=(
                        issue(
                            severity="ERROR",
                            code="BROWSER_SNAPSHOT_CLEANUP_FAILED",
                            message_key="error.browser.snapshot_cleanup_failed",
                            developer_message=(
                                "Browser SQLite snapshot cleanup failed before analysis results "
                                "could be returned."
                            ),
                            node=node,
                            details={
                                "error": str(error.original_error),
                                "snapshot_directory": str(error.snapshot_directory),
                            },
                        ),
                    ),
                    parse_status=ArtifactParseStatus.FAILED,
                )
            cleanup_warning = issue(
                severity="WARNING",
                code="BROWSER_SNAPSHOT_CLEANUP_FAILED",
                message_key="warning.browser.snapshot_cleanup_failed",
                developer_message=(
                    "Browser SQLite snapshot cleanup failed after extraction; analysis results "
                    "were preserved."
                ),
                node=node,
                details={
                    "error": str(error.original_error),
                    "snapshot_directory": str(error.snapshot_directory),
                },
            )
        except sqlite3.DatabaseError as error:
            artifact = _corrupt_db_artifact(
                evidence=evidence,
                node=node,
                source=source,
                content_sha256=content_sha256,
                profile=profile,
                error=str(error),
            )
            return _result_with_warnings(artifact, node, ArtifactParseStatus.CORRUPT)
        except OSError as error:
            return ArtifactAnalysisResult(
                errors=(
                    issue(
                        severity="ERROR",
                        code="BROWSER_DB_OPEN_FAILED",
                        message_key="error.browser.db_open_failed",
                        developer_message="Browser SQLite database could not be opened.",
                        node=node,
                        details={"error": str(error)},
                    ),
                ),
                parse_status=ArtifactParseStatus.FAILED,
            )

        if page is None:
            return ArtifactAnalysisResult(parse_status=ArtifactParseStatus.FAILED)
        warnings = tuple(
            warning for artifact in page.artifacts for warning in _artifact_warnings(artifact, node)
        )
        if cleanup_warning is not None:
            warnings = (*warnings, cleanup_warning)
        status = (
            ArtifactParseStatus.PARTIAL
            if warnings or not page.source_complete
            else ArtifactParseStatus.SUCCESS
        )
        return ArtifactAnalysisResult(
            artifacts=page.artifacts,
            warnings=warnings,
            coverage={
                "database_kind": db_kind,
                "artifact_count": len(page.artifacts),
            },
            parse_status=status,
            source_checkpoint=page.checkpoint,
            source_complete=page.source_complete,
            inspected_count=page.inspected_count,
            source_fingerprint=profile["snapshot"].get("source_fingerprint"),
        )


def _connect_read_only(path: Path) -> sqlite3.Connection:
    resolved = path.resolve(strict=True)
    uri = f"{resolved.as_uri()}?mode=ro"
    return sqlite3.connect(uri, uri=True)


@contextmanager
def _browser_sqlite_snapshot(path: Path) -> Iterator[_BrowserSQLiteSnapshot]:
    temporary_directory = tempfile.TemporaryDirectory(prefix="apex-browser-snapshot-")
    temp_dir = Path(temporary_directory.name)
    try:
        snapshot_main = temp_dir / path.name
        shutil.copy2(path, snapshot_main)
        component_hashes = {"main": _sha256_file(path)}
        component_sizes = {"main": path.stat().st_size}
        wal_preserved = False
        shm_preserved = False
        for suffix, key in (("-wal", "wal"), ("-shm", "shm")):
            source_component = path.with_name(path.name + suffix)
            if not source_component.exists():
                continue
            target_component = snapshot_main.with_name(snapshot_main.name + suffix)
            shutil.copy2(source_component, target_component)
            component_hashes[key] = _sha256_file(source_component)
            component_sizes[key] = source_component.stat().st_size
            if key == "wal":
                wal_preserved = True
            else:
                shm_preserved = True
        snapshot_hash = canonical_sha256(
            {
                "source_path": str(path),
                "component_hashes": component_hashes,
                "component_sizes": component_sizes,
            }
        )
        yield _BrowserSQLiteSnapshot(
            database_path=snapshot_main,
            metadata={
                "snapshot_hash": snapshot_hash,
                "source_fingerprint": snapshot_hash,
                "component_hashes": component_hashes,
                "component_sizes": component_sizes,
                "wal_preserved": wal_preserved,
                "shm_preserved": shm_preserved,
                "snapshot_location": str(temp_dir.parent),
                "cleanup_policy": "temporary_directory_cleanup_after_analysis",
                "read_policy": "copied_snapshot_read_only_selects",
            },
        )
    except BaseException:
        with suppress(OSError):
            temporary_directory.cleanup()
        raise
    else:
        try:
            temporary_directory.cleanup()
        except OSError as error:
            raise _BrowserSQLiteSnapshotCleanupError(temp_dir, error) from error


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_text(value: Any) -> str | None:
    text = _none_or_str(value)
    if text is None:
        return None
    return hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()


def _bytes_or_none(value: Any) -> bytes | None:
    if value is None:
        return None
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray):
        return bytes(value)
    if isinstance(value, memoryview):
        return value.tobytes()
    if isinstance(value, str):
        return value.encode("utf-8", "surrogatepass")
    try:
        return bytes(value)
    except (TypeError, ValueError):
        return None


def _none_or_str(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value)
    return text if text else None


def _str_or_empty(value: Any) -> str:
    return _none_or_str(value) or ""


def _text_length(value: Any) -> int | None:
    text = _none_or_str(value)
    return None if text is None else len(text)


def _first_non_empty(*values: Any) -> Any | None:
    for value in values:
        if value not in (None, ""):
            return value
    return None


def _bool_or_none(value: Any) -> bool | None:
    if value is None:
        return None
    try:
        return bool(int(value))
    except (TypeError, ValueError):
        return bool(value)


def _sql_column_or_null(tables: dict[str, list[str]], table: str, column: str) -> str:
    alias = _quote_identifier(column)
    if _has_columns(tables, table, {column}):
        return f"{_quote_identifier(table)}.{_quote_identifier(column)} AS {alias}"
    return f"NULL AS {alias}"


def _pragma_int(connection: sqlite3.Connection, name: str) -> int:
    row = connection.execute(f"PRAGMA {name}").fetchone()
    if row is None:
        return 0
    try:
        return int(row[0] or 0)
    except (TypeError, ValueError):
        return 0


def _cookie_secret_metadata(
    *,
    plaintext_value: Any,
    encrypted_value: Any,
    store_kind: str,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    encrypted_blob = _bytes_or_none(encrypted_value)
    plaintext = _none_or_str(plaintext_value)
    metadata = _secret_value_policy(store_kind)
    metadata["plaintext_value_present"] = plaintext is not None
    metadata["plaintext_value_redacted"] = plaintext is not None
    metadata["encrypted_value_present"] = bool(encrypted_blob)
    if encrypted_blob:
        metadata |= _chromium_secret_blob_metadata(encrypted_blob)
        return metadata, [_secret_warning("BROWSER_SECRET_DECRYPTION_KEY_UNAVAILABLE")]
    if plaintext is not None:
        metadata["decryption_status"] = "PLAINTEXT_REDACTED"
        metadata["decryption_failure_reason"] = None
        return metadata, [_secret_warning("BROWSER_SECRET_REDACTED")]
    metadata["decryption_status"] = "NO_SECRET_VALUE"
    metadata["decryption_failure_reason"] = None
    return metadata, []


def _credential_secret_metadata(
    *,
    username_value: Any,
    password_value: Any,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    password_blob = _bytes_or_none(password_value)
    username = _none_or_str(username_value)
    metadata = _secret_value_policy("CHROMIUM_LOGIN")
    metadata.update(
        {
            "username_present": username is not None,
            "username_sha256": _sha256_text(username),
            "username_length": _text_length(username),
            "username_plaintext_redacted": username is not None,
            "password_value_present": bool(password_blob),
            "password_plaintext_emitted": False,
        }
    )
    if password_blob:
        metadata |= _chromium_secret_blob_metadata(password_blob)
        return metadata, [_secret_warning("BROWSER_SECRET_DECRYPTION_KEY_UNAVAILABLE")]
    metadata["decryption_status"] = "NO_SECRET_VALUE"
    metadata["decryption_failure_reason"] = None
    return metadata, []


def _secret_value_policy(store_kind: str) -> dict[str, Any]:
    return {
        "secret_store_kind": store_kind,
        "secret_redaction": {
            "plaintext_emitted": False,
            "search_index_default_exclude": True,
            "log_safe": True,
        },
        "auth_context": {
            "mode": "OFFLINE_ANALYSIS",
            "live_user_context_used": False,
            "evidence_libraries_loaded": False,
        },
        "key_provider": {
            "id": None,
            "version": None,
            "status": "KEY_UNAVAILABLE",
        },
    }


def _chromium_secret_blob_metadata(encrypted_blob: bytes) -> dict[str, Any]:
    encrypted = encrypted_blob.startswith(_CHROMIUM_SECRET_PREFIXES)
    return {
        "encrypted_value_sha256": _sha256_bytes(encrypted_blob),
        "encrypted_value_length": len(encrypted_blob),
        "encrypted_value_format": _chromium_secret_format(encrypted_blob),
        "encrypted_blob_policy": {
            "raw_blob_emitted": False,
            "hash_algorithm": "SHA256",
            "hash_only": True,
        },
        "decryption_status": "KEY_UNAVAILABLE" if encrypted else "UNSUPPORTED_SECRET_FORMAT",
        "decryption_failure_reason": "EXTERNAL_KEY_REQUIRED"
        if encrypted
        else "UNSUPPORTED_OR_LEGACY_SECRET_FORMAT",
    }


def _chromium_secret_format(value: bytes) -> str:
    for prefix in _CHROMIUM_SECRET_PREFIXES:
        if value.startswith(prefix):
            return f"CHROMIUM_AES_GCM_{prefix.decode('ascii').upper()}"
    return "UNKNOWN_OR_LEGACY"


def _secret_warning(code: str) -> dict[str, Any]:
    if code == "BROWSER_SECRET_DECRYPTION_KEY_UNAVAILABLE":
        return {
            "code": code,
            "message_key": "warning.browser.secret_key_unavailable",
            "developer_message": (
                "Encrypted browser secret value was not decrypted because no explicit external "
                "key provider was supplied."
            ),
        }
    return {
        "code": code,
        "message_key": "warning.browser.secret_redacted",
        "developer_message": "Browser secret plaintext exists in the source but was redacted.",
    }


def decrypt_chromium_aes_gcm_secret(
    encrypted_value: bytes,
    *,
    key: bytes | None,
    key_provider_id: str | None,
    key_provider_version: str | None,
    include_plaintext: bool = False,
) -> dict[str, Any]:
    """Decrypt a Chromium AES-GCM secret only when an explicit external key is supplied."""

    if key is None:
        return {
            "status": "KEY_UNAVAILABLE",
            "failure_reason": "EXTERNAL_KEY_REQUIRED",
            "key_provider": {"id": key_provider_id, "version": key_provider_version},
            "plaintext_emitted": False,
        }
    if not encrypted_value.startswith(_CHROMIUM_SECRET_PREFIXES) or len(encrypted_value) < 16:
        return {
            "status": "UNSUPPORTED_SECRET_FORMAT",
            "failure_reason": "EXPECTED_CHROMIUM_AES_GCM_V10_OR_NEWER",
            "plaintext_emitted": False,
        }
    if not _aes_gcm_available():
        return {
            "status": "CAPABILITY_UNAVAILABLE",
            "failure_reason": "CRYPTOGRAPHY_AESGCM_UNAVAILABLE",
            "plaintext_emitted": False,
        }
    aesgcm_type = importlib.import_module("cryptography.hazmat.primitives.ciphers.aead").AESGCM
    nonce = encrypted_value[3:15]
    ciphertext_and_tag = encrypted_value[15:]
    try:
        plaintext = aesgcm_type(key).decrypt(nonce, ciphertext_and_tag, None)
    except Exception as error:  # pragma: no cover - depends on crypto backend exception type.
        return {
            "status": "DECRYPTION_FAILED",
            "failure_reason": "AES_GCM_AUTHENTICATION_FAILED",
            "failure_type": type(error).__name__,
            "plaintext_emitted": False,
        }
    result: dict[str, Any] = {
        "status": "DECRYPTED",
        "failure_reason": None,
        "key_provider": {"id": key_provider_id, "version": key_provider_version},
        "plaintext_sha256": _sha256_bytes(plaintext),
        "plaintext_length": len(plaintext),
        "plaintext_emitted": include_plaintext,
    }
    if include_plaintext:
        result["plaintext"] = plaintext
    return result


def _aes_gcm_available() -> bool:
    try:
        importlib.import_module("cryptography.hazmat.primitives.ciphers.aead")
    except ImportError:
        return False
    return True


def _browser_secret_policy() -> dict[str, Any]:
    return {
        "plaintext_default": "REDACTED",
        "encrypted_blob_default": "HASH_ONLY",
        "search_index_default_exclude": True,
        "live_user_context_used": False,
        "loads_evidence_libraries": False,
        "plaintext_requires_explicit_protected_workflow": True,
    }


def _private_mode_policy() -> dict[str, Any]:
    return {
        "candidate_only": True,
        "auto_assert_private_use": False,
        "auto_assert_no_private_use": False,
        "absence_of_evidence_semantics": "NOT_EVIDENCE_OF_ABSENCE",
    }


def _private_mode_indicators(node: FileSystemNode, profile: dict[str, Any]) -> list[str]:
    path = node.original_relative_path.casefold()
    profile_name = str(profile.get("name") or "").casefold()
    indicators: list[str] = []
    if profile_name == "guest profile":
        indicators.append("PROFILE_NAME_GUEST_PROFILE")
    for needle, label in (
        ("incognito", "PATH_CONTAINS_INCOGNITO"),
        ("off the record", "PATH_CONTAINS_OFF_THE_RECORD"),
        ("offtherecord", "PATH_CONTAINS_OFFTHERECORD"),
        ("private browsing", "PATH_CONTAINS_PRIVATE_BROWSING"),
    ):
        if needle in path:
            indicators.append(label)
    return indicators


def _cache_file_info(node: FileSystemNode) -> dict[str, Any] | None:
    parts = PurePosixPath(node.original_relative_path).parts
    if len(parts) < 4:
        return None
    normalized_parts = [part.casefold() for part in parts]
    normalized_path = "/".join(normalized_parts)
    cache_markers = {"cache", "cache_data", "code cache", "gpu cache"}
    if not any(part in cache_markers for part in normalized_parts):
        return None
    browser_family, browser_name = _chromium_identity(normalized_path)
    synthetic_fixture = any(
        part in {"chrome", "chromium", "edge", "brave"} for part in normalized_parts
    )
    if browser_family == "UNKNOWN" and not synthetic_fixture:
        return None
    if browser_family == "UNKNOWN":
        browser_family, browser_name = "CHROMIUM", "GOOGLE_CHROME"
    profile_name = _cache_profile_name(parts, normalized_parts)
    profile_path = str(PurePosixPath(*parts[:-1]))
    operating_system = _operating_system(normalized_parts)
    profile_id = canonical_sha256(
        {
            "case_id": node.case_id,
            "evidence_id": node.evidence_id,
            "browser_family": browser_family,
            "browser_name": browser_name,
            "profile_path": profile_path,
        }
    )
    return {
        "profile_id": profile_id,
        "name": profile_name,
        "profile_name": profile_name,
        "path": profile_path,
        "profile_path": profile_path,
        "browser": browser_name,
        "browser_family": browser_family,
        "browser_name": browser_name,
        "operating_system": operating_system,
        "user_candidate": _user_candidate(parts, normalized_parts, operating_system),
        "discovery_method": "FS_NODE_BROWSER_CACHE_PATH_CANDIDATE",
        "source_revision": node.index_revision,
        "usage_confirmed": False,
        "source_role": "CACHE",
        "database_name": None,
    }


def _cache_profile_name(parts: tuple[str, ...], normalized_parts: list[str]) -> str:
    for index, part in enumerate(normalized_parts):
        if part in {"default", "guest profile", "system profile"} or part.startswith("profile "):
            return parts[index]
    return "UNKNOWN"


def _analyze_cache_file(
    *,
    evidence: Evidence,
    node: FileSystemNode,
    source: ArtifactSource,
    file_path: Path,
) -> ArtifactAnalysisResult:
    profile = _cache_file_info(node)
    if profile is None:
        return ArtifactAnalysisResult(parse_status=ArtifactParseStatus.UNSUPPORTED)
    try:
        content_sha256 = _sha256_file(file_path)
        size = file_path.stat().st_size
    except OSError as error:
        return ArtifactAnalysisResult(
            errors=(
                issue(
                    severity="ERROR",
                    code="BROWSER_CACHE_READ_FAILED",
                    message_key="error.browser.cache_read_failed",
                    developer_message="Browser cache file could not be read.",
                    node=node,
                    details={"error": str(error)},
                ),
            ),
            parse_status=ArtifactParseStatus.FAILED,
        )
    artifact = _cache_file_artifact(
        evidence=evidence,
        node=node,
        source=source,
        profile=profile,
        content_sha256=content_sha256,
        size=size,
    )
    warnings = tuple(_artifact_warnings(artifact, node))
    return ArtifactAnalysisResult(
        artifacts=(artifact,),
        warnings=warnings,
        coverage={
            "source_kind": ArtifactSourceKind.BROWSER_CACHE_FILE.value,
            "artifact_count": 1,
            "cache_parser_status": "OPAQUE_FILE_CANDIDATE",
        },
        parse_status=ArtifactParseStatus.PARTIAL,
        source_complete=True,
        inspected_count=1,
        source_fingerprint=canonical_sha256(
            {
                "source_path": str(file_path),
                "content_sha256": content_sha256,
                "size": size,
            }
        ),
    )


def _cache_file_artifact(
    *,
    evidence: Evidence,
    node: FileSystemNode,
    source: ArtifactSource,
    profile: dict[str, Any],
    content_sha256: str,
    size: int,
) -> ArtifactRecord:
    observed = _file_modified_observed(node)
    preview_length = min(size, _BROWSER_CACHE_PREVIEW_MAX_BYTES)
    fields = _base_browser_fields(
        node=node,
        content_sha256=content_sha256,
        profile=profile,
        db_kind="CHROMIUM_CACHE",
        table="cache_file",
        row_id=None,
        joined_tables=[],
    ) | {
        "cache_entry_candidate": True,
        "entry_confirmed": False,
        "cache_format": "CHROMIUM_DISK_CACHE_OPAQUE_FILE_CANDIDATE",
        "cache_key_sha256": _sha256_text(node.original_relative_path),
        "cache_url": None,
        "body_offset": 0,
        "body_length": size,
        "body_sha256": content_sha256,
        "bounded_extraction": {
            "max_bytes": _BROWSER_CACHE_PREVIEW_MAX_BYTES,
            "preview_length": preview_length,
            "truncated": size > _BROWSER_CACHE_PREVIEW_MAX_BYTES,
        },
        "timeline_integration": "FILESYSTEM_MODIFIED_TIME",
        "search_index_default_exclude": False,
    }
    raw_locator = make_raw_locator(
        evidence_id=evidence.evidence_id,
        source_file_node_id=node.node_id,
        source_path=node.display_path,
        source_reference="browser-cache:file-bytes",
        locator_type="BYTE_RANGE",
        offset=0,
        length=max(1, preview_length) if size > 0 else None,
        encoding="binary",
        view_types=["HEX"],
        content_sha256=content_sha256,
        limitations=[
            "Cache parser treats this object as an opaque file candidate.",
            "Raw locator length is bounded for safe preview.",
        ],
        details={
            "body_offset": 0,
            "body_length": size,
            "body_sha256": content_sha256,
        },
    )
    return make_artifact(
        evidence=evidence,
        node=node,
        source=source,
        artifact_type=ArtifactType.BROWSER_CACHE_ENTRY,
        artifact_subtype="CHROMIUM_CACHE_FILE_CANDIDATE",
        fields=fields,
        raw_locator=raw_locator,
        title=f"Browser cache file candidate: {node.original_name}",
        summary=(
            "Chromium cache file candidate observed with bounded byte-range provenance; HTTP "
            "cache header parsing is unavailable."
        ),
        parse_status=ArtifactParseStatus.PARTIAL,
        confidence=0.55,
        observed_at_raw=observed["raw"],
        observed_at_utc=observed["utc"],
        timezone_source=observed["timezone_source"],
        timezone_confidence=observed["timezone_confidence"],
        warnings=[
            {
                "code": "BROWSER_CACHE_FORMAT_PARTIAL",
                "message_key": "warning.browser.cache_format_partial",
                "developer_message": (
                    "Browser cache object was recorded as an opaque file candidate; HTTP "
                    "cache headers and URL keys were not decoded."
                ),
            }
        ],
    )


def _fetchmany(
    cursor: sqlite3.Cursor, batch_size: int = _BROWSER_SQLITE_BATCH_SIZE
) -> Iterator[sqlite3.Row]:
    while True:
        rows = cursor.fetchmany(batch_size)
        if not rows:
            return
        yield from rows


def _int_or_none(value: Any) -> int | None:
    try:
        return None if value is None else int(value)
    except (TypeError, ValueError):
        return None


def _table_columns(connection: sqlite3.Connection) -> dict[str, list[str]]:
    table_cursor = connection.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name"
    )
    tables: dict[str, list[str]] = {}
    for row in _fetchmany(table_cursor):
        table = str(row["name"])
        column_cursor = connection.execute(f"PRAGMA table_info({_quote_identifier(table)})")
        tables[table] = [str(item["name"]) for item in _fetchmany(column_cursor)]
    return tables


def _database_kind(tables: dict[str, list[str]], profile: dict[str, Any]) -> str:
    source_role = str(profile.get("source_role") or "")
    if source_role == "COOKIE_STORE":
        if _has_columns(tables, "cookies", {"host_key", "name"}):
            return "CHROMIUM_COOKIES"
        if _has_columns(tables, "moz_cookies", {"host", "name"}):
            return "FIREFOX_COOKIES"
    if source_role == "CREDENTIAL_STORE" and _has_columns(
        tables, "logins", {"origin_url", "password_value"}
    ):
        return "CHROMIUM_LOGIN_DATA"
    if {"urls", "visits"}.issubset(tables):
        return "CHROMIUM"
    if {"moz_places", "moz_historyvisits"}.issubset(tables):
        return "FIREFOX"
    return "UNKNOWN"


def _profile_info(node: FileSystemNode) -> dict[str, Any] | None:
    parts = PurePosixPath(node.original_relative_path).parts
    if len(parts) < 2:
        return None
    name = node.original_name.casefold()
    if name not in {"history", "places.sqlite", "cookies", "cookies.sqlite", "login data"}:
        return None
    normalized_parts = [part.casefold() for part in parts]
    normalized_path = "/".join(normalized_parts)
    if name in {"history", "cookies", "login data"}:
        profile_index = len(parts) - 2
        profile_name = parts[profile_index]
        synthetic_fixture = _is_synthetic_chromium_fixture(parts)
        if not _is_chromium_profile_name(profile_name) and not synthetic_fixture:
            return None
        browser_family, browser_name = _chromium_identity(normalized_path)
        if browser_family == "UNKNOWN" and not synthetic_fixture:
            return None
        if browser_family == "UNKNOWN":
            browser_family, browser_name = "CHROMIUM", "GOOGLE_CHROME"
        source_role = {
            "history": "HISTORY",
            "cookies": "COOKIE_STORE",
            "login data": "CREDENTIAL_STORE",
        }[name]
    else:
        profile_index = len(parts) - 2
        profile_name = parts[profile_index]
        if not _is_firefox_profile_path(normalized_parts):
            return None
        browser_family, browser_name = "FIREFOX", "FIREFOX"
        source_role = "HISTORY" if name == "places.sqlite" else "COOKIE_STORE"
    profile_path = str(PurePosixPath(*parts[:-1]))
    operating_system = _operating_system(normalized_parts)
    user_candidate = _user_candidate(parts, normalized_parts, operating_system)
    profile_id = canonical_sha256(
        {
            "case_id": node.case_id,
            "evidence_id": node.evidence_id,
            "browser_family": browser_family,
            "browser_name": browser_name,
            "profile_path": profile_path,
        }
    )
    return {
        "profile_id": profile_id,
        "name": profile_name,
        "profile_name": profile_name,
        "path": profile_path,
        "profile_path": profile_path,
        "browser": browser_name,
        "browser_family": browser_family,
        "browser_name": browser_name,
        "operating_system": operating_system,
        "user_candidate": user_candidate,
        "discovery_method": "FS_NODE_BROWSER_PROFILE_ALLOWLIST",
        "source_revision": node.index_revision,
        "usage_confirmed": False,
        "source_role": source_role,
        "database_name": node.original_name,
    }


def _chromium_identity(normalized_path: str) -> tuple[str, str]:
    for needle, identity in _BROWSER_NAMES.items():
        if needle in normalized_path and identity[0] == "CHROMIUM":
            return identity
    return "UNKNOWN", "UNKNOWN"


def _is_chromium_profile_name(profile_name: str) -> bool:
    folded = profile_name.casefold()
    return folded in _CHROMIUM_PROFILE_NAMES or folded.startswith("profile ")


def _is_firefox_profile_path(parts: list[str]) -> bool:
    normalized_path = "/".join(parts)
    return (
        "mozilla/firefox/profiles" in normalized_path
        or ".mozilla/firefox" in normalized_path
        or _is_synthetic_firefox_fixture(parts)
    )


def _is_synthetic_chromium_fixture(parts: tuple[str, ...]) -> bool:
    if len(parts) < 3:
        return False
    browser_dir = parts[-3].casefold()
    return browser_dir in {"chrome", "chromium", "edge", "brave", "browser"}


def _is_synthetic_firefox_fixture(parts: list[str]) -> bool:
    return len(parts) >= 3 and parts[-3] in {"firefox", "browser"}


def _operating_system(parts: list[str]) -> str:
    normalized_path = "/".join(parts)
    if parts and parts[0] == "users":
        return "WINDOWS"
    if normalized_path.startswith("home/"):
        return "LINUX"
    return "UNKNOWN"


def _user_candidate(
    parts: tuple[str, ...], normalized_parts: list[str], operating_system: str
) -> str | None:
    if operating_system == "WINDOWS" and len(parts) > 1 and normalized_parts[0] == "users":
        return parts[1]
    if operating_system == "LINUX" and len(parts) > 1 and normalized_parts[0] == "home":
        return parts[1]
    return None


def _profile_artifact(
    *,
    evidence: Evidence,
    node: FileSystemNode,
    source: ArtifactSource,
    content_sha256: str,
    profile: dict[str, Any],
    db_kind: str,
    tables: dict[str, list[str]],
    parse_status: ArtifactParseStatus,
    warnings: list[dict[str, Any]],
) -> ArtifactRecord:
    fields = _base_browser_fields(
        node=node,
        content_sha256=content_sha256,
        profile=profile,
        db_kind=db_kind,
        table="sqlite_master",
        row_id=None,
        joined_tables=[],
    ) | {
        "table_counts": dict.fromkeys(sorted(tables)),
        "tables": {table: sorted(columns) for table, columns in tables.items()},
    }
    raw_locator = _browser_locator(
        evidence=evidence,
        node=node,
        content_sha256=content_sha256,
        table="sqlite_master",
        row_id=None,
        joined_tables=[],
    )
    observed = _file_modified_observed(node)
    return make_artifact(
        evidence=evidence,
        node=node,
        source=source,
        artifact_type=ArtifactType.BROWSER_PROFILE,
        artifact_subtype=f"BROWSER_PROFILE_{db_kind}",
        fields=fields,
        raw_locator=raw_locator,
        title=f"Browser profile database: {profile['name']}",
        summary="Browser profile/database metadata observed without AI.",
        parse_status=parse_status,
        confidence=0.85 if db_kind != "UNKNOWN" else 0.35,
        observed_at_raw=observed["raw"],
        observed_at_utc=observed["utc"],
        timezone_source=observed["timezone_source"],
        timezone_confidence=observed["timezone_confidence"],
        warnings=warnings,
    )


_BROWSER_STREAMS = {
    "CHROMIUM": (
        "profile",
        "private_mode_candidates",
        "chromium_visits",
        "chromium_search_terms",
        "chromium_downloads",
        "sqlite_deleted_candidates",
    ),
    "CHROMIUM_COOKIES": (
        "profile",
        "private_mode_candidates",
        "chromium_cookies",
        "sqlite_deleted_candidates",
    ),
    "CHROMIUM_LOGIN_DATA": (
        "profile",
        "private_mode_candidates",
        "chromium_credentials",
        "sqlite_deleted_candidates",
    ),
    "FIREFOX": (
        "profile",
        "private_mode_candidates",
        "firefox_visits",
        "firefox_download_annotations",
        "firefox_input_history",
        "sqlite_deleted_candidates",
    ),
    "FIREFOX_COOKIES": (
        "profile",
        "private_mode_candidates",
        "firefox_cookies",
        "sqlite_deleted_candidates",
    ),
}


def _browser_extraction_page(
    *,
    connection: sqlite3.Connection,
    evidence: Evidence,
    node: FileSystemNode,
    source: ArtifactSource,
    content_sha256: str,
    profile: dict[str, Any],
    db_kind: str,
    tables: dict[str, list[str]],
    item_budget: int | None,
) -> _BrowserExtractionPage:
    source_fingerprint = str(profile["snapshot"].get("source_fingerprint") or "")
    checkpoint = _browser_resume_checkpoint(source, db_kind, source_fingerprint)
    stream = str(checkpoint["stream"])
    last_row_id = _int_or_none(checkpoint.get("last_row_id"))
    max_items = item_budget if item_budget is not None and item_budget > 0 else None
    artifacts: list[ArtifactRecord] = []
    inspected_count = 0

    while max_items is None or inspected_count < max_items:
        remaining = None if max_items is None else max_items - inspected_count
        if stream == "profile":
            artifacts.append(
                _profile_artifact(
                    evidence=evidence,
                    node=node,
                    source=source,
                    content_sha256=content_sha256,
                    profile=profile,
                    db_kind=db_kind,
                    tables=tables,
                    parse_status=ArtifactParseStatus.SUCCESS,
                    warnings=[],
                )
            )
            inspected_count += 1
            next_stream = _next_browser_stream(db_kind, stream)
            if next_stream is None:
                return _BrowserExtractionPage(tuple(artifacts), None, True, inspected_count)
            stream = next_stream
            last_row_id = None
            if max_items is not None and inspected_count >= max_items:
                return _BrowserExtractionPage(
                    tuple(artifacts),
                    _browser_checkpoint(db_kind, source_fingerprint, stream, last_row_id),
                    False,
                    inspected_count,
                )
            continue

        page = _browser_stream_page(
            stream=stream,
            connection=connection,
            evidence=evidence,
            node=node,
            source=source,
            content_sha256=content_sha256,
            profile=profile,
            tables=tables,
            after_row_id=last_row_id,
            limit=remaining,
        )
        artifacts.extend(page.artifacts)
        inspected_count += len(page.artifacts)
        if page.has_more:
            return _BrowserExtractionPage(
                tuple(artifacts),
                _browser_checkpoint(db_kind, source_fingerprint, stream, page.last_row_id),
                False,
                inspected_count,
            )
        next_stream = _next_browser_stream(db_kind, stream)
        if next_stream is None:
            return _BrowserExtractionPage(tuple(artifacts), None, True, inspected_count)
        stream = next_stream
        last_row_id = None
        if max_items is not None and inspected_count >= max_items:
            return _BrowserExtractionPage(
                tuple(artifacts),
                _browser_checkpoint(db_kind, source_fingerprint, stream, last_row_id),
                False,
                inspected_count,
            )
    return _BrowserExtractionPage(
        tuple(artifacts),
        _browser_checkpoint(db_kind, source_fingerprint, stream, last_row_id),
        False,
        inspected_count,
    )


def _browser_resume_checkpoint(
    source: ArtifactSource,
    db_kind: str,
    source_fingerprint: str,
) -> dict[str, Any]:
    checkpoint = source.source_checkpoint
    if (
        checkpoint.get("version") == 1
        and checkpoint.get("database_kind") == db_kind
        and checkpoint.get("source_fingerprint") == source_fingerprint
        and checkpoint.get("stream") in _BROWSER_STREAMS[db_kind]
    ):
        return checkpoint
    return _browser_checkpoint(db_kind, source_fingerprint, "profile", None)


def _browser_checkpoint(
    db_kind: str,
    source_fingerprint: str,
    stream: str,
    last_row_id: int | None,
) -> dict[str, Any]:
    return {
        "version": 1,
        "database_kind": db_kind,
        "source_fingerprint": source_fingerprint,
        "stream": stream,
        "last_row_id": last_row_id,
    }


def _next_browser_stream(db_kind: str, stream: str) -> str | None:
    streams = _BROWSER_STREAMS[db_kind]
    index = streams.index(stream)
    if index + 1 >= len(streams):
        return None
    return streams[index + 1]


def _browser_stream_page(
    *,
    stream: str,
    connection: sqlite3.Connection,
    evidence: Evidence,
    node: FileSystemNode,
    source: ArtifactSource,
    content_sha256: str,
    profile: dict[str, Any],
    tables: dict[str, list[str]],
    after_row_id: int | None,
    limit: int | None,
) -> _BrowserStreamPage:
    if stream == "chromium_visits":
        return _chromium_visits_page(
            connection=connection,
            evidence=evidence,
            node=node,
            source=source,
            content_sha256=content_sha256,
            profile=profile,
            tables=tables,
            after_row_id=after_row_id,
            limit=limit,
        )
    if stream == "chromium_search_terms":
        return _chromium_search_terms_page(
            connection=connection,
            evidence=evidence,
            node=node,
            source=source,
            content_sha256=content_sha256,
            profile=profile,
            tables=tables,
            after_row_id=after_row_id,
            limit=limit,
        )
    if stream == "chromium_downloads":
        return _chromium_downloads_page(
            connection=connection,
            evidence=evidence,
            node=node,
            source=source,
            content_sha256=content_sha256,
            profile=profile,
            tables=tables,
            after_row_id=after_row_id,
            limit=limit,
        )
    if stream == "private_mode_candidates":
        return _private_mode_candidates_page(
            evidence=evidence,
            node=node,
            source=source,
            content_sha256=content_sha256,
            profile=profile,
            tables=tables,
            after_row_id=after_row_id,
        )
    if stream == "chromium_cookies":
        return _chromium_cookies_page(
            connection=connection,
            evidence=evidence,
            node=node,
            source=source,
            content_sha256=content_sha256,
            profile=profile,
            tables=tables,
            after_row_id=after_row_id,
            limit=limit,
        )
    if stream == "chromium_credentials":
        return _chromium_credentials_page(
            connection=connection,
            evidence=evidence,
            node=node,
            source=source,
            content_sha256=content_sha256,
            profile=profile,
            tables=tables,
            after_row_id=after_row_id,
            limit=limit,
        )
    if stream == "firefox_visits":
        return _firefox_visits_page(
            connection=connection,
            evidence=evidence,
            node=node,
            source=source,
            content_sha256=content_sha256,
            profile=profile,
            after_row_id=after_row_id,
            limit=limit,
        )
    if stream == "firefox_download_annotations":
        return _firefox_download_annotations_page(
            connection=connection,
            evidence=evidence,
            node=node,
            source=source,
            content_sha256=content_sha256,
            profile=profile,
            tables=tables,
            after_row_id=after_row_id,
            limit=limit,
        )
    if stream == "firefox_input_history":
        return _firefox_input_history_page(
            connection=connection,
            evidence=evidence,
            node=node,
            source=source,
            content_sha256=content_sha256,
            profile=profile,
            tables=tables,
            after_row_id=after_row_id,
            limit=limit,
        )
    if stream == "firefox_cookies":
        return _firefox_cookies_page(
            connection=connection,
            evidence=evidence,
            node=node,
            source=source,
            content_sha256=content_sha256,
            profile=profile,
            tables=tables,
            after_row_id=after_row_id,
            limit=limit,
        )
    if stream == "sqlite_deleted_candidates":
        return _sqlite_deleted_candidates_page(
            connection=connection,
            evidence=evidence,
            node=node,
            source=source,
            content_sha256=content_sha256,
            profile=profile,
            tables=tables,
            after_row_id=after_row_id,
        )
    return _BrowserStreamPage((), None, False)


def _rows_with_limit(
    connection: sqlite3.Connection,
    sql: str,
    params: list[Any],
    limit: int | None,
) -> tuple[list[sqlite3.Row], bool]:
    query = sql
    query_params = list(params)
    if limit is not None:
        query += "\nLIMIT ?"
        query_params.append(limit + 1)
    rows = list(_fetchmany(connection.execute(query, tuple(query_params))))
    has_more = limit is not None and len(rows) > limit
    if has_more:
        rows = rows[:limit]
    return rows, has_more


def _stream_result(
    rows: list[sqlite3.Row],
    has_more: bool,
    artifacts: list[ArtifactRecord],
) -> _BrowserStreamPage:
    last_row_id = int(rows[-1]["row_id"]) if rows else None
    return _BrowserStreamPage(tuple(artifacts), last_row_id, has_more)


def _chromium_visits_page(
    *,
    connection: sqlite3.Connection,
    evidence: Evidence,
    node: FileSystemNode,
    source: ArtifactSource,
    content_sha256: str,
    profile: dict[str, Any],
    tables: dict[str, list[str]],
    after_row_id: int | None,
    limit: int | None,
) -> _BrowserStreamPage:
    if not (
        _has_columns(tables, "visits", {"id", "url", "visit_time"})
        and _has_columns(tables, "urls", {"id", "url"})
    ):
        return _BrowserStreamPage((), None, False)
    where = "WHERE visits.id > ?" if after_row_id is not None else ""
    params = [] if after_row_id is None else [after_row_id]
    rows, has_more = _rows_with_limit(
        connection,
        f"""
        SELECT
            visits.id AS row_id,
            visits.url AS url_id,
            visits.visit_time AS visit_time,
            visits.from_visit AS from_visit,
            visits.transition AS transition,
            urls.url AS url,
            urls.title AS title,
            urls.visit_count AS visit_count,
            urls.typed_count AS typed_count,
            urls.last_visit_time AS last_visit_time
        FROM visits
        JOIN urls ON urls.id = visits.url
        {where}
        ORDER BY visits.id
        """,
        params,
        limit,
    )
    artifacts = [
        _browser_row_artifact(
            evidence=evidence,
            node=node,
            source=source,
            content_sha256=content_sha256,
            profile=profile,
            db_kind="CHROMIUM",
            artifact_type=ArtifactType.BROWSER_VISIT,
            subtype="CHROMIUM_VISIT",
            table="visits",
            row_id=int(row["row_id"]),
            joined_tables=["urls"],
            observed_raw=str(row["visit_time"]),
            observed_utc=_webkit_timestamp(row["visit_time"]),
            title=str(row["title"] or row["url"]),
            summary="Chromium visit history row observed.",
            extra_fields={
                "url": row["url"],
                "url_id": row["url_id"],
                "page_title": row["title"],
                "visit_count": row["visit_count"],
                "typed_count": row["typed_count"],
                "from_visit": row["from_visit"],
                "transition": row["transition"],
            },
        )
        for row in rows
    ]
    return _stream_result(rows, has_more, artifacts)


def _chromium_search_terms_page(
    *,
    connection: sqlite3.Connection,
    evidence: Evidence,
    node: FileSystemNode,
    source: ArtifactSource,
    content_sha256: str,
    profile: dict[str, Any],
    tables: dict[str, list[str]],
    after_row_id: int | None,
    limit: int | None,
) -> _BrowserStreamPage:
    if not (
        "keyword_search_terms" in tables
        and _has_columns(tables, "keyword_search_terms", {"term", "url_id"})
    ):
        return _BrowserStreamPage((), None, False)
    where = "WHERE keyword_search_terms.rowid > ?" if after_row_id is not None else ""
    params = [] if after_row_id is None else [after_row_id]
    rows, has_more = _rows_with_limit(
        connection,
        f"""
        SELECT
            keyword_search_terms.rowid AS row_id,
            keyword_search_terms.term AS term,
            keyword_search_terms.url_id AS url_id,
            urls.url AS url,
            urls.title AS title,
            urls.last_visit_time AS last_visit_time
        FROM keyword_search_terms
        LEFT JOIN urls ON urls.id = keyword_search_terms.url_id
        {where}
        ORDER BY keyword_search_terms.rowid
        """,
        params,
        limit,
    )
    artifacts = [
        _browser_row_artifact(
            evidence=evidence,
            node=node,
            source=source,
            content_sha256=content_sha256,
            profile=profile,
            db_kind="CHROMIUM",
            artifact_type=ArtifactType.BROWSER_SEARCH,
            subtype="CHROMIUM_SEARCH_TERM",
            table="keyword_search_terms",
            row_id=int(row["row_id"]),
            joined_tables=["urls"],
            observed_raw=None if row["last_visit_time"] is None else str(row["last_visit_time"]),
            observed_utc=_webkit_timestamp(row["last_visit_time"]),
            title=f"Search: {row['term']}",
            summary="Chromium search history row observed.",
            extra_fields={
                "search_term": row["term"],
                "url": row["url"],
                "url_id": row["url_id"],
                "page_title": row["title"],
            },
        )
        for row in rows
    ]
    return _stream_result(rows, has_more, artifacts)


def _chromium_downloads_page(
    *,
    connection: sqlite3.Connection,
    evidence: Evidence,
    node: FileSystemNode,
    source: ArtifactSource,
    content_sha256: str,
    profile: dict[str, Any],
    tables: dict[str, list[str]],
    after_row_id: int | None,
    limit: int | None,
) -> _BrowserStreamPage:
    if not ("downloads" in tables and _has_columns(tables, "downloads", {"id", "start_time"})):
        return _BrowserStreamPage((), None, False)
    rows, has_more = _rows_with_limit(
        connection,
        _chromium_download_query(tables, after_row_id=after_row_id),
        [] if after_row_id is None else [after_row_id],
        limit,
    )
    artifacts = [
        _browser_row_artifact(
            evidence=evidence,
            node=node,
            source=source,
            content_sha256=content_sha256,
            profile=profile,
            db_kind="CHROMIUM",
            artifact_type=ArtifactType.BROWSER_DOWNLOAD,
            subtype="CHROMIUM_DOWNLOAD",
            table="downloads",
            row_id=int(row["row_id"]),
            joined_tables=["downloads_url_chains"] if "downloads_url_chains" in tables else [],
            observed_raw=None if row["start_time"] is None else str(row["start_time"]),
            observed_utc=_webkit_timestamp(row["start_time"]),
            title=f"Download: {row['download_path'] or row['download_url']}",
            summary="Chromium download history row observed.",
            extra_fields={
                "download_path": row["download_path"],
                "download_url": row["download_url"],
                "tab_url": row["tab_url"],
                "referrer_url": row["referrer_url"],
                "received_bytes": row["received_bytes"],
                "total_bytes": row["total_bytes"],
                "state": row["state"],
                "state_label": _chromium_download_state(row["state"]),
                "danger_type": row["danger_type"],
                "danger_type_note": (
                    "danger_type is preserved as browser metadata only; "
                    "it is not a malware finding."
                ),
                "interrupt_reason": row["interrupt_reason"],
                "end_time_raw": None if row["end_time"] is None else str(row["end_time"]),
                "end_time_utc": _timestamp_string(_webkit_timestamp(row["end_time"])),
            },
        )
        for row in rows
    ]
    return _stream_result(rows, has_more, artifacts)


def _firefox_visits_page(
    *,
    connection: sqlite3.Connection,
    evidence: Evidence,
    node: FileSystemNode,
    source: ArtifactSource,
    content_sha256: str,
    profile: dict[str, Any],
    after_row_id: int | None,
    limit: int | None,
) -> _BrowserStreamPage:
    where = "WHERE moz_historyvisits.id > ?" if after_row_id is not None else ""
    params = [] if after_row_id is None else [after_row_id]
    rows, has_more = _rows_with_limit(
        connection,
        f"""
        SELECT
            moz_historyvisits.id AS row_id,
            moz_historyvisits.place_id AS place_id,
            moz_historyvisits.visit_date AS visit_date,
            moz_historyvisits.from_visit AS from_visit,
            moz_historyvisits.visit_type AS visit_type,
            moz_places.url AS url,
            moz_places.title AS title,
            moz_places.visit_count AS visit_count
        FROM moz_historyvisits
        JOIN moz_places ON moz_places.id = moz_historyvisits.place_id
        {where}
        ORDER BY moz_historyvisits.id
        """,
        params,
        limit,
    )
    artifacts = [
        _browser_row_artifact(
            evidence=evidence,
            node=node,
            source=source,
            content_sha256=content_sha256,
            profile=profile,
            db_kind="FIREFOX",
            artifact_type=ArtifactType.BROWSER_VISIT,
            subtype="FIREFOX_VISIT",
            table="moz_historyvisits",
            row_id=int(row["row_id"]),
            joined_tables=["moz_places"],
            observed_raw=None if row["visit_date"] is None else str(row["visit_date"]),
            observed_utc=_unix_microseconds(row["visit_date"]),
            title=str(row["title"] or row["url"]),
            summary="Firefox visit history row observed.",
            extra_fields={
                "url": row["url"],
                "place_id": row["place_id"],
                "page_title": row["title"],
                "visit_count": row["visit_count"],
                "from_visit": row["from_visit"],
                "visit_type": row["visit_type"],
            },
        )
        for row in rows
    ]
    return _stream_result(rows, has_more, artifacts)


def _firefox_download_annotations_page(
    *,
    connection: sqlite3.Connection,
    evidence: Evidence,
    node: FileSystemNode,
    source: ArtifactSource,
    content_sha256: str,
    profile: dict[str, Any],
    tables: dict[str, list[str]],
    after_row_id: int | None,
    limit: int | None,
) -> _BrowserStreamPage:
    if not (
        _has_columns(tables, "moz_annos", {"id", "place_id", "anno_attribute_id", "content"})
        and _has_columns(tables, "moz_anno_attributes", {"id", "name"})
    ):
        return _BrowserStreamPage((), None, False)
    row_filter = "AND moz_annos.id > ?" if after_row_id is not None else ""
    params = [] if after_row_id is None else [after_row_id]
    rows, has_more = _rows_with_limit(
        connection,
        f"""
        SELECT
            moz_annos.id AS row_id,
            moz_annos.place_id AS place_id,
            moz_annos.content AS content,
            moz_annos.dateAdded AS date_added,
            moz_annos.lastModified AS last_modified,
            moz_anno_attributes.name AS annotation_name,
            moz_places.url AS url,
            moz_places.title AS title
        FROM moz_annos
        JOIN moz_anno_attributes ON moz_anno_attributes.id = moz_annos.anno_attribute_id
        LEFT JOIN moz_places ON moz_places.id = moz_annos.place_id
        WHERE moz_anno_attributes.name IN (
            'downloads/destinationFileURI',
            'downloads/destinationFileName',
            'downloads/metaData',
            'downloads/sourceURI'
        )
        {row_filter}
        ORDER BY moz_annos.id
        """,
        params,
        limit,
    )
    artifacts = [
        _browser_row_artifact(
            evidence=evidence,
            node=node,
            source=source,
            content_sha256=content_sha256,
            profile=profile,
            db_kind="FIREFOX",
            artifact_type=ArtifactType.BROWSER_DOWNLOAD,
            subtype="FIREFOX_DOWNLOAD_ANNOTATION_CANDIDATE",
            table="moz_annos",
            row_id=int(row["row_id"]),
            joined_tables=["moz_anno_attributes", "moz_places"],
            observed_raw=None if row["last_modified"] is None else str(row["last_modified"]),
            observed_utc=_unix_microseconds(row["last_modified"]),
            title=f"Firefox download candidate: {row['content']}",
            summary="Firefox download annotation candidate observed; metadata may be incomplete.",
            extra_fields={
                "url": row["url"],
                "page_title": row["title"],
                "download_path": row["content"]
                if str(row["annotation_name"]).endswith("destinationFileName")
                else None,
                "download_url": row["url"],
                "annotation_name": row["annotation_name"],
                "annotation_content": row["content"],
                "date_added_raw": None if row["date_added"] is None else str(row["date_added"]),
                "download_metadata_is_partial": True,
            },
            parse_status=ArtifactParseStatus.PARTIAL,
            warnings=[
                {
                    "code": "FIREFOX_DOWNLOAD_METADATA_PARTIAL",
                    "message_key": "warning.browser.firefox_download_metadata_partial",
                    "developer_message": (
                        "Firefox download annotation metadata is version-dependent and incomplete."
                    ),
                }
            ],
        )
        for row in rows
    ]
    return _stream_result(rows, has_more, artifacts)


def _firefox_input_history_page(
    *,
    connection: sqlite3.Connection,
    evidence: Evidence,
    node: FileSystemNode,
    source: ArtifactSource,
    content_sha256: str,
    profile: dict[str, Any],
    tables: dict[str, list[str]],
    after_row_id: int | None,
    limit: int | None,
) -> _BrowserStreamPage:
    if not _has_columns(tables, "moz_inputhistory", {"place_id", "input"}):
        return _BrowserStreamPage((), None, False)
    where = "WHERE moz_inputhistory.rowid > ?" if after_row_id is not None else ""
    params = [] if after_row_id is None else [after_row_id]
    rows, has_more = _rows_with_limit(
        connection,
        f"""
        SELECT
            moz_inputhistory.rowid AS row_id,
            moz_inputhistory.place_id AS place_id,
            moz_inputhistory.input AS input,
            moz_inputhistory.use_count AS use_count,
            moz_places.url AS url,
            moz_places.title AS title
        FROM moz_inputhistory
        LEFT JOIN moz_places ON moz_places.id = moz_inputhistory.place_id
        {where}
        ORDER BY moz_inputhistory.rowid
        """,
        params,
        limit,
    )
    artifacts = [
        _browser_row_artifact(
            evidence=evidence,
            node=node,
            source=source,
            content_sha256=content_sha256,
            profile=profile,
            db_kind="FIREFOX",
            artifact_type=ArtifactType.BROWSER_PROFILE,
            subtype="FIREFOX_URLBAR_INPUT_HISTORY_CANDIDATE",
            table="moz_inputhistory",
            row_id=int(row["row_id"]),
            joined_tables=["moz_places"],
            observed_raw=None,
            observed_utc=None,
            title=f"Firefox URL-bar input candidate: {row['input']}",
            summary=(
                "Firefox URL-bar input history candidate observed; this is not a confirmed "
                "web search term."
            ),
            extra_fields={
                "input_text": row["input"],
                "url": row["url"],
                "place_id": row["place_id"],
                "page_title": row["title"],
                "use_count": row["use_count"],
                "timestamp_semantics": "FIREFOX_INPUT_HISTORY_NO_DIRECT_TIMESTAMP",
                "search_term_confirmed": False,
            },
            parse_status=ArtifactParseStatus.PARTIAL,
            warnings=[
                {
                    "code": "FIREFOX_INPUT_HISTORY_NOT_CONFIRMED_SEARCH",
                    "message_key": "warning.browser.firefox_input_history_not_confirmed_search",
                    "developer_message": (
                        "Firefox moz_inputhistory stores URL-bar input history and is not "
                        "classified as confirmed search-term evidence."
                    ),
                }
            ],
        )
        for row in rows
    ]
    return _stream_result(rows, has_more, artifacts)


def _chromium_cookies_page(
    *,
    connection: sqlite3.Connection,
    evidence: Evidence,
    node: FileSystemNode,
    source: ArtifactSource,
    content_sha256: str,
    profile: dict[str, Any],
    tables: dict[str, list[str]],
    after_row_id: int | None,
    limit: int | None,
) -> _BrowserStreamPage:
    if not _has_columns(tables, "cookies", {"host_key", "name"}):
        return _BrowserStreamPage((), None, False)
    where = "WHERE cookies.rowid > ?" if after_row_id is not None else ""
    params = [] if after_row_id is None else [after_row_id]
    rows, has_more = _rows_with_limit(
        connection,
        f"""
        SELECT
            cookies.rowid AS row_id,
            {_sql_column_or_null(tables, "cookies", "host_key")},
            {_sql_column_or_null(tables, "cookies", "name")},
            {_sql_column_or_null(tables, "cookies", "path")},
            {_sql_column_or_null(tables, "cookies", "creation_utc")},
            {_sql_column_or_null(tables, "cookies", "expires_utc")},
            {_sql_column_or_null(tables, "cookies", "last_access_utc")},
            {_sql_column_or_null(tables, "cookies", "is_secure")},
            {_sql_column_or_null(tables, "cookies", "is_httponly")},
            {_sql_column_or_null(tables, "cookies", "has_expires")},
            {_sql_column_or_null(tables, "cookies", "is_persistent")},
            {_sql_column_or_null(tables, "cookies", "samesite")},
            {_sql_column_or_null(tables, "cookies", "source_scheme")},
            {_sql_column_or_null(tables, "cookies", "source_port")},
            {_sql_column_or_null(tables, "cookies", "value")},
            {_sql_column_or_null(tables, "cookies", "encrypted_value")}
        FROM cookies
        {where}
        ORDER BY cookies.rowid
        """,
        params,
        limit,
    )
    artifacts: list[ArtifactRecord] = []
    for row in rows:
        secret_fields, secret_warnings = _cookie_secret_metadata(
            plaintext_value=row["value"],
            encrypted_value=row["encrypted_value"],
            store_kind="CHROMIUM_COOKIE",
        )
        host = _str_or_empty(row["host_key"])
        observed_raw = _first_non_empty(row["last_access_utc"], row["creation_utc"])
        artifacts.append(
            _browser_row_artifact(
                evidence=evidence,
                node=node,
                source=source,
                content_sha256=content_sha256,
                profile=profile,
                db_kind="CHROMIUM_COOKIES",
                artifact_type=ArtifactType.BROWSER_COOKIE,
                subtype="CHROMIUM_COOKIE_METADATA_REDACTED",
                table="cookies",
                row_id=int(row["row_id"]),
                joined_tables=[],
                observed_raw=None if observed_raw is None else str(observed_raw),
                observed_utc=_webkit_timestamp(observed_raw),
                title=f"Chromium cookie metadata: {host or 'unknown domain'}",
                summary="Chromium cookie row metadata observed; secret value is redacted.",
                extra_fields={
                    "cookie_domain": host or None,
                    "cookie_name_sha256": _sha256_text(row["name"]),
                    "cookie_name_length": _text_length(row["name"]),
                    "cookie_path": row["path"],
                    "creation_time_raw": _none_or_str(row["creation_utc"]),
                    "expires_time_raw": _none_or_str(row["expires_utc"]),
                    "last_access_time_raw": _none_or_str(row["last_access_utc"]),
                    "expires_time_utc": _timestamp_string(_webkit_timestamp(row["expires_utc"])),
                    "is_secure": _bool_or_none(row["is_secure"]),
                    "is_httponly": _bool_or_none(row["is_httponly"]),
                    "has_expires": _bool_or_none(row["has_expires"]),
                    "is_persistent": _bool_or_none(row["is_persistent"]),
                    "samesite": row["samesite"],
                    "source_scheme": row["source_scheme"],
                    "source_port": row["source_port"],
                    **secret_fields,
                },
                parse_status=ArtifactParseStatus.PARTIAL,
                warnings=secret_warnings,
            )
        )
    return _stream_result(rows, has_more, artifacts)


def _firefox_cookies_page(
    *,
    connection: sqlite3.Connection,
    evidence: Evidence,
    node: FileSystemNode,
    source: ArtifactSource,
    content_sha256: str,
    profile: dict[str, Any],
    tables: dict[str, list[str]],
    after_row_id: int | None,
    limit: int | None,
) -> _BrowserStreamPage:
    if not _has_columns(tables, "moz_cookies", {"host", "name"}):
        return _BrowserStreamPage((), None, False)
    where = "WHERE moz_cookies.rowid > ?" if after_row_id is not None else ""
    params = [] if after_row_id is None else [after_row_id]
    rows, has_more = _rows_with_limit(
        connection,
        f"""
        SELECT
            moz_cookies.rowid AS row_id,
            {_sql_column_or_null(tables, "moz_cookies", "host")},
            {_sql_column_or_null(tables, "moz_cookies", "name")},
            {_sql_column_or_null(tables, "moz_cookies", "value")},
            {_sql_column_or_null(tables, "moz_cookies", "path")},
            {_sql_column_or_null(tables, "moz_cookies", "expiry")},
            {_sql_column_or_null(tables, "moz_cookies", "lastAccessed")},
            {_sql_column_or_null(tables, "moz_cookies", "creationTime")},
            {_sql_column_or_null(tables, "moz_cookies", "isSecure")},
            {_sql_column_or_null(tables, "moz_cookies", "isHttpOnly")}
        FROM moz_cookies
        {where}
        ORDER BY moz_cookies.rowid
        """,
        params,
        limit,
    )
    artifacts: list[ArtifactRecord] = []
    for row in rows:
        secret_fields, secret_warnings = _cookie_secret_metadata(
            plaintext_value=row["value"],
            encrypted_value=None,
            store_kind="FIREFOX_COOKIE",
        )
        host = _str_or_empty(row["host"])
        observed_raw = _first_non_empty(row["lastAccessed"], row["creationTime"])
        artifacts.append(
            _browser_row_artifact(
                evidence=evidence,
                node=node,
                source=source,
                content_sha256=content_sha256,
                profile=profile,
                db_kind="FIREFOX_COOKIES",
                artifact_type=ArtifactType.BROWSER_COOKIE,
                subtype="FIREFOX_COOKIE_METADATA_REDACTED",
                table="moz_cookies",
                row_id=int(row["row_id"]),
                joined_tables=[],
                observed_raw=None if observed_raw is None else str(observed_raw),
                observed_utc=_unix_microseconds(observed_raw),
                title=f"Firefox cookie metadata: {host or 'unknown domain'}",
                summary="Firefox cookie row metadata observed; secret value is redacted.",
                extra_fields={
                    "cookie_domain": host or None,
                    "cookie_name_sha256": _sha256_text(row["name"]),
                    "cookie_name_length": _text_length(row["name"]),
                    "cookie_path": row["path"],
                    "expiry_raw": _none_or_str(row["expiry"]),
                    "expiry_utc": _timestamp_string(_unix_seconds(row["expiry"])),
                    "last_access_time_raw": _none_or_str(row["lastAccessed"]),
                    "creation_time_raw": _none_or_str(row["creationTime"]),
                    "is_secure": _bool_or_none(row["isSecure"]),
                    "is_httponly": _bool_or_none(row["isHttpOnly"]),
                    **secret_fields,
                },
                parse_status=ArtifactParseStatus.PARTIAL,
                warnings=secret_warnings,
            )
        )
    return _stream_result(rows, has_more, artifacts)


def _chromium_credentials_page(
    *,
    connection: sqlite3.Connection,
    evidence: Evidence,
    node: FileSystemNode,
    source: ArtifactSource,
    content_sha256: str,
    profile: dict[str, Any],
    tables: dict[str, list[str]],
    after_row_id: int | None,
    limit: int | None,
) -> _BrowserStreamPage:
    if not _has_columns(tables, "logins", {"origin_url", "password_value"}):
        return _BrowserStreamPage((), None, False)
    where = "WHERE logins.rowid > ?" if after_row_id is not None else ""
    params = [] if after_row_id is None else [after_row_id]
    rows, has_more = _rows_with_limit(
        connection,
        f"""
        SELECT
            logins.rowid AS row_id,
            {_sql_column_or_null(tables, "logins", "origin_url")},
            {_sql_column_or_null(tables, "logins", "action_url")},
            {_sql_column_or_null(tables, "logins", "signon_realm")},
            {_sql_column_or_null(tables, "logins", "username_value")},
            {_sql_column_or_null(tables, "logins", "password_value")},
            {_sql_column_or_null(tables, "logins", "date_created")},
            {_sql_column_or_null(tables, "logins", "date_last_used")},
            {_sql_column_or_null(tables, "logins", "date_password_modified")},
            {_sql_column_or_null(tables, "logins", "times_used")},
            {_sql_column_or_null(tables, "logins", "scheme")}
        FROM logins
        {where}
        ORDER BY logins.rowid
        """,
        params,
        limit,
    )
    artifacts: list[ArtifactRecord] = []
    for row in rows:
        secret_fields, secret_warnings = _credential_secret_metadata(
            username_value=row["username_value"],
            password_value=row["password_value"],
        )
        origin_url = _none_or_str(row["origin_url"])
        domain = _safe_domain(origin_url) if origin_url else None
        observed_raw = _first_non_empty(row["date_last_used"], row["date_created"])
        artifacts.append(
            _browser_row_artifact(
                evidence=evidence,
                node=node,
                source=source,
                content_sha256=content_sha256,
                profile=profile,
                db_kind="CHROMIUM_LOGIN_DATA",
                artifact_type=ArtifactType.BROWSER_CREDENTIAL,
                subtype="CHROMIUM_LOGIN_METADATA_REDACTED",
                table="logins",
                row_id=int(row["row_id"]),
                joined_tables=[],
                observed_raw=None if observed_raw is None else str(observed_raw),
                observed_utc=_webkit_timestamp(observed_raw),
                title=f"Chromium credential metadata: {domain or 'unknown origin'}",
                summary="Chromium login row metadata observed; credential values are redacted.",
                extra_fields={
                    "origin_url": origin_url,
                    "action_url": row["action_url"],
                    "signon_realm_sha256": _sha256_text(row["signon_realm"]),
                    "credential_origin_domain": domain,
                    "date_created_raw": _none_or_str(row["date_created"]),
                    "date_last_used_raw": _none_or_str(row["date_last_used"]),
                    "date_password_modified_raw": _none_or_str(
                        row["date_password_modified"]
                    ),
                    "times_used": row["times_used"],
                    "scheme": row["scheme"],
                    **secret_fields,
                },
                parse_status=ArtifactParseStatus.PARTIAL,
                warnings=secret_warnings,
            )
        )
    return _stream_result(rows, has_more, artifacts)


def _sqlite_deleted_candidates_page(
    *,
    connection: sqlite3.Connection,
    evidence: Evidence,
    node: FileSystemNode,
    source: ArtifactSource,
    content_sha256: str,
    profile: dict[str, Any],
    tables: dict[str, list[str]],
    after_row_id: int | None,
) -> _BrowserStreamPage:
    if after_row_id is not None:
        return _BrowserStreamPage((), None, False)
    freelist_count = _pragma_int(connection, "freelist_count")
    page_count = _pragma_int(connection, "page_count")
    page_size = _pragma_int(connection, "page_size")
    snapshot_value = profile.get("snapshot")
    snapshot: dict[str, Any] = snapshot_value if isinstance(snapshot_value, dict) else {}
    wal_preserved = bool(snapshot.get("wal_preserved"))
    if freelist_count <= 0:
        return _BrowserStreamPage((), None, False)
    observed = _file_modified_observed(node)
    candidate_basis: list[str] = []
    if freelist_count > 0:
        candidate_basis.append("SQLITE_FREELIST_PAGES_PRESENT")
    if wal_preserved:
        candidate_basis.append("SQLITE_WAL_COMPONENT_PRESERVED")
    db_kind = _database_kind(tables, profile)
    artifact = _browser_row_artifact(
        evidence=evidence,
        node=node,
        source=source,
        content_sha256=content_sha256,
        profile=profile,
        db_kind=db_kind,
        artifact_type=ArtifactType.BROWSER_DELETED_SQLITE_ROW,
        subtype="SQLITE_DELETED_ROW_CANDIDATE",
        table="sqlite_freelist",
        row_id=1,
        joined_tables=[],
        observed_raw=observed["raw"],
        observed_utc=observed["utc"],
        title=f"SQLite deleted-row candidate evidence: {node.original_name}",
        summary=(
            "SQLite freelist/WAL evidence indicates possible deleted or unapplied rows; "
            "no deleted row content was recovered."
        ),
        extra_fields={
            "candidate_semantics": "DELETED_OR_UNAPPLIED_ROW_CANDIDATE_NOT_CONFIRMED_ROW",
            "candidate_basis": candidate_basis,
            "freelist_page_count": freelist_count,
            "page_count": page_count,
            "page_size": page_size,
            "wal_preserved": wal_preserved,
            "deleted_record_content_recovered": False,
            "confirmed_row": False,
            "page_cell_provenance": {
                "page_numbers": "UNKNOWN_FREELIST_CHAIN_NOT_PARSED",
                "cell_offsets": "UNKNOWN",
                "recovery_method": "SQLITE_PRAGMA_AND_WAL_COMPONENT_PRESENCE",
                "confidence": "LOW",
            },
            "search_index_default_exclude": False,
        },
        parse_status=ArtifactParseStatus.PARTIAL,
        warnings=[
            {
                "code": "SQLITE_DELETED_ROW_CONTENT_NOT_RECOVERED",
                "message_key": "warning.browser.sqlite_deleted_row_content_not_recovered",
                "developer_message": (
                    "SQLite deleted-row content recovery is unavailable; this artifact is a "
                    "low-confidence presence candidate only."
                ),
            }
        ],
    )
    return _BrowserStreamPage((artifact,), 1, False)


def _private_mode_candidates_page(
    *,
    evidence: Evidence,
    node: FileSystemNode,
    source: ArtifactSource,
    content_sha256: str,
    profile: dict[str, Any],
    tables: dict[str, list[str]],
    after_row_id: int | None,
) -> _BrowserStreamPage:
    if after_row_id is not None:
        return _BrowserStreamPage((), None, False)
    indicators = _private_mode_indicators(node, profile)
    if not indicators:
        return _BrowserStreamPage((), None, False)
    observed = _file_modified_observed(node)
    artifact = _browser_row_artifact(
        evidence=evidence,
        node=node,
        source=source,
        content_sha256=content_sha256,
        profile=profile,
        db_kind=_database_kind(tables, profile),
        artifact_type=ArtifactType.BROWSER_PRIVATE_MODE_CANDIDATE,
        subtype="PRIVATE_MODE_PROFILE_PATH_CANDIDATE",
        table="browser_profile_path",
        row_id=1,
        joined_tables=[],
        observed_raw=observed["raw"],
        observed_utc=observed["utc"],
        title=f"Private-mode profile candidate: {profile['name']}",
        summary=(
            "Browser profile path contains private-mode candidate indicators; this does not "
            "confirm private browsing use."
        ),
        extra_fields={
            "private_mode_candidate": True,
            "private_mode_confirmed": False,
            "candidate_basis": indicators,
            "absence_of_evidence_not_private_mode_evidence": True,
            "policy": _private_mode_policy(),
        },
        parse_status=ArtifactParseStatus.PARTIAL,
        warnings=[
            {
                "code": "PRIVATE_MODE_CANDIDATE_ONLY",
                "message_key": "warning.browser.private_mode_candidate_only",
                "developer_message": (
                    "Private/incognito use is recorded only as a candidate when explicit "
                    "path evidence exists; absence of artifacts is never asserted as no use."
                ),
            }
        ],
    )
    return _BrowserStreamPage((artifact,), 1, False)


def _chromium_artifacts(
    *,
    connection: sqlite3.Connection,
    evidence: Evidence,
    node: FileSystemNode,
    source: ArtifactSource,
    content_sha256: str,
    profile: dict[str, Any],
    tables: dict[str, list[str]],
) -> list[ArtifactRecord]:
    artifacts: list[ArtifactRecord] = []
    if _has_columns(tables, "visits", {"id", "url", "visit_time"}) and _has_columns(
        tables,
        "urls",
        {"id", "url"},
    ):
        for row in _fetchmany(
            connection.execute(
                """
            SELECT
                visits.id AS row_id,
                visits.url AS url_id,
                visits.visit_time AS visit_time,
                visits.from_visit AS from_visit,
                visits.transition AS transition,
                urls.url AS url,
                urls.title AS title,
                urls.visit_count AS visit_count,
                urls.typed_count AS typed_count,
                urls.last_visit_time AS last_visit_time
            FROM visits
            JOIN urls ON urls.id = visits.url
            ORDER BY visits.id
            """
            )
        ):
            artifacts.append(
                _browser_row_artifact(
                    evidence=evidence,
                    node=node,
                    source=source,
                    content_sha256=content_sha256,
                    profile=profile,
                    db_kind="CHROMIUM",
                    artifact_type=ArtifactType.BROWSER_VISIT,
                    subtype="CHROMIUM_VISIT",
                    table="visits",
                    row_id=int(row["row_id"]),
                    joined_tables=["urls"],
                    observed_raw=str(row["visit_time"]),
                    observed_utc=_webkit_timestamp(row["visit_time"]),
                    title=str(row["title"] or row["url"]),
                    summary="Chromium visit history row observed.",
                    extra_fields={
                        "url": row["url"],
                        "url_id": row["url_id"],
                        "page_title": row["title"],
                        "visit_count": row["visit_count"],
                        "typed_count": row["typed_count"],
                        "from_visit": row["from_visit"],
                        "transition": row["transition"],
                    },
                )
            )
    if "keyword_search_terms" in tables and _has_columns(
        tables,
        "keyword_search_terms",
        {"term", "url_id"},
    ):
        for row in _fetchmany(
            connection.execute(
                """
            SELECT
                keyword_search_terms.rowid AS row_id,
                keyword_search_terms.term AS term,
                keyword_search_terms.url_id AS url_id,
                urls.url AS url,
                urls.title AS title,
                urls.last_visit_time AS last_visit_time
            FROM keyword_search_terms
            LEFT JOIN urls ON urls.id = keyword_search_terms.url_id
            ORDER BY keyword_search_terms.rowid
            """
            )
        ):
            artifacts.append(
                _browser_row_artifact(
                    evidence=evidence,
                    node=node,
                    source=source,
                    content_sha256=content_sha256,
                    profile=profile,
                    db_kind="CHROMIUM",
                    artifact_type=ArtifactType.BROWSER_SEARCH,
                    subtype="CHROMIUM_SEARCH_TERM",
                    table="keyword_search_terms",
                    row_id=int(row["row_id"]),
                    joined_tables=["urls"],
                    observed_raw=None
                    if row["last_visit_time"] is None
                    else str(row["last_visit_time"]),
                    observed_utc=_webkit_timestamp(row["last_visit_time"]),
                    title=f"Search: {row['term']}",
                    summary="Chromium search history row observed.",
                    extra_fields={
                        "search_term": row["term"],
                        "url": row["url"],
                        "url_id": row["url_id"],
                        "page_title": row["title"],
                    },
                )
            )
    if "downloads" in tables and _has_columns(tables, "downloads", {"id", "start_time"}):
        for row in _fetchmany(connection.execute(_chromium_download_query(tables))):
            artifacts.append(
                _browser_row_artifact(
                    evidence=evidence,
                    node=node,
                    source=source,
                    content_sha256=content_sha256,
                    profile=profile,
                    db_kind="CHROMIUM",
                    artifact_type=ArtifactType.BROWSER_DOWNLOAD,
                    subtype="CHROMIUM_DOWNLOAD",
                    table="downloads",
                    row_id=int(row["row_id"]),
                    joined_tables=["downloads_url_chains"]
                    if "downloads_url_chains" in tables
                    else [],
                    observed_raw=None if row["start_time"] is None else str(row["start_time"]),
                    observed_utc=_webkit_timestamp(row["start_time"]),
                    title=f"Download: {row['download_path'] or row['download_url']}",
                    summary="Chromium download history row observed.",
                    extra_fields={
                        "download_path": row["download_path"],
                        "download_url": row["download_url"],
                        "tab_url": row["tab_url"],
                        "referrer_url": row["referrer_url"],
                        "received_bytes": row["received_bytes"],
                        "total_bytes": row["total_bytes"],
                        "state": row["state"],
                        "state_label": _chromium_download_state(row["state"]),
                        "danger_type": row["danger_type"],
                        "danger_type_note": (
                            "danger_type is preserved as browser metadata only; "
                            "it is not a malware finding."
                        ),
                        "interrupt_reason": row["interrupt_reason"],
                        "end_time_raw": None if row["end_time"] is None else str(row["end_time"]),
                        "end_time_utc": _timestamp_string(_webkit_timestamp(row["end_time"])),
                    },
                )
            )
    return artifacts


def _firefox_artifacts(
    *,
    connection: sqlite3.Connection,
    evidence: Evidence,
    node: FileSystemNode,
    source: ArtifactSource,
    content_sha256: str,
    profile: dict[str, Any],
    tables: dict[str, list[str]],
) -> list[ArtifactRecord]:
    artifacts: list[ArtifactRecord] = []
    for row in _fetchmany(
        connection.execute(
            """
        SELECT
            moz_historyvisits.id AS row_id,
            moz_historyvisits.place_id AS place_id,
            moz_historyvisits.visit_date AS visit_date,
            moz_historyvisits.from_visit AS from_visit,
            moz_historyvisits.visit_type AS visit_type,
            moz_places.url AS url,
            moz_places.title AS title,
            moz_places.visit_count AS visit_count
        FROM moz_historyvisits
        JOIN moz_places ON moz_places.id = moz_historyvisits.place_id
        ORDER BY moz_historyvisits.id
        """
        )
    ):
        artifacts.append(
            _browser_row_artifact(
                evidence=evidence,
                node=node,
                source=source,
                content_sha256=content_sha256,
                profile=profile,
                db_kind="FIREFOX",
                artifact_type=ArtifactType.BROWSER_VISIT,
                subtype="FIREFOX_VISIT",
                table="moz_historyvisits",
                row_id=int(row["row_id"]),
                joined_tables=["moz_places"],
                observed_raw=None if row["visit_date"] is None else str(row["visit_date"]),
                observed_utc=_unix_microseconds(row["visit_date"]),
                title=str(row["title"] or row["url"]),
                summary="Firefox visit history row observed.",
                extra_fields={
                    "url": row["url"],
                    "place_id": row["place_id"],
                    "page_title": row["title"],
                    "visit_count": row["visit_count"],
                    "from_visit": row["from_visit"],
                    "visit_type": row["visit_type"],
                },
            )
        )
    if _has_columns(
        tables, "moz_annos", {"id", "place_id", "anno_attribute_id", "content"}
    ) and _has_columns(
        tables,
        "moz_anno_attributes",
        {"id", "name"},
    ):
        for row in _fetchmany(
            connection.execute(
                """
            SELECT
                moz_annos.id AS row_id,
                moz_annos.place_id AS place_id,
                moz_annos.content AS content,
                moz_annos.dateAdded AS date_added,
                moz_annos.lastModified AS last_modified,
                moz_anno_attributes.name AS annotation_name,
                moz_places.url AS url,
                moz_places.title AS title
            FROM moz_annos
            JOIN moz_anno_attributes ON moz_anno_attributes.id = moz_annos.anno_attribute_id
            LEFT JOIN moz_places ON moz_places.id = moz_annos.place_id
            WHERE moz_anno_attributes.name IN (
                'downloads/destinationFileURI',
                'downloads/destinationFileName',
                'downloads/metaData',
                'downloads/sourceURI'
            )
            ORDER BY moz_annos.id
            """
            )
        ):
            artifacts.append(
                _browser_row_artifact(
                    evidence=evidence,
                    node=node,
                    source=source,
                    content_sha256=content_sha256,
                    profile=profile,
                    db_kind="FIREFOX",
                    artifact_type=ArtifactType.BROWSER_DOWNLOAD,
                    subtype="FIREFOX_DOWNLOAD_ANNOTATION_CANDIDATE",
                    table="moz_annos",
                    row_id=int(row["row_id"]),
                    joined_tables=["moz_anno_attributes", "moz_places"],
                    observed_raw=None
                    if row["last_modified"] is None
                    else str(row["last_modified"]),
                    observed_utc=_unix_microseconds(row["last_modified"]),
                    title=f"Firefox download candidate: {row['content']}",
                    summary=(
                        "Firefox download annotation candidate observed; metadata may be "
                        "incomplete."
                    ),
                    extra_fields={
                        "url": row["url"],
                        "page_title": row["title"],
                        "download_path": row["content"]
                        if str(row["annotation_name"]).endswith("destinationFileName")
                        else None,
                        "download_url": row["url"],
                        "annotation_name": row["annotation_name"],
                        "annotation_content": row["content"],
                        "date_added_raw": None
                        if row["date_added"] is None
                        else str(row["date_added"]),
                        "download_metadata_is_partial": True,
                    },
                    parse_status=ArtifactParseStatus.PARTIAL,
                    warnings=[
                        {
                            "code": "FIREFOX_DOWNLOAD_METADATA_PARTIAL",
                            "message_key": "warning.browser.firefox_download_metadata_partial",
                            "developer_message": (
                                "Firefox download annotation metadata is version-dependent "
                                "and incomplete."
                            ),
                        }
                    ],
                )
            )

    if "moz_inputhistory" in tables and _has_columns(
        tables,
        "moz_inputhistory",
        {"place_id", "input"},
    ):
        for row in _fetchmany(
            connection.execute(
                """
            SELECT
                moz_inputhistory.rowid AS row_id,
                moz_inputhistory.place_id AS place_id,
                moz_inputhistory.input AS input,
                moz_inputhistory.use_count AS use_count,
                moz_places.url AS url,
                moz_places.title AS title,
                moz_places.last_visit_date AS last_visit_date
            FROM moz_inputhistory
            LEFT JOIN moz_places ON moz_places.id = moz_inputhistory.place_id
            ORDER BY moz_inputhistory.rowid
            """
            )
        ):
            artifacts.append(
                _browser_row_artifact(
                    evidence=evidence,
                    node=node,
                    source=source,
                    content_sha256=content_sha256,
                    profile=profile,
                    db_kind="FIREFOX",
                    artifact_type=ArtifactType.BROWSER_PROFILE,
                    subtype="FIREFOX_URLBAR_INPUT_HISTORY_CANDIDATE",
                    table="moz_inputhistory",
                    row_id=int(row["row_id"]),
                    joined_tables=["moz_places"],
                    observed_raw=None,
                    observed_utc=None,
                    title=f"Firefox URL-bar input candidate: {row['input']}",
                    summary=(
                        "Firefox URL-bar input history candidate observed; this is not a "
                        "confirmed web search term."
                    ),
                    extra_fields={
                        "input_text": row["input"],
                        "url": row["url"],
                        "place_id": row["place_id"],
                        "page_title": row["title"],
                        "use_count": row["use_count"],
                        "timestamp_semantics": "FIREFOX_INPUT_HISTORY_NO_DIRECT_TIMESTAMP",
                        "search_term_confirmed": False,
                    },
                    parse_status=ArtifactParseStatus.PARTIAL,
                    warnings=[
                        {
                            "code": "FIREFOX_INPUT_HISTORY_NOT_CONFIRMED_SEARCH",
                            "message_key": (
                                "warning.browser.firefox_input_history_not_confirmed_search"
                            ),
                            "developer_message": (
                                "Firefox moz_inputhistory stores URL-bar input history and is "
                                "not classified as confirmed search-term evidence."
                            ),
                        }
                    ],
                )
            )
    return artifacts


def _browser_row_artifact(
    *,
    evidence: Evidence,
    node: FileSystemNode,
    source: ArtifactSource,
    content_sha256: str,
    profile: dict[str, Any],
    db_kind: str,
    artifact_type: ArtifactType,
    subtype: str,
    table: str,
    row_id: int,
    joined_tables: list[str],
    observed_raw: str | None,
    observed_utc: datetime | None,
    title: str,
    summary: str,
    extra_fields: dict[str, Any],
    parse_status: ArtifactParseStatus = ArtifactParseStatus.SUCCESS,
    warnings: list[dict[str, Any]] | None = None,
) -> ArtifactRecord:
    fields = (
        _base_browser_fields(
            node=node,
            content_sha256=content_sha256,
            profile=profile,
            db_kind=db_kind,
            table=table,
            row_id=row_id,
            joined_tables=joined_tables,
        )
        | extra_fields
    )
    primary_url = fields.get("url") or fields.get("download_url") or fields.get("origin_url")
    if isinstance(primary_url, str):
        fields["domain"] = _safe_domain(primary_url)
    if fields.get("cookie_domain") and "domain" not in fields:
        fields["domain"] = fields["cookie_domain"]
    if fields.get("credential_origin_domain") and "domain" not in fields:
        fields["domain"] = fields["credential_origin_domain"]
    fields.setdefault("timestamp_semantics", _browser_timestamp_semantics(db_kind, table))
    raw_locator = _browser_locator(
        evidence=evidence,
        node=node,
        content_sha256=content_sha256,
        table=table,
        row_id=row_id,
        joined_tables=joined_tables,
    )
    return make_artifact(
        evidence=evidence,
        node=node,
        source=source,
        artifact_type=artifact_type,
        artifact_subtype=subtype,
        fields=fields,
        raw_locator=raw_locator,
        title=title,
        summary=summary,
        parse_status=parse_status,
        confidence=0.9 if parse_status is ArtifactParseStatus.SUCCESS else 0.65,
        observed_at_raw=observed_raw,
        observed_at_utc=observed_utc,
        timezone_source="BROWSER_NATIVE_UTC" if observed_utc is not None else None,
        timezone_confidence="HIGH" if observed_utc is not None else "UNKNOWN",
        warnings=warnings or [],
    )


def _base_browser_fields(
    *,
    node: FileSystemNode,
    content_sha256: str,
    profile: dict[str, Any],
    db_kind: str,
    table: str,
    row_id: int | None,
    joined_tables: list[str],
) -> dict[str, Any]:
    snapshot = profile.get("snapshot") if isinstance(profile.get("snapshot"), dict) else {}
    return {
        "browser": profile["browser"],
        "browser_family": profile.get("browser_family", "UNKNOWN"),
        "browser_name": profile.get("browser_name", profile["browser"]),
        "browser_profile": profile,
        "browser_profile_name": profile["name"],
        "profile_id": profile.get("profile_id"),
        "operating_system": profile.get("operating_system", "UNKNOWN"),
        "user_candidate": profile.get("user_candidate"),
        "discovery_method": profile.get("discovery_method"),
        "source_revision": profile.get("source_revision"),
        "usage_confirmed": False,
        "source_role": profile.get("source_role"),
        "secret_handling_policy": _browser_secret_policy(),
        "private_mode_policy": _private_mode_policy(),
        "incognito_candidate": False,
        "absence_of_private_mode_evidence_means": "UNKNOWN_NOT_NOT_USED",
        "database": {
            "type": db_kind,
            "path": node.display_path,
            "content_sha256": content_sha256,
        },
        "snapshot": snapshot,
        "database_path": node.display_path,
        "table": table,
        "row_id": row_id,
        "row_provenance": {
            "profile": profile,
            "database_path": node.display_path,
            "database_type": db_kind,
            "table": table,
            "row_id": row_id,
            "joined_tables": joined_tables,
        },
    }


def _browser_locator(
    *,
    evidence: Evidence,
    node: FileSystemNode,
    content_sha256: str,
    table: str,
    row_id: int | None,
    joined_tables: list[str],
) -> dict[str, Any]:
    return make_raw_locator(
        evidence_id=evidence.evidence_id,
        source_file_node_id=node.node_id,
        source_path=node.display_path,
        source_reference=f"sqlite:{table}:{row_id}" if row_id is not None else f"sqlite:{table}",
        locator_type="SQLITE_ROW",
        offset=None,
        length=None,
        encoding="sqlite",
        view_types=["TEXT"],
        content_sha256=content_sha256,
        limitations=["SQLite logical row provenance does not expose byte offsets."],
        details={"table": table, "row_id": row_id, "joined_tables": joined_tables},
    )


def _corrupt_db_artifact(
    *,
    evidence: Evidence,
    node: FileSystemNode,
    source: ArtifactSource,
    content_sha256: str,
    profile: dict[str, Any],
    error: str,
) -> ArtifactRecord:
    return _profile_artifact(
        evidence=evidence,
        node=node,
        source=source,
        content_sha256=content_sha256,
        profile=profile,
        db_kind="CORRUPT",
        tables={},
        parse_status=ArtifactParseStatus.CORRUPT,
        warnings=[
            {
                "code": "BROWSER_DB_CORRUPT",
                "message_key": "warning.browser.db_corrupt",
                "developer_message": (
                    "Browser SQLite database is corrupt or unreadable; analysis continued."
                ),
                "details": {"error": error},
            }
        ],
    )


def _result_with_warnings(
    artifact: ArtifactRecord,
    node: FileSystemNode,
    parse_status: ArtifactParseStatus,
) -> ArtifactAnalysisResult:
    return ArtifactAnalysisResult(
        artifacts=(artifact,),
        warnings=tuple(_artifact_warnings(artifact, node)),
        coverage={
            "database_kind": artifact.fields["database"]["type"],
            "artifact_count": 1,
        },
        parse_status=parse_status,
    )


def _artifact_warnings(
    artifact: ArtifactRecord,
    node: FileSystemNode,
) -> list[ArtifactIssue]:
    return [
        issue(
            severity="WARNING",
            code=str(warning["code"]),
            message_key=str(warning["message_key"]),
            developer_message=str(warning["developer_message"]),
            node=node,
            details=dict(warning.get("details", {})),
            artifact_id=artifact.artifact_id,
        )
        for warning in artifact.warnings
    ]


def _chromium_download_query(
    tables: dict[str, list[str]],
    *,
    after_row_id: int | None = None,
) -> str:
    columns = set(tables.get("downloads", []))
    path_expr = (
        "downloads.target_path"
        if "target_path" in columns
        else "downloads.current_path"
        if "current_path" in columns
        else "NULL"
    )
    end_time_expr = "downloads.end_time" if "end_time" in columns else "NULL"
    received_expr = "downloads.received_bytes" if "received_bytes" in columns else "NULL"
    total_expr = "downloads.total_bytes" if "total_bytes" in columns else "NULL"
    state_expr = "downloads.state" if "state" in columns else "NULL"
    danger_expr = "downloads.danger_type" if "danger_type" in columns else "NULL"
    interrupt_expr = "downloads.interrupt_reason" if "interrupt_reason" in columns else "NULL"
    tab_expr = "downloads.tab_url" if "tab_url" in columns else "NULL"
    referrer_expr = "downloads.tab_referrer_url" if "tab_referrer_url" in columns else "NULL"
    chain_columns = set(tables.get("downloads_url_chains", []))
    chain_link_column = (
        "download_id" if "download_id" in chain_columns else "id" if "id" in chain_columns else None
    )
    chain_order_column = "chain_index" if "chain_index" in chain_columns else "rowid"
    if "url" in chain_columns and chain_link_column is not None:
        url_expr = f"""
            (
                SELECT url
                FROM downloads_url_chains
                WHERE downloads_url_chains.{chain_link_column} = downloads.id
                ORDER BY {chain_order_column}
                LIMIT 1
            )
        """
    else:
        url_expr = "downloads.url" if "url" in columns else "NULL"
    where = "WHERE downloads.id > ?" if after_row_id is not None else ""
    return f"""
        SELECT
            downloads.id AS row_id,
            {path_expr} AS download_path,
            {url_expr} AS download_url,
            downloads.start_time AS start_time,
            {end_time_expr} AS end_time,
            {tab_expr} AS tab_url,
            {referrer_expr} AS referrer_url,
            {received_expr} AS received_bytes,
            {total_expr} AS total_bytes,
            {state_expr} AS state,
            {danger_expr} AS danger_type,
            {interrupt_expr} AS interrupt_reason
        FROM downloads
        {where}
        ORDER BY downloads.id
    """


def _safe_domain(url: str) -> str | None:
    parsed = urlparse(url)
    return parsed.hostname


def _browser_timestamp_semantics(db_kind: str, table: str) -> str:
    if db_kind.startswith("CHROMIUM"):
        return f"CHROMIUM_WEBKIT_MICROSECONDS_UTC:{table}"
    if db_kind.startswith("FIREFOX"):
        return f"FIREFOX_UNIX_MICROSECONDS_UTC:{table}"
    return f"BROWSER_TIMESTAMP_UNKNOWN:{table}"


def _chromium_download_state(value: Any) -> str:
    states = {
        0: "IN_PROGRESS",
        1: "COMPLETE",
        2: "CANCELLED",
        3: "INTERRUPTED",
        4: "INTERRUPTED",
    }
    try:
        return states.get(int(value), f"UNKNOWN_{value}")
    except (TypeError, ValueError):
        return "UNKNOWN"


def _has_columns(tables: dict[str, list[str]], table: str, required: set[str]) -> bool:
    return table in tables and required.issubset(set(tables[table]))


def _quote_identifier(value: str) -> str:
    return '"' + value.replace('"', '""') + '"'


def _webkit_timestamp(value: Any) -> datetime | None:
    try:
        micros = int(value)
    except (TypeError, ValueError):
        return None
    if micros <= 0:
        return None
    return _WEBKIT_EPOCH + timedelta(microseconds=micros)


def _unix_microseconds(value: Any) -> datetime | None:
    try:
        micros = int(value)
    except (TypeError, ValueError):
        return None
    if micros <= 0:
        return None
    return _UNIX_EPOCH + timedelta(microseconds=micros)


def _unix_seconds(value: Any) -> datetime | None:
    try:
        seconds = int(value)
    except (TypeError, ValueError):
        return None
    if seconds <= 0:
        return None
    return _UNIX_EPOCH + timedelta(seconds=seconds)


def _timestamp_string(value: datetime | None) -> str | None:
    return None if value is None else to_json_timestamp(value)


def _file_modified_observed(node: FileSystemNode) -> dict[str, Any]:
    raw = node.raw_timestamps.get("modified")
    utc = node.utc_timestamps.get("modified")
    return {
        "raw": None if raw is None else str(raw),
        "utc": utc,
        "timezone_source": "FILESYSTEM_METADATA" if utc is not None else None,
        "timezone_confidence": "HIGH" if utc is not None else "UNKNOWN",
    }
