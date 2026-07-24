"""Browser communications artifact analyzer for Phase 5."""

from __future__ import annotations

import hashlib
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
            supported_source_kinds=(ArtifactSourceKind.BROWSER_SQLITE_DB,),
            supported_artifact_types=(
                ArtifactType.BROWSER_PROFILE,
                ArtifactType.BROWSER_VISIT,
                ArtifactType.BROWSER_SEARCH,
                ArtifactType.BROWSER_DOWNLOAD,
            ),
            capabilities=(
                "BROWSER_PROFILE",
                "CHROMIUM_HISTORY_VISITS",
                "CHROMIUM_SEARCH_TERMS",
                "CHROMIUM_DOWNLOADS",
                "FIREFOX_PLACES_VISITS",
                "FIREFOX_URLBAR_INPUT_HISTORY_CANDIDATE",
                "SQLITE_TABLE_ROW_PROVENANCE",
                "READ_ONLY_SQLITE_OPEN",
            ),
            unavailable_capabilities=("EMAIL", "MESSENGER_PLUGINS"),
            warnings=(
                {
                    "code": "COMMUNICATION_PLUGINS_DEFERRED",
                    "message_key": "warning.browser.communication_plugins_deferred",
                    "developer_message": (
                        "Email and messenger analyzers are plugin scope and are not part of "
                        "the Phase 5 MVP."
                    ),
                },
            ),
            metadata={
                "supported_databases": ["Chromium History", "Firefox places.sqlite"],
            },
        )

    def detect_source(self, node: FileSystemNode) -> ArtifactSource | None:
        if node.node_type is not FileSystemNodeType.FILE:
            return None
        if _profile_info(node) is None:
            return None
        return source_shell(
            node=node,
            source_kind=ArtifactSourceKind.BROWSER_SQLITE_DB,
            analyzer_id=self.analyzer_id,
            analyzer_version=self.analyzer_version,
            parser_backend=self.parser_backend,
            parser_backend_version=self.parser_backend_version,
            priority=55,
        )

    def supports_source(self, source: ArtifactSource) -> bool:
        return source.source_kind is ArtifactSourceKind.BROWSER_SQLITE_DB

    def analyze(
        self,
        *,
        evidence: Evidence,
        node: FileSystemNode,
        source: ArtifactSource,
        file_path: Path,
        item_budget: int | None = None,
    ) -> ArtifactAnalysisResult:
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
                    db_kind = _database_kind(tables)
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


def _database_kind(tables: dict[str, list[str]]) -> str:
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
    if name not in {"history", "places.sqlite"}:
        return None
    normalized_parts = [part.casefold() for part in parts]
    normalized_path = "/".join(normalized_parts)
    if name == "history":
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
    else:
        profile_index = len(parts) - 2
        profile_name = parts[profile_index]
        if not _is_firefox_profile_path(normalized_parts):
            return None
        browser_family, browser_name = "FIREFOX", "FIREFOX"
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
        "chromium_visits",
        "chromium_search_terms",
        "chromium_downloads",
    ),
    "FIREFOX": (
        "profile",
        "firefox_visits",
        "firefox_download_annotations",
        "firefox_input_history",
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
    primary_url = fields.get("url") or fields.get("download_url")
    if isinstance(primary_url, str):
        fields["domain"] = _safe_domain(primary_url)
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
    if db_kind == "CHROMIUM":
        return f"CHROMIUM_WEBKIT_MICROSECONDS_UTC:{table}"
    if db_kind == "FIREFOX":
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
