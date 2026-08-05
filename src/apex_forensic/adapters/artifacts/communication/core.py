"""Core communication plugin analyzer for bounded fixture-backed stores."""

from __future__ import annotations

import hashlib
import re
import sqlite3
from collections.abc import Iterable
from contextlib import closing
from dataclasses import dataclass
from datetime import UTC, datetime
from email import policy
from email.message import EmailMessage, Message
from email.parser import BytesParser
from email.utils import getaddresses, parsedate_to_datetime
from pathlib import Path, PurePosixPath
from typing import Any, ClassVar

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

_MAX_MESSAGE_BODY_CHARS = 20_000
_SECRET_PATTERNS = (
    re.compile(r"(?i)\b(api[_-]?key|token|secret|password)\s*[:=]\s*([^\s,;]+)"),
    re.compile(r"(?i)\b(authorization)\s*[:=]\s*bearer\s+([^\s,;]+)"),
)


@dataclass(frozen=True, slots=True)
class _CommunicationRecord:
    artifact_type: ArtifactType
    subtype: str
    title: str
    summary: str
    fields: dict[str, Any]
    source_reference: str
    locator_type: str
    observed_raw: str | None = None
    observed_utc: datetime | None = None
    parse_status: ArtifactParseStatus = ArtifactParseStatus.SUCCESS
    confidence: float = 0.85
    warnings: list[dict[str, Any]] | None = None


class _CommunicationApplicationAnalyzer:
    """Concrete per-application analyzer contract used by the core plugin."""

    analyzer_id: ClassVar[str]
    application: ClassVar[str]
    platform: ClassVar[str]
    source_kinds: ClassVar[tuple[ArtifactSourceKind, ...]]
    runtime_status: ClassVar[str]
    capabilities_list: ClassVar[tuple[str, ...]]
    unavailable_list: ClassVar[tuple[str, ...]]
    matrix_entry: ClassVar[dict[str, Any]]

    analyzer_version: ClassVar[str] = ENGINE_VERSION

    @property
    def parser_backend(self) -> str:
        return f"apex.communication_{self.application.casefold()}"

    @property
    def parser_backend_version(self) -> str:
        return ENGINE_VERSION

    def capabilities(self) -> ArtifactCapability:
        return ArtifactCapability(
            analyzer_id=self.analyzer_id,
            analyzer_version=self.analyzer_version,
            parser_backend=self.parser_backend,
            parser_backend_version=self.parser_backend_version,
            supported_source_kinds=self.source_kinds,
            supported_artifact_types=(
                ArtifactType.COMMUNICATION_PROFILE,
                ArtifactType.COMMUNICATION_ACCOUNT,
                ArtifactType.COMMUNICATION_CONVERSATION,
                ArtifactType.COMMUNICATION_MESSAGE,
                ArtifactType.COMMUNICATION_ATTACHMENT,
                ArtifactType.COMMUNICATION_UNSUPPORTED_STORE,
            ),
            capabilities=self.capabilities_list,
            unavailable_capabilities=self.unavailable_list,
            warnings=(
                {
                    "code": "COMMUNICATION_ANALYZER_SCOPE_LIMITED",
                    "message_key": "warning.communication.analyzer_scope_limited",
                    "developer_message": (
                        f"{self.application} analyzer is limited to the verified fixture "
                        "schema declared in metadata."
                    ),
                },
            )
            if self.runtime_status != "IMPLEMENTED_RUNTIME"
            else (),
            metadata={
                "application": self.application,
                "platform": self.platform,
                "runtime_status": self.runtime_status,
                "application_capability": self.matrix_entry,
                "credential_token_policy": _secret_policy(),
            },
        )

    def detect_source(self, node: FileSystemNode) -> ArtifactSource | None:
        if not self._supports_node(node):
            return None
        source_kind = _communication_source_kind(node)
        if source_kind is None:
            return None
        return source_shell(
            node=node,
            source_kind=source_kind,
            analyzer_id=self.analyzer_id,
            analyzer_version=self.analyzer_version,
            parser_backend=self.parser_backend,
            parser_backend_version=self.parser_backend_version,
            priority=40,
        )

    def supports_source(self, source: ArtifactSource) -> bool:
        return source.source_kind in self.source_kinds

    def analyze(
        self,
        *,
        evidence: Evidence,
        node: FileSystemNode,
        source: ArtifactSource,
        file_path: Path,
        item_budget: int | None = None,
    ) -> ArtifactAnalysisResult:
        if not self.supports_source(source) or not self._supports_node(node):
            return ArtifactAnalysisResult(
                warnings=(
                    issue(
                        severity="WARNING",
                        code="COMMUNICATION_SOURCE_UNSUPPORTED_FOR_ANALYZER",
                        message_key="warning.communication.source_unsupported_for_analyzer",
                        developer_message=(
                            "Communication source does not match this application analyzer."
                        ),
                        node=node,
                        details={"application": self.application},
                    ),
                ),
                parse_status=ArtifactParseStatus.UNSUPPORTED,
                coverage={"source_kind": source.source_kind.value},
            )
        return _analyze_communication_source(
            evidence=evidence,
            node=node,
            source=source,
            file_path=file_path,
            item_budget=item_budget,
            forced_application=self.application,
        )

    def _supports_node(self, node: FileSystemNode) -> bool:
        if node.node_type is not FileSystemNodeType.FILE:
            return False
        source_kind = _communication_source_kind(node)
        if source_kind not in self.source_kinds:
            return False
        if self.application == "EMAIL":
            return source_kind is ArtifactSourceKind.EMAIL_MBOX
        return _app_from_path(node) == self.application


class EmailMboxFixtureAnalyzer(_CommunicationApplicationAnalyzer):
    """Runtime MBOX analyzer for RFC5322 e-mail fixtures."""

    analyzer_id = "communication.email"
    application = "EMAIL"
    platform = "MBOX_RFC5322"
    source_kinds = (ArtifactSourceKind.EMAIL_MBOX,)
    runtime_status = "IMPLEMENTED_RUNTIME"
    capabilities_list = (
        "EMAIL_MBOX_RFC5322_FIXTURE",
        "MESSAGE_CONVERSATION_ATTACHMENT_PROVENANCE",
        "STABLE_LINEAR_CHECKPOINT",
        "UNICODE_KOREAN_PRESERVATION",
        "SECRET_TOKEN_REDACTION",
    )
    unavailable_list = ("EMAIL_PST_OST", "LIVE_CREDENTIAL_TOKEN_EXTRACTION")
    matrix_entry: ClassVar[dict[str, Any]] = {
        "application": "EMAIL",
        "analyzer": "EmailMboxFixtureAnalyzer",
        "analyzer_id": analyzer_id,
        "status": runtime_status,
        "platform": platform,
        "verified_fixture": "archive.mbox",
        "source_kind": ArtifactSourceKind.EMAIL_MBOX.value,
        "tables": [],
        "message_body": "TEXT_PLAIN_ONLY",
        "attachments": "REFERENCE_ONLY",
    }


class DiscordSQLiteFixtureAnalyzer(_CommunicationApplicationAnalyzer):
    """Runtime Discord analyzer for the verified simple SQLite fixture schema."""

    analyzer_id = "communication.discord"
    application = "DISCORD"
    platform = "DESKTOP_SQLITE_FIXTURE"
    source_kinds = (ArtifactSourceKind.COMMUNICATION_SQLITE_DB,)
    runtime_status = "IMPLEMENTED_RUNTIME"
    capabilities_list = (
        "DISCORD_SQLITE_MESSAGES_FIXTURE",
        "MESSAGE_CONVERSATION_ATTACHMENT_PROVENANCE",
        "STABLE_LINEAR_CHECKPOINT",
        "UNICODE_KOREAN_PRESERVATION",
        "SECRET_TOKEN_REDACTION",
    )
    unavailable_list = ("DISCORD_LEVELDB_NATIVE_CACHE", "LIVE_CREDENTIAL_TOKEN_EXTRACTION")
    matrix_entry: ClassVar[dict[str, Any]] = {
        "application": "DISCORD",
        "analyzer": "DiscordSQLiteFixtureAnalyzer",
        "analyzer_id": analyzer_id,
        "status": runtime_status,
        "platform": platform,
        "verified_fixture": "messages.sqlite",
        "source_kind": ArtifactSourceKind.COMMUNICATION_SQLITE_DB.value,
        "tables": [
            "messages(id, conversation_id, sender, recipients, timestamp, body)"
        ],
        "attachments": "REFERENCE_ONLY",
    }


class TelegramSQLiteFixtureAnalyzer(_CommunicationApplicationAnalyzer):
    """Runtime Telegram analyzer for the verified simple SQLite fixture schema."""

    analyzer_id = "communication.telegram"
    application = "TELEGRAM"
    platform = "DESKTOP_SQLITE_FIXTURE"
    source_kinds = (ArtifactSourceKind.COMMUNICATION_SQLITE_DB,)
    runtime_status = "IMPLEMENTED_RUNTIME"
    capabilities_list = (
        "TELEGRAM_SQLITE_MESSAGES_FIXTURE",
        "MESSAGE_CONVERSATION_ATTACHMENT_PROVENANCE",
        "STABLE_LINEAR_CHECKPOINT",
        "UNICODE_KOREAN_PRESERVATION",
        "SECRET_TOKEN_REDACTION",
    )
    unavailable_list = ("TELEGRAM_TDESKTOP_NATIVE_BINARY", "LIVE_CREDENTIAL_TOKEN_EXTRACTION")
    matrix_entry: ClassVar[dict[str, Any]] = {
        "application": "TELEGRAM",
        "analyzer": "TelegramSQLiteFixtureAnalyzer",
        "analyzer_id": analyzer_id,
        "status": runtime_status,
        "platform": platform,
        "verified_fixture": "messages.sqlite",
        "source_kind": ArtifactSourceKind.COMMUNICATION_SQLITE_DB.value,
        "tables": [
            "messages(id, conversation_id, sender, recipients, timestamp, body)"
        ],
        "attachments": "REFERENCE_ONLY",
    }


class KakaoTalkEncryptedStoreDiscoveryAnalyzer(_CommunicationApplicationAnalyzer):
    """Structured unsupported KakaoTalk encrypted-store discovery analyzer."""

    analyzer_id = "communication.kakaotalk"
    application = "KAKAOTALK"
    platform = "ENCRYPTED_SQLITE_CANDIDATE"
    source_kinds = (ArtifactSourceKind.COMMUNICATION_SQLITE_DB,)
    runtime_status = "UNSUPPORTED"
    capabilities_list = ("KAKAOTALK_ENCRYPTED_STORE_DISCOVERY",)
    unavailable_list = (
        "KAKAOTALK_ENCRYPTED_DB_DECRYPTION",
        "LIVE_CREDENTIAL_TOKEN_EXTRACTION",
    )
    matrix_entry: ClassVar[dict[str, Any]] = {
        "application": "KAKAOTALK",
        "analyzer": "KakaoTalkEncryptedStoreDiscoveryAnalyzer",
        "analyzer_id": analyzer_id,
        "status": runtime_status,
        "platform": platform,
        "verified_fixture": "kakaotalk.db",
        "source_kind": ArtifactSourceKind.COMMUNICATION_SQLITE_DB.value,
        "tables": [],
        "reason": "KEY_UNAVAILABLE",
    }


_APPLICATION_ANALYZERS: tuple[_CommunicationApplicationAnalyzer, ...] = (
    EmailMboxFixtureAnalyzer(),
    DiscordSQLiteFixtureAnalyzer(),
    TelegramSQLiteFixtureAnalyzer(),
    KakaoTalkEncryptedStoreDiscoveryAnalyzer(),
)


class CommunicationCorePluginAnalyzer:
    """Read-only core communication plugin for selected fixture-backed stores."""

    analyzer_id = "communication.core"
    analyzer_version = ENGINE_VERSION

    @property
    def parser_backend(self) -> str:
        return "apex.communication_core"

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
                ArtifactSourceKind.EMAIL_MBOX,
                ArtifactSourceKind.COMMUNICATION_SQLITE_DB,
            ),
            supported_artifact_types=(
                ArtifactType.COMMUNICATION_PROFILE,
                ArtifactType.COMMUNICATION_ACCOUNT,
                ArtifactType.COMMUNICATION_CONVERSATION,
                ArtifactType.COMMUNICATION_MESSAGE,
                ArtifactType.COMMUNICATION_ATTACHMENT,
                ArtifactType.COMMUNICATION_UNSUPPORTED_STORE,
            ),
            capabilities=(
                "EMAIL_MBOX_RFC5322_FIXTURE",
                "DISCORD_SQLITE_MESSAGES_FIXTURE",
                "TELEGRAM_SQLITE_MESSAGES_FIXTURE",
                "KAKAOTALK_STRUCTURED_UNSUPPORTED",
                "MESSAGE_CONVERSATION_ATTACHMENT_PROVENANCE",
                "STABLE_LINEAR_CHECKPOINT",
                "UNICODE_KOREAN_PRESERVATION",
                "SECRET_TOKEN_REDACTION",
            ),
            unavailable_capabilities=(
                "EMAIL_PST_OST",
                "DISCORD_LEVELDB_NATIVE_CACHE",
                "TELEGRAM_TDESKTOP_NATIVE_BINARY",
                "KAKAOTALK_ENCRYPTED_DB_DECRYPTION",
                "LIVE_CREDENTIAL_TOKEN_EXTRACTION",
            ),
            warnings=(
                {
                    "code": "COMMUNICATION_PLUGIN_SCOPE_LIMITED",
                    "message_key": "warning.communication.plugin_scope_limited",
                    "developer_message": (
                        "Only fixture-backed MBOX and simple Discord/Telegram SQLite message "
                        "schemas are parsed. Other app versions are capability-unavailable."
                    ),
                },
            ),
            metadata={
                "core_plugin": True,
                "verified_fixture_versions": [
                    {
                        "app": "EMAIL",
                        "platform": "MBOX_RFC5322",
                        "schema": "mbox fixture messages",
                    },
                    {
                        "app": "DISCORD",
                        "platform": "DESKTOP_SQLITE_FIXTURE",
                        "schema": (
                            "messages(id, conversation_id, sender, recipients, "
                            "timestamp, body)"
                        ),
                    },
                    {
                        "app": "TELEGRAM",
                        "platform": "DESKTOP_SQLITE_FIXTURE",
                        "schema": (
                            "messages(id, conversation_id, sender, recipients, "
                            "timestamp, body)"
                        ),
                    },
                ],
                "kakaotalk": {
                    "status": "STRUCTURED_UNSUPPORTED",
                    "reason": "No validated offline KakaoTalk key provider is configured.",
                    "success_without_key": False,
                },
                "application_capability_matrix": [
                    dict(analyzer.matrix_entry) for analyzer in _APPLICATION_ANALYZERS
                ],
                "credential_token_policy": _secret_policy(),
            },
        )

    def detect_source(self, node: FileSystemNode) -> ArtifactSource | None:
        if node.node_type is not FileSystemNodeType.FILE:
            return None
        source_kind = _communication_source_kind(node)
        if source_kind is None:
            return None
        return source_shell(
            node=node,
            source_kind=source_kind,
            analyzer_id=self.analyzer_id,
            analyzer_version=self.analyzer_version,
            parser_backend=self.parser_backend,
            parser_backend_version=self.parser_backend_version,
            priority=40,
        )

    def supports_source(self, source: ArtifactSource) -> bool:
        return source.source_kind in {
            ArtifactSourceKind.EMAIL_MBOX,
            ArtifactSourceKind.COMMUNICATION_SQLITE_DB,
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
        return _analyze_communication_source(
            evidence=evidence,
            node=node,
            source=source,
            file_path=file_path,
            item_budget=item_budget,
            forced_application=None,
        )


def _analyze_communication_source(
    *,
    evidence: Evidence,
    node: FileSystemNode,
    source: ArtifactSource,
    file_path: Path,
    item_budget: int | None,
    forced_application: str | None,
) -> ArtifactAnalysisResult:
    try:
        content_sha256 = _sha256_file(file_path)
    except OSError as error:
        return ArtifactAnalysisResult(
            errors=(
                issue(
                    severity="ERROR",
                    code="COMMUNICATION_SOURCE_READ_FAILED",
                    message_key="error.communication.source_read_failed",
                    developer_message="Communication source could not be read.",
                    node=node,
                    details={"error": str(error)},
                ),
            ),
            parse_status=ArtifactParseStatus.FAILED,
        )
    try:
        if source.source_kind is ArtifactSourceKind.EMAIL_MBOX:
            records = _mbox_records(
                node=node,
                file_path=file_path,
                content_sha256=content_sha256,
            )
        else:
            records = _sqlite_records(
                node=node,
                file_path=file_path,
                content_sha256=content_sha256,
                forced_application=forced_application,
            )
    except sqlite3.DatabaseError as error:
        artifact = _unsupported_record(
            node=node,
            app=forced_application or _app_from_path(node) or "UNKNOWN",
            platform="SQLITE",
            reason="CORRUPT_OR_UNREADABLE_SQLITE",
            content_sha256=content_sha256,
            error=str(error),
        )
        return _page_result(
            evidence=evidence,
            node=node,
            source=source,
            content_sha256=content_sha256,
            records=[artifact],
            start=0,
            item_budget=item_budget,
            parse_status=ArtifactParseStatus.CORRUPT,
            source_fingerprint=content_sha256,
        )
    except OSError as error:
        return ArtifactAnalysisResult(
            errors=(
                issue(
                    severity="ERROR",
                    code="COMMUNICATION_SOURCE_OPEN_FAILED",
                    message_key="error.communication.source_open_failed",
                    developer_message="Communication source could not be opened.",
                    node=node,
                    details={"error": str(error)},
                ),
            ),
            parse_status=ArtifactParseStatus.FAILED,
        )
    start = _checkpoint_offset(source, content_sha256)
    return _page_result(
        evidence=evidence,
        node=node,
        source=source,
        content_sha256=content_sha256,
        records=records,
        start=start,
        item_budget=item_budget,
        parse_status=_records_status(records),
        source_fingerprint=content_sha256,
    )


def _communication_source_kind(node: FileSystemNode) -> ArtifactSourceKind | None:
    name = node.original_name.casefold()
    extension = (node.extension or "").casefold()
    path = node.original_relative_path.casefold()
    if extension == "mbox" or name.endswith(".mbox"):
        return ArtifactSourceKind.EMAIL_MBOX
    if extension in {"sqlite", "sqlite3", "db"} and any(
        marker in path for marker in ("discord", "telegram", "kakaotalk", "kakao")
    ):
        return ArtifactSourceKind.COMMUNICATION_SQLITE_DB
    if name in {"messages.sqlite", "messages.db", "kakaotalk.db", "talk.sqlite"}:
        return ArtifactSourceKind.COMMUNICATION_SQLITE_DB
    return None


def _page_result(
    *,
    evidence: Evidence,
    node: FileSystemNode,
    source: ArtifactSource,
    content_sha256: str,
    records: list[_CommunicationRecord],
    start: int,
    item_budget: int | None,
    parse_status: ArtifactParseStatus,
    source_fingerprint: str,
) -> ArtifactAnalysisResult:
    limit = item_budget if item_budget is not None and item_budget > 0 else None
    end = len(records) if limit is None else min(len(records), start + limit)
    page_records = records[start:end]
    artifacts = tuple(
        _record_to_artifact(
            evidence=evidence,
            node=node,
            source=source,
            content_sha256=content_sha256,
            record=record,
        )
        for record in page_records
    )
    complete = end >= len(records)
    checkpoint = None
    if not complete:
        checkpoint = {
            "version": 1,
            "source_fingerprint": source_fingerprint,
            "next_offset": end,
        }
    warnings = tuple(
        warning for artifact in artifacts for warning in _artifact_warnings(artifact, node)
    )
    return ArtifactAnalysisResult(
        artifacts=artifacts,
        warnings=warnings,
        coverage={
            "artifact_count": len(artifacts),
            "available_records": len(records),
            "source_kind": source.source_kind.value,
        },
        parse_status=ArtifactParseStatus.PARTIAL
        if not complete or warnings
        else parse_status,
        source_checkpoint=checkpoint,
        source_complete=complete,
        inspected_count=len(page_records),
        source_fingerprint=source_fingerprint,
    )


def _record_to_artifact(
    *,
    evidence: Evidence,
    node: FileSystemNode,
    source: ArtifactSource,
    content_sha256: str,
    record: _CommunicationRecord,
) -> ArtifactRecord:
    raw_locator = make_raw_locator(
        evidence_id=evidence.evidence_id,
        source_file_node_id=node.node_id,
        source_path=node.display_path,
        source_reference=record.source_reference,
        locator_type=record.locator_type,
        offset=None,
        length=None,
        encoding="sqlite" if record.locator_type == "SQLITE_ROW" else "rfc5322",
        view_types=["TEXT"],
        content_sha256=content_sha256,
        limitations=["Logical communication provenance does not expose byte offsets."],
        details={"source_reference": record.source_reference},
    )
    return make_artifact(
        evidence=evidence,
        node=node,
        source=source,
        artifact_type=record.artifact_type,
        artifact_subtype=record.subtype,
        fields=record.fields,
        raw_locator=raw_locator,
        title=record.title,
        summary=record.summary,
        parse_status=record.parse_status,
        confidence=record.confidence,
        observed_at_raw=record.observed_raw,
        observed_at_utc=record.observed_utc,
        timezone_source="COMMUNICATION_NATIVE_TIMESTAMP"
        if record.observed_utc is not None
        else None,
        timezone_confidence="HIGH" if record.observed_utc is not None else "UNKNOWN",
        warnings=record.warnings or [],
    )


def _mbox_records(
    *,
    node: FileSystemNode,
    file_path: Path,
    content_sha256: str,
) -> list[_CommunicationRecord]:
    raw = file_path.read_bytes()
    messages = list(_parse_mbox(raw))
    profile = _profile_fields(
        node,
        app="EMAIL",
        platform="MBOX_RFC5322",
        content_sha256=content_sha256,
    )
    records = [
        _profile_record(profile, source_reference="mbox:profile"),
        _account_record(
            profile,
            account_id=canonical_sha256({"path": node.original_relative_path, "app": "EMAIL"}),
            display="MBOX account candidate",
            source_reference="mbox:account",
        ),
    ]
    conversations: set[str] = set()
    for index, message in enumerate(messages, start=1):
        subject = _header(message, "subject") or "(no subject)"
        conversation_id = canonical_sha256({"app": "EMAIL", "subject": subject})
        if conversation_id not in conversations:
            conversations.add(conversation_id)
            records.append(
                _conversation_record(
                    profile,
                    conversation_id=conversation_id,
                    title=f"Email conversation: {subject}",
                    source_reference=f"mbox:conversation:{conversation_id}",
                    extra={"subject": subject},
                )
            )
        sender = _addresses(message, "from")
        recipients = (
            _addresses(message, "to")
            + _addresses(message, "cc")
            + _addresses(message, "bcc")
        )
        raw_date = _header(message, "date")
        observed = _email_timestamp(raw_date)
        body, redacted = _message_body(message)
        message_id = _header(message, "message-id") or f"mbox-index-{index}"
        records.append(
            _message_record(
                profile,
                message_id=message_id,
                conversation_id=conversation_id,
                sender=", ".join(sender),
                recipients=recipients,
                body=body,
                redaction_applied=redacted,
                observed_raw=raw_date,
                observed_utc=observed,
                source_reference=f"mbox:message:{index}",
                row_provenance={"format": "MBOX", "message_index": index},
            )
        )
        for attachment_index, attachment in enumerate(_attachments(message), start=1):
            records.append(
                _attachment_record(
                    profile,
                    message_id=message_id,
                    conversation_id=conversation_id,
                    attachment=attachment,
                    source_reference=f"mbox:message:{index}:attachment:{attachment_index}",
                )
            )
    return records


def _sqlite_records(
    *,
    node: FileSystemNode,
    file_path: Path,
    content_sha256: str,
    forced_application: str | None = None,
) -> list[_CommunicationRecord]:
    app = forced_application or _app_from_path(node) or "UNKNOWN"
    if app == "KAKAOTALK":
        return [
            _unsupported_record(
                node=node,
                app=app,
                platform="KAKAOTALK_SQLITE_ENCRYPTED_CANDIDATE",
                reason="KEY_UNAVAILABLE",
                content_sha256=content_sha256,
                error=None,
            )
        ]
    with closing(_connect_read_only(file_path)) as connection:
        connection.row_factory = sqlite3.Row
        tables = _table_columns(connection)
        if not _has_columns(tables, "messages", {"id", "conversation_id", "sender", "body"}):
            return [
                _unsupported_record(
                    node=node,
                    app=app,
                    platform="SQLITE",
                    reason="UNSUPPORTED_SCHEMA",
                    content_sha256=content_sha256,
                    error=None,
                )
            ]
        rows = list(_fetch_messages(connection, tables))
    platform = f"{app}_SQLITE_FIXTURE"
    profile = _profile_fields(node, app=app, platform=platform, content_sha256=content_sha256)
    records = [
        _profile_record(profile, source_reference="sqlite:profile"),
        _account_record(
            profile,
            account_id=canonical_sha256({"path": node.original_relative_path, "app": app}),
            display=f"{app.title()} account candidate",
            source_reference="sqlite:account",
        ),
    ]
    conversations: set[str] = set()
    for row in rows:
        conversation_id = str(row["conversation_id"])
        if conversation_id not in conversations:
            conversations.add(conversation_id)
            records.append(
                _conversation_record(
                    profile,
                    conversation_id=conversation_id,
                    title=f"{app.title()} conversation: {conversation_id}",
                    source_reference=f"sqlite:messages:conversation:{conversation_id}",
                    extra={},
                )
            )
        body, redacted = _redact_text(_none_or_str(row["body"]) or "")
        observed_raw = _none_or_str(row["timestamp"])
        records.append(
            _message_record(
                profile,
                message_id=str(row["id"]),
                conversation_id=conversation_id,
                sender=_none_or_str(row["sender"]),
                recipients=_split_recipients(row["recipients"]),
                body=body,
                redaction_applied=redacted,
                observed_raw=observed_raw,
                observed_utc=_sqlite_timestamp(row["timestamp"]),
                source_reference=f"sqlite:messages:{row['row_id']}",
                row_provenance={
                    "database": node.display_path,
                    "table": "messages",
                    "row_id": int(row["row_id"]),
                    "deleted_candidate": _bool_value(row["deleted"]),
                    "recovered_candidate": _bool_value(row["recovered"]),
                },
                parse_status=ArtifactParseStatus.PARTIAL
                if _bool_value(row["deleted"]) or _bool_value(row["recovered"]) or redacted
                else ArtifactParseStatus.SUCCESS,
            )
        )
        attachment_name = _none_or_str(row["attachment_name"])
        attachment_reference = _none_or_str(row["attachment_path"])
        if attachment_name or attachment_reference:
            records.append(
                _attachment_record(
                    profile,
                    message_id=str(row["id"]),
                    conversation_id=conversation_id,
                    attachment={
                        "filename": attachment_name,
                        "content_type": row["attachment_mime"],
                        "size": row["attachment_size"],
                        "sha256": _sha256_text(attachment_reference or attachment_name or ""),
                        "reference": attachment_reference,
                    },
                    source_reference=f"sqlite:messages:{row['row_id']}:attachment",
                )
            )
    return records


def _profile_fields(
    node: FileSystemNode,
    *,
    app: str,
    platform: str,
    content_sha256: str,
) -> dict[str, Any]:
    profile_id = canonical_sha256(
        {
            "case_id": node.case_id,
            "evidence_id": node.evidence_id,
            "app": app,
            "path": node.original_relative_path,
        }
    )
    return {
        "profile_id": profile_id,
        "communication_app": app,
        "communication_platform": platform,
        "profile_path": str(PurePosixPath(node.original_relative_path).parent),
        "source_revision": node.index_revision,
        "source_file_sha256": content_sha256,
        "credential_token_policy": _secret_policy(),
    }


def _profile_record(profile: dict[str, Any], *, source_reference: str) -> _CommunicationRecord:
    return _CommunicationRecord(
        artifact_type=ArtifactType.COMMUNICATION_PROFILE,
        subtype=f"{profile['communication_app']}_PROFILE_CANDIDATE",
        title=f"{profile['communication_app'].title()} profile candidate",
        summary="Communication profile candidate observed from supported source path.",
        fields=profile | {"candidate_semantics": "PROFILE_ACCOUNT_CANDIDATE"},
        source_reference=source_reference,
        locator_type="LOGICAL_PATH",
    )


def _account_record(
    profile: dict[str, Any],
    *,
    account_id: str,
    display: str,
    source_reference: str,
) -> _CommunicationRecord:
    return _CommunicationRecord(
        artifact_type=ArtifactType.COMMUNICATION_ACCOUNT,
        subtype=f"{profile['communication_app']}_ACCOUNT_CANDIDATE",
        title=display,
        summary="Communication account candidate observed; credentials are not extracted.",
        fields=profile
        | {
            "account_id": account_id,
            "account_candidate": True,
            "credentials_extracted": False,
            "tokens_extracted": False,
        },
        source_reference=source_reference,
        locator_type="LOGICAL_PATH",
    )


def _conversation_record(
    profile: dict[str, Any],
    *,
    conversation_id: str,
    title: str,
    source_reference: str,
    extra: dict[str, Any],
) -> _CommunicationRecord:
    return _CommunicationRecord(
        artifact_type=ArtifactType.COMMUNICATION_CONVERSATION,
        subtype=f"{profile['communication_app']}_CONVERSATION",
        title=title,
        summary="Communication conversation candidate observed.",
        fields=profile | {"conversation_id": conversation_id, **extra},
        source_reference=source_reference,
        locator_type="LOGICAL_PATH",
    )


def _message_record(
    profile: dict[str, Any],
    *,
    message_id: str,
    conversation_id: str,
    sender: str | None,
    recipients: list[str],
    body: str,
    redaction_applied: bool,
    observed_raw: str | None,
    observed_utc: datetime | None,
    source_reference: str,
    row_provenance: dict[str, Any],
    parse_status: ArtifactParseStatus = ArtifactParseStatus.SUCCESS,
) -> _CommunicationRecord:
    warnings = []
    if redaction_applied:
        warnings.append(
            {
                "code": "COMMUNICATION_SECRET_TOKEN_REDACTED",
                "message_key": "warning.communication.secret_token_redacted",
                "developer_message": (
                    "Potential credential or token text was redacted from message body."
                ),
            }
        )
        parse_status = ArtifactParseStatus.PARTIAL
    return _CommunicationRecord(
        artifact_type=ArtifactType.COMMUNICATION_MESSAGE,
        subtype=f"{profile['communication_app']}_MESSAGE",
        title=f"{profile['communication_app'].title()} message: {message_id}",
        summary="Communication message observed from supported fixture-backed source.",
        fields=profile
        | {
            "message_id": message_id,
            "conversation_id": conversation_id,
            "sender": sender,
            "recipients": recipients,
            "message_body": body[:_MAX_MESSAGE_BODY_CHARS],
            "message_body_truncated": len(body) > _MAX_MESSAGE_BODY_CHARS,
            "raw_timestamp": observed_raw,
            "normalized_timestamp": None
            if observed_utc is None
            else to_json_timestamp(observed_utc),
            "attachment_reference": None,
            "deleted_candidate": bool(row_provenance.get("deleted_candidate")),
            "recovered_candidate": bool(row_provenance.get("recovered_candidate")),
            "row_provenance": row_provenance,
            "credential_token_redaction_applied": redaction_applied,
        },
        source_reference=source_reference,
        locator_type="SQLITE_ROW" if source_reference.startswith("sqlite:") else "LOGICAL_PATH",
        observed_raw=observed_raw,
        observed_utc=observed_utc,
        parse_status=parse_status,
        warnings=warnings,
    )


def _attachment_record(
    profile: dict[str, Any],
    *,
    message_id: str,
    conversation_id: str,
    attachment: dict[str, Any],
    source_reference: str,
) -> _CommunicationRecord:
    return _CommunicationRecord(
        artifact_type=ArtifactType.COMMUNICATION_ATTACHMENT,
        subtype=f"{profile['communication_app']}_ATTACHMENT_REFERENCE",
        title=f"Attachment reference: {attachment.get('filename') or 'unnamed'}",
        summary="Communication attachment reference observed; payload is not extracted.",
        fields=profile
        | {
            "message_id": message_id,
            "conversation_id": conversation_id,
            "attachment_name": attachment.get("filename"),
            "attachment_reference": attachment.get("reference"),
            "attachment_content_type": attachment.get("content_type"),
            "attachment_size": attachment.get("size"),
            "attachment_sha256": attachment.get("sha256"),
            "attachment_payload_extracted": False,
        },
        source_reference=source_reference,
        locator_type="SQLITE_ROW" if source_reference.startswith("sqlite:") else "LOGICAL_PATH",
        parse_status=ArtifactParseStatus.PARTIAL,
        warnings=[
            {
                "code": "COMMUNICATION_ATTACHMENT_REFERENCE_ONLY",
                "message_key": "warning.communication.attachment_reference_only",
                "developer_message": (
                    "Attachment payload was not extracted; reference metadata only."
                ),
            }
        ],
    )


def _unsupported_record(
    *,
    node: FileSystemNode,
    app: str,
    platform: str,
    reason: str,
    content_sha256: str,
    error: str | None,
) -> _CommunicationRecord:
    profile = _profile_fields(node, app=app, platform=platform, content_sha256=content_sha256)
    return _CommunicationRecord(
        artifact_type=ArtifactType.COMMUNICATION_UNSUPPORTED_STORE,
        subtype=f"{app}_STRUCTURED_UNSUPPORTED",
        title=f"{app.title()} communication store unsupported",
        summary=(
            "Communication source was discovered but cannot be parsed with configured adapters."
        ),
        fields=profile
        | {
            "unsupported_reason": reason,
            "key_provider": {"id": None, "version": None, "status": "KEY_UNAVAILABLE"},
            "success_without_key": False,
            "error": error,
        },
        source_reference="communication:unsupported",
        locator_type="LOGICAL_PATH",
        parse_status=ArtifactParseStatus.UNSUPPORTED,
        confidence=0.4,
        warnings=[
            {
                "code": f"{app}_COMMUNICATION_STORE_UNSUPPORTED",
                "message_key": "warning.communication.store_unsupported",
                "developer_message": (
                    "Communication source is outside verified fixture scope or requires an "
                    "unavailable key provider."
                ),
            }
        ],
    )


def _parse_mbox(raw: bytes) -> Iterable[EmailMessage]:
    chunks: list[bytes] = []
    current: list[bytes] = []
    for line in raw.splitlines(keepends=True):
        if line.startswith(b"From ") and current:
            chunks.append(b"".join(current))
            current = []
            continue
        if line.startswith(b"From ") and not current:
            continue
        current.append(line)
    if current:
        chunks.append(b"".join(current))
    parser = BytesParser(policy=policy.default)
    for chunk in chunks:
        parsed = parser.parsebytes(chunk)
        if isinstance(parsed, EmailMessage):
            yield parsed


def _message_body(message: Message) -> tuple[str, bool]:
    if message.is_multipart():
        parts: list[str] = []
        redacted = False
        for part in message.walk():
            if part.get_content_disposition() == "attachment":
                continue
            if part.get_content_type() != "text/plain":
                continue
            payload = _part_text(part)
            text, changed = _redact_text(payload)
            parts.append(text)
            redacted = redacted or changed
        return "\n".join(parts), redacted
    return _redact_text(_part_text(message))


def _part_text(part: Message) -> str:
    try:
        payload = part.get_payload(decode=True)
    except (LookupError, ValueError):
        payload = None
    charset = part.get_content_charset() or "utf-8"
    if isinstance(payload, bytes):
        return payload.decode(charset, errors="replace")
    text = part.get_payload()
    return text if isinstance(text, str) else ""


def _attachments(message: Message) -> Iterable[dict[str, Any]]:
    for part in message.walk() if message.is_multipart() else ():
        if part.get_content_disposition() != "attachment":
            continue
        payload = part.get_payload(decode=True)
        data = payload if isinstance(payload, bytes) else b""
        yield {
            "filename": part.get_filename(),
            "content_type": part.get_content_type(),
            "size": len(data),
            "sha256": _sha256_bytes(data),
            "reference": part.get_filename(),
        }


def _fetch_messages(
    connection: sqlite3.Connection,
    tables: dict[str, list[str]],
) -> Iterable[sqlite3.Row]:
    sql = f"""
        SELECT
            messages.rowid AS row_id,
            {_column_or_null(tables, "messages", "id")},
            {_column_or_null(tables, "messages", "conversation_id")},
            {_column_or_null(tables, "messages", "sender")},
            {_column_or_null(tables, "messages", "recipients")},
            {_column_or_null(tables, "messages", "timestamp")},
            {_column_or_null(tables, "messages", "body")},
            {_column_or_null(tables, "messages", "deleted")},
            {_column_or_null(tables, "messages", "recovered")},
            {_column_or_null(tables, "messages", "attachment_name")},
            {_column_or_null(tables, "messages", "attachment_path")},
            {_column_or_null(tables, "messages", "attachment_mime")},
            {_column_or_null(tables, "messages", "attachment_size")}
        FROM messages
        ORDER BY messages.rowid
    """
    yield from connection.execute(sql)


def _connect_read_only(path: Path) -> sqlite3.Connection:
    resolved = path.resolve(strict=True)
    return sqlite3.connect(f"{resolved.as_uri()}?mode=ro", uri=True)


def _table_columns(connection: sqlite3.Connection) -> dict[str, list[str]]:
    tables: dict[str, list[str]] = {}
    for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'"):
        table = str(row["name"])
        tables[table] = [
            str(item["name"])
            for item in connection.execute(f"PRAGMA table_info({_quote_identifier(table)})")
        ]
    return tables


def _column_or_null(tables: dict[str, list[str]], table: str, column: str) -> str:
    if _has_columns(tables, table, {column}):
        return (
            f"{_quote_identifier(table)}.{_quote_identifier(column)} "
            f"AS {_quote_identifier(column)}"
        )
    return f"NULL AS {_quote_identifier(column)}"


def _has_columns(tables: dict[str, list[str]], table: str, required: set[str]) -> bool:
    return table in tables and required.issubset(set(tables[table]))


def _quote_identifier(value: str) -> str:
    return '"' + value.replace('"', '""') + '"'


def _header(message: Message, name: str) -> str | None:
    value = message.get(name)
    return None if value is None else str(value)


def _addresses(message: Message, name: str) -> list[str]:
    return [address for _, address in getaddresses(message.get_all(name, [])) if address]


def _email_timestamp(raw_date: str | None) -> datetime | None:
    if raw_date is None:
        return None
    try:
        parsed = parsedate_to_datetime(raw_date)
    except (TypeError, ValueError):
        return None
    return parsed.astimezone(UTC) if parsed.tzinfo is not None else None


def _sqlite_timestamp(value: Any) -> datetime | None:
    text = _none_or_str(value)
    if text is None:
        return None
    try:
        if text.isdecimal():
            parsed = int(text)
            if parsed > 10_000_000_000_000:
                return datetime.fromtimestamp(parsed / 1_000_000, UTC)
            if parsed > 10_000_000_000:
                return datetime.fromtimestamp(parsed / 1000, UTC)
            return datetime.fromtimestamp(parsed, UTC)
        return datetime.fromisoformat(text.replace("Z", "+00:00")).astimezone(UTC)
    except (ValueError, OSError, OverflowError):
        return None


def _redact_text(value: str) -> tuple[str, bool]:
    redacted = value
    changed = False
    for pattern in _SECRET_PATTERNS:
        redacted, count = pattern.subn(lambda match: f"{match.group(1)}=<REDACTED>", redacted)
        changed = changed or count > 0
    return redacted, changed


def _split_recipients(value: Any) -> list[str]:
    text = _none_or_str(value)
    if text is None:
        return []
    return [item.strip() for item in re.split(r"[,;]", text) if item.strip()]


def _app_from_path(node: FileSystemNode) -> str | None:
    path = node.original_relative_path.casefold()
    if "discord" in path:
        return "DISCORD"
    if "telegram" in path:
        return "TELEGRAM"
    if "kakaotalk" in path or "kakao" in path:
        return "KAKAOTALK"
    return None


def _checkpoint_offset(source: ArtifactSource, source_fingerprint: str) -> int:
    checkpoint = source.source_checkpoint
    if checkpoint.get("version") != 1:
        return 0
    if checkpoint.get("source_fingerprint") != source_fingerprint:
        return 0
    try:
        return max(0, int(checkpoint.get("next_offset") or 0))
    except (TypeError, ValueError):
        return 0


def _records_status(records: list[_CommunicationRecord]) -> ArtifactParseStatus:
    if any(record.parse_status is ArtifactParseStatus.UNSUPPORTED for record in records):
        return ArtifactParseStatus.UNSUPPORTED
    if any(record.parse_status is ArtifactParseStatus.CORRUPT for record in records):
        return ArtifactParseStatus.CORRUPT
    if any(record.parse_status is ArtifactParseStatus.PARTIAL for record in records):
        return ArtifactParseStatus.PARTIAL
    return ArtifactParseStatus.SUCCESS


def _artifact_warnings(
    artifact: ArtifactRecord,
    node: FileSystemNode,
) -> list[ArtifactIssue]:
    return [
        issue(
            severity="WARNING",
            code=str(warning.get("code", "COMMUNICATION_ARTIFACT_WARNING")),
            message_key=str(warning.get("message_key", "warning.communication.artifact")),
            developer_message=str(warning.get("developer_message", "")),
            node=node,
            artifact_id=artifact.artifact_id,
            details=dict(warning.get("details", {})),
        )
        for warning in artifact.warnings
    ]


def _secret_policy() -> dict[str, Any]:
    return {
        "credentials_extracted": False,
        "tokens_extracted": False,
        "redaction_patterns": ["api_key", "token", "secret", "password", "authorization bearer"],
        "live_account_access": False,
    }


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", "surrogatepass")).hexdigest()


def _none_or_str(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value)
    return text if text else None


def _bool_value(value: Any) -> bool:
    try:
        return bool(int(value or 0))
    except (TypeError, ValueError):
        return bool(value)
