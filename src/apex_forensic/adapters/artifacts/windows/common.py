"""Shared helpers for Windows artifact analyzers."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import NAMESPACE_URL, uuid5

from apex_forensic.domain.enums import ArtifactParseStatus, ArtifactSourceKind, ArtifactType
from apex_forensic.domain.models import ArtifactIssue, ArtifactRecord, ArtifactSource, Evidence
from apex_forensic.domain.models.filesystem import FileSystemNode
from apex_forensic.domain.services.canonical import canonical_sha256

_WINDOWS_EPOCH = datetime(1601, 1, 1, tzinfo=UTC)
_MAX_RAW_READ_LENGTH = 1_048_576


def artifact_id_for(dedup_key: str) -> str:
    return str(uuid5(NAMESPACE_URL, f"apex-artifact-v1:{dedup_key}"))


def source_id_for(
    *,
    node: FileSystemNode,
    analyzer_id: str,
    analyzer_version: str,
    option_fingerprint: str,
    source_fingerprint: str | None = None,
) -> str:
    key = ":".join(
        [
            "apex-artifact-source-v1",
            node.case_id,
            node.evidence_id,
            node.node_id,
            analyzer_id,
            analyzer_version,
            option_fingerprint,
            source_fingerprint or "",
        ]
    )
    return str(uuid5(NAMESPACE_URL, key))


def source_shell(
    *,
    node: FileSystemNode,
    source_kind: ArtifactSourceKind,
    analyzer_id: str,
    analyzer_version: str,
    parser_backend: str,
    parser_backend_version: str,
    option_fingerprint: str = "",
    priority: int = 100,
    source_order: int = 0,
) -> ArtifactSource:
    now = datetime.now(UTC)
    return ArtifactSource(
        source_id=source_id_for(
            node=node,
            analyzer_id=analyzer_id,
            analyzer_version=analyzer_version,
            option_fingerprint=option_fingerprint,
        ),
        job_id=None,
        case_id=node.case_id,
        evidence_id=node.evidence_id,
        source_file_node_id=node.node_id,
        source_path=node.display_path,
        source_kind=source_kind,
        comparison_key=node.comparison_path,
        analyzer_id=analyzer_id,
        analyzer_version=analyzer_version,
        parser_backend=parser_backend,
        parser_backend_version=parser_backend_version,
        option_fingerprint=option_fingerprint,
        status="DISCOVERED",
        priority=priority,
        source_order=source_order,
        is_partial=node.is_partial,
        warning_count=0,
        error_count=0,
        artifact_count=0,
        parse_status=None,
        last_error=None,
        discovered_at=now,
        analyzed_at=None,
        updated_at=now,
        source_fingerprint=None,
        source_checkpoint={},
        inspected_count=0,
    )


def make_raw_locator(
    *,
    evidence_id: str,
    source_file_node_id: str,
    source_path: str,
    source_reference: str | None,
    locator_type: str,
    offset: int | None = None,
    length: int | None = None,
    encoding: str | None = None,
    view_types: list[str] | None = None,
    content_sha256: str | None = None,
    limitations: list[str] | None = None,
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if offset is not None and offset < 0:
        raise ValueError("raw locator offset cannot be negative")
    if length is not None:
        if length < 1:
            raise ValueError("raw locator length must be positive when present")
        length = min(length, _MAX_RAW_READ_LENGTH)
    return {
        "evidence_id": evidence_id,
        "source_kind": "FILE",
        "source_id": source_file_node_id,
        "source_path": source_path,
        "source_reference": source_reference,
        "locator_type": locator_type,
        "offset": offset,
        "length": length,
        "encoding": encoding,
        "view_types": view_types or (["TEXT"] if encoding else ["HEX"]),
        "content_sha256": content_sha256,
        "limitations": limitations or [],
        "details": details or {},
    }


def make_citation(
    *,
    artifact_id: str,
    case_id: str,
    evidence_id: str,
    source_file_node_id: str,
    source_path: str,
    source_reference: str | None,
    raw_locator: dict[str, Any],
    label_index: int = 1,
    excerpt: str | None = None,
) -> dict[str, Any]:
    citation_key = canonical_sha256(
        {
            "artifact_id": artifact_id,
            "source_file_node_id": source_file_node_id,
            "source_reference": source_reference,
            "label_index": label_index,
        }
    )
    return {
        "id": str(uuid5(NAMESPACE_URL, f"apex-citation-v1:{citation_key}")),
        "label": f"CIT-{label_index:03d}",
        "case_id": case_id,
        "evidence_id": evidence_id,
        "source_kind": "FILE",
        "source_id": source_file_node_id,
        "file_id": source_file_node_id,
        "artifact_id": artifact_id,
        "timeline_event_id": None,
        "search_result_id": None,
        "source_path": source_path,
        "source_offset": raw_locator.get("offset"),
        "source_length": raw_locator.get("length"),
        "source_reference": source_reference,
        "excerpt": excerpt,
        "content_sha256": raw_locator.get("content_sha256"),
        "created_at": datetime.now(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z"),
        "encoding": raw_locator.get("encoding"),
        "raw_locator": raw_locator,
    }


def make_artifact(
    *,
    evidence: Evidence,
    node: FileSystemNode,
    source: ArtifactSource,
    artifact_type: ArtifactType,
    artifact_subtype: str,
    fields: dict[str, Any],
    raw_locator: dict[str, Any],
    title: str,
    summary: str,
    parse_status: ArtifactParseStatus = ArtifactParseStatus.SUCCESS,
    confidence: float = 1.0,
    observed_at_raw: str | None = None,
    observed_at_utc: datetime | None = None,
    timezone_source: str | None = None,
    timezone_confidence: str = "UNKNOWN",
    warnings: list[dict[str, Any]] | None = None,
) -> ArtifactRecord:
    dedup_key = canonical_sha256(
        {
            "case_id": evidence.case_id,
            "evidence_id": evidence.evidence_id,
            "source_file_node_id": node.node_id,
            "analyzer_id": source.analyzer_id,
            "analyzer_version": source.analyzer_version,
            "parser_backend": source.parser_backend,
            "parser_backend_version": source.parser_backend_version,
            "artifact_type": artifact_type.value,
            "artifact_subtype": artifact_subtype,
            "fields": fields,
            "raw_locator": raw_locator,
        }
    )
    artifact_id = artifact_id_for(dedup_key)
    citations = [
        make_citation(
            artifact_id=artifact_id,
            case_id=evidence.case_id,
            evidence_id=evidence.evidence_id,
            source_file_node_id=node.node_id,
            source_path=node.display_path,
            source_reference=raw_locator.get("source_reference"),
            raw_locator=raw_locator,
        )
    ]
    now = datetime.now(UTC)
    return ArtifactRecord(
        artifact_id=artifact_id,
        case_id=evidence.case_id,
        evidence_id=evidence.evidence_id,
        source_file_node_id=node.node_id,
        artifact_type=artifact_type,
        artifact_subtype=artifact_subtype,
        analyzer_id=source.analyzer_id,
        analyzer_version=source.analyzer_version,
        parser_backend=source.parser_backend,
        parser_backend_version=source.parser_backend_version,
        source_path=node.display_path,
        source_kind=source.source_kind,
        observed_at_raw=observed_at_raw,
        observed_at_utc=observed_at_utc,
        timezone_source=timezone_source,
        timezone_confidence=timezone_confidence,
        title=title,
        summary=summary,
        fields=fields,
        raw_locator=raw_locator,
        citations=citations,
        warnings=warnings or [],
        parse_status=parse_status,
        confidence=max(0.0, min(1.0, confidence)),
        is_partial=source.is_partial or parse_status is not ArtifactParseStatus.SUCCESS,
        index_revision=node.index_revision,
        created_at=now,
        updated_at=now,
        dedup_key=dedup_key,
    )


def issue(
    *,
    severity: str,
    code: str,
    message_key: str,
    developer_message: str,
    node: FileSystemNode,
    details: dict[str, Any] | None = None,
    artifact_id: str | None = None,
) -> ArtifactIssue:
    return ArtifactIssue(
        severity=severity,
        code=code,
        message_key=message_key,
        developer_message=developer_message,
        source_file_node_id=node.node_id,
        artifact_id=artifact_id,
        source_path=node.display_path,
        details=details or {},
    )


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def filetime_to_utc(value: int) -> datetime | None:
    if value <= 0:
        return None
    try:
        return _WINDOWS_EPOCH + timedelta(microseconds=value / 10)
    except OverflowError:
        return None
