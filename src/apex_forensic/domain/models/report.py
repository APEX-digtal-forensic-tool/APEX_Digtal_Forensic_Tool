"""Phase 8 report review, approval, custody snapshot, and export DTOs."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from apex_forensic._time import parse_timestamp, to_json_timestamp
from apex_forensic.constants import SCHEMA_VERSION


def _ts(value: datetime | None) -> str | None:
    return None if value is None else to_json_timestamp(value)


def _dt(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value
    return parse_timestamp(str(value))


@dataclass(slots=True)
class ReportRecord:
    report_id: str
    case_id: str
    title: str
    description: str | None
    report_type: str
    locale: str
    timezone: str
    status: str
    active_version_id: str | None
    latest_version_number: int
    created_by: str
    created_at: datetime
    updated_at: datetime
    archived_at: datetime | None
    report_fingerprint: str
    report_schema_version: str = SCHEMA_VERSION

    def to_schema_dict(self) -> dict[str, Any]:
        return {
            "report_id": self.report_id,
            "case_id": self.case_id,
            "title": self.title,
            "description": self.description,
            "report_type": self.report_type,
            "locale": self.locale,
            "timezone": self.timezone,
            "status": self.status,
            "active_version_id": self.active_version_id,
            "latest_version_number": self.latest_version_number,
            "created_by": self.created_by,
            "created_at": _ts(self.created_at),
            "updated_at": _ts(self.updated_at),
            "archived_at": _ts(self.archived_at),
            "report_fingerprint": self.report_fingerprint,
            "report_schema_version": self.report_schema_version,
        }

    @classmethod
    def from_schema_dict(cls, data: dict[str, Any]) -> ReportRecord:
        return cls(
            report_id=str(data["report_id"]),
            case_id=str(data["case_id"]),
            title=str(data["title"]),
            description=data.get("description"),
            report_type=str(data["report_type"]),
            locale=str(data["locale"]),
            timezone=str(data["timezone"]),
            status=str(data["status"]),
            active_version_id=data.get("active_version_id"),
            latest_version_number=int(data["latest_version_number"]),
            created_by=str(data["created_by"]),
            created_at=_dt(data["created_at"]),
            updated_at=_dt(data["updated_at"]),
            archived_at=None if data.get("archived_at") is None else _dt(data["archived_at"]),
            report_fingerprint=str(data["report_fingerprint"]),
            report_schema_version=str(data.get("report_schema_version", SCHEMA_VERSION)),
        )


@dataclass(slots=True)
class ReportSection:
    section_id: str
    section_type: str
    title: str
    order: int
    content_kind: str
    content: str
    structured_data: dict[str, Any]
    source_kind: str
    source_resource_ids: list[str]
    context_snapshot_ids: list[str]
    citations: list[dict[str, Any]]
    is_partial: bool
    stale_reasons: list[str]
    coverage: dict[str, Any]
    warnings: list[dict[str, Any]]
    section_fingerprint: str

    def to_schema_dict(self) -> dict[str, Any]:
        return {
            "section_id": self.section_id,
            "section_type": self.section_type,
            "title": self.title,
            "order": self.order,
            "content_kind": self.content_kind,
            "content": self.content,
            "structured_data": self.structured_data,
            "source_kind": self.source_kind,
            "source_resource_ids": self.source_resource_ids,
            "context_snapshot_ids": self.context_snapshot_ids,
            "citations": self.citations,
            "is_partial": self.is_partial,
            "stale_reasons": self.stale_reasons,
            "coverage": self.coverage,
            "warnings": self.warnings,
            "section_fingerprint": self.section_fingerprint,
        }

    @classmethod
    def from_schema_dict(cls, data: dict[str, Any]) -> ReportSection:
        return cls(
            section_id=str(data["section_id"]),
            section_type=str(data["section_type"]),
            title=str(data["title"]),
            order=int(data["order"]),
            content_kind=str(data["content_kind"]),
            content=str(data["content"]),
            structured_data=dict(data.get("structured_data", {})),
            source_kind=str(data["source_kind"]),
            source_resource_ids=[str(item) for item in data.get("source_resource_ids", [])],
            context_snapshot_ids=[str(item) for item in data.get("context_snapshot_ids", [])],
            citations=[dict(item) for item in data.get("citations", [])],
            is_partial=bool(data.get("is_partial", False)),
            stale_reasons=[str(item) for item in data.get("stale_reasons", [])],
            coverage=dict(data.get("coverage", {})),
            warnings=[dict(item) for item in data.get("warnings", [])],
            section_fingerprint=str(data["section_fingerprint"]),
        )


@dataclass(slots=True)
class ReportVersion:
    report_version_id: str
    report_id: str
    case_id: str
    version_number: int
    previous_version_id: str | None
    source_kind: str
    source_reference_id: str | None
    created_by: str
    title: str
    executive_summary: str
    sections: list[ReportSection]
    context_snapshot_ids: list[str]
    evidence_ids: list[str]
    search_execution_ids: list[str]
    timeline_revisions: list[int]
    ai_assistance_request_ids: list[str]
    ai_result_ids: list[str]
    citation_ids: list[str]
    partial_state: dict[str, Any]
    stale_state: dict[str, Any]
    coverage_summary: dict[str, Any]
    limitations: list[str]
    analyzer_versions: dict[str, Any]
    source_revisions: list[dict[str, Any]]
    content_fingerprint: str
    previous_content_fingerprint: str | None
    review_state: dict[str, Any]
    approval_state: dict[str, Any]
    created_at: datetime
    report_schema_version: str = SCHEMA_VERSION

    def to_schema_dict(self) -> dict[str, Any]:
        return {
            "report_version_id": self.report_version_id,
            "report_id": self.report_id,
            "case_id": self.case_id,
            "version_number": self.version_number,
            "previous_version_id": self.previous_version_id,
            "source_kind": self.source_kind,
            "source_reference_id": self.source_reference_id,
            "created_by": self.created_by,
            "title": self.title,
            "executive_summary": self.executive_summary,
            "sections": [item.to_schema_dict() for item in self.sections],
            "context_snapshot_ids": self.context_snapshot_ids,
            "evidence_ids": self.evidence_ids,
            "search_execution_ids": self.search_execution_ids,
            "timeline_revisions": self.timeline_revisions,
            "ai_assistance_request_ids": self.ai_assistance_request_ids,
            "ai_result_ids": self.ai_result_ids,
            "citation_ids": self.citation_ids,
            "partial_state": self.partial_state,
            "stale_state": self.stale_state,
            "coverage_summary": self.coverage_summary,
            "limitations": self.limitations,
            "analyzer_versions": self.analyzer_versions,
            "source_revisions": self.source_revisions,
            "content_fingerprint": self.content_fingerprint,
            "previous_content_fingerprint": self.previous_content_fingerprint,
            "review_state": self.review_state,
            "approval_state": self.approval_state,
            "created_at": _ts(self.created_at),
            "report_schema_version": self.report_schema_version,
        }

    @classmethod
    def from_schema_dict(cls, data: dict[str, Any]) -> ReportVersion:
        return cls(
            report_version_id=str(data["report_version_id"]),
            report_id=str(data["report_id"]),
            case_id=str(data["case_id"]),
            version_number=int(data["version_number"]),
            previous_version_id=data.get("previous_version_id"),
            source_kind=str(data["source_kind"]),
            source_reference_id=data.get("source_reference_id"),
            created_by=str(data["created_by"]),
            title=str(data["title"]),
            executive_summary=str(data["executive_summary"]),
            sections=[
                ReportSection.from_schema_dict(dict(item)) for item in data.get("sections", [])
            ],
            context_snapshot_ids=[str(item) for item in data.get("context_snapshot_ids", [])],
            evidence_ids=[str(item) for item in data.get("evidence_ids", [])],
            search_execution_ids=[str(item) for item in data.get("search_execution_ids", [])],
            timeline_revisions=[int(item) for item in data.get("timeline_revisions", [])],
            ai_assistance_request_ids=[
                str(item) for item in data.get("ai_assistance_request_ids", [])
            ],
            ai_result_ids=[str(item) for item in data.get("ai_result_ids", [])],
            citation_ids=[str(item) for item in data.get("citation_ids", [])],
            partial_state=dict(data.get("partial_state", {})),
            stale_state=dict(data.get("stale_state", {})),
            coverage_summary=dict(data.get("coverage_summary", {})),
            limitations=[str(item) for item in data.get("limitations", [])],
            analyzer_versions=dict(data.get("analyzer_versions", {})),
            source_revisions=[dict(item) for item in data.get("source_revisions", [])],
            content_fingerprint=str(data["content_fingerprint"]),
            previous_content_fingerprint=data.get("previous_content_fingerprint"),
            review_state=dict(data.get("review_state", {})),
            approval_state=dict(data.get("approval_state", {})),
            created_at=_dt(data["created_at"]),
            report_schema_version=str(data.get("report_schema_version", SCHEMA_VERSION)),
        )


@dataclass(slots=True)
class ReportReviewEvent:
    review_event_id: str
    report_id: str
    report_version_id: str
    case_id: str
    action: str
    actor_id: str
    reason: str
    section_id: str | None
    comment: str | None
    requested_changes: list[str]
    expected_review_revision: int | None
    review_revision: int
    previous_event_hash: str | None
    event_hash: str
    created_at: datetime

    def to_schema_dict(self) -> dict[str, Any]:
        return {
            "review_event_id": self.review_event_id,
            "report_id": self.report_id,
            "report_version_id": self.report_version_id,
            "case_id": self.case_id,
            "action": self.action,
            "actor_id": self.actor_id,
            "reason": self.reason,
            "section_id": self.section_id,
            "comment": self.comment,
            "requested_changes": self.requested_changes,
            "expected_review_revision": self.expected_review_revision,
            "review_revision": self.review_revision,
            "previous_event_hash": self.previous_event_hash,
            "event_hash": self.event_hash,
            "created_at": _ts(self.created_at),
        }

    @classmethod
    def from_schema_dict(cls, data: dict[str, Any]) -> ReportReviewEvent:
        return cls(
            review_event_id=str(data["review_event_id"]),
            report_id=str(data["report_id"]),
            report_version_id=str(data["report_version_id"]),
            case_id=str(data["case_id"]),
            action=str(data["action"]),
            actor_id=str(data["actor_id"]),
            reason=str(data["reason"]),
            section_id=data.get("section_id"),
            comment=data.get("comment"),
            requested_changes=[str(item) for item in data.get("requested_changes", [])],
            expected_review_revision=data.get("expected_review_revision"),
            review_revision=int(data["review_revision"]),
            previous_event_hash=data.get("previous_event_hash"),
            event_hash=str(data["event_hash"]),
            created_at=_dt(data["created_at"]),
        )


@dataclass(slots=True)
class ReportApprovalRecord:
    approval_id: str
    report_id: str
    report_version_id: str
    case_id: str
    approver_id: str
    decision: str
    reason: str
    content_fingerprint: str
    custody_snapshot_id: str | None
    approval_revision: int
    previous_approval_hash: str | None
    approval_hash: str
    decided_at: datetime

    def to_schema_dict(self) -> dict[str, Any]:
        return {
            "approval_id": self.approval_id,
            "report_id": self.report_id,
            "report_version_id": self.report_version_id,
            "case_id": self.case_id,
            "approver_id": self.approver_id,
            "decision": self.decision,
            "reason": self.reason,
            "content_fingerprint": self.content_fingerprint,
            "custody_snapshot_id": self.custody_snapshot_id,
            "approval_revision": self.approval_revision,
            "previous_approval_hash": self.previous_approval_hash,
            "approval_hash": self.approval_hash,
            "decided_at": _ts(self.decided_at),
        }

    @classmethod
    def from_schema_dict(cls, data: dict[str, Any]) -> ReportApprovalRecord:
        return cls(
            approval_id=str(data["approval_id"]),
            report_id=str(data["report_id"]),
            report_version_id=str(data["report_version_id"]),
            case_id=str(data["case_id"]),
            approver_id=str(data["approver_id"]),
            decision=str(data["decision"]),
            reason=str(data["reason"]),
            content_fingerprint=str(data["content_fingerprint"]),
            custody_snapshot_id=data.get("custody_snapshot_id"),
            approval_revision=int(data["approval_revision"]),
            previous_approval_hash=data.get("previous_approval_hash"),
            approval_hash=str(data["approval_hash"]),
            decided_at=_dt(data["decided_at"]),
        )


@dataclass(slots=True)
class CustodySnapshotRecord:
    custody_snapshot_id: str
    case_id: str
    report_id: str
    report_version_id: str
    evidence_ids: list[str]
    custody_event_ids: list[str]
    ledger_head_hash: str | None
    verification_status: str
    verification_errors: list[dict[str, Any]]
    event_count: int
    first_event_at: datetime | None
    last_event_at: datetime | None
    captured_by: str
    captured_at: datetime
    snapshot_fingerprint: str
    snapshot_version: str = SCHEMA_VERSION

    def to_schema_dict(self) -> dict[str, Any]:
        return {
            "custody_snapshot_id": self.custody_snapshot_id,
            "case_id": self.case_id,
            "report_id": self.report_id,
            "report_version_id": self.report_version_id,
            "evidence_ids": self.evidence_ids,
            "custody_event_ids": self.custody_event_ids,
            "ledger_head_hash": self.ledger_head_hash,
            "verification_status": self.verification_status,
            "verification_errors": self.verification_errors,
            "event_count": self.event_count,
            "first_event_at": _ts(self.first_event_at),
            "last_event_at": _ts(self.last_event_at),
            "captured_by": self.captured_by,
            "captured_at": _ts(self.captured_at),
            "snapshot_fingerprint": self.snapshot_fingerprint,
            "snapshot_version": self.snapshot_version,
        }

    @classmethod
    def from_schema_dict(cls, data: dict[str, Any]) -> CustodySnapshotRecord:
        return cls(
            custody_snapshot_id=str(data["custody_snapshot_id"]),
            case_id=str(data["case_id"]),
            report_id=str(data["report_id"]),
            report_version_id=str(data["report_version_id"]),
            evidence_ids=[str(item) for item in data.get("evidence_ids", [])],
            custody_event_ids=[str(item) for item in data.get("custody_event_ids", [])],
            ledger_head_hash=data.get("ledger_head_hash"),
            verification_status=str(data["verification_status"]),
            verification_errors=[dict(item) for item in data.get("verification_errors", [])],
            event_count=int(data["event_count"]),
            first_event_at=(
                None if data.get("first_event_at") is None else _dt(data["first_event_at"])
            ),
            last_event_at=(
                None if data.get("last_event_at") is None else _dt(data["last_event_at"])
            ),
            captured_by=str(data["captured_by"]),
            captured_at=_dt(data["captured_at"]),
            snapshot_fingerprint=str(data["snapshot_fingerprint"]),
            snapshot_version=str(data.get("snapshot_version", SCHEMA_VERSION)),
        )


@dataclass(slots=True)
class ReportRenderPackage:
    package_id: str
    report_id: str
    report_version_id: str
    case_id: str
    locale: str
    timezone: str
    report_metadata: dict[str, Any]
    sections: list[dict[str, Any]]
    evidence_manifest: list[dict[str, Any]]
    hash_integrity_summary: dict[str, Any]
    custody_snapshot_id: str | None
    context_snapshot_ids: list[str]
    citations: list[dict[str, Any]]
    partial_state: dict[str, Any]
    stale_state: dict[str, Any]
    coverage_summary: dict[str, Any]
    limitations: list[str]
    renderer_requirements: dict[str, Any]
    package_fingerprint: str
    created_at: datetime
    package_version: str = SCHEMA_VERSION

    def to_schema_dict(self) -> dict[str, Any]:
        return {
            "package_id": self.package_id,
            "report_id": self.report_id,
            "report_version_id": self.report_version_id,
            "case_id": self.case_id,
            "locale": self.locale,
            "timezone": self.timezone,
            "report_metadata": self.report_metadata,
            "sections": self.sections,
            "evidence_manifest": self.evidence_manifest,
            "hash_integrity_summary": self.hash_integrity_summary,
            "custody_snapshot_id": self.custody_snapshot_id,
            "context_snapshot_ids": self.context_snapshot_ids,
            "citations": self.citations,
            "partial_state": self.partial_state,
            "stale_state": self.stale_state,
            "coverage_summary": self.coverage_summary,
            "limitations": self.limitations,
            "renderer_requirements": self.renderer_requirements,
            "package_fingerprint": self.package_fingerprint,
            "created_at": _ts(self.created_at),
            "package_version": self.package_version,
        }

    @classmethod
    def from_schema_dict(cls, data: dict[str, Any]) -> ReportRenderPackage:
        return cls(
            package_id=str(data["package_id"]),
            report_id=str(data["report_id"]),
            report_version_id=str(data["report_version_id"]),
            case_id=str(data["case_id"]),
            locale=str(data["locale"]),
            timezone=str(data["timezone"]),
            report_metadata=dict(data.get("report_metadata", {})),
            sections=[dict(item) for item in data.get("sections", [])],
            evidence_manifest=[dict(item) for item in data.get("evidence_manifest", [])],
            hash_integrity_summary=dict(data.get("hash_integrity_summary", {})),
            custody_snapshot_id=data.get("custody_snapshot_id"),
            context_snapshot_ids=[str(item) for item in data.get("context_snapshot_ids", [])],
            citations=[dict(item) for item in data.get("citations", [])],
            partial_state=dict(data.get("partial_state", {})),
            stale_state=dict(data.get("stale_state", {})),
            coverage_summary=dict(data.get("coverage_summary", {})),
            limitations=[str(item) for item in data.get("limitations", [])],
            renderer_requirements=dict(data.get("renderer_requirements", {})),
            package_fingerprint=str(data["package_fingerprint"]),
            created_at=_dt(data["created_at"]),
            package_version=str(data.get("package_version", SCHEMA_VERSION)),
        )


@dataclass(slots=True)
class ReportExportManifest:
    export_manifest_id: str
    report_id: str
    report_version_id: str
    case_id: str
    format: str
    render_package_id: str
    renderer_id: str
    renderer_version: str
    requested_filename: str
    derived_output_root_id: str
    overwrite_policy: str
    redaction_policy: str
    include_citations: bool
    include_custody: bool
    include_technical_appendix: bool
    content_fingerprint: str
    manifest_fingerprint: str
    approval_id: str
    custody_snapshot_id: str | None
    status: str
    warnings: list[dict[str, Any]]
    created_by: str
    created_at: datetime
    manifest_version: str = SCHEMA_VERSION

    def to_schema_dict(self) -> dict[str, Any]:
        return {
            "export_manifest_id": self.export_manifest_id,
            "report_id": self.report_id,
            "report_version_id": self.report_version_id,
            "case_id": self.case_id,
            "format": self.format,
            "render_package_id": self.render_package_id,
            "renderer_id": self.renderer_id,
            "renderer_version": self.renderer_version,
            "requested_filename": self.requested_filename,
            "derived_output_root_id": self.derived_output_root_id,
            "overwrite_policy": self.overwrite_policy,
            "redaction_policy": self.redaction_policy,
            "include_citations": self.include_citations,
            "include_custody": self.include_custody,
            "include_technical_appendix": self.include_technical_appendix,
            "content_fingerprint": self.content_fingerprint,
            "manifest_fingerprint": self.manifest_fingerprint,
            "approval_id": self.approval_id,
            "custody_snapshot_id": self.custody_snapshot_id,
            "status": self.status,
            "warnings": self.warnings,
            "created_by": self.created_by,
            "created_at": _ts(self.created_at),
            "manifest_version": self.manifest_version,
        }

    @classmethod
    def from_schema_dict(cls, data: dict[str, Any]) -> ReportExportManifest:
        return cls(
            export_manifest_id=str(data["export_manifest_id"]),
            report_id=str(data["report_id"]),
            report_version_id=str(data["report_version_id"]),
            case_id=str(data["case_id"]),
            format=str(data["format"]),
            render_package_id=str(data["render_package_id"]),
            renderer_id=str(data["renderer_id"]),
            renderer_version=str(data["renderer_version"]),
            requested_filename=str(data["requested_filename"]),
            derived_output_root_id=str(data["derived_output_root_id"]),
            overwrite_policy=str(data["overwrite_policy"]),
            redaction_policy=str(data["redaction_policy"]),
            include_citations=bool(data["include_citations"]),
            include_custody=bool(data["include_custody"]),
            include_technical_appendix=bool(data["include_technical_appendix"]),
            content_fingerprint=str(data["content_fingerprint"]),
            manifest_fingerprint=str(data.get("manifest_fingerprint", "")),
            approval_id=str(data["approval_id"]),
            custody_snapshot_id=data.get("custody_snapshot_id"),
            status=str(data["status"]),
            warnings=[dict(item) for item in data.get("warnings", [])],
            created_by=str(data["created_by"]),
            created_at=_dt(data["created_at"]),
            manifest_version=str(data.get("manifest_version", SCHEMA_VERSION)),
        )


@dataclass(slots=True)
class RenderedReportArtifact:
    rendered_artifact_id: str
    export_manifest_id: str
    report_version_id: str
    format: str
    renderer_id: str
    renderer_version: str
    output_reference: str
    filename: str
    mime_type: str
    size_bytes: int
    sha256: str
    rendered_at: datetime
    warnings: list[dict[str, Any]]
    artifact_fingerprint: str

    def to_schema_dict(self) -> dict[str, Any]:
        return {
            "rendered_artifact_id": self.rendered_artifact_id,
            "export_manifest_id": self.export_manifest_id,
            "report_version_id": self.report_version_id,
            "format": self.format,
            "renderer_id": self.renderer_id,
            "renderer_version": self.renderer_version,
            "output_reference": self.output_reference,
            "filename": self.filename,
            "mime_type": self.mime_type,
            "size_bytes": self.size_bytes,
            "sha256": self.sha256,
            "rendered_at": _ts(self.rendered_at),
            "warnings": self.warnings,
            "artifact_fingerprint": self.artifact_fingerprint,
        }

    @classmethod
    def from_schema_dict(cls, data: dict[str, Any]) -> RenderedReportArtifact:
        return cls(
            rendered_artifact_id=str(data["rendered_artifact_id"]),
            export_manifest_id=str(data["export_manifest_id"]),
            report_version_id=str(data["report_version_id"]),
            format=str(data["format"]),
            renderer_id=str(data["renderer_id"]),
            renderer_version=str(data["renderer_version"]),
            output_reference=str(data["output_reference"]),
            filename=str(data["filename"]),
            mime_type=str(data["mime_type"]),
            size_bytes=int(data["size_bytes"]),
            sha256=str(data["sha256"]),
            rendered_at=_dt(data["rendered_at"]),
            warnings=[dict(item) for item in data.get("warnings", [])],
            artifact_fingerprint=str(data["artifact_fingerprint"]),
        )


@dataclass(slots=True)
class ReportExportAuditEvent:
    audit_event_id: str
    export_manifest_id: str
    report_id: str
    report_version_id: str
    case_id: str
    action: str
    actor_id: str | None
    status: str
    details: dict[str, Any]
    previous_event_hash: str | None
    event_hash: str
    created_at: datetime

    def to_schema_dict(self) -> dict[str, Any]:
        return {
            "audit_event_id": self.audit_event_id,
            "export_manifest_id": self.export_manifest_id,
            "report_id": self.report_id,
            "report_version_id": self.report_version_id,
            "case_id": self.case_id,
            "action": self.action,
            "actor_id": self.actor_id,
            "status": self.status,
            "details": self.details,
            "previous_event_hash": self.previous_event_hash,
            "event_hash": self.event_hash,
            "created_at": _ts(self.created_at),
        }

    @classmethod
    def from_schema_dict(cls, data: dict[str, Any]) -> ReportExportAuditEvent:
        return cls(
            audit_event_id=str(data["audit_event_id"]),
            export_manifest_id=str(data["export_manifest_id"]),
            report_id=str(data["report_id"]),
            report_version_id=str(data["report_version_id"]),
            case_id=str(data["case_id"]),
            action=str(data["action"]),
            actor_id=data.get("actor_id"),
            status=str(data["status"]),
            details=dict(data.get("details", {})),
            previous_event_hash=data.get("previous_event_hash"),
            event_hash=str(data["event_hash"]),
            created_at=_dt(data["created_at"]),
        )


@dataclass(slots=True)
class ReportRendererCapability:
    renderer_id: str
    renderer_version: str
    supported_formats: list[str]
    is_available: bool
    unavailable_reason: str | None
    warnings: list[dict[str, Any]] = field(default_factory=list)
    generated_at: datetime | None = None
    capability_version: str = SCHEMA_VERSION

    def to_schema_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.capability_version,
            "renderer_id": self.renderer_id,
            "renderer_version": self.renderer_version,
            "supported_formats": self.supported_formats,
            "is_available": self.is_available,
            "unavailable_reason": self.unavailable_reason,
            "warnings": self.warnings,
            "generated_at": _ts(self.generated_at),
        }

    @classmethod
    def from_schema_dict(cls, data: dict[str, Any]) -> ReportRendererCapability:
        return cls(
            renderer_id=str(data["renderer_id"]),
            renderer_version=str(data["renderer_version"]),
            supported_formats=[str(item) for item in data.get("supported_formats", [])],
            is_available=bool(data["is_available"]),
            unavailable_reason=data.get("unavailable_reason"),
            warnings=[dict(item) for item in data.get("warnings", [])],
            generated_at=None if data.get("generated_at") is None else _dt(data["generated_at"]),
            capability_version=str(data.get("schema_version", SCHEMA_VERSION)),
        )
