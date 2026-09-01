"""Phase 8 report review, approval, custody snapshot, and export contract service."""

from __future__ import annotations

import base64
import json
import re
from collections.abc import Mapping
from dataclasses import replace
from pathlib import PurePosixPath
from typing import Any, cast

from apex_forensic._time import parse_timestamp, to_json_timestamp
from apex_forensic.constants import DEFAULT_LOCALE, DEFAULT_TIMEZONE, SCHEMA_VERSION
from apex_forensic.domain.enums import (
    CustodySnapshotVerificationStatus,
    ReportApprovalDecision,
    ReportContentKind,
    ReportExportFormat,
    ReportExportStatus,
    ReportReviewAction,
    ReportSectionType,
    ReportSourceKind,
    ReportStatus,
    ReportType,
)
from apex_forensic.domain.errors import ApexError, NotFoundError, ReportError, ValidationError
from apex_forensic.domain.models import (
    CustodySnapshotRecord,
    RenderedReportArtifact,
    ReportApprovalRecord,
    ReportExportAuditEvent,
    ReportExportManifest,
    ReportRecord,
    ReportRendererCapability,
    ReportRenderPackage,
    ReportReviewEvent,
    ReportSection,
    ReportVersion,
)
from apex_forensic.domain.services.canonical import canonical_json_bytes, canonical_sha256
from apex_forensic.ports.clock import Clock
from apex_forensic.ports.id_generator import IdGenerator
from apex_forensic.ports.report_renderer import ReportRendererPort, UnavailableReportRenderer

REPORT_SCHEMA_VERSION = SCHEMA_VERSION
DEFAULT_DERIVED_OUTPUT_ROOT_ID = "apex-derived-default"
MAX_REPORT_TEXT_LENGTH = 40_000
MAX_SECTION_COUNT = 200
MAX_SECTION_CONTENT_LENGTH = 20_000
MAX_LIMITATION_COUNT = 100
MAX_JSON_DEPTH = 8
MAX_JSON_BYTES = 512 * 1024
MAX_REASON_LENGTH = 4000
MAX_FILENAME_LENGTH = 180
MAX_ID_LENGTH = 128
MAX_ACTOR_ID_LENGTH = 256
MAX_REPORT_TITLE_LENGTH = 500
MAX_REPORT_DESCRIPTION_LENGTH = 4000
MAX_SECTION_TITLE_LENGTH = 500
MAX_LIMITATION_LENGTH = 4000
MAX_CONTEXT_SNAPSHOT_COUNT = 1000
MAX_CITATION_COUNT = 1000
MAX_WARNING_COUNT = 1000
MAX_WARNING_MESSAGE_LENGTH = 2000
MAX_STALE_REASON_COUNT = 1000
MAX_STALE_REASON_LENGTH = 500
MAX_REQUESTED_CHANGE_COUNT = 100
MAX_REQUESTED_CHANGE_LENGTH = 4000
MAX_RENDERER_ID_LENGTH = 256
MAX_RENDERER_VERSION_LENGTH = 80
MAX_REDACTION_POLICY_LENGTH = 80
_FORBIDDEN_KEY_PARTS = (
    "api_key",
    "apikey",
    "secret",
    "credential",
    "password",
    "prompt",
    "system_prompt",
    "chain_of_thought",
    "chain-of-thought",
    "reasoning_trace",
    "raw_body",
    "raw_response",
)
_RAW_BLOB_KEYS = ("raw_blob", "blob", "binary", "bytes", "base64", "attachment_bytes")
_DANGEROUS_TEXT = re.compile(r"<\s*(script|iframe|object|embed|img|svg|html)\b", re.IGNORECASE)
_BASE64_DATA = re.compile(r"data\s*:\s*[^;]+;\s*base64\s*,", re.IGNORECASE)
_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_WINDOWS_DRIVE_PREFIX = re.compile(r"^[A-Za-z]:")
_WINDOWS_FORBIDDEN_NAME_CHARS = re.compile(r'[<>:"\\|?*\x00-\x1f]')
_WINDOWS_RESERVED_BASENAMES = {
    "con",
    "prn",
    "aux",
    "nul",
    *(f"com{index}" for index in range(1, 10)),
    *(f"lpt{index}" for index in range(1, 10)),
}
_COMPLETABLE_EXPORT_STATES = {
    ReportExportStatus.PREPARED.value,
    ReportExportStatus.RENDERING.value,
}


class ReportService:
    """Validates and persists Phase 8 report contracts.

    The service never generates report prose and never renders PDF/HTML bytes. External draft and
    renderer outputs must enter through validation methods before persistence.
    """

    def __init__(
        self,
        *,
        repository: Any,
        contexts: Any,
        ai: Any,
        custody: Any,
        clock: Clock,
        id_generator: IdGenerator,
        renderer: ReportRendererPort | None = None,
        derived_output_root_id: str = DEFAULT_DERIVED_OUTPUT_ROOT_ID,
    ) -> None:
        self._repository = repository
        self._contexts = contexts
        self._ai = ai
        self._custody = custody
        self._clock = clock
        self._id_generator = id_generator
        self._renderer = renderer or UnavailableReportRenderer()
        self._derived_output_root_id = _required_non_empty(
            derived_output_root_id, "derived_output_root_id"
        )

    def capabilities(self) -> dict[str, Any]:
        capability = self._renderer.capabilities()
        capability.generated_at = capability.generated_at or self._clock.now()
        self._repository.save_report_renderer_capability(capability)
        return {
            "schema_version": SCHEMA_VERSION,
            "engine_capabilities": [
                "REPORT_ENGINE_CONTRACT",
                "REPORT_IMMUTABLE_VERSION",
                "REPORT_REVIEW_APPROVAL",
                "REPORT_CUSTODY_SNAPSHOT",
                "REPORT_EXPORT_MANIFEST",
            ],
            "unavailable_capabilities": [
                "RUNTIME_REPORT_RENDERER",
                "PDF_RENDERING",
                "HTML_RENDERING",
                "AI_REPORT_DRAFT_GENERATION",
                "MCP_REPORT_TOOL",
                "GUI_REPORT_PREVIEW",
            ],
            "renderer": capability.to_schema_dict(),
        }

    def create_report(
        self,
        *,
        case_id: str,
        title: str,
        created_by: str,
        description: str | None = None,
        report_type: ReportType | str = ReportType.INVESTIGATION,
        locale: str | None = None,
        timezone: str | None = None,
    ) -> ReportRecord:
        title = _bounded_non_empty(title, "title", MAX_REPORT_TITLE_LENGTH)
        created_by = _bounded_non_empty(created_by, "created_by", MAX_ACTOR_ID_LENGTH)
        description = _bounded_optional_text(
            description,
            "description",
            MAX_REPORT_DESCRIPTION_LENGTH,
        )
        case = self._require_case(case_id)
        title = _safe_text(title, "title")
        description = None if description is None else _safe_text(description, "description")
        report_type_value = _enum_value(ReportType, report_type, "report_type")
        now = self._clock.now()
        fingerprint = canonical_sha256(
            {
                "case_id": case_id,
                "title": title,
                "description": description,
                "report_type": report_type_value,
                "locale": locale or case.locale or DEFAULT_LOCALE,
                "timezone": timezone or case.timezone or DEFAULT_TIMEZONE,
                "created_by": created_by,
            }
        )
        record = ReportRecord(
            report_id=self._id_generator.new_id(),
            case_id=case_id,
            title=title,
            description=description,
            report_type=report_type_value,
            locale=locale or case.locale or DEFAULT_LOCALE,
            timezone=timezone or case.timezone or DEFAULT_TIMEZONE,
            status=ReportStatus.DRAFT.value,
            active_version_id=None,
            latest_version_number=0,
            created_by=created_by,
            created_at=now,
            updated_at=now,
            archived_at=None,
            report_fingerprint=fingerprint,
            report_schema_version=REPORT_SCHEMA_VERSION,
        )
        self._repository.save_report(record)
        return record

    def get_report(self, report_id: str) -> ReportRecord:
        report = self._repository.get_report(report_id)
        if report is None:
            raise NotFoundError(
                "REPORT_NOT_FOUND",
                "Report not found.",
                target="report_id",
            )
        return cast(ReportRecord, report)

    def list_reports(
        self, *, case_id: str, cursor: str | None = None, limit: int = 100
    ) -> dict[str, Any]:
        self._require_case(case_id)
        limit = _limit(limit, minimum=1, maximum=1000, target="limit")
        after = _decode_cursor(cursor, field="report_id")
        rows = self._repository.list_reports(
            case_id=case_id,
            after_report_id=after,
            limit=limit + 1,
        )
        has_more = len(rows) > limit
        items = [item.to_schema_dict() for item in rows[:limit]]
        next_cursor = (
            _encode_cursor("report_id", items[-1]["report_id"]) if has_more and items else None
        )
        return {
            "items": items,
            "page": {"next_cursor": next_cursor, "has_more": has_more, "returned": len(items)},
        }

    def archive_report(self, *, report_id: str, actor_id: str, reason: str) -> ReportRecord:
        _bounded_non_empty(actor_id, "actor_id", MAX_ACTOR_ID_LENGTH)
        _required_reason(reason)
        report = self.get_report(report_id)
        now = self._clock.now()
        report.status = ReportStatus.ARCHIVED.value
        report.archived_at = now
        report.updated_at = now
        self._repository.update_report(report)
        return report

    def create_version(
        self,
        *,
        report_id: str,
        source_kind: ReportSourceKind | str,
        created_by: str,
        title: str,
        executive_summary: str,
        sections: list[Mapping[str, Any]],
        source_reference_id: str | None = None,
        context_snapshot_ids: list[str] | None = None,
        evidence_ids: list[str] | None = None,
        search_execution_ids: list[str] | None = None,
        timeline_revisions: list[int] | None = None,
        ai_assistance_request_ids: list[str] | None = None,
        ai_result_ids: list[str] | None = None,
        citations: list[Mapping[str, Any]] | None = None,
        limitations: list[str] | None = None,
        analyzer_versions: Mapping[str, Any] | None = None,
    ) -> ReportVersion:
        report = self.get_report(report_id)
        if report.status == ReportStatus.ARCHIVED.value:
            raise ReportError(
                "REPORT_REVIEW_TRANSITION_INVALID",
                "Archived reports cannot receive new versions.",
                target="report_id",
            )
        source_kind_value = _enum_value(ReportSourceKind, source_kind, "source_kind")
        created_by = _bounded_non_empty(created_by, "created_by", MAX_ACTOR_ID_LENGTH)
        title = _safe_text(
            _bounded_non_empty(title, "title", MAX_REPORT_TITLE_LENGTH),
            "title",
        )
        source_reference_id = _bounded_optional_text(
            source_reference_id,
            "source_reference_id",
            MAX_ID_LENGTH,
        )
        executive_summary = _safe_text(
            _required_non_empty(executive_summary, "executive_summary"),
            "executive_summary",
        )
        if len(executive_summary) > MAX_REPORT_TEXT_LENGTH:
            raise ReportError(
                "REPORT_CONTENT_LIMIT_EXCEEDED",
                "Executive summary exceeds the maximum length.",
                target="executive_summary",
            )
        if not sections or len(sections) > MAX_SECTION_COUNT:
            raise ReportError(
                "REPORT_CONTENT_LIMIT_EXCEEDED",
                "Report version must contain a bounded non-empty section list.",
                target="sections",
            )
        context_snapshot_ids = _string_list(
            context_snapshot_ids or [],
            "context_snapshot_ids",
            max_items=MAX_CONTEXT_SNAPSHOT_COUNT,
        )
        snapshots = self._require_snapshots(report.case_id, context_snapshot_ids)
        evidence_ids = self._validate_evidence_ids(
            report.case_id,
            _string_list(evidence_ids or [], "evidence_ids", max_items=10_000),
        )
        search_execution_ids = self._validate_search_execution_ids(
            report.case_id,
            _string_list(
                search_execution_ids or [],
                "search_execution_ids",
                max_items=10_000,
            ),
        )
        ai_assistance_request_ids = self._validate_ai_request_ids(
            report.case_id,
            _string_list(
                ai_assistance_request_ids or [],
                "ai_assistance_request_ids",
                max_items=10_000,
            ),
        )
        ai_result_ids = self._validate_ai_result_ids(
            report.case_id,
            _string_list(ai_result_ids or [], "ai_result_ids", max_items=10_000),
        )
        timeline_revisions = _integer_list(
            timeline_revisions or [],
            "timeline_revisions",
            max_items=10_000,
        )
        normalized_citations = self._validate_citations(
            case_id=report.case_id,
            snapshots=snapshots,
            citations=[dict(item) for item in (citations or [])],
            require_direct=False,
            target="citations",
        )
        limitations = _string_list(
            limitations or [],
            "limitations",
            max_items=MAX_LIMITATION_COUNT,
        )
        if not limitations:
            raise ReportError(
                "REPORT_LIMITATIONS_REQUIRED",
                "Report versions must record limitations.",
                target="limitations",
            )
        _validate_string_lengths(
            limitations,
            "limitations",
            MAX_LIMITATION_LENGTH,
        )
        analyzer_versions = dict(analyzer_versions or {})
        _validate_contract_payload(analyzer_versions, target="analyzer_versions")
        section_objects = [
            self._section_from_input(
                case_id=report.case_id,
                snapshots=snapshots,
                raw=dict(raw),
                index=index,
            )
            for index, raw in enumerate(sections, start=1)
        ]
        section_objects = sorted(section_objects, key=lambda item: (item.order, item.section_id))
        previous = (
            self.get_version(report.active_version_id)
            if report.active_version_id is not None
            else None
        )
        previous_version_id = None if previous is None else previous.report_version_id
        previous_fingerprint = None if previous is None else previous.content_fingerprint
        partial_state = _partial_state(snapshots, section_objects)
        stale_state = _stale_state(snapshots, section_objects)
        coverage_summary = _coverage_summary(snapshots, section_objects)
        source_revisions = _source_revisions(snapshots)
        version_payload = {
            "report_id": report.report_id,
            "case_id": report.case_id,
            "source_kind": source_kind_value,
            "source_reference_id": source_reference_id,
            "title": title,
            "executive_summary": executive_summary,
            "sections": [item.to_schema_dict() for item in section_objects],
            "context_snapshot_ids": [item.context_snapshot_id for item in snapshots],
            "evidence_ids": sorted(evidence_ids),
            "search_execution_ids": sorted(search_execution_ids),
            "timeline_revisions": sorted(timeline_revisions),
            "ai_assistance_request_ids": sorted(ai_assistance_request_ids),
            "ai_result_ids": sorted(ai_result_ids),
            "citations": normalized_citations,
            "limitations": limitations,
            "analyzer_versions": analyzer_versions,
            "partial_state": partial_state,
            "stale_state": stale_state,
            "coverage_summary": coverage_summary,
            "source_revisions": source_revisions,
        }
        content_fingerprint = canonical_sha256(version_payload)
        existing = self._repository.get_report_version_by_content_fingerprint(
            report.report_id, content_fingerprint
        )
        if existing is not None:
            return self._with_states(cast(ReportVersion, existing))
        now = self._clock.now()
        version = ReportVersion(
            report_version_id=self._id_generator.new_id(),
            report_id=report.report_id,
            case_id=report.case_id,
            version_number=report.latest_version_number + 1,
            previous_version_id=previous_version_id,
            source_kind=source_kind_value,
            source_reference_id=source_reference_id,
            created_by=created_by,
            title=title,
            executive_summary=executive_summary,
            sections=section_objects,
            context_snapshot_ids=[item.context_snapshot_id for item in snapshots],
            evidence_ids=sorted(evidence_ids),
            search_execution_ids=sorted(search_execution_ids),
            timeline_revisions=sorted(timeline_revisions),
            ai_assistance_request_ids=sorted(ai_assistance_request_ids),
            ai_result_ids=sorted(ai_result_ids),
            citation_ids=sorted(
                {
                    str(citation.get("id"))
                    for citation in normalized_citations
                    if citation.get("id") is not None
                }
            ),
            partial_state=partial_state,
            stale_state=stale_state,
            coverage_summary=coverage_summary,
            limitations=limitations,
            analyzer_versions=analyzer_versions,
            source_revisions=source_revisions,
            content_fingerprint=content_fingerprint,
            previous_content_fingerprint=previous_fingerprint,
            review_state={"status": "DRAFT", "review_revision": 0},
            approval_state={"decision": None, "approval_revision": 0},
            created_at=now,
            report_schema_version=REPORT_SCHEMA_VERSION,
        )
        report.active_version_id = version.report_version_id
        report.latest_version_number = version.version_number
        report.status = ReportStatus.REVIEW_REQUIRED.value
        report.updated_at = now
        self._repository.save_report_version(version, report)
        return self._with_states(version)

    def create_version_from_analyst_draft(
        self,
        *,
        report_id: str,
        created_by: str,
        title: str,
        executive_summary: str,
        sections: list[Mapping[str, Any]],
        **kwargs: Any,
    ) -> ReportVersion:
        return self.create_version(
            report_id=report_id,
            source_kind=ReportSourceKind.ANALYST_DRAFT,
            created_by=created_by,
            title=title,
            executive_summary=executive_summary,
            sections=sections,
            **kwargs,
        )

    def ingest_ai_draft(
        self,
        *,
        payload: Mapping[str, Any],
        report_id: str | None = None,
        created_by: str = "external-ai-layer",
    ) -> ReportVersion:
        _validate_contract_payload(payload, target="ai_report_draft")
        case_id = _required_non_empty(payload.get("case_id"), "case_id")
        request = self._ai.get_request(_required_non_empty(
            payload.get("assistance_request_id"), "assistance_request_id"
        ))
        if request.case_id != case_id:
            raise ReportError(
                "REPORT_REFERENCE_CASE_MISMATCH",
                "AI assistance request belongs to another case.",
                target="assistance_request_id",
            )
        context_snapshot_ids = _string_list(
            payload.get("context_snapshot_ids", [request.context_snapshot_id]),
            "context_snapshot_ids",
            max_items=MAX_CONTEXT_SNAPSHOT_COUNT,
        )
        if request.context_snapshot_id not in context_snapshot_ids:
            context_snapshot_ids.append(request.context_snapshot_id)
        ai_result_ids = _string_list(payload.get("ai_result_ids", []), "ai_result_ids")
        self._validate_ai_result_ids(case_id, ai_result_ids)
        provider_metadata = {
            "provider_id": _metadata_string(payload.get("provider_id", "UNKNOWN"), "provider_id"),
            "provider_version": _metadata_string(
                payload.get("provider_version", "UNKNOWN"), "provider_version"
            ),
            "model_id": _metadata_string(payload.get("model_id", "UNKNOWN"), "model_id"),
            "external_request_id": payload.get("external_request_id"),
            "response_hash": _required_non_empty(payload.get("response_hash"), "response_hash"),
            "generated_at": payload.get("generated_at"),
            "correlation_id": payload.get("correlation_id"),
        }
        created_by = _bounded_non_empty(
            created_by,
            "created_by",
            MAX_ACTOR_ID_LENGTH,
        )
        title = _safe_text(
            _bounded_non_empty(
                payload.get("title"),
                "title",
                MAX_REPORT_TITLE_LENGTH,
            ),
            "title",
        )
        executive_summary = _safe_text(
            _bounded_non_empty(
                payload.get("executive_summary"),
                "executive_summary",
                MAX_REPORT_TEXT_LENGTH,
            ),
            "executive_summary",
        )
        raw_sections = _required_list(payload, "sections")
        if not raw_sections or len(raw_sections) > MAX_SECTION_COUNT:
            raise ReportError(
                "REPORT_CONTENT_LIMIT_EXCEEDED",
                "Report version must contain a bounded non-empty section list.",
                target="sections",
            )
        if any(not isinstance(item, Mapping) for item in raw_sections):
            raise ValidationError("Sections must be JSON objects.", target="sections")
        sections = [dict(item) for item in raw_sections]
        for section in sections:
            section.setdefault("source_kind", ReportSourceKind.AI_DRAFT.value)
        citations: list[Mapping[str, Any]] = [
            dict(item) for item in _list_or_empty(payload.get("citations"))
        ]
        limitations = _string_list(
            payload.get("limitations", ["AI draft requires human review."]),
            "limitations",
            max_items=MAX_LIMITATION_COUNT,
        )
        _validate_string_lengths(limitations, "limitations", MAX_LIMITATION_LENGTH)
        snapshots = self._require_snapshots(case_id, context_snapshot_ids)
        for index, section in enumerate(sections, start=1):
            self._section_from_input(
                case_id=case_id,
                snapshots=snapshots,
                raw=section,
                index=index,
            )
        self._validate_citations(
            case_id=case_id,
            snapshots=snapshots,
            citations=[dict(item) for item in citations],
            require_direct=False,
            target="citations",
        )
        source_reference = _bounded_non_empty(
            provider_metadata.get("external_request_id") or request.assistance_request_id,
            "source_reference_id",
            MAX_ID_LENGTH,
        )
        if report_id is None:
            report = self.create_report(
                case_id=case_id,
                title=title,
                description="AI draft ingest placeholder; content remains in immutable versions.",
                report_type=ReportType.INVESTIGATION,
                created_by=created_by,
            )
            report_id = report.report_id
        return self.create_version(
            report_id=report_id,
            source_kind=ReportSourceKind.AI_DRAFT,
            source_reference_id=source_reference,
            created_by=created_by,
            title=title,
            executive_summary=executive_summary,
            sections=cast(list[Mapping[str, Any]], sections),
            context_snapshot_ids=context_snapshot_ids,
            ai_assistance_request_ids=[request.assistance_request_id],
            ai_result_ids=ai_result_ids,
            citations=citations,
            limitations=limitations,
            analyzer_versions=provider_metadata,
        )

    def clone_version(
        self, *, report_version_id: str, created_by: str, reason: str
    ) -> ReportVersion:
        source = self.get_version(report_version_id)
        return self.create_version(
            report_id=source.report_id,
            source_kind=ReportSourceKind.IMPORTED_DRAFT,
            source_reference_id=source.report_version_id,
            created_by=created_by,
            title=source.title,
            executive_summary=source.executive_summary,
            sections=[item.to_schema_dict() for item in source.sections],
            context_snapshot_ids=source.context_snapshot_ids,
            evidence_ids=source.evidence_ids,
            search_execution_ids=source.search_execution_ids,
            timeline_revisions=source.timeline_revisions,
            ai_assistance_request_ids=source.ai_assistance_request_ids,
            ai_result_ids=source.ai_result_ids,
            citations=[citation for section in source.sections for citation in section.citations],
            limitations=[*source.limitations, reason],
            analyzer_versions=source.analyzer_versions,
        )

    def get_version(self, report_version_id: str) -> ReportVersion:
        version = self._repository.get_report_version(report_version_id)
        if version is None:
            raise NotFoundError(
                "REPORT_VERSION_NOT_FOUND",
                "Report version not found.",
                target="report_version_id",
            )
        return self._with_states(cast(ReportVersion, version))

    def list_versions(self, report_id: str) -> list[ReportVersion]:
        self.get_report(report_id)
        return [
            self._with_states(item)
            for item in self._repository.list_report_versions(report_id=report_id)
        ]

    def compare_versions(self, left_version_id: str, right_version_id: str) -> dict[str, Any]:
        left = self.get_version(left_version_id)
        right = self.get_version(right_version_id)
        if left.report_id != right.report_id:
            raise ReportError(
                "REPORT_VERSION_MISMATCH",
                "Report versions belong to different reports.",
                target="report_version_id",
            )
        return {
            "report_id": left.report_id,
            "left_report_version_id": left.report_version_id,
            "right_report_version_id": right.report_version_id,
            "same_content": left.content_fingerprint == right.content_fingerprint,
            "left_content_fingerprint": left.content_fingerprint,
            "right_content_fingerprint": right.content_fingerprint,
            "section_fingerprints_added": sorted(
                {item.section_fingerprint for item in right.sections}
                - {item.section_fingerprint for item in left.sections}
            ),
            "section_fingerprints_removed": sorted(
                {item.section_fingerprint for item in left.sections}
                - {item.section_fingerprint for item in right.sections}
            ),
        }

    def set_active_version(
        self, *, report_id: str, report_version_id: str, actor_id: str, reason: str
    ) -> ReportRecord:
        _bounded_non_empty(actor_id, "actor_id", MAX_ACTOR_ID_LENGTH)
        _required_reason(reason)
        report = self.get_report(report_id)
        version = self.get_version(report_version_id)
        if version.report_id != report.report_id:
            raise ReportError(
                "REPORT_APPROVAL_VERSION_MISMATCH",
                "Report version belongs to another report.",
                target="report_version_id",
            )
        report.active_version_id = version.report_version_id
        report.status = ReportStatus.REVIEW_REQUIRED.value
        report.updated_at = self._clock.now()
        self._repository.update_report(report)
        return report

    def submit_review(
        self,
        *,
        report_version_id: str,
        actor_id: str,
        reason: str,
        expected_review_revision: int | None = None,
    ) -> ReportReviewEvent:
        return self._append_review_event(
            report_version_id=report_version_id,
            action=ReportReviewAction.SUBMIT_FOR_REVIEW,
            actor_id=actor_id,
            reason=reason,
            expected_review_revision=expected_review_revision,
        )

    def comment_review(
        self,
        *,
        report_version_id: str,
        actor_id: str,
        reason: str,
        comment: str,
        section_id: str | None = None,
        expected_review_revision: int | None = None,
    ) -> ReportReviewEvent:
        return self._append_review_event(
            report_version_id=report_version_id,
            action=ReportReviewAction.COMMENT,
            actor_id=actor_id,
            reason=reason,
            section_id=section_id,
            comment=comment,
            expected_review_revision=expected_review_revision,
        )

    def request_changes(
        self,
        *,
        report_version_id: str,
        actor_id: str,
        reason: str,
        requested_changes: list[str],
        section_id: str | None = None,
        expected_review_revision: int | None = None,
    ) -> ReportReviewEvent:
        return self._append_review_event(
            report_version_id=report_version_id,
            action=ReportReviewAction.REQUEST_CHANGES,
            actor_id=actor_id,
            reason=reason,
            section_id=section_id,
            requested_changes=requested_changes,
            expected_review_revision=expected_review_revision,
        )

    def complete_review(
        self,
        *,
        report_version_id: str,
        actor_id: str,
        reason: str,
        expected_review_revision: int | None = None,
    ) -> ReportReviewEvent:
        return self._append_review_event(
            report_version_id=report_version_id,
            action=ReportReviewAction.MARK_REVIEW_COMPLETE,
            actor_id=actor_id,
            reason=reason,
            expected_review_revision=expected_review_revision,
        )

    def accept_section(
        self,
        *,
        report_version_id: str,
        section_id: str,
        actor_id: str,
        reason: str,
        comment: str | None = None,
        expected_review_revision: int | None = None,
    ) -> ReportReviewEvent:
        return self._append_review_event(
            report_version_id=report_version_id,
            action=ReportReviewAction.ACCEPT_SECTION,
            actor_id=actor_id,
            reason=reason,
            section_id=section_id,
            comment=comment,
            expected_review_revision=expected_review_revision,
        )

    def reject_section(
        self,
        *,
        report_version_id: str,
        section_id: str,
        actor_id: str,
        reason: str,
        requested_changes: list[str] | None = None,
        comment: str | None = None,
        expected_review_revision: int | None = None,
    ) -> ReportReviewEvent:
        return self._append_review_event(
            report_version_id=report_version_id,
            action=ReportReviewAction.REJECT_SECTION,
            actor_id=actor_id,
            reason=reason,
            section_id=section_id,
            comment=comment,
            requested_changes=requested_changes,
            expected_review_revision=expected_review_revision,
        )

    def reopen_review(
        self,
        *,
        report_version_id: str,
        actor_id: str,
        reason: str,
        expected_review_revision: int | None = None,
    ) -> ReportReviewEvent:
        return self._append_review_event(
            report_version_id=report_version_id,
            action=ReportReviewAction.REOPEN_REVIEW,
            actor_id=actor_id,
            reason=reason,
            expected_review_revision=expected_review_revision,
        )

    def review_history(self, report_version_id: str) -> list[ReportReviewEvent]:
        self.get_version(report_version_id)
        return cast(
            list[ReportReviewEvent],
            self._repository.list_report_review_events(report_version_id=report_version_id),
        )

    def approve(
        self,
        *,
        report_version_id: str,
        approver_id: str,
        reason: str,
        custody_snapshot_id: str | None = None,
        expected_review_revision: int | None = None,
        expected_approval_revision: int | None = None,
    ) -> ReportApprovalRecord:
        approver_id = _bounded_non_empty(
            approver_id,
            "approver_id",
            MAX_ACTOR_ID_LENGTH,
        )
        reason = _required_reason(reason)
        version = self.get_version(report_version_id)
        review_revision = int(version.review_state.get("review_revision", 0))
        if expected_review_revision is not None and expected_review_revision != review_revision:
            raise ReportError(
                "REPORT_REVIEW_REVISION_CONFLICT",
                "Report review revision changed.",
                target="expected_review_revision",
                retryable=True,
            )
        if version.review_state.get("status") != "REVIEW_COMPLETE":
            raise ReportError(
                "REPORT_APPROVAL_REVIEW_INCOMPLETE",
                "Report approval requires completed review.",
                target="report_version_id",
            )
        custody_snapshot = (
            self.get_custody_snapshot(custody_snapshot_id)
            if custody_snapshot_id is not None
            else self.create_custody_snapshot(
                report_version_id=version.report_version_id,
                captured_by=approver_id,
            )
        )
        if custody_snapshot.report_version_id != version.report_version_id:
            raise ReportError(
                "REPORT_APPROVAL_VERSION_MISMATCH",
                "Custody snapshot belongs to another report version.",
                target="custody_snapshot_id",
            )
        if custody_snapshot.verification_status != CustodySnapshotVerificationStatus.VERIFIED.value:
            raise ReportError(
                "REPORT_APPROVAL_REVIEW_INCOMPLETE",
                "Invalid or incomplete custody verification blocks approval.",
                target="custody_snapshot_id",
                details={"verification_status": custody_snapshot.verification_status},
            )
        return self._append_approval(
            version=version,
            decision=ReportApprovalDecision.APPROVED,
            actor_id=approver_id,
            reason=reason,
            custody_snapshot_id=custody_snapshot.custody_snapshot_id,
            expected_approval_revision=expected_approval_revision,
        )

    def reject(
        self,
        *,
        report_version_id: str,
        approver_id: str,
        reason: str,
        expected_approval_revision: int | None = None,
    ) -> ReportApprovalRecord:
        version = self.get_version(report_version_id)
        return self._append_approval(
            version=version,
            decision=ReportApprovalDecision.REJECTED,
            actor_id=approver_id,
            reason=_required_reason(reason),
            custody_snapshot_id=None,
            expected_approval_revision=expected_approval_revision,
        )

    def revoke_approval(
        self,
        *,
        report_version_id: str,
        actor_id: str,
        reason: str,
        expected_approval_revision: int | None = None,
    ) -> ReportApprovalRecord:
        version = self.get_version(report_version_id)
        latest = self._latest_approval(version.report_version_id)
        if latest is None or latest.decision != ReportApprovalDecision.APPROVED.value:
            raise ReportError(
                "REPORT_APPROVAL_TRANSITION_INVALID",
                "Only the latest approved report version can be revoked.",
                target="report_version_id",
            )
        return self._append_approval(
            version=version,
            decision=ReportApprovalDecision.REVOKED,
            actor_id=actor_id,
            reason=_required_reason(reason),
            custody_snapshot_id=latest.custody_snapshot_id,
            expected_approval_revision=expected_approval_revision,
        )

    def get_approval(self, report_version_id: str) -> ReportApprovalRecord | None:
        self.get_version(report_version_id)
        return self._latest_approval(report_version_id)

    def create_custody_snapshot(
        self,
        *,
        report_version_id: str,
        captured_by: str,
        evidence_ids: list[str] | None = None,
    ) -> CustodySnapshotRecord:
        captured_by = _bounded_non_empty(
            captured_by,
            "captured_by",
            MAX_ACTOR_ID_LENGTH,
        )
        version = self.get_version(report_version_id)
        evidence_ids = self._validate_evidence_ids(
            version.case_id,
            _string_list(
                evidence_ids if evidence_ids is not None else version.evidence_ids,
                "evidence_ids",
                max_items=10_000,
            ),
        )
        events: list[Any] = []
        verification_errors: list[dict[str, Any]] = []
        ledger_heads: list[str] = []
        for evidence_id in sorted(evidence_ids):
            evidence_events = self._repository.list_custody_events(evidence_id)
            if not evidence_events:
                verification_errors.append(
                    {"code": "CUSTODY_EVENTS_MISSING", "evidence_id": evidence_id}
                )
                continue
            if not self._custody.verify_chain(evidence_id):
                verification_errors.append(
                    {"code": "CUSTODY_CHAIN_INVALID", "evidence_id": evidence_id}
                )
            events.extend(evidence_events)
            ledger_heads.append(evidence_events[-1].event_hash)
        if not evidence_ids:
            status = CustodySnapshotVerificationStatus.UNKNOWN.value
            verification_errors.append({"code": "CUSTODY_EVIDENCE_SCOPE_EMPTY"})
        elif verification_errors:
            status = CustodySnapshotVerificationStatus.INVALID.value
        else:
            status = CustodySnapshotVerificationStatus.VERIFIED.value
        event_ids = [event.event_id for event in events]
        if len(event_ids) > 100_000 or len(verification_errors) > 10_000:
            raise ReportError(
                "REPORT_CONTENT_LIMIT_EXCEEDED",
                "Custody snapshot collections exceed the schema limits.",
                target="custody_snapshot",
            )
        event_times = [
            parse_timestamp(str(event.to_schema_dict()["occurred_at_utc"])) for event in events
        ]
        ledger_head_hash = canonical_sha256(sorted(ledger_heads)) if ledger_heads else None
        fingerprint_payload = {
            "case_id": version.case_id,
            "report_id": version.report_id,
            "report_version_id": version.report_version_id,
            "evidence_ids": sorted(evidence_ids),
            "custody_event_ids": event_ids,
            "ledger_head_hash": ledger_head_hash,
            "verification_status": status,
            "verification_errors": verification_errors,
        }
        snapshot_fingerprint = canonical_sha256(fingerprint_payload)
        existing = self._repository.get_custody_snapshot_by_fingerprint(snapshot_fingerprint)
        if existing is not None:
            return cast(CustodySnapshotRecord, existing)
        now = self._clock.now()
        snapshot = CustodySnapshotRecord(
            custody_snapshot_id=self._id_generator.new_id(),
            case_id=version.case_id,
            report_id=version.report_id,
            report_version_id=version.report_version_id,
            evidence_ids=sorted(evidence_ids),
            custody_event_ids=event_ids,
            ledger_head_hash=ledger_head_hash,
            verification_status=status,
            verification_errors=verification_errors,
            event_count=len(events),
            first_event_at=min(event_times) if event_times else None,
            last_event_at=max(event_times) if event_times else None,
            captured_by=captured_by,
            captured_at=now,
            snapshot_fingerprint=snapshot_fingerprint,
            snapshot_version=REPORT_SCHEMA_VERSION,
        )
        self._repository.save_custody_snapshot(snapshot)
        return snapshot

    def get_custody_snapshot(self, custody_snapshot_id: str) -> CustodySnapshotRecord:
        snapshot = self._repository.get_custody_snapshot(custody_snapshot_id)
        if snapshot is None:
            raise NotFoundError(
                "CUSTODY_SNAPSHOT_NOT_FOUND",
                "Report custody snapshot not found.",
                target="custody_snapshot_id",
            )
        return cast(CustodySnapshotRecord, snapshot)

    def create_render_package(
        self,
        *,
        report_version_id: str,
        created_by: str,
        for_export: bool = False,
        custody_snapshot_id: str | None = None,
        stale_confirmed: bool = False,
    ) -> ReportRenderPackage:
        created_by = _bounded_non_empty(
            created_by,
            "created_by",
            MAX_ACTOR_ID_LENGTH,
        )
        version = self.get_version(report_version_id)
        if for_export:
            approval = self._require_approved_version(version)
            custody_snapshot_id = custody_snapshot_id or approval.custody_snapshot_id
        if version.stale_state.get("is_stale") and for_export and not stale_confirmed:
            raise ReportError(
                "REPORT_APPROVAL_TRANSITION_INVALID",
                "Stale report export requires explicit confirmation.",
                target="stale_confirmed",
            )
        evidence_manifest = [self._evidence_manifest_item(eid) for eid in version.evidence_ids]
        citations = _stable_citations(
            [citation for section in version.sections for citation in section.citations]
        )
        if len(citations) > MAX_CITATION_COUNT:
            raise ReportError(
                "REPORT_CONTENT_LIMIT_EXCEEDED",
                "Render package exceeds the maximum citation count.",
                target="citations",
            )
        package_payload = {
            "report_id": version.report_id,
            "report_version_id": version.report_version_id,
            "case_id": version.case_id,
            "sections": [item.to_schema_dict() for item in version.sections],
            "evidence_manifest": evidence_manifest,
            "custody_snapshot_id": custody_snapshot_id,
            "context_snapshot_ids": version.context_snapshot_ids,
            "citations": citations,
            "partial_state": version.partial_state,
            "stale_state": version.stale_state,
            "coverage_summary": version.coverage_summary,
            "limitations": version.limitations,
            "for_export": for_export,
        }
        package_fingerprint = canonical_sha256(package_payload)
        existing = self._repository.get_report_render_package_by_fingerprint(package_fingerprint)
        if existing is not None:
            return cast(ReportRenderPackage, existing)
        report = self.get_report(version.report_id)
        package = ReportRenderPackage(
            package_id=self._id_generator.new_id(),
            report_id=version.report_id,
            report_version_id=version.report_version_id,
            case_id=version.case_id,
            locale=report.locale,
            timezone=report.timezone,
            report_metadata={
                "title": version.title,
                "executive_summary": version.executive_summary,
                "version_number": version.version_number,
                "source_kind": version.source_kind,
                "approval_state": version.approval_state,
                "preview_allowed": True,
                "export_allowed": for_export,
                "created_by": created_by,
            },
            sections=[item.to_schema_dict() for item in version.sections],
            evidence_manifest=evidence_manifest,
            hash_integrity_summary={
                "evidence_count": len(evidence_manifest),
                "hash_record_count": sum(len(item.get("hashes", [])) for item in evidence_manifest),
            },
            custody_snapshot_id=custody_snapshot_id,
            context_snapshot_ids=version.context_snapshot_ids,
            citations=citations,
            partial_state=version.partial_state,
            stale_state=version.stale_state,
            coverage_summary=version.coverage_summary,
            limitations=version.limitations,
            renderer_requirements={
                "formats": [ReportExportFormat.PDF.value, ReportExportFormat.HTML.value],
                "binary_attachments_embedded": False,
                "schema_version": REPORT_SCHEMA_VERSION,
            },
            package_fingerprint=package_fingerprint,
            created_at=self._clock.now(),
            package_version=REPORT_SCHEMA_VERSION,
        )
        self._repository.save_report_render_package(package)
        return package

    def get_render_package(self, package_id: str) -> ReportRenderPackage:
        package = self._repository.get_report_render_package(package_id)
        if package is None:
            raise NotFoundError(
                "REPORT_PACKAGE_NOT_FOUND",
                "Report render package not found.",
                target="package_id",
            )
        return cast(ReportRenderPackage, package)

    def prepare_export(
        self,
        *,
        report_version_id: str,
        format: ReportExportFormat | str,
        filename: str,
        created_by: str,
        redaction_policy: str = "STANDARD",
        overwrite_policy: str = "DENY",
        include_citations: bool = True,
        include_custody: bool = True,
        include_technical_appendix: bool = True,
        stale_confirmed: bool = False,
        expected_content_fingerprint: str | None = None,
        expected_approval_id: str | None = None,
        expected_custody_snapshot_id: str | None = None,
        renderer: ReportRendererPort | None = None,
    ) -> ReportExportManifest:
        created_by = _bounded_non_empty(
            created_by,
            "created_by",
            MAX_ACTOR_ID_LENGTH,
        )
        redaction_policy = _bounded_non_empty(
            redaction_policy,
            "redaction_policy",
            MAX_REDACTION_POLICY_LENGTH,
        )
        _bounded_non_empty(
            self._derived_output_root_id,
            "derived_output_root_id",
            MAX_ID_LENGTH,
        )
        version = self.get_version(report_version_id)
        approval = self._require_approved_version(version)
        if (
            expected_content_fingerprint is not None
            and expected_content_fingerprint != version.content_fingerprint
        ):
            raise ReportError(
                "REPORT_APPROVAL_FINGERPRINT_MISMATCH",
                "Expected content fingerprint does not match the approved version.",
                target="expected_content_fingerprint",
                retryable=True,
            )
        if expected_approval_id is not None and expected_approval_id != approval.approval_id:
            raise ReportError(
                "REPORT_APPROVAL_TRANSITION_INVALID",
                "Expected approval does not match the latest approved decision.",
                target="expected_approval_id",
                retryable=True,
            )
        if (
            expected_custody_snapshot_id is not None
            and expected_custody_snapshot_id != approval.custody_snapshot_id
        ):
            raise ReportError(
                "REPORT_APPROVAL_TRANSITION_INVALID",
                "Expected custody snapshot does not match the approved decision.",
                target="expected_custody_snapshot_id",
                retryable=True,
            )
        format_value = _enum_value(ReportExportFormat, format, "format")
        filename = _safe_filename(filename, format_value)
        if overwrite_policy != "DENY":
            raise ReportError(
                "REPORT_OUTPUT_INVALID",
                "Overwrite is denied by default and other overwrite policies are not implemented.",
                target="overwrite_policy",
            )
        fingerprint_payload = {
            "report_version_id": version.report_version_id,
            "format": format_value,
            "filename": filename,
            "content_fingerprint": version.content_fingerprint,
            "approval_id": approval.approval_id,
            "custody_snapshot_id": approval.custody_snapshot_id,
            "redaction_policy": redaction_policy,
            "include_citations": include_citations,
            "include_custody": include_custody,
            "include_technical_appendix": include_technical_appendix,
        }
        manifest_fingerprint = canonical_sha256(fingerprint_payload)
        existing = self._repository.get_report_export_manifest_by_fingerprint(
            manifest_fingerprint
        )
        if existing is not None:
            return cast(ReportExportManifest, existing)
        package = self.create_render_package(
            report_version_id=version.report_version_id,
            created_by=created_by,
            for_export=True,
            custody_snapshot_id=approval.custody_snapshot_id,
            stale_confirmed=stale_confirmed,
        )
        active_renderer = renderer or self._renderer
        capability = active_renderer.capabilities()
        capability.generated_at = capability.generated_at or self._clock.now()
        _validate_renderer_capability(capability)
        self._repository.save_report_renderer_capability(capability)
        renderer_available = (
            capability.is_available and format_value in capability.supported_formats
        )
        status = (
            ReportExportStatus.PREPARED.value
            if renderer_available
            else ReportExportStatus.CAPABILITY_UNAVAILABLE.value
        )
        warnings = (
            []
            if renderer_available
            else _bounded_warnings(capability.warnings, "warnings")
        )
        manifest = ReportExportManifest(
            export_manifest_id=self._id_generator.new_id(),
            report_id=version.report_id,
            report_version_id=version.report_version_id,
            case_id=version.case_id,
            format=format_value,
            render_package_id=package.package_id,
            renderer_id=capability.renderer_id,
            renderer_version=capability.renderer_version,
            requested_filename=filename,
            derived_output_root_id=self._derived_output_root_id,
            overwrite_policy=overwrite_policy,
            redaction_policy=redaction_policy,
            include_citations=include_citations,
            include_custody=include_custody,
            include_technical_appendix=include_technical_appendix,
            content_fingerprint=version.content_fingerprint,
            manifest_fingerprint=manifest_fingerprint,
            approval_id=approval.approval_id,
            custody_snapshot_id=approval.custody_snapshot_id,
            status=status,
            warnings=warnings,
            created_by=created_by,
            created_at=self._clock.now(),
            manifest_version=REPORT_SCHEMA_VERSION,
        )
        report = self.get_report(version.report_id)
        report.status = (
            ReportStatus.EXPORT_READY.value
            if status == ReportExportStatus.PREPARED.value
            else ReportStatus.EXPORT_FAILED.value
        )
        report.updated_at = self._clock.now()
        self._repository.save_report_export_manifest(manifest, report)
        self._append_export_audit(manifest, "PREPARE", manifest.created_by, status, {})
        return manifest

    def get_export_manifest(self, export_manifest_id: str) -> ReportExportManifest:
        manifest = self._repository.get_report_export_manifest(export_manifest_id)
        if manifest is None:
            raise NotFoundError(
                "REPORT_EXPORT_MANIFEST_NOT_FOUND",
                "Report export manifest not found.",
                target="export_manifest_id",
            )
        return cast(ReportExportManifest, manifest)

    def export_status(self, export_manifest_id: str) -> dict[str, Any]:
        manifest = self.get_export_manifest(export_manifest_id)
        artifacts = self._repository.list_rendered_report_artifacts(
            export_manifest_id=export_manifest_id
        )
        return {
            "manifest": manifest.to_schema_dict(),
            "artifacts": [item.to_schema_dict() for item in artifacts],
        }

    def render_export(
        self,
        *,
        export_manifest_id: str,
        renderer: ReportRendererPort | None = None,
    ) -> ReportExportManifest:
        manifest = self.get_export_manifest(export_manifest_id)
        if manifest.status != ReportExportStatus.PREPARED.value:
            raise ReportError(
                "REPORT_RENDER_FAILED",
                "Export manifest is not prepared for rendering.",
                target="export_manifest_id",
                details={"manifest_status": manifest.status},
            )
        active_renderer = renderer or self._renderer
        capability = active_renderer.capabilities()
        _validate_renderer_capability(capability)
        if not capability.is_available or manifest.format not in capability.supported_formats:
            warnings = _bounded_warnings(
                [*manifest.warnings, *capability.warnings],
                "warnings",
            )
            manifest.status = ReportExportStatus.CAPABILITY_UNAVAILABLE.value
            manifest.warnings = warnings
            self._repository.update_report_export_manifest(manifest)
            self._append_export_audit(manifest, "RENDER_UNAVAILABLE", None, manifest.status, {})
            return manifest
        package = self.get_render_package(manifest.render_package_id)
        manifest.status = ReportExportStatus.RENDERING.value
        self._repository.update_report_export_manifest(manifest)
        self._append_export_audit(manifest, "RENDER_START", None, manifest.status, {})
        try:
            active_renderer.validate_package(package)
            result = active_renderer.render(
                package,
                export_manifest_id=manifest.export_manifest_id,
                requested_filename=manifest.requested_filename,
            )
            active_renderer.verify_output(result)
            self.record_export_result(
                export_manifest_id=manifest.export_manifest_id,
                payload=result,
            )
        except ReportError as error:
            warnings = _bounded_warnings(
                [
                    *manifest.warnings,
                    {"code": error.code, "developer_message": error.developer_message},
                ],
                "warnings",
            )
            manifest.status = ReportExportStatus.FAILED.value
            manifest.warnings = warnings
            self._repository.update_report_export_manifest(manifest)
            self._append_export_audit(
                manifest, "RENDER_FAILED", None, manifest.status, error.to_api_error()
            )
        return self.get_export_manifest(manifest.export_manifest_id)

    def record_export_result(
        self,
        *,
        export_manifest_id: str,
        payload: Mapping[str, Any],
    ) -> RenderedReportArtifact | ReportExportManifest:
        manifest = self.get_export_manifest(export_manifest_id)
        _validate_contract_payload(payload, target="render_result")
        result_warnings = _bounded_warnings(payload.get("warnings", []), "warnings")
        status = str(payload.get("status", ReportExportStatus.COMPLETED.value))
        if status in {ReportExportStatus.FAILED.value, ReportExportStatus.CANCELLED.value}:
            merged_warnings = _bounded_warnings(
                [*manifest.warnings, *result_warnings],
                "warnings",
            )
            manifest.status = status
            manifest.warnings = merged_warnings
            self._repository.update_report_export_manifest(manifest)
            self._append_export_audit(manifest, "RENDER_RESULT", None, status, dict(payload))
            return manifest
        if status != ReportExportStatus.COMPLETED.value:
            raise ReportError(
                "REPORT_OUTPUT_INVALID",
                "Renderer result status is invalid.",
                target="status",
            )
        if manifest.status not in _COMPLETABLE_EXPORT_STATES:
            raise ReportError(
                "REPORT_OUTPUT_INVALID",
                "Renderer completion is invalid for the current export manifest state.",
                target="export_manifest_id",
                details={"manifest_status": manifest.status},
            )
        output_reference = _required_non_empty(payload.get("output_reference"), "output_reference")
        self._validate_output_reference(output_reference, manifest.derived_output_root_id)
        filename = _safe_filename(
            str(payload.get("filename", manifest.requested_filename)),
            manifest.format,
        )
        size_bytes = _limit(
            payload.get("size_bytes"),
            minimum=1,
            maximum=10**12,
            target="size_bytes",
        )
        sha256 = _required_non_empty(payload.get("sha256"), "sha256").lower()
        if _SHA256_RE.match(sha256) is None:
            raise ReportError(
                "REPORT_OUTPUT_INVALID",
                "Renderer output hash is invalid.",
                target="sha256",
            )
        renderer_id = _bounded_non_empty(
            payload.get("renderer_id", manifest.renderer_id),
            "renderer_id",
            MAX_RENDERER_ID_LENGTH,
        )
        renderer_version = _bounded_non_empty(
            payload.get("renderer_version", manifest.renderer_version),
            "renderer_version",
            MAX_RENDERER_VERSION_LENGTH,
        )
        mime_type = str(payload.get("mime_type") or _mime_type(manifest.format))
        artifact_payload: dict[str, str | int] = {
            "export_manifest_id": manifest.export_manifest_id,
            "report_version_id": manifest.report_version_id,
            "format": manifest.format,
            "renderer_id": renderer_id,
            "renderer_version": renderer_version,
            "output_reference": output_reference,
            "filename": filename,
            "mime_type": mime_type,
            "size_bytes": size_bytes,
            "sha256": sha256,
        }
        artifact = RenderedReportArtifact(
            rendered_artifact_id=self._id_generator.new_id(),
            export_manifest_id=manifest.export_manifest_id,
            report_version_id=manifest.report_version_id,
            format=manifest.format,
            renderer_id=renderer_id,
            renderer_version=renderer_version,
            output_reference=output_reference,
            filename=filename,
            mime_type=mime_type,
            size_bytes=size_bytes,
            sha256=sha256,
            rendered_at=self._clock.now(),
            warnings=result_warnings,
            artifact_fingerprint=canonical_sha256(artifact_payload),
        )
        manifest.status = ReportExportStatus.COMPLETED.value
        manifest.warnings = _bounded_warnings(
            [*manifest.warnings, *artifact.warnings],
            "warnings",
        )
        report = self.get_report(manifest.report_id)
        report.status = ReportStatus.EXPORTED.value
        report.updated_at = self._clock.now()
        self._repository.save_rendered_report_artifact(artifact, manifest, report)
        self._append_export_audit(
            manifest,
            "RENDER_COMPLETED",
            None,
            manifest.status,
            artifact_payload,
        )
        return artifact

    def renderer_capabilities(self) -> ReportRendererCapability:
        capability = self._renderer.capabilities()
        capability.generated_at = capability.generated_at or self._clock.now()
        _validate_renderer_capability(capability)
        self._repository.save_report_renderer_capability(capability)
        return capability

    def _append_review_event(
        self,
        *,
        report_version_id: str,
        action: ReportReviewAction | str,
        actor_id: str,
        reason: str,
        section_id: str | None = None,
        comment: str | None = None,
        requested_changes: list[str] | None = None,
        expected_review_revision: int | None = None,
    ) -> ReportReviewEvent:
        version = self.get_version(report_version_id)
        action_value = _enum_value(ReportReviewAction, action, "action")
        actor_id = _bounded_non_empty(actor_id, "actor_id", MAX_ACTOR_ID_LENGTH)
        reason = _required_reason(reason)
        if comment is not None:
            comment = _safe_text(
                _bounded_optional_text(comment, "comment", MAX_REQUESTED_CHANGE_LENGTH) or "",
                "comment",
            )
        requested_changes = _string_list(
            requested_changes or [],
            "requested_changes",
            max_items=MAX_REQUESTED_CHANGE_COUNT,
        )
        _validate_string_lengths(
            requested_changes,
            "requested_changes",
            MAX_REQUESTED_CHANGE_LENGTH,
        )
        events = self._repository.list_report_review_events(
            report_version_id=version.report_version_id
        )
        latest_revision = events[-1].review_revision if events else 0
        if expected_review_revision is not None and expected_review_revision != latest_revision:
            raise ReportError(
                "REPORT_REVIEW_REVISION_CONFLICT",
                "Report review revision changed.",
                target="expected_review_revision",
                retryable=True,
            )
        latest_status = _review_status_from_events(events)
        if action_value == ReportReviewAction.MARK_REVIEW_COMPLETE.value and latest_status not in {
            "IN_REVIEW",
            "CHANGES_REQUESTED",
        }:
            raise ReportError(
                "REPORT_REVIEW_TRANSITION_INVALID",
                "Review must be submitted before completion.",
                target="action",
            )
        section_actions = {
            ReportReviewAction.ACCEPT_SECTION.value,
            ReportReviewAction.REJECT_SECTION.value,
        }
        if action_value in section_actions and section_id is None:
            raise ReportError(
                "REPORT_REVIEW_REQUIRED",
                "Section review actions require section_id.",
                target="section_id",
            )
        if section_id is not None and section_id not in {
            item.section_id for item in version.sections
        }:
            raise ReportError(
                "REPORT_REVIEW_TARGET_NOT_FOUND",
                "Review section not found on the target report version.",
                target="section_id",
            )
        if action_value == ReportReviewAction.MARK_REVIEW_COMPLETE.value:
            missing = _missing_required_section_reviews(version, events)
            if missing:
                raise ReportError(
                    "REPORT_REVIEW_REQUIRED",
                    "All required report sections must be accepted before review completion.",
                    target="section_id",
                    details={"missing_section_ids": missing},
                )
        if action_value == ReportReviewAction.REQUEST_CHANGES.value and not requested_changes:
            raise ReportError(
                "REPORT_REVIEW_REQUIRED",
                "Request changes requires requested_changes.",
                target="requested_changes",
            )
        previous_event_hash = events[-1].event_hash if events else None
        created_at = self._clock.now()
        event_id = self._id_generator.new_id()
        payload = {
            "review_event_id": event_id,
            "report_id": version.report_id,
            "report_version_id": version.report_version_id,
            "case_id": version.case_id,
            "action": action_value,
            "actor_id": actor_id,
            "reason": reason,
            "section_id": section_id,
            "comment": comment,
            "requested_changes": requested_changes,
            "expected_review_revision": expected_review_revision,
            "review_revision": latest_revision + 1,
            "previous_event_hash": previous_event_hash,
            "created_at": to_json_timestamp(created_at),
        }
        event = ReportReviewEvent(
            review_event_id=event_id,
            report_id=version.report_id,
            report_version_id=version.report_version_id,
            case_id=version.case_id,
            action=action_value,
            actor_id=actor_id,
            reason=reason,
            section_id=section_id,
            comment=comment,
            requested_changes=requested_changes,
            expected_review_revision=expected_review_revision,
            review_revision=latest_revision + 1,
            previous_event_hash=previous_event_hash,
            event_hash=canonical_sha256(payload),
            created_at=created_at,
        )
        report = self.get_report(version.report_id)
        if action_value == ReportReviewAction.REQUEST_CHANGES.value:
            report.status = ReportStatus.REJECTED.value
        elif action_value in {
            ReportReviewAction.SUBMIT_FOR_REVIEW.value,
            ReportReviewAction.REOPEN_REVIEW.value,
        }:
            report.status = ReportStatus.REVIEW_REQUIRED.value
        report.updated_at = created_at
        self._repository.append_report_review_event(event, report)
        return event

    def _append_approval(
        self,
        *,
        version: ReportVersion,
        decision: ReportApprovalDecision,
        actor_id: str,
        reason: str,
        custody_snapshot_id: str | None,
        expected_approval_revision: int | None,
    ) -> ReportApprovalRecord:
        actor_id = _bounded_non_empty(actor_id, "approver_id", MAX_ACTOR_ID_LENGTH)
        reason = _required_reason(reason)
        approvals = self._repository.list_report_approval_records(report_id=version.report_id)
        latest_revision = approvals[-1].approval_revision if approvals else 0
        if expected_approval_revision is not None and expected_approval_revision != latest_revision:
            raise ReportError(
                "REPORT_APPROVAL_TRANSITION_INVALID",
                "Report approval revision changed.",
                target="expected_approval_revision",
                retryable=True,
            )
        previous_hash = approvals[-1].approval_hash if approvals else None
        decided_at = self._clock.now()
        approval_id = self._id_generator.new_id()
        payload = {
            "approval_id": approval_id,
            "report_id": version.report_id,
            "report_version_id": version.report_version_id,
            "case_id": version.case_id,
            "approver_id": actor_id,
            "decision": decision.value,
            "reason": reason,
            "content_fingerprint": version.content_fingerprint,
            "custody_snapshot_id": custody_snapshot_id,
            "approval_revision": latest_revision + 1,
            "previous_approval_hash": previous_hash,
            "decided_at": to_json_timestamp(decided_at),
        }
        approval = ReportApprovalRecord(
            approval_id=approval_id,
            report_id=version.report_id,
            report_version_id=version.report_version_id,
            case_id=version.case_id,
            approver_id=actor_id,
            decision=decision.value,
            reason=reason,
            content_fingerprint=version.content_fingerprint,
            custody_snapshot_id=custody_snapshot_id,
            approval_revision=latest_revision + 1,
            previous_approval_hash=previous_hash,
            approval_hash=canonical_sha256(payload),
            decided_at=decided_at,
        )
        report = self.get_report(version.report_id)
        if decision is ReportApprovalDecision.APPROVED:
            report.status = ReportStatus.APPROVED.value
        elif decision is ReportApprovalDecision.REJECTED:
            report.status = ReportStatus.REJECTED.value
        elif decision is ReportApprovalDecision.REVOKED:
            report.status = ReportStatus.REVIEW_REQUIRED.value
        report.updated_at = decided_at
        self._repository.append_report_approval_record(approval, report)
        return approval

    def _with_states(self, version: ReportVersion) -> ReportVersion:
        return replace(
            version,
            review_state=self._review_state(version.report_version_id),
            approval_state=self._approval_state(version.report_version_id),
        )

    def _review_state(self, report_version_id: str) -> dict[str, Any]:
        events = self._repository.list_report_review_events(report_version_id=report_version_id)
        status = _review_status_from_events(events)
        return {
            "status": status,
            "review_revision": events[-1].review_revision if events else 0,
            "latest_event_hash": events[-1].event_hash if events else None,
            "section_status": _section_review_state(events),
        }

    def _approval_state(self, report_version_id: str) -> dict[str, Any]:
        approvals = self._repository.list_report_approval_records(
            report_version_id=report_version_id
        )
        latest = approvals[-1] if approvals else None
        return {
            "decision": None if latest is None else latest.decision,
            "approval_revision": 0 if latest is None else latest.approval_revision,
            "approval_id": None if latest is None else latest.approval_id,
            "approval_hash": None if latest is None else latest.approval_hash,
        }

    def _latest_approval(self, report_version_id: str) -> ReportApprovalRecord | None:
        approvals = self._repository.list_report_approval_records(
            report_version_id=report_version_id
        )
        return None if not approvals else approvals[-1]

    def _require_approved_version(self, version: ReportVersion) -> ReportApprovalRecord:
        approval = self._latest_approval(version.report_version_id)
        if approval is None or approval.decision != ReportApprovalDecision.APPROVED.value:
            raise ReportError(
                "REPORT_APPROVAL_TRANSITION_INVALID",
                "Export requires an approved report version.",
                target="report_version_id",
            )
        if approval.content_fingerprint != version.content_fingerprint:
            raise ReportError(
                "REPORT_APPROVAL_FINGERPRINT_MISMATCH",
                "Approval fingerprint does not match the report version.",
                target="report_version_id",
            )
        return approval

    def _section_from_input(
        self,
        *,
        case_id: str,
        snapshots: list[Any],
        raw: dict[str, Any],
        index: int,
    ) -> ReportSection:
        _validate_contract_payload(raw, target="section")
        section_type = _enum_value(
            ReportSectionType,
            raw.get("section_type", ReportSectionType.OTHER.value),
            "section_type",
        )
        content_kind = _enum_value(
            ReportContentKind,
            raw.get("content_kind", ReportContentKind.PLAIN_TEXT.value),
            "content_kind",
        )
        title = _safe_text(
            _bounded_non_empty(
                raw.get("title"),
                "section.title",
                MAX_SECTION_TITLE_LENGTH,
            ),
            "section.title",
        )
        content = _safe_text(str(raw.get("content", "")), "section.content")
        if len(content) > MAX_SECTION_CONTENT_LENGTH:
            raise ReportError(
                "REPORT_CONTENT_LIMIT_EXCEEDED",
                "Report section content exceeds the maximum length.",
                target="section.content",
            )
        structured_data = dict(raw.get("structured_data") or {})
        _validate_contract_payload(structured_data, target="section.structured_data")
        order = _limit(raw.get("order", index), minimum=1, maximum=10_000, target="order")
        source_kind = _enum_value(
            ReportSourceKind,
            raw.get("source_kind", ReportSourceKind.ANALYST_DRAFT.value),
            "source_kind",
        )
        context_snapshot_ids = _string_list(
            raw.get("context_snapshot_ids", [item.context_snapshot_id for item in snapshots]),
            "context_snapshot_ids",
            max_items=MAX_CONTEXT_SNAPSHOT_COUNT,
        )
        section_snapshots = [
            snapshot
            for snapshot in snapshots
            if snapshot.context_snapshot_id in context_snapshot_ids
        ]
        citations = self._validate_citations(
            case_id=case_id,
            snapshots=section_snapshots or snapshots,
            citations=[dict(item) for item in _list_or_empty(raw.get("citations"))],
            require_direct=bool(raw.get("require_citation", False)),
            target="section.citations",
        )
        source_resource_ids = _string_list(
            raw.get("source_resource_ids", []), "source_resource_ids"
        )
        self._validate_source_resource_ids(section_snapshots or snapshots, source_resource_ids)
        is_partial = bool(raw.get("is_partial", False)) or any(
            _snapshot_is_partial(snapshot) for snapshot in section_snapshots
        )
        raw_stale_reasons = _string_list(
            raw.get("stale_reasons", []),
            "section.stale_reasons",
            max_items=MAX_STALE_REASON_COUNT,
        )
        stale_reasons = _dedupe(
            [
                *raw_stale_reasons,
                *[
                    str(reason)
                    for snapshot in section_snapshots
                    for reason in _snapshot_stale_reasons(snapshot)
                ],
            ]
        )
        if len(stale_reasons) > MAX_STALE_REASON_COUNT:
            raise ReportError(
                "REPORT_CONTENT_LIMIT_EXCEEDED",
                "Section stale reasons exceed the maximum item count.",
                target="section.stale_reasons",
            )
        _validate_string_lengths(
            stale_reasons,
            "section.stale_reasons",
            MAX_STALE_REASON_LENGTH,
        )
        coverage = dict(raw.get("coverage") or {})
        coverage.setdefault("status", "UNKNOWN" if not section_snapshots else "SNAPSHOT_DERIVED")
        raw_warnings = _required_optional_list(raw.get("warnings", []), "section.warnings")
        warnings = _bounded_warnings(
            [
                *raw_warnings,
                *(
                    [{"code": "REPORT_SECTION_PARTIAL"}]
                    if is_partial
                    and not _has_warning(raw_warnings, "REPORT_SECTION_PARTIAL")
                    else []
                ),
                *(
                    [{"code": "REPORT_SECTION_STALE"}]
                    if stale_reasons
                    and not _has_warning(raw_warnings, "REPORT_SECTION_STALE")
                    else []
                ),
            ],
            "section.warnings",
        )
        fingerprint_payload = {
            "section_type": section_type,
            "title": title,
            "order": order,
            "content_kind": content_kind,
            "content": content,
            "structured_data": structured_data,
            "source_kind": source_kind,
            "source_resource_ids": sorted(source_resource_ids),
            "context_snapshot_ids": sorted(context_snapshot_ids),
            "citations": citations,
            "is_partial": is_partial,
            "stale_reasons": stale_reasons,
            "coverage": coverage,
            "warnings": warnings,
        }
        section_fingerprint = canonical_sha256(fingerprint_payload)
        section_id = _bounded_non_empty(
            raw.get("section_id") or f"section-{section_fingerprint[:32]}",
            "section.section_id",
            MAX_ID_LENGTH,
        )
        return ReportSection(
            section_id=section_id,
            section_type=section_type,
            title=title,
            order=order,
            content_kind=content_kind,
            content=content,
            structured_data=structured_data,
            source_kind=source_kind,
            source_resource_ids=sorted(source_resource_ids),
            context_snapshot_ids=sorted(context_snapshot_ids),
            citations=citations,
            is_partial=is_partial,
            stale_reasons=stale_reasons,
            coverage=coverage,
            warnings=warnings,
            section_fingerprint=section_fingerprint,
        )

    def _validate_citations(
        self,
        *,
        case_id: str,
        snapshots: list[Any],
        citations: list[dict[str, Any]],
        require_direct: bool,
        target: str,
    ) -> list[dict[str, Any]]:
        if not citations:
            if require_direct:
                raise ReportError(
                    "REPORT_CITATION_REQUIRED",
                    "Report content requires at least one citation.",
                    target=target,
                )
            return []
        if len(citations) > MAX_CITATION_COUNT:
            raise ReportError(
                "REPORT_CONTENT_LIMIT_EXCEEDED",
                "Citation collection exceeds the maximum item count.",
                target=target,
            )
        normalized: list[dict[str, Any]] = []
        for citation in citations:
            _validate_citation_fields(citation, target)
            if citation.get("case_id") != case_id:
                raise ReportError(
                    "REPORT_REFERENCE_CASE_MISMATCH",
                    "Citation case_id does not match report case.",
                    target=target,
                )
            evidence_id = citation.get("evidence_id")
            if evidence_id is not None:
                self._validate_evidence_ids(case_id, [str(evidence_id)])
            source_kind = str(citation.get("source_kind", ""))
            source_id = str(citation.get("source_id", ""))
            if source_kind and source_id:
                try:
                    info = self._contexts.resolve_resource(
                        resource_type=_resource_type_for_citation(source_kind),
                        resource_id=source_id,
                    )
                except ApexError as exc:
                    raise ReportError(
                        "REPORT_CITATION_NOT_FOUND",
                        "Citation source could not be resolved.",
                        target=target,
                    ) from exc
                if info["case_id"] != case_id:
                    raise ReportError(
                        "REPORT_REFERENCE_CASE_MISMATCH",
                        "Citation source belongs to another case.",
                        target=target,
                    )
                if (
                    evidence_id is not None
                    and info.get("evidence_id") is not None
                    and str(info["evidence_id"]) != str(evidence_id)
                ):
                    raise ReportError(
                        "REPORT_REFERENCE_CASE_MISMATCH",
                        "Citation evidence_id does not match cited resource.",
                        target=target,
                    )
                if snapshots and not any(
                    _snapshot_contains(snapshot, str(info["resource_type"]), source_id)
                    for snapshot in snapshots
                ):
                    raise ReportError(
                        "REPORT_CITATION_SCOPE_MISMATCH",
                        "Citation source is outside the report context snapshots.",
                        target=target,
                    )
            normalized.append(dict(citation))
        return _stable_citations(normalized)

    def _require_case(self, case_id: str) -> Any:
        case = self._repository.get_case(case_id)
        if case is None:
            raise NotFoundError("CASE_NOT_FOUND", "Case not found.", target="case_id")
        return case

    def _require_snapshots(self, case_id: str, snapshot_ids: list[str]) -> list[Any]:
        snapshots: list[Any] = []
        for snapshot_id in _dedupe(snapshot_ids):
            try:
                snapshot = self._contexts.get_snapshot(snapshot_id)
            except ApexError as exc:
                raise ReportError(
                    "REPORT_REFERENCE_NOT_FOUND",
                    "Context snapshot not found.",
                    target="context_snapshot_id",
                ) from exc
            if snapshot.case_id != case_id:
                raise ReportError(
                    "REPORT_REFERENCE_CASE_MISMATCH",
                    "Context snapshot belongs to another case.",
                    target="context_snapshot_id",
                )
            snapshots.append(snapshot)
        return snapshots

    def _validate_evidence_ids(self, case_id: str, evidence_ids: list[str]) -> list[str]:
        validated: list[str] = []
        for evidence_id in _dedupe(evidence_ids):
            evidence = self._repository.get_evidence(evidence_id)
            if evidence is None:
                raise ReportError(
                    "REPORT_REFERENCE_NOT_FOUND",
                    "Evidence not found.",
                    target="evidence_ids",
                )
            if evidence.case_id != case_id:
                raise ReportError(
                    "REPORT_REFERENCE_CASE_MISMATCH",
                    "Evidence belongs to another case.",
                    target="evidence_ids",
                )
            validated.append(evidence_id)
        return validated

    def _validate_search_execution_ids(
        self, case_id: str, execution_ids: list[str]
    ) -> list[str]:
        validated: list[str] = []
        for execution_id in _dedupe(execution_ids):
            execution = self._repository.get_search_execution(execution_id)
            if execution is None:
                raise ReportError(
                    "REPORT_REFERENCE_NOT_FOUND",
                    "Search execution not found.",
                    target="search_execution_ids",
                )
            if execution.case_id != case_id:
                raise ReportError(
                    "REPORT_REFERENCE_CASE_MISMATCH",
                    "Search execution belongs to another case.",
                    target="search_execution_ids",
                )
            validated.append(execution_id)
        return validated

    def _validate_ai_request_ids(self, case_id: str, request_ids: list[str]) -> list[str]:
        validated: list[str] = []
        for request_id in _dedupe(request_ids):
            request = self._ai.get_request(request_id)
            if request.case_id != case_id:
                raise ReportError(
                    "REPORT_REFERENCE_CASE_MISMATCH",
                    "AI assistance request belongs to another case.",
                    target="ai_assistance_request_ids",
                )
            validated.append(request_id)
        return validated

    def _validate_ai_result_ids(self, case_id: str, result_ids: list[str]) -> list[str]:
        validated: list[str] = []
        for result_id in _dedupe(result_ids):
            result = self._repository.get_ai_keyword_recommendation(result_id)
            if result is None:
                result = self._repository.get_ai_scope_summary(result_id)
            if result is None:
                raise ReportError(
                    "REPORT_REFERENCE_NOT_FOUND",
                    "AI result not found.",
                    target="ai_result_ids",
                )
            if result.case_id != case_id:
                raise ReportError(
                    "REPORT_REFERENCE_CASE_MISMATCH",
                    "AI result belongs to another case.",
                    target="ai_result_ids",
                )
            validated.append(result_id)
        return validated

    def _validate_source_resource_ids(self, snapshots: list[Any], resource_ids: list[str]) -> None:
        if not snapshots or not resource_ids:
            return
        allowed = {
            resource_id
            for snapshot in snapshots
            for values in snapshot.included_resource_ids.values()
            for resource_id in values
        }
        for resource_id in resource_ids:
            if resource_id not in allowed:
                raise ReportError(
                    "REPORT_CITATION_SCOPE_MISMATCH",
                    "Section source resource is outside report context snapshots.",
                    target="source_resource_ids",
                )

    def _evidence_manifest_item(self, evidence_id: str) -> dict[str, Any]:
        evidence = self._repository.get_evidence(evidence_id)
        if evidence is None:
            raise ReportError(
                "REPORT_REFERENCE_NOT_FOUND",
                "Evidence not found.",
                target="evidence_ids",
            )
        data = evidence.to_schema_dict()
        return {
            "evidence_id": evidence.evidence_id,
            "display_name": evidence.display_name,
            "format": data["format"],
            "size_bytes": evidence.size_bytes,
            "hashes": data.get("hashes", []),
            "fingerprint": data.get("fingerprint"),
        }

    def _validate_output_reference(self, output_reference: str, root_id: str) -> None:
        prefix = f"derived://{root_id}/"
        if not output_reference.startswith(prefix):
            raise ReportError(
                "REPORT_OUTPUT_OUTSIDE_DERIVED_ROOT",
                "Renderer output reference is outside the configured derived root.",
                target="output_reference",
            )
        relative = output_reference[len(prefix) :]
        pure = PurePosixPath(relative)
        if pure.is_absolute() or any(part in {"", ".", ".."} for part in pure.parts):
            raise ReportError(
                "REPORT_OUTPUT_OUTSIDE_DERIVED_ROOT",
                "Renderer output reference escapes the derived root.",
                target="output_reference",
            )
        for part in pure.parts:
            _validate_output_path_segment(part, target="output_reference")

    def _append_export_audit(
        self,
        manifest: ReportExportManifest,
        action: str,
        actor_id: str | None,
        status: str,
        details: dict[str, Any],
    ) -> None:
        events = self._repository.list_report_export_audit_events(
            export_manifest_id=manifest.export_manifest_id
        )
        previous_hash = events[-1].event_hash if events else None
        created_at = self._clock.now()
        event_id = self._id_generator.new_id()
        payload = {
            "audit_event_id": event_id,
            "export_manifest_id": manifest.export_manifest_id,
            "report_id": manifest.report_id,
            "report_version_id": manifest.report_version_id,
            "case_id": manifest.case_id,
            "action": action,
            "actor_id": actor_id,
            "status": status,
            "details": details,
            "previous_event_hash": previous_hash,
            "created_at": to_json_timestamp(created_at),
        }
        event = ReportExportAuditEvent(
            audit_event_id=event_id,
            export_manifest_id=manifest.export_manifest_id,
            report_id=manifest.report_id,
            report_version_id=manifest.report_version_id,
            case_id=manifest.case_id,
            action=action,
            actor_id=actor_id,
            status=status,
            details=details,
            previous_event_hash=previous_hash,
            event_hash=canonical_sha256(payload),
            created_at=created_at,
        )
        self._repository.append_report_export_audit_event(event)


def _enum_value(enum_type: Any, value: Any, target: str) -> str:
    if hasattr(value, "value"):
        value = value.value
    if not isinstance(value, str) or not value:
        raise ValidationError("Field must be a non-empty string.", target=target)
    try:
        return str(enum_type(value).value)
    except ValueError as error:
        raise ValidationError(
            "Field has an unsupported enum value.",
            target=target,
            details={"value": value},
        ) from error


def _required_non_empty(value: Any, target: str) -> str:
    if value is None or not str(value).strip():
        raise ValidationError("Field must be a non-empty string.", target=target)
    return str(value).strip()


def _bounded_non_empty(value: Any, target: str, maximum: int) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValidationError("Field must be a non-empty string.", target=target)
    normalized = value.strip()
    if len(value) > maximum:
        raise ReportError(
            "REPORT_CONTENT_LIMIT_EXCEEDED",
            "Text field exceeds the maximum length.",
            target=target,
        )
    return normalized


def _bounded_optional_text(value: Any, target: str, maximum: int) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValidationError("Field must be a string.", target=target)
    if len(value) > maximum:
        raise ReportError(
            "REPORT_CONTENT_LIMIT_EXCEEDED",
            "Text field exceeds the maximum length.",
            target=target,
        )
    return value


def _required_reason(value: Any) -> str:
    reason = _required_non_empty(value, "reason")
    if len(reason) > MAX_REASON_LENGTH:
        raise ValidationError("Reason exceeds maximum length.", target="reason")
    return reason


def _required_list(payload: Mapping[str, Any], field: str) -> list[Any]:
    value = payload.get(field)
    if not isinstance(value, list):
        raise ValidationError("Field must be a list.", target=field)
    return value


def _list_or_empty(value: Any) -> list[Any]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValidationError("Field must be a list.")
    return value


def _required_optional_list(value: Any, target: str) -> list[Any]:
    if not isinstance(value, list):
        raise ValidationError("Field must be a list.", target=target)
    return value


def _string_list(value: Any, target: str, *, max_items: int = 10_000) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or any(not isinstance(item, str) or not item for item in value):
        raise ValidationError("Field must be a list of non-empty strings.", target=target)
    if len(value) > max_items:
        raise ReportError(
            "REPORT_CONTENT_LIMIT_EXCEEDED",
            "List field exceeds the maximum item count.",
            target=target,
        )
    return _dedupe(value)


def _integer_list(value: Any, target: str, *, max_items: int) -> list[int]:
    if not isinstance(value, list) or any(
        not isinstance(item, int) or isinstance(item, bool) for item in value
    ):
        raise ValidationError("Field must be a list of integers.", target=target)
    if len(value) > max_items:
        raise ReportError(
            "REPORT_CONTENT_LIMIT_EXCEEDED",
            "List field exceeds the maximum item count.",
            target=target,
        )
    return list(value)


def _validate_string_lengths(values: list[str], target: str, maximum: int) -> None:
    if any(len(value) > maximum for value in values):
        raise ReportError(
            "REPORT_CONTENT_LIMIT_EXCEEDED",
            "List item exceeds the maximum length.",
            target=target,
        )


def _metadata_string(value: Any, target: str) -> str:
    if value is None:
        return "UNKNOWN"
    if not isinstance(value, str) or value == "":
        raise ValidationError("Provider metadata must be a non-empty string.", target=target)
    if len(value) > MAX_RENDERER_ID_LENGTH:
        raise ReportError(
            "REPORT_CONTENT_LIMIT_EXCEEDED",
            "Provider metadata exceeds the maximum length.",
            target=target,
        )
    if any(part in target.casefold() for part in _FORBIDDEN_KEY_PARTS):
        raise ValidationError("Provider metadata target is forbidden.", target=target)
    return value


def _safe_text(value: str, target: str) -> str:
    if "\x00" in value:
        raise ValidationError("Text cannot contain a null byte.", target=target)
    if _DANGEROUS_TEXT.search(value) is not None or _BASE64_DATA.search(value) is not None:
        raise ValidationError(
            "Text cannot contain executable HTML or embedded base64 data.",
            target=target,
        )
    return value


def _validate_contract_payload(value: Any, *, target: str) -> None:
    _reject_forbidden_json(value, target=target)
    if _depth(value) > MAX_JSON_DEPTH:
        raise ReportError(
            "REPORT_CONTENT_LIMIT_EXCEEDED",
            "Report payload exceeds the maximum JSON depth.",
            target=target,
        )
    if len(canonical_json_bytes(value)) > MAX_JSON_BYTES:
        raise ReportError(
            "REPORT_CONTENT_LIMIT_EXCEEDED",
            "Report payload exceeds the maximum serialized size.",
            target=target,
        )


def _reject_forbidden_json(value: Any, *, target: str) -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            normalized = str(key).casefold().replace("-", "_")
            if any(part in normalized for part in _FORBIDDEN_KEY_PARTS):
                raise ValidationError(
                    "Report contracts cannot store prompts, secrets, or raw provider bodies.",
                    target=target,
                )
            if any(part == normalized for part in _RAW_BLOB_KEYS):
                raise ValidationError("Report contracts cannot store raw blobs.", target=target)
            _reject_forbidden_json(item, target=target)
    elif isinstance(value, list):
        for item in value:
            _reject_forbidden_json(item, target=target)


def _depth(value: Any, level: int = 0) -> int:
    if isinstance(value, Mapping):
        if not value:
            return level + 1
        return max(_depth(item, level + 1) for item in value.values())
    if isinstance(value, list):
        if not value:
            return level + 1
        return max(_depth(item, level + 1) for item in value)
    return level + 1


def _limit(value: Any, *, minimum: int, maximum: int, target: str) -> int:
    if isinstance(value, bool):
        raise ValidationError("Field must be an integer.", target=target)
    try:
        parsed = int(value)
    except (TypeError, ValueError) as error:
        raise ValidationError("Field must be an integer.", target=target) from error
    if parsed < minimum or parsed > maximum:
        raise ValidationError(
            "Field is outside the allowed range.",
            target=target,
            details={"minimum": minimum, "maximum": maximum, "value": parsed},
        )
    return parsed


def _dedupe(values: list[str]) -> list[str]:
    return sorted(dict.fromkeys(str(item) for item in values if str(item)))


def _stable_warnings(warnings: list[Any]) -> list[dict[str, Any]]:
    normalized: dict[str, dict[str, Any]] = {}
    for item in warnings:
        if not isinstance(item, Mapping):
            continue
        normalized[canonical_sha256(dict(item))] = dict(item)
    return [normalized[key] for key in sorted(normalized)]


def _bounded_warnings(value: Any, target: str) -> list[dict[str, Any]]:
    warnings = _required_optional_list(value, target)
    if len(warnings) > MAX_WARNING_COUNT:
        raise ReportError(
            "REPORT_CONTENT_LIMIT_EXCEEDED",
            "Warning collection exceeds the maximum item count.",
            target=target,
        )
    for warning in warnings:
        if not isinstance(warning, Mapping):
            raise ValidationError("Warning must be a JSON object.", target=target)
        code = warning.get("code")
        if not isinstance(code, str) or re.fullmatch(r"[A-Z][A-Z0-9_]*", code) is None:
            raise ValidationError("Warning code is invalid.", target=target)
        message = warning.get("developer_message")
        if message is not None:
            _bounded_optional_text(
                message,
                f"{target}.developer_message",
                MAX_WARNING_MESSAGE_LENGTH,
            )
    return _stable_warnings(warnings)


def _validate_citation_fields(citation: Mapping[str, Any], target: str) -> None:
    for field in (
        "id",
        "case_id",
        "evidence_id",
        "source_id",
        "file_id",
        "artifact_id",
        "timeline_event_id",
        "search_result_id",
    ):
        if citation.get(field) is not None:
            _bounded_non_empty(citation[field], f"{target}.{field}", MAX_ID_LENGTH)
    _bounded_non_empty(citation.get("source_kind"), f"{target}.source_kind", 80)
    for field, maximum in (
        ("label", 100),
        ("source_path", 4096),
        ("source_reference", 4096),
        ("excerpt", 4000),
        ("encoding", 80),
    ):
        if citation.get(field) is not None:
            _bounded_optional_text(citation[field], f"{target}.{field}", maximum)


def _validate_renderer_capability(capability: ReportRendererCapability) -> None:
    _bounded_non_empty(
        capability.renderer_id,
        "renderer_id",
        MAX_RENDERER_ID_LENGTH,
    )
    _bounded_non_empty(
        capability.renderer_version,
        "renderer_version",
        MAX_RENDERER_VERSION_LENGTH,
    )
    _bounded_optional_text(
        capability.unavailable_reason,
        "unavailable_reason",
        256,
    )
    _bounded_warnings(capability.warnings, "warnings")


def _stable_citations(citations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    normalized: dict[str, dict[str, Any]] = {}
    for citation in citations:
        normalized[canonical_sha256(citation)] = dict(citation)
    return [normalized[key] for key in sorted(normalized)]


def _has_warning(warnings: Any, code: str) -> bool:
    return any(isinstance(item, Mapping) and item.get("code") == code for item in warnings or [])


def _encode_cursor(field: str, value: str) -> str:
    raw = json.dumps({field: value}, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return base64.urlsafe_b64encode(raw.encode("utf-8")).decode("ascii")


def _decode_cursor(value: str | None, *, field: str) -> str | None:
    if value is None:
        return None
    try:
        payload = json.loads(base64.urlsafe_b64decode(value.encode("ascii")).decode("utf-8"))
    except Exception as error:
        raise ValidationError("Cursor is not a valid report cursor.", target="cursor") from error
    if not isinstance(payload, Mapping) or payload.get(field) is None:
        raise ValidationError("Cursor is not valid for this report query.", target="cursor")
    return str(payload[field])


def _snapshot_is_partial(snapshot: Any) -> bool:
    if hasattr(snapshot, "is_partial"):
        return bool(snapshot.is_partial)
    return bool(dict(getattr(snapshot, "partial_state", {})).get("is_partial", False))


def _snapshot_stale_reasons(snapshot: Any) -> list[str]:
    if hasattr(snapshot, "stale_reasons"):
        return [str(item) for item in snapshot.stale_reasons]
    state = dict(getattr(snapshot, "stale_state", {}))
    reasons = state.get("stale_reasons", [])
    if isinstance(reasons, list):
        return [str(item) for item in reasons]
    return []


def _snapshot_coverage(snapshot: Any) -> dict[str, Any]:
    if hasattr(snapshot, "coverage_summary"):
        return dict(snapshot.coverage_summary)
    included = getattr(snapshot, "included_resource_ids", {})
    if isinstance(included, Mapping):
        return {
            "status": "SNAPSHOT_DERIVED",
            "resource_counts": {
                str(resource_type): len(values) if isinstance(values, list) else 0
                for resource_type, values in included.items()
            },
        }
    return {"status": "UNKNOWN"}


def _snapshot_source_revision_fingerprint(snapshot: Any) -> str:
    value = getattr(snapshot, "source_revision_fingerprint", None)
    if isinstance(value, str) and value:
        return value
    if hasattr(snapshot, "to_schema_dict"):
        data = snapshot.to_schema_dict()
        source_revisions = data.get("source_revisions", [])
        if source_revisions:
            return canonical_sha256(source_revisions)
    return canonical_sha256({"context_snapshot_id": snapshot.context_snapshot_id})


def _partial_state(snapshots: list[Any], sections: list[ReportSection]) -> dict[str, Any]:
    reasons = [
        *[
            f"snapshot:{snapshot.context_snapshot_id}"
            for snapshot in snapshots
            if _snapshot_is_partial(snapshot)
        ],
        *[
            f"section:{section.section_id}"
            for section in sections
            if section.is_partial
        ],
    ]
    return {"is_partial": bool(reasons), "partial_reasons": _dedupe(reasons)}


def _stale_state(snapshots: list[Any], sections: list[ReportSection]) -> dict[str, Any]:
    reasons = [
        *[str(reason) for snapshot in snapshots for reason in _snapshot_stale_reasons(snapshot)],
        *[str(reason) for section in sections for reason in section.stale_reasons],
    ]
    return {"is_stale": bool(reasons), "stale_reasons": _dedupe(reasons)}


def _coverage_summary(snapshots: list[Any], sections: list[ReportSection]) -> dict[str, Any]:
    return {
        "snapshot_count": len(snapshots),
        "section_count": len(sections),
        "coverage": {
            snapshot.context_snapshot_id: _snapshot_coverage(snapshot) for snapshot in snapshots
        },
        "section_coverage": {section.section_id: section.coverage for section in sections},
    }


def _source_revisions(snapshots: list[Any]) -> list[dict[str, Any]]:
    return [
        {
            "context_snapshot_id": snapshot.context_snapshot_id,
            "context_fingerprint": snapshot.context_fingerprint,
            "source_revision_fingerprint": _snapshot_source_revision_fingerprint(snapshot),
            "generated_at": to_json_timestamp(snapshot.created_at),
            "is_partial": _snapshot_is_partial(snapshot),
            "is_stale": bool(_snapshot_stale_reasons(snapshot)),
        }
        for snapshot in sorted(snapshots, key=lambda item: item.context_snapshot_id)
    ]


def _review_status_from_events(events: list[ReportReviewEvent]) -> str:
    if not events:
        return "DRAFT"
    action = events[-1].action
    if action == ReportReviewAction.MARK_REVIEW_COMPLETE.value:
        return "REVIEW_COMPLETE"
    if action == ReportReviewAction.REQUEST_CHANGES.value:
        return "CHANGES_REQUESTED"
    return "IN_REVIEW"


def _section_review_state(events: list[ReportReviewEvent]) -> dict[str, str]:
    state: dict[str, str] = {}
    for event in events:
        if event.section_id is None:
            continue
        if event.action == ReportReviewAction.ACCEPT_SECTION.value:
            state[event.section_id] = "ACCEPTED"
        elif event.action == ReportReviewAction.REJECT_SECTION.value:
            state[event.section_id] = "REJECTED"
        elif event.action == ReportReviewAction.REQUEST_CHANGES.value:
            state[event.section_id] = "CHANGES_REQUESTED"
    return state


def _missing_required_section_reviews(
    version: ReportVersion, events: list[ReportReviewEvent]
) -> list[str]:
    state = _section_review_state(events)
    required = [
        section.section_id
        for section in version.sections
        if section.coverage.get("review_required", True) is not False
    ]
    return [section_id for section_id in required if state.get(section_id) != "ACCEPTED"]


def _resource_type_for_citation(source_kind: str) -> str:
    aliases = {
        "FILE": "FILE_SYSTEM_NODE",
        "FILE_SYSTEM_NODE": "FILE_SYSTEM_NODE",
        "ARTIFACT": "ARTIFACT",
        "WINDOWS_ARTIFACT": "ARTIFACT",
        "BROWSER_ARTIFACT": "ARTIFACT",
        "MEDIA_ARTIFACT": "ARTIFACT",
        "TIMELINE_EVENT": "TIMELINE_EVENT",
        "SEARCH_RESULT": "SEARCH_RESULT",
        "MACHINE_CANDIDATE": "MACHINE_CANDIDATE",
    }
    return aliases.get(source_kind, source_kind)


def _snapshot_contains(snapshot: Any, resource_type: str, resource_id: str) -> bool:
    values = snapshot.included_resource_ids.get(resource_type, [])
    return resource_id in values


def _safe_filename(filename: str, format_value: str) -> str:
    filename = _required_non_empty(filename, "filename").strip()
    if _WINDOWS_DRIVE_PREFIX.match(filename) is not None:
        raise ReportError(
            "REPORT_OUTPUT_INVALID",
            "Export filename cannot use a Windows drive prefix.",
            target="filename",
        )
    pure = PurePosixPath(filename.replace("\\", "/"))
    if (
        pure.is_absolute()
        or len(pure.parts) != 1
        or any(part in {"", ".", ".."} for part in pure.parts)
    ):
        raise ReportError(
            "REPORT_OUTPUT_INVALID",
            "Export filename cannot be an absolute path or contain traversal.",
            target="filename",
        )
    cleaned = re.sub(r"\s+", "_", pure.name.strip())
    if not cleaned or len(cleaned) > MAX_FILENAME_LENGTH:
        raise ReportError("REPORT_OUTPUT_INVALID", "Export filename is invalid.", target="filename")
    extension = ".pdf" if format_value == ReportExportFormat.PDF.value else ".html"
    if not cleaned.casefold().endswith(extension):
        cleaned = f"{cleaned}{extension}"
    if len(cleaned) > MAX_FILENAME_LENGTH:
        raise ReportError(
            "REPORT_OUTPUT_INVALID",
            "Export filename is invalid.",
            target="filename",
        )
    _validate_output_path_segment(cleaned, target="filename")
    return cleaned


def _validate_output_path_segment(segment: str, *, target: str) -> None:
    if (
        not segment
        or segment in {".", ".."}
        or segment.rstrip(" .") != segment
        or _WINDOWS_DRIVE_PREFIX.match(segment) is not None
        or _WINDOWS_FORBIDDEN_NAME_CHARS.search(segment) is not None
        or segment.split(".", 1)[0].casefold() in _WINDOWS_RESERVED_BASENAMES
    ):
        raise ReportError(
            "REPORT_OUTPUT_INVALID",
            "Report output path segment is not portable or safe.",
            target=target,
        )


def _mime_type(format_value: str) -> str:
    return "application/pdf" if format_value == ReportExportFormat.PDF.value else "text/html"
