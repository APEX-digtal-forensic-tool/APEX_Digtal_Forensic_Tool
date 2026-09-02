"""M5 report draft, human review, approval, custody, and export bindings."""

from __future__ import annotations

from typing import Any

from apex_mcp.m1_tools import _ID, _object_schema
from apex_mcp.m4_tools import M4_TOOL_NAMES, m4_bindings
from apex_mcp.tool_registry import ToolBinding

_SCHEMA_ROOT = "https://schemas.apex-forensics.dev/v1/"
_SHA256 = {"type": "string", "pattern": "^[0-9a-fA-F]{64}$"}
_REASON = {"type": "string", "minLength": 1, "maxLength": 4000}
_COMMENT = {"type": "string", "minLength": 1, "maxLength": 4000}
_REPORT_TYPES = [
    "INVESTIGATION",
    "TRIAGE",
    "INCIDENT_RESPONSE",
    "EVIDENCE_SUMMARY",
    "CHAIN_OF_CUSTODY",
    "TECHNICAL_APPENDIX",
    "OTHER",
]
_SECTION_TYPES = [
    "CASE_OVERVIEW",
    "ANALYSIS_PURPOSE",
    "EVIDENCE",
    "HASH_INTEGRITY",
    "CHAIN_OF_CUSTODY",
    "ANALYSIS_ENVIRONMENT",
    "ANALYSIS_SCOPE",
    "PARTIAL_STALE_WARNING",
    "TIMEZONE",
    "KEY_FINDINGS",
    "FILE_SYSTEM",
    "WINDOWS_ARTIFACT",
    "BROWSER",
    "MEDIA",
    "TIMELINE",
    "KEYWORD_SEARCH",
    "AI_ASSISTANCE",
    "MACHINE_CANDIDATE",
    "LIMITATIONS",
    "CONCLUSION",
    "RECOMMENDATION",
    "TECHNICAL_APPENDIX",
    "OTHER",
]
_CONTENT_KINDS = [
    "PLAIN_TEXT",
    "MARKDOWN_SUBSET",
    "STRUCTURED_DATA",
    "REFERENCE_LIST",
    "TABLE_DATA",
    "OTHER",
]


def _id_array(*, max_items: int = 10_000, min_items: int = 0) -> dict[str, Any]:
    return {
        "type": "array",
        "minItems": min_items,
        "maxItems": max_items,
        "uniqueItems": True,
        "items": _ID,
    }


def _string_array(*, max_items: int = 100, min_items: int = 0) -> dict[str, Any]:
    return {
        "type": "array",
        "minItems": min_items,
        "maxItems": max_items,
        "items": {"type": "string", "minLength": 1, "maxLength": 4000},
    }


_CITATION = {"$ref": f"{_SCHEMA_ROOT}report-section.schema.json#/$defs/citationRef"}
_CITATIONS = {"type": "array", "maxItems": 1000, "items": _CITATION}
_WARNING = {
    "type": "object",
    "additionalProperties": True,
    "required": ["code"],
    "properties": {
        "code": {"type": "string", "pattern": "^[A-Z][A-Z0-9_]*$"},
        "developer_message": {
            "anyOf": [
                {"type": "string", "maxLength": 2000},
                {"type": "null"},
            ]
        },
        "details": {"type": "object"},
    },
}
_SECTION_INPUT = {
    "type": "object",
    "additionalProperties": False,
    "required": ["title", "content"],
    "properties": {
        "section_id": _ID,
        "section_type": {"enum": _SECTION_TYPES},
        "title": {"type": "string", "minLength": 1, "maxLength": 500},
        "order": {"type": "integer", "minimum": 1, "maximum": 10_000},
        "content_kind": {"enum": _CONTENT_KINDS},
        "content": {"type": "string", "maxLength": 20_000},
        "structured_data": {"type": "object"},
        "source_resource_ids": _id_array(),
        "context_snapshot_ids": _id_array(max_items=1000),
        "citations": _CITATIONS,
        "require_citation": {"type": "boolean", "default": False},
        "is_partial": {"type": "boolean", "default": False},
        "stale_reasons": {
            "type": "array",
            "maxItems": 1000,
            "items": {"type": "string", "minLength": 1, "maxLength": 500},
        },
        "coverage": {"type": "object"},
        "warnings": {"type": "array", "maxItems": 1000, "items": _WARNING},
    },
}
_SECTIONS = {"type": "array", "minItems": 1, "maxItems": 200, "items": _SECTION_INPUT}
_REVISION = {"type": "integer", "minimum": 0}

REPORT_CAPABILITIES_INPUT = _object_schema({}, [], schema_id="report-capabilities-input")
REPORT_CREATE_INPUT = _object_schema(
    {
        "case_id": _ID,
        "title": {"type": "string", "minLength": 1, "maxLength": 500},
        "description": {"type": "string", "minLength": 1, "maxLength": 4000},
        "report_type": {"enum": _REPORT_TYPES, "default": "INVESTIGATION"},
        "locale": {"type": "string", "minLength": 1, "maxLength": 35},
        "timezone": {"type": "string", "minLength": 1, "maxLength": 128},
    },
    ["case_id", "title"],
    schema_id="report-create-input",
)
REPORT_GET_INPUT = _object_schema(
    {"case_id": _ID, "report_id": _ID},
    ["case_id", "report_id"],
    schema_id="report-get-input",
)
REPORT_LIST_INPUT = _object_schema(
    {
        "case_id": _ID,
        "cursor": {"type": "string", "minLength": 1, "maxLength": 4096},
        "limit": {"type": "integer", "minimum": 1, "maximum": 1000, "default": 100},
    },
    ["case_id"],
    schema_id="report-list-input",
)
REPORT_VERSION_GET_INPUT = _object_schema(
    {"case_id": _ID, "report_version_id": _ID},
    ["case_id", "report_version_id"],
    schema_id="report-version-get-input",
)
REPORT_VERSION_LIST_INPUT = _object_schema(
    {"case_id": _ID, "report_id": _ID},
    ["case_id", "report_id"],
    schema_id="report-version-list-input",
)
REPORT_VERSION_COMPARE_INPUT = _object_schema(
    {
        "case_id": _ID,
        "left_report_version_id": _ID,
        "right_report_version_id": _ID,
    },
    ["case_id", "left_report_version_id", "right_report_version_id"],
    schema_id="report-version-compare-input",
)
REPORT_REVIEW_HISTORY_INPUT = _object_schema(
    {"case_id": _ID, "report_version_id": _ID},
    ["case_id", "report_version_id"],
    schema_id="report-review-history-input",
)
REPORT_APPROVAL_GET_INPUT = _object_schema(
    {"case_id": _ID, "report_version_id": _ID},
    ["case_id", "report_version_id"],
    schema_id="report-approval-get-input",
)
REPORT_CUSTODY_GET_INPUT = _object_schema(
    {"case_id": _ID, "custody_snapshot_id": _ID},
    ["case_id", "custody_snapshot_id"],
    schema_id="report-custody-get-input",
)
REPORT_RENDER_PACKAGE_GET_INPUT = _object_schema(
    {"case_id": _ID, "package_id": _ID},
    ["case_id", "package_id"],
    schema_id="report-render-package-get-input",
)
REPORT_EXPORT_MANIFEST_GET_INPUT = _object_schema(
    {"case_id": _ID, "export_manifest_id": _ID},
    ["case_id", "export_manifest_id"],
    schema_id="report-export-manifest-get-input",
)
REPORT_EXPORT_STATUS_INPUT = _object_schema(
    {"case_id": _ID, "export_manifest_id": _ID},
    ["case_id", "export_manifest_id"],
    schema_id="report-export-status-input",
)

_VERSION_FIELDS: dict[str, Any] = {
    "case_id": _ID,
    "report_id": _ID,
    "title": {"type": "string", "minLength": 1, "maxLength": 500},
    "executive_summary": {"type": "string", "minLength": 1, "maxLength": 40_000},
    "sections": _SECTIONS,
    "source_reference_id": _ID,
    "context_snapshot_ids": _id_array(max_items=1000),
    "evidence_ids": _id_array(),
    "search_execution_ids": _id_array(),
    "timeline_revisions": {
        "type": "array",
        "maxItems": 10_000,
        "uniqueItems": True,
        "items": {"type": "integer", "minimum": 1},
    },
    "ai_assistance_request_ids": _id_array(),
    "ai_result_ids": _id_array(),
    "citations": _CITATIONS,
    "limitations": _string_array(min_items=1),
    "analyzer_versions": {"type": "object"},
}
REPORT_VERSION_CREATE_INPUT = _object_schema(
    _VERSION_FIELDS,
    [
        "case_id",
        "report_id",
        "title",
        "executive_summary",
        "sections",
        "limitations",
    ],
    schema_id="report-version-create-input",
)
REPORT_AI_DRAFT_INGEST_INPUT = _object_schema(
    {
        "case_id": _ID,
        "report_id": _ID,
        "assistance_request_id": _ID,
        "context_snapshot_ids": _id_array(max_items=1000, min_items=1),
        "ai_result_ids": _id_array(),
        "provider_id": {"type": "string", "minLength": 1, "maxLength": 256},
        "provider_version": {"type": "string", "minLength": 1, "maxLength": 256},
        "model_id": {"type": "string", "minLength": 1, "maxLength": 256},
        "external_request_id": {
            "anyOf": [
                {"type": "string", "maxLength": 256},
                {"type": "null"},
            ]
        },
        "title": {"type": "string", "minLength": 1, "maxLength": 500},
        "executive_summary": {"type": "string", "minLength": 1, "maxLength": 40_000},
        "sections": _SECTIONS,
        "citations": _CITATIONS,
        "generated_at": {
            "oneOf": [
                {"$ref": f"{_SCHEMA_ROOT}common.schema.json#/$defs/timestamp"},
                {"type": "null"},
            ]
        },
        "response_hash": _SHA256,
        "correlation_id": {
            "anyOf": [
                {"type": "string", "maxLength": 256},
                {"type": "null"},
            ]
        },
        "limitations": _string_array(min_items=1),
    },
    [
        "case_id",
        "assistance_request_id",
        "context_snapshot_ids",
        "ai_result_ids",
        "provider_id",
        "provider_version",
        "model_id",
        "title",
        "executive_summary",
        "sections",
        "citations",
        "response_hash",
        "limitations",
    ],
    schema_id="report-ai-draft-ingest-input",
)


def _review_input(
    schema_id: str,
    *,
    section_allowed: bool = False,
    section_required: bool = False,
    comment_allowed: bool = False,
    comment_required: bool = False,
    requested_changes_allowed: bool = False,
    requested_changes_required: bool = False,
) -> dict[str, Any]:
    fields: dict[str, Any] = {
        "case_id": _ID,
        "report_version_id": _ID,
        "reason": _REASON,
        "expected_review_revision": _REVISION,
    }
    required = ["case_id", "report_version_id", "reason", "expected_review_revision"]
    if section_allowed or section_required:
        fields["section_id"] = _ID
    if section_required:
        required.append("section_id")
    if comment_allowed or comment_required:
        fields["comment"] = _COMMENT
    if comment_required:
        required.append("comment")
    if requested_changes_allowed or requested_changes_required:
        fields["requested_changes"] = _string_array(min_items=1)
    if requested_changes_required:
        required.append("requested_changes")
    return _object_schema(fields, required, schema_id=schema_id)


REPORT_REVIEW_SUBMIT_INPUT = _review_input("report-review-submit-input")
REPORT_REVIEW_COMMENT_INPUT = _review_input(
    "report-review-comment-input",
    section_allowed=True,
    comment_required=True,
)
REPORT_REVIEW_REQUEST_CHANGES_INPUT = _review_input(
    "report-review-request-changes-input",
    section_allowed=True,
    requested_changes_required=True,
)
REPORT_REVIEW_ACCEPT_SECTION_INPUT = _review_input(
    "report-review-accept-section-input",
    section_required=True,
    comment_allowed=True,
)
REPORT_REVIEW_REJECT_SECTION_INPUT = _review_input(
    "report-review-reject-section-input",
    section_required=True,
    comment_allowed=True,
    requested_changes_allowed=True,
)
REPORT_REVIEW_COMPLETE_INPUT = _review_input("report-review-complete-input")
REPORT_REVIEW_REOPEN_INPUT = _review_input("report-review-reopen-input")
REPORT_APPROVE_INPUT = _object_schema(
    {
        "case_id": _ID,
        "report_version_id": _ID,
        "reason": _REASON,
        "custody_snapshot_id": _ID,
        "expected_review_revision": {"type": "integer", "minimum": 1},
        "expected_approval_revision": _REVISION,
    },
    [
        "case_id",
        "report_version_id",
        "reason",
        "expected_review_revision",
        "expected_approval_revision",
    ],
    schema_id="report-approve-input",
)
REPORT_REJECT_INPUT = _object_schema(
    {
        "case_id": _ID,
        "report_version_id": _ID,
        "reason": _REASON,
        "expected_approval_revision": _REVISION,
    },
    ["case_id", "report_version_id", "reason", "expected_approval_revision"],
    schema_id="report-reject-input",
)
REPORT_APPROVAL_REVOKE_INPUT = _object_schema(
    {
        "case_id": _ID,
        "report_version_id": _ID,
        "reason": _REASON,
        "expected_approval_revision": {"type": "integer", "minimum": 1},
    },
    ["case_id", "report_version_id", "reason", "expected_approval_revision"],
    schema_id="report-approval-revoke-input",
)
REPORT_CUSTODY_CREATE_INPUT = _object_schema(
    {
        "case_id": _ID,
        "report_version_id": _ID,
        "evidence_ids": _id_array(),
    },
    ["case_id", "report_version_id"],
    schema_id="report-custody-create-input",
)
REPORT_RENDER_PACKAGE_CREATE_INPUT = _object_schema(
    {
        "case_id": _ID,
        "report_version_id": _ID,
        "custody_snapshot_id": _ID,
    },
    ["case_id", "report_version_id"],
    schema_id="report-render-package-create-input",
)
REPORT_EXPORT_PREPARE_INPUT = _object_schema(
    {
        "case_id": _ID,
        "report_version_id": _ID,
        "format": {"enum": ["PDF", "HTML"]},
        "filename": {
            "type": "string",
            "minLength": 1,
            "maxLength": 180,
            "pattern": "^[^/\\\\]+$",
        },
        "redaction_policy": {"type": "string", "minLength": 1, "maxLength": 80},
        "include_citations": {"type": "boolean", "default": True},
        "include_custody": {"type": "boolean", "default": True},
        "include_technical_appendix": {"type": "boolean", "default": True},
        "stale_confirmed": {"type": "boolean", "default": False},
        "expected_content_fingerprint": _SHA256,
        "expected_approval_id": _ID,
        "expected_custody_snapshot_id": _ID,
    },
    [
        "case_id",
        "report_version_id",
        "format",
        "filename",
        "expected_content_fingerprint",
        "expected_approval_id",
        "expected_custody_snapshot_id",
    ],
    schema_id="report-export-prepare-input",
)
REPORT_ARCHIVE_INPUT = _object_schema(
    {"case_id": _ID, "report_id": _ID, "reason": _REASON},
    ["case_id", "report_id", "reason"],
    schema_id="report-archive-input",
)

_PAGE = {
    "type": "object",
    "additionalProperties": False,
    "required": ["next_cursor", "has_more", "returned"],
    "properties": {
        "next_cursor": {"type": ["string", "null"], "minLength": 1},
        "has_more": {"type": "boolean"},
        "returned": {"type": "integer", "minimum": 0, "maximum": 1000},
    },
}
REPORT_LIST_OUTPUT: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "urn:apex-mcp:m5:report-list-output",
    "type": "object",
    "additionalProperties": False,
    "required": ["items", "page"],
    "properties": {
        "items": {
            "type": "array",
            "maxItems": 1000,
            "items": {"$ref": f"{_SCHEMA_ROOT}report-record.schema.json"},
        },
        "page": _PAGE,
    },
}
REPORT_VERSION_LIST_OUTPUT: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "urn:apex-mcp:m5:report-version-list-output",
    "type": "array",
    "maxItems": 1000,
    "items": {"$ref": f"{_SCHEMA_ROOT}report-version.schema.json"},
}
REPORT_VERSION_COMPARE_OUTPUT: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "urn:apex-mcp:m5:report-version-compare-output",
    "type": "object",
    "additionalProperties": False,
    "required": [
        "report_id",
        "left_report_version_id",
        "right_report_version_id",
        "same_content",
        "left_content_fingerprint",
        "right_content_fingerprint",
        "section_fingerprints_added",
        "section_fingerprints_removed",
    ],
    "properties": {
        "report_id": _ID,
        "left_report_version_id": _ID,
        "right_report_version_id": _ID,
        "same_content": {"type": "boolean"},
        "left_content_fingerprint": _SHA256,
        "right_content_fingerprint": _SHA256,
        "section_fingerprints_added": {
            "type": "array",
            "maxItems": 200,
            "items": _SHA256,
        },
        "section_fingerprints_removed": {
            "type": "array",
            "maxItems": 200,
            "items": _SHA256,
        },
    },
}
REPORT_REVIEW_HISTORY_OUTPUT: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "urn:apex-mcp:m5:report-review-history-output",
    "type": "array",
    "maxItems": 1000,
    "items": {"$ref": f"{_SCHEMA_ROOT}report-review-event.schema.json"},
}
REPORT_APPROVAL_GET_OUTPUT: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "urn:apex-mcp:m5:report-approval-get-output",
    "oneOf": [
        {"$ref": f"{_SCHEMA_ROOT}report-approval-record.schema.json"},
        {"type": "null"},
    ],
}
REPORT_EXPORT_STATUS_OUTPUT: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "urn:apex-mcp:m5:report-export-status-output",
    "type": "object",
    "additionalProperties": False,
    "required": ["manifest", "artifacts"],
    "properties": {
        "manifest": {"$ref": f"{_SCHEMA_ROOT}report-export-manifest.schema.json"},
        "artifacts": {
            "type": "array",
            "maxItems": 100,
            "items": {"$ref": f"{_SCHEMA_ROOT}rendered-report-artifact.schema.json"},
        },
    },
}
REPORT_CAPABILITIES_OUTPUT: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "urn:apex-mcp:m5:report-capabilities-output",
    "type": "object",
    "additionalProperties": False,
    "required": [
        "schema_version",
        "engine_capabilities",
        "unavailable_capabilities",
        "renderer",
    ],
    "properties": {
        "schema_version": {"const": "1.0.0"},
        "engine_capabilities": _id_array(max_items=100),
        "unavailable_capabilities": _id_array(max_items=100),
        "renderer": {"$ref": f"{_SCHEMA_ROOT}report-renderer-capability.schema.json"},
    },
}

M5_REPORT_TOOL_NAMES = frozenset(
    {
        "report.get",
        "report.list",
        "report.version.get",
        "report.version.list",
        "report.version.compare",
        "report.review.history",
        "report.approval.get",
        "report.custody-snapshot.get",
        "report.render-package.get",
        "report.export-manifest.get",
        "report.export-status",
        "report.capabilities",
        "report.create",
        "report.version.create",
        "report.ai-draft.ingest",
        "report.review.submit",
        "report.review.comment",
        "report.review.request-changes",
        "report.review.accept-section",
        "report.review.reject-section",
        "report.review.complete",
        "report.review.reopen",
        "report.approve",
        "report.reject",
        "report.approval.revoke",
        "report.custody-snapshot.create",
        "report.render-package.create",
        "report.export.prepare",
        "report.archive",
    }
)
M5_TOOL_NAMES = M4_TOOL_NAMES | M5_REPORT_TOOL_NAMES


def m5_bindings() -> tuple[ToolBinding, ...]:
    return (
        *m4_bindings(),
        ToolBinding(
            "report.get",
            "report.get",
            REPORT_GET_INPUT,
            output_schema_ref="report-record.schema.json",
            description="Return one case-bound report record.",
        ),
        ToolBinding(
            "report.list",
            "report.list",
            REPORT_LIST_INPUT,
            output_data_schema=REPORT_LIST_OUTPUT,
            description="Page report records for one case.",
        ),
        ToolBinding(
            "report.version.get",
            "report.version.get",
            REPORT_VERSION_GET_INPUT,
            output_schema_ref="report-version.schema.json",
            description="Return one immutable case-bound report version.",
        ),
        ToolBinding(
            "report.version.list",
            "report.version.list",
            REPORT_VERSION_LIST_INPUT,
            output_data_schema=REPORT_VERSION_LIST_OUTPUT,
            description="List immutable versions for one case-bound report.",
        ),
        ToolBinding(
            "report.version.compare",
            "report.version.compare",
            REPORT_VERSION_COMPARE_INPUT,
            output_data_schema=REPORT_VERSION_COMPARE_OUTPUT,
            description="Compare two immutable versions of the same case report.",
        ),
        ToolBinding(
            "report.review.history",
            "report.review.history",
            REPORT_REVIEW_HISTORY_INPUT,
            output_data_schema=REPORT_REVIEW_HISTORY_OUTPUT,
            description="Return append-only human review history.",
        ),
        ToolBinding(
            "report.approval.get",
            "report.approval.get",
            REPORT_APPROVAL_GET_INPUT,
            output_data_schema=REPORT_APPROVAL_GET_OUTPUT,
            description="Return the latest human approval decision, if present.",
        ),
        ToolBinding(
            "report.custody-snapshot.get",
            "report.custody-snapshot.get",
            REPORT_CUSTODY_GET_INPUT,
            output_schema_ref="custody-snapshot.schema.json",
            description="Return one immutable report custody snapshot.",
        ),
        ToolBinding(
            "report.render-package.get",
            "report.render-package.get",
            REPORT_RENDER_PACKAGE_GET_INPUT,
            output_schema_ref="report-render-package.schema.json",
            description="Return one deterministic render package.",
        ),
        ToolBinding(
            "report.export-manifest.get",
            "report.export-manifest.get",
            REPORT_EXPORT_MANIFEST_GET_INPUT,
            output_schema_ref="report-export-manifest.schema.json",
            description="Return one approved report export manifest.",
        ),
        ToolBinding(
            "report.export-status",
            "report.export-status",
            REPORT_EXPORT_STATUS_INPUT,
            output_data_schema=REPORT_EXPORT_STATUS_OUTPUT,
            description="Return an export manifest and bounded rendered artifacts.",
        ),
        ToolBinding(
            "report.capabilities",
            "report.capabilities",
            REPORT_CAPABILITIES_INPUT,
            output_data_schema=REPORT_CAPABILITIES_OUTPUT,
            description="Report current report engine and renderer capabilities.",
        ),
        ToolBinding(
            "report.create",
            "report.create",
            REPORT_CREATE_INPUT,
            output_schema_ref="report-record.schema.json",
            description="Create an empty report container using the server-authenticated actor.",
        ),
        ToolBinding(
            "report.version.create",
            "report.version.create",
            REPORT_VERSION_CREATE_INPUT,
            output_schema_ref="report-version.schema.json",
            description="Create an immutable analyst draft version using the trusted actor.",
            idempotent=True,
        ),
        ToolBinding(
            "report.ai-draft.ingest",
            "report.ai-draft.ingest",
            REPORT_AI_DRAFT_INGEST_INPUT,
            output_schema_ref="report-version.schema.json",
            description="Validate and ingest an AI-authored draft without review or approval.",
            idempotent=True,
        ),
        ToolBinding(
            "report.review.submit",
            "report.review.submit",
            REPORT_REVIEW_SUBMIT_INPUT,
            output_schema_ref="report-review-event.schema.json",
            description="Submit a report version for trusted human review.",
        ),
        ToolBinding(
            "report.review.comment",
            "report.review.comment",
            REPORT_REVIEW_COMMENT_INPUT,
            output_schema_ref="report-review-event.schema.json",
            description="Append a trusted human review comment.",
        ),
        ToolBinding(
            "report.review.request-changes",
            "report.review.request-changes",
            REPORT_REVIEW_REQUEST_CHANGES_INPUT,
            output_schema_ref="report-review-event.schema.json",
            description="Request bounded changes during human review.",
            destructive=True,
        ),
        ToolBinding(
            "report.review.accept-section",
            "report.review.accept-section",
            REPORT_REVIEW_ACCEPT_SECTION_INPUT,
            output_schema_ref="report-review-event.schema.json",
            description="Accept one immutable report section during human review.",
        ),
        ToolBinding(
            "report.review.reject-section",
            "report.review.reject-section",
            REPORT_REVIEW_REJECT_SECTION_INPUT,
            output_schema_ref="report-review-event.schema.json",
            description="Reject one report section during human review.",
            destructive=True,
        ),
        ToolBinding(
            "report.review.complete",
            "report.review.complete",
            REPORT_REVIEW_COMPLETE_INPUT,
            output_schema_ref="report-review-event.schema.json",
            description="Mark a fully section-reviewed version as review complete.",
        ),
        ToolBinding(
            "report.review.reopen",
            "report.review.reopen",
            REPORT_REVIEW_REOPEN_INPUT,
            output_schema_ref="report-review-event.schema.json",
            description="Reopen a completed human review.",
            destructive=True,
        ),
        ToolBinding(
            "report.approve",
            "report.approve",
            REPORT_APPROVE_INPUT,
            output_schema_ref="report-approval-record.schema.json",
            description="Approve a completed immutable version using a trusted human actor.",
            destructive=True,
        ),
        ToolBinding(
            "report.reject",
            "report.reject",
            REPORT_REJECT_INPUT,
            output_schema_ref="report-approval-record.schema.json",
            description="Record a trusted human rejection decision.",
            destructive=True,
        ),
        ToolBinding(
            "report.approval.revoke",
            "report.approval.revoke",
            REPORT_APPROVAL_REVOKE_INPUT,
            output_schema_ref="report-approval-record.schema.json",
            description="Revoke the latest approval using a trusted human actor.",
            destructive=True,
        ),
        ToolBinding(
            "report.custody-snapshot.create",
            "report.custody-snapshot.create",
            REPORT_CUSTODY_CREATE_INPUT,
            output_schema_ref="custody-snapshot.schema.json",
            description="Capture immutable custody state for a case-bound report version.",
            idempotent=True,
        ),
        ToolBinding(
            "report.render-package.create",
            "report.render-package.create",
            REPORT_RENDER_PACKAGE_CREATE_INPUT,
            output_schema_ref="report-render-package.schema.json",
            description="Create a preview-only deterministic render package.",
            idempotent=True,
        ),
        ToolBinding(
            "report.export.prepare",
            "report.export.prepare",
            REPORT_EXPORT_PREPARE_INPUT,
            output_schema_ref="report-export-manifest.schema.json",
            description=(
                "Prepare export for the exact approved version, custody snapshot, and fingerprint."
            ),
            destructive=True,
            idempotent=True,
        ),
        ToolBinding(
            "report.archive",
            "report.archive",
            REPORT_ARCHIVE_INPUT,
            output_schema_ref="report-record.schema.json",
            description="Archive a case-bound report after trusted human confirmation.",
            destructive=True,
            idempotent=True,
        ),
    )


__all__ = [
    "M5_REPORT_TOOL_NAMES",
    "M5_TOOL_NAMES",
    "REPORT_AI_DRAFT_INGEST_INPUT",
    "REPORT_APPROVE_INPUT",
    "REPORT_EXPORT_PREPARE_INPUT",
    "REPORT_VERSION_CREATE_INPUT",
    "m5_bindings",
]
