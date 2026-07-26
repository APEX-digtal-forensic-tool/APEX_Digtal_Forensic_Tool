"""Phase 6 GUI context, snapshot, view, and interface DTOs."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from apex_forensic._time import to_json_timestamp
from apex_forensic.domain.enums import (
    AnalysisContextPurpose,
    AnalysisScopeType,
    GuiRoute,
    RawLocatorType,
    ResourceType,
    RevisionStatus,
    ViewMode,
)


def _value(value: Any) -> Any:
    return value.value if hasattr(value, "value") else value


def _timestamp(value: datetime | None) -> str | None:
    return None if value is None else to_json_timestamp(value)


def _states(values: list[RevisionState]) -> list[dict[str, Any]]:
    return [item.to_schema_dict() for item in values]


@dataclass(slots=True)
class RevisionState:
    """Current/stale/partial state for a referenced resource revision."""

    resource_type: ResourceType | str
    resource_id: str
    expected_revision: str | int | None
    current_revision: str | int | None
    status: RevisionStatus | str
    reason: str | None
    detected_at: datetime

    def to_schema_dict(self) -> dict[str, Any]:
        return {
            "resource_type": _value(self.resource_type),
            "resource_id": self.resource_id,
            "expected_revision": self.expected_revision,
            "current_revision": self.current_revision,
            "status": _value(self.status),
            "reason": self.reason,
            "detected_at": to_json_timestamp(self.detected_at),
        }


@dataclass(slots=True)
class GuiSessionContext:
    """Live GUI session state persisted as selected IDs and query options."""

    session_context_id: str
    session_id: str
    case_id: str
    actor_id: str | None
    locale: str
    timezone: str
    current_route: GuiRoute | str
    current_panel: str | None
    active_evidence_id: str | None
    selected_file_node_ids: list[str] = field(default_factory=list)
    selected_artifact_ids: list[str] = field(default_factory=list)
    selected_timeline_event_ids: list[str] = field(default_factory=list)
    selected_search_result_ids: list[str] = field(default_factory=list)
    selected_media_artifact_ids: list[str] = field(default_factory=list)
    selected_browser_artifact_ids: list[str] = field(default_factory=list)
    selected_candidate_ids: list[str] = field(default_factory=list)
    active_filters: dict[str, Any] = field(default_factory=dict)
    active_sort: dict[str, Any] = field(default_factory=dict)
    active_time_range: dict[str, Any] = field(default_factory=dict)
    active_keyword_set_id: str | None = None
    active_keyword_set_version: int | None = None
    active_search_execution_id: str | None = None
    active_timeline_revision: int | None = None
    active_context_scope: AnalysisScopeType | str = AnalysisScopeType.CASE
    ui_preferences: dict[str, Any] = field(default_factory=dict)
    context_revision: int = 1
    source_revision_fingerprint: str = ""
    is_partial: bool = False
    stale_reasons: list[str] = field(default_factory=list)
    created_at: datetime | None = None
    updated_at: datetime | None = None
    expires_at: datetime | None = None

    def to_schema_dict(self) -> dict[str, Any]:
        return {
            "session_context_id": self.session_context_id,
            "session_id": self.session_id,
            "case_id": self.case_id,
            "actor_id": self.actor_id,
            "locale": self.locale,
            "timezone": self.timezone,
            "current_route": _value(self.current_route),
            "current_panel": self.current_panel,
            "active_evidence_id": self.active_evidence_id,
            "selected_file_node_ids": self.selected_file_node_ids,
            "selected_artifact_ids": self.selected_artifact_ids,
            "selected_timeline_event_ids": self.selected_timeline_event_ids,
            "selected_search_result_ids": self.selected_search_result_ids,
            "selected_media_artifact_ids": self.selected_media_artifact_ids,
            "selected_browser_artifact_ids": self.selected_browser_artifact_ids,
            "selected_candidate_ids": self.selected_candidate_ids,
            "active_filters": self.active_filters,
            "active_sort": self.active_sort,
            "active_time_range": self.active_time_range,
            "active_keyword_set_id": self.active_keyword_set_id,
            "active_keyword_set_version": self.active_keyword_set_version,
            "active_search_execution_id": self.active_search_execution_id,
            "active_timeline_revision": self.active_timeline_revision,
            "active_context_scope": _value(self.active_context_scope),
            "ui_preferences": self.ui_preferences,
            "context_revision": self.context_revision,
            "source_revision_fingerprint": self.source_revision_fingerprint,
            "is_partial": self.is_partial,
            "stale_reasons": self.stale_reasons,
            "created_at": _timestamp(self.created_at),
            "updated_at": _timestamp(self.updated_at),
            "expires_at": _timestamp(self.expires_at),
        }


@dataclass(slots=True)
class AnalysisContextSnapshot:
    """Immutable analysis context used for AI, MCP, reports, audit, and export."""

    context_snapshot_id: str
    case_id: str
    session_context_id: str | None
    session_context_revision: int | None
    actor_id: str | None
    purpose: AnalysisContextPurpose | str
    scopes: list[str]
    included_resource_ids: dict[str, list[str]]
    excluded_resource_ids: dict[str, list[str]]
    filters: dict[str, Any]
    time_range: dict[str, Any]
    source_revisions: list[RevisionState]
    analyzer_versions: dict[str, str]
    search_index_revision: int | None
    timeline_revision: int | None
    keyword_set_id: str | None
    keyword_set_version: int | None
    search_execution_id: str | None
    partial_state: dict[str, Any]
    stale_state: dict[str, Any]
    warnings: list[dict[str, Any]]
    citations: list[dict[str, Any]]
    context_fingerprint: str
    previous_snapshot_id: str | None
    created_at: datetime

    def to_schema_dict(self) -> dict[str, Any]:
        return {
            "context_snapshot_id": self.context_snapshot_id,
            "case_id": self.case_id,
            "session_context_id": self.session_context_id,
            "session_context_revision": self.session_context_revision,
            "actor_id": self.actor_id,
            "purpose": _value(self.purpose),
            "scopes": self.scopes,
            "included_resource_ids": self.included_resource_ids,
            "excluded_resource_ids": self.excluded_resource_ids,
            "filters": self.filters,
            "time_range": self.time_range,
            "source_revisions": _states(self.source_revisions),
            "analyzer_versions": self.analyzer_versions,
            "search_index_revision": self.search_index_revision,
            "timeline_revision": self.timeline_revision,
            "keyword_set_id": self.keyword_set_id,
            "keyword_set_version": self.keyword_set_version,
            "search_execution_id": self.search_execution_id,
            "partial_state": self.partial_state,
            "stale_state": self.stale_state,
            "warnings": self.warnings,
            "citations": self.citations,
            "context_fingerprint": self.context_fingerprint,
            "previous_snapshot_id": self.previous_snapshot_id,
            "created_at": to_json_timestamp(self.created_at),
        }


@dataclass(slots=True)
class AnalysisScopeContext:
    """One scope page summary inside an immutable analysis context snapshot."""

    scope_context_id: str
    context_snapshot_id: str
    scope_type: AnalysisScopeType | str
    case_id: str
    evidence_ids: list[str]
    resource_ids: list[str]
    source_revisions: list[RevisionState]
    analyzer_versions: dict[str, str]
    filters: dict[str, Any]
    sort: dict[str, Any]
    time_range: dict[str, Any]
    result_count: int
    included_count: int
    excluded_count: int
    is_partial: bool
    coverage: dict[str, Any]
    stale_reasons: list[str]
    warnings: list[dict[str, Any]]
    citations: list[dict[str, Any]]
    continuation_cursor: str | None
    scope_fingerprint: str
    created_at: datetime

    def to_schema_dict(self) -> dict[str, Any]:
        return {
            "scope_context_id": self.scope_context_id,
            "context_snapshot_id": self.context_snapshot_id,
            "scope_type": _value(self.scope_type),
            "case_id": self.case_id,
            "evidence_ids": self.evidence_ids,
            "resource_ids": self.resource_ids,
            "source_revisions": _states(self.source_revisions),
            "analyzer_versions": self.analyzer_versions,
            "filters": self.filters,
            "sort": self.sort,
            "time_range": self.time_range,
            "result_count": self.result_count,
            "included_count": self.included_count,
            "excluded_count": self.excluded_count,
            "is_partial": self.is_partial,
            "coverage": self.coverage,
            "stale_reasons": self.stale_reasons,
            "warnings": self.warnings,
            "citations": self.citations,
            "continuation_cursor": self.continuation_cursor,
            "scope_fingerprint": self.scope_fingerprint,
            "created_at": to_json_timestamp(self.created_at),
        }


@dataclass(slots=True)
class ViewProjection:
    """Simple, detailed, or raw projection over an immutable resource revision."""

    projection_id: str
    case_id: str
    resource_type: ResourceType | str
    resource_id: str
    view_mode: ViewMode | str
    title: str
    subtitle: str | None
    summary: str | None
    severity: str | None
    badges: list[str]
    primary_fields: dict[str, Any]
    secondary_fields: dict[str, Any]
    technical_fields: dict[str, Any]
    raw_fields: dict[str, Any]
    timestamps: dict[str, Any]
    timezone: str | None
    confidence: float | None
    partial_state: dict[str, Any]
    stale_state: dict[str, Any]
    warnings: list[dict[str, Any]]
    citations: list[dict[str, Any]]
    raw_locator: dict[str, Any] | None
    available_actions: list[str]
    source_revision: str | int | None
    analyzer_id: str | None
    analyzer_version: str | None
    projection_version: str
    created_at: datetime

    def to_schema_dict(self) -> dict[str, Any]:
        return {
            "projection_id": self.projection_id,
            "case_id": self.case_id,
            "resource_type": _value(self.resource_type),
            "resource_id": self.resource_id,
            "view_mode": _value(self.view_mode),
            "title": self.title,
            "subtitle": self.subtitle,
            "summary": self.summary,
            "severity": self.severity,
            "badges": self.badges,
            "primary_fields": self.primary_fields,
            "secondary_fields": self.secondary_fields,
            "technical_fields": self.technical_fields,
            "raw_fields": self.raw_fields,
            "timestamps": self.timestamps,
            "timezone": self.timezone,
            "confidence": self.confidence,
            "partial_state": self.partial_state,
            "stale_state": self.stale_state,
            "warnings": self.warnings,
            "citations": self.citations,
            "raw_locator": self.raw_locator,
            "available_actions": self.available_actions,
            "source_revision": self.source_revision,
            "analyzer_id": self.analyzer_id,
            "analyzer_version": self.analyzer_version,
            "projection_version": self.projection_version,
            "created_at": to_json_timestamp(self.created_at),
        }


@dataclass(slots=True)
class RawViewProjection:
    """Bounded raw byte or logical-field projection returned by the raw reader."""

    projection_id: str
    case_id: str
    evidence_id: str | None
    resource_type: ResourceType | str
    resource_id: str
    source_path: str | None
    raw_locator: dict[str, Any]
    locator_type: RawLocatorType | str
    requested_offset: int | None
    requested_length: int | None
    returned_offset: int | None
    returned_length: int | None
    total_length: int | None
    encoding: str | None
    content_type: str
    hex_preview: str | None
    text_preview: str | None
    structured_raw_fields: dict[str, Any]
    truncated: bool
    hash: dict[str, Any]
    citations: list[dict[str, Any]]
    warnings: list[dict[str, Any]]
    source_revision: str | int | None
    created_at: datetime

    def to_schema_dict(self) -> dict[str, Any]:
        return {
            "projection_id": self.projection_id,
            "case_id": self.case_id,
            "evidence_id": self.evidence_id,
            "resource_type": _value(self.resource_type),
            "resource_id": self.resource_id,
            "source_path": self.source_path,
            "raw_locator": self.raw_locator,
            "locator_type": _value(self.locator_type),
            "requested_offset": self.requested_offset,
            "requested_length": self.requested_length,
            "returned_offset": self.returned_offset,
            "returned_length": self.returned_length,
            "total_length": self.total_length,
            "encoding": self.encoding,
            "content_type": self.content_type,
            "hex_preview": self.hex_preview,
            "text_preview": self.text_preview,
            "structured_raw_fields": self.structured_raw_fields,
            "truncated": self.truncated,
            "hash": self.hash,
            "citations": self.citations,
            "warnings": self.warnings,
            "source_revision": self.source_revision,
            "created_at": to_json_timestamp(self.created_at),
        }


@dataclass(frozen=True, slots=True)
class EngineToolDescriptor:
    """Provider-neutral descriptor for future MCP adapter consumers."""

    tool_name: str
    tool_version: str
    description_key: str
    input_schema_ref: str
    output_schema_ref: str
    required_capabilities: list[str]
    mutates_state: bool
    requires_confirmation: bool
    supports_pagination: bool
    supports_partial: bool
    supports_citation: bool
    max_result_items: int

    def to_schema_dict(self) -> dict[str, Any]:
        return {
            "tool_name": self.tool_name,
            "tool_version": self.tool_version,
            "description_key": self.description_key,
            "input_schema_ref": self.input_schema_ref,
            "output_schema_ref": self.output_schema_ref,
            "required_capabilities": self.required_capabilities,
            "mutates_state": self.mutates_state,
            "requires_confirmation": self.requires_confirmation,
            "supports_pagination": self.supports_pagination,
            "supports_partial": self.supports_partial,
            "supports_citation": self.supports_citation,
            "max_result_items": self.max_result_items,
        }


@dataclass(frozen=True, slots=True)
class EngineInterfaceVersion:
    """Version and capability statement for public engine consumers."""

    interface_name: str
    interface_version: str
    engine_version: str
    schema_version: str
    capabilities: list[str]
    unavailable_capabilities: list[str]
    generated_at: datetime

    def to_schema_dict(self) -> dict[str, Any]:
        return {
            "interface_name": self.interface_name,
            "interface_version": self.interface_version,
            "engine_version": self.engine_version,
            "schema_version": self.schema_version,
            "capabilities": self.capabilities,
            "unavailable_capabilities": self.unavailable_capabilities,
            "generated_at": to_json_timestamp(self.generated_at),
        }
