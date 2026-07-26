"""Phase 6 GUI context, view projection, safe raw read, and interface services."""

from __future__ import annotations

import base64
import hashlib
import json
from collections.abc import Iterable, Mapping
from dataclasses import replace
from datetime import timedelta
from pathlib import Path, PurePosixPath
from typing import Any, cast

from apex_forensic._time import parse_timestamp, to_json_timestamp
from apex_forensic.constants import ENGINE_VERSION, SCHEMA_VERSION
from apex_forensic.domain.enums import (
    AiAssistancePurpose,
    AiVerificationAction,
    AnalysisContextPurpose,
    AnalysisScopeType,
    ArtifactType,
    GuiRoute,
    RawLocatorType,
    ResourceType,
    RevisionStatus,
    StaleReason,
    ViewMode,
)
from apex_forensic.domain.errors import (
    ApexError,
    ContextExpiredError,
    ContextFilterLimitExceededError,
    ContextRevisionConflictError,
    ContextScopeMismatchError,
    ContextSelectionLimitExceededError,
    CursorInvalidError,
    NotFoundError,
    RawReadError,
    UnsupportedCapabilityError,
    ValidationError,
)
from apex_forensic.domain.models import (
    AnalysisContextSnapshot,
    AnalysisScopeContext,
    EngineInterfaceVersion,
    EngineToolDescriptor,
    GuiSessionContext,
    RawViewProjection,
    RevisionState,
    ViewProjection,
)
from apex_forensic.domain.services.canonical import canonical_json_bytes, canonical_sha256
from apex_forensic.jobs import CancellationToken
from apex_forensic.ports.clock import Clock
from apex_forensic.ports.id_generator import IdGenerator

DEFAULT_CONTEXT_TTL_SECONDS = 8 * 60 * 60
MAX_SELECTION_IDS = 1000
MAX_FILTER_BYTES = 64 * 1024
MAX_JSON_DEPTH = 8
MAX_SCOPE_ITEMS = 1000
MAX_CONTEXT_PAYLOAD_BYTES = 256 * 1024
MAX_CITATIONS = 100
DEFAULT_RAW_READ_LENGTH = 4096
MAX_RAW_READ_LENGTH = 1024 * 1024
RAW_PREVIEW_BYTES = 4096
PROJECTION_VERSION = "1.0.0"
INTERFACE_VERSION = "1.0.0"
_SECRET_KEY_PARTS = ("api_key", "apikey", "secret", "token", "credential", "password", "prompt")
_RAW_BLOB_KEYS = ("raw_blob", "blob", "binary", "bytes")

_RESOURCE_SELECTION_FIELDS: dict[str, str] = {
    ResourceType.FILE_SYSTEM_NODE.value: "selected_file_node_ids",
    ResourceType.ARTIFACT.value: "selected_artifact_ids",
    ResourceType.REGISTRY.value: "selected_artifact_ids",
    ResourceType.EVENT_LOG.value: "selected_artifact_ids",
    ResourceType.PREFETCH.value: "selected_artifact_ids",
    ResourceType.BROWSER.value: "selected_browser_artifact_ids",
    ResourceType.MEDIA.value: "selected_media_artifact_ids",
    ResourceType.TIMELINE_EVENT.value: "selected_timeline_event_ids",
    ResourceType.SEARCH_RESULT.value: "selected_search_result_ids",
    ResourceType.MACHINE_CANDIDATE.value: "selected_candidate_ids",
}
_ARTIFACT_SCOPE_BY_TYPE: dict[str, str] = {
    ArtifactType.REGISTRY_KEY.value: AnalysisScopeType.REGISTRY.value,
    ArtifactType.REGISTRY_VALUE.value: AnalysisScopeType.REGISTRY.value,
    ArtifactType.REGISTRY_AUTORUN.value: AnalysisScopeType.REGISTRY.value,
    ArtifactType.REGISTRY_USB_DEVICE.value: AnalysisScopeType.REGISTRY.value,
    ArtifactType.REGISTRY_TIMEZONE.value: AnalysisScopeType.REGISTRY.value,
    ArtifactType.REGISTRY_USERASSIST.value: AnalysisScopeType.REGISTRY.value,
    ArtifactType.EVENT_LOG_RECORD.value: AnalysisScopeType.EVENTLOG.value,
    ArtifactType.PREFETCH_EXECUTION.value: AnalysisScopeType.PREFETCH.value,
    ArtifactType.BROWSER_PROFILE.value: AnalysisScopeType.BROWSER.value,
    ArtifactType.BROWSER_VISIT.value: AnalysisScopeType.BROWSER.value,
    ArtifactType.BROWSER_SEARCH.value: AnalysisScopeType.BROWSER.value,
    ArtifactType.BROWSER_DOWNLOAD.value: AnalysisScopeType.BROWSER.value,
    ArtifactType.MEDIA_IMAGE.value: AnalysisScopeType.MEDIA.value,
    ArtifactType.MEDIA_VIDEO.value: AnalysisScopeType.MEDIA.value,
    ArtifactType.MEDIA_AUDIO.value: AnalysisScopeType.MEDIA.value,
}
_ARTIFACT_RESOURCE_TYPE_BY_SCOPE: dict[str, str] = {
    AnalysisScopeType.REGISTRY.value: ResourceType.REGISTRY.value,
    AnalysisScopeType.EVENTLOG.value: ResourceType.EVENT_LOG.value,
    AnalysisScopeType.PREFETCH.value: ResourceType.PREFETCH.value,
    AnalysisScopeType.BROWSER.value: ResourceType.BROWSER.value,
    AnalysisScopeType.MEDIA.value: ResourceType.MEDIA.value,
}
_RESOURCE_SCOPE_BY_TYPE: dict[str, str] = {
    ResourceType.EVIDENCE.value: AnalysisScopeType.EVIDENCE.value,
    ResourceType.FILE_SYSTEM_NODE.value: AnalysisScopeType.FILESYSTEM.value,
    ResourceType.REGISTRY.value: AnalysisScopeType.REGISTRY.value,
    ResourceType.EVENT_LOG.value: AnalysisScopeType.EVENTLOG.value,
    ResourceType.PREFETCH.value: AnalysisScopeType.PREFETCH.value,
    ResourceType.BROWSER.value: AnalysisScopeType.BROWSER.value,
    ResourceType.MEDIA.value: AnalysisScopeType.MEDIA.value,
    ResourceType.TIMELINE_EVENT.value: AnalysisScopeType.TIMELINE.value,
    ResourceType.SEARCH_RESULT.value: AnalysisScopeType.KEYWORD_SEARCH.value,
    ResourceType.MACHINE_CANDIDATE.value: AnalysisScopeType.MACHINE_CANDIDATE.value,
    ResourceType.CUSTODY_EVENT.value: AnalysisScopeType.CHAIN_OF_CUSTODY.value,
}
_SELECTION_RESOURCE_TYPES: tuple[str, ...] = (
    ResourceType.EVIDENCE.value,
    *tuple(_RESOURCE_SELECTION_FIELDS),
)
_SCOPE_RESOURCE_TYPES: dict[str, tuple[str, ...]] = {
    AnalysisScopeType.EVIDENCE.value: (ResourceType.EVIDENCE.value,),
    AnalysisScopeType.FILESYSTEM.value: (ResourceType.FILE_SYSTEM_NODE.value,),
    AnalysisScopeType.REGISTRY.value: (ResourceType.REGISTRY.value,),
    AnalysisScopeType.EVENTLOG.value: (ResourceType.EVENT_LOG.value,),
    AnalysisScopeType.PREFETCH.value: (ResourceType.PREFETCH.value,),
    AnalysisScopeType.BROWSER.value: (ResourceType.BROWSER.value,),
    AnalysisScopeType.MEDIA.value: (ResourceType.MEDIA.value,),
    AnalysisScopeType.TIMELINE.value: (ResourceType.TIMELINE_EVENT.value,),
    AnalysisScopeType.KEYWORD_SEARCH.value: (ResourceType.SEARCH_RESULT.value,),
    AnalysisScopeType.MACHINE_CANDIDATE.value: (ResourceType.MACHINE_CANDIDATE.value,),
    AnalysisScopeType.CHAIN_OF_CUSTODY.value: (ResourceType.CUSTODY_EVENT.value,),
    AnalysisScopeType.SELECTION.value: _SELECTION_RESOURCE_TYPES,
}
_OPERATION_ALIASES: dict[str, str] = {
    "context.get": "context.get",
    "apex.context.get": "context.get",
    "context.snapshot": "context.snapshot",
    "apex.context.snapshot": "context.snapshot",
    "context.snapshot-show": "context.snapshot-show",
    "context.snapshot_show": "context.snapshot-show",
    "apex.context.snapshot_show": "context.snapshot-show",
    "apex.context.snapshot-show": "context.snapshot-show",
    "context.scope-page": "context.scope-page",
    "context.scope_page": "context.scope-page",
    "apex.context.scope_page": "context.scope-page",
    "apex.context.scope-page": "context.scope-page",
    "view.simple": "view.simple",
    "apex.view.simple": "view.simple",
    "view.detailed": "view.detailed",
    "apex.view.detailed": "view.detailed",
    "view.raw": "view.raw",
    "apex.view.raw": "view.raw",
    "view.raw-read": "view.raw-read",
    "view.raw_read": "view.raw-read",
    "apex.view.raw_read": "view.raw-read",
    "apex.view.raw-read": "view.raw-read",
    "ai.request.create": "ai.request.create",
    "ai.request.get": "ai.request.get",
    "ai.request.list": "ai.request.list",
    "ai.keyword-batch.get": "ai.keyword-batch.get",
    "ai.keyword_batch.get": "ai.keyword-batch.get",
    "ai.keyword-recommendation.get": "ai.keyword-recommendation.get",
    "ai.keyword_recommendation.get": "ai.keyword-recommendation.get",
    "ai.keyword-recommendation.list": "ai.keyword-recommendation.list",
    "ai.keyword_recommendation.list": "ai.keyword-recommendation.list",
    "ai.scope-summary.get": "ai.scope-summary.get",
    "ai.scope_summary.get": "ai.scope-summary.get",
    "ai.scope-summary.list": "ai.scope-summary.list",
    "ai.scope_summary.list": "ai.scope-summary.list",
    "ai.verification.history": "ai.verification.history",
    "ai.promotion.preview": "ai.promotion.preview",
    "ai.capabilities": "ai.capabilities",
    "ai.keyword-batch.ingest": "ai.keyword-batch.ingest",
    "ai.keyword_batch.ingest": "ai.keyword-batch.ingest",
    "ai.scope-summary.ingest": "ai.scope-summary.ingest",
    "ai.scope_summary.ingest": "ai.scope-summary.ingest",
    "ai.keyword-recommendation.review": "ai.keyword-recommendation.review",
    "ai.keyword_recommendation.review": "ai.keyword-recommendation.review",
    "ai.scope-summary.review": "ai.scope-summary.review",
    "ai.scope_summary.review": "ai.scope-summary.review",
    "ai.keyword-recommendation.promote": "ai.keyword-recommendation.promote",
    "ai.keyword_recommendation.promote": "ai.keyword-recommendation.promote",
}
_TOOL_DESCRIPTOR_SPECS: tuple[
    tuple[str, str, str, str, str, list[str], bool, bool, bool, bool, bool, int], ...
] = (
    (
        "apex.context.get",
        "context.get",
        "tool.apex.context.get",
        "gui-session-context.schema.json",
        "gui-session-context.schema.json",
        ["CONTEXT_SNAPSHOT"],
        False,
        False,
        False,
        True,
        True,
        1,
    ),
    (
        "apex.context.snapshot",
        "context.snapshot",
        "tool.apex.context.snapshot",
        "gui-session-context.schema.json",
        "analysis-context-snapshot.schema.json",
        ["CONTEXT_SNAPSHOT"],
        True,
        False,
        False,
        True,
        True,
        1,
    ),
    (
        "apex.context.snapshot_show",
        "context.snapshot-show",
        "tool.apex.context.snapshot_show",
        "analysis-context-snapshot.schema.json",
        "analysis-context-snapshot.schema.json",
        ["CONTEXT_SNAPSHOT"],
        False,
        False,
        False,
        True,
        True,
        1,
    ),
    (
        "apex.context.scope_page",
        "context.scope-page",
        "tool.apex.context.scope_page",
        "analysis-scope-context.schema.json",
        "view-projection.schema.json",
        ["CONTEXT_SNAPSHOT"],
        False,
        False,
        True,
        True,
        True,
        MAX_SCOPE_ITEMS,
    ),
    (
        "apex.view.simple",
        "view.simple",
        "tool.apex.view.simple",
        "view-projection.schema.json",
        "view-projection.schema.json",
        ["SIMPLE_DETAILED_RAW_VIEW"],
        False,
        False,
        False,
        True,
        True,
        1,
    ),
    (
        "apex.view.detailed",
        "view.detailed",
        "tool.apex.view.detailed",
        "view-projection.schema.json",
        "view-projection.schema.json",
        ["SIMPLE_DETAILED_RAW_VIEW"],
        False,
        False,
        False,
        True,
        True,
        1,
    ),
    (
        "apex.view.raw",
        "view.raw",
        "tool.apex.view.raw",
        "view-projection.schema.json",
        "view-projection.schema.json",
        ["SIMPLE_DETAILED_RAW_VIEW"],
        False,
        False,
        False,
        True,
        True,
        1,
    ),
    (
        "apex.view.raw_read",
        "view.raw-read",
        "tool.apex.view.raw_read",
        "raw-read-request.schema.json",
        "raw-read-response.schema.json",
        ["SAFE_RAW_READ"],
        False,
        True,
        True,
        True,
        True,
        1,
    ),
    (
        "ai.request.create",
        "ai.request.create",
        "tool.ai.request.create",
        "ai-assistance-request.schema.json",
        "ai-assistance-request.schema.json",
        ["AI_ASSISTANCE_ENGINE_CONTRACT"],
        True,
        False,
        False,
        True,
        True,
        1,
    ),
    (
        "ai.request.get",
        "ai.request.get",
        "tool.ai.request.get",
        "ai-assistance-request.schema.json",
        "ai-assistance-request.schema.json",
        ["AI_ASSISTANCE_ENGINE_CONTRACT"],
        False,
        False,
        False,
        True,
        True,
        1,
    ),
    (
        "ai.request.list",
        "ai.request.list",
        "tool.ai.request.list",
        "ai-assistance-request.schema.json",
        "ai-assistance-request.schema.json",
        ["AI_ASSISTANCE_ENGINE_CONTRACT"],
        False,
        False,
        True,
        True,
        True,
        MAX_SCOPE_ITEMS,
    ),
    (
        "ai.keyword-batch.ingest",
        "ai.keyword-batch.ingest",
        "tool.ai.keyword_batch.ingest",
        "ai-keyword-recommendation-batch.schema.json",
        "ai-keyword-recommendation-batch.schema.json",
        ["AI_ASSISTANCE_ENGINE_CONTRACT"],
        True,
        False,
        False,
        True,
        True,
        1,
    ),
    (
        "ai.keyword-batch.get",
        "ai.keyword-batch.get",
        "tool.ai.keyword_batch.get",
        "ai-keyword-recommendation-batch.schema.json",
        "ai-keyword-recommendation-batch.schema.json",
        ["AI_ASSISTANCE_ENGINE_CONTRACT"],
        False,
        False,
        False,
        True,
        True,
        1,
    ),
    (
        "ai.keyword-recommendation.get",
        "ai.keyword-recommendation.get",
        "tool.ai.keyword_recommendation.get",
        "ai-keyword-recommendation.schema.json",
        "ai-keyword-recommendation.schema.json",
        ["AI_ASSISTANCE_ENGINE_CONTRACT"],
        False,
        False,
        False,
        True,
        True,
        1,
    ),
    (
        "ai.keyword-recommendation.list",
        "ai.keyword-recommendation.list",
        "tool.ai.keyword_recommendation.list",
        "ai-keyword-recommendation.schema.json",
        "ai-keyword-recommendation.schema.json",
        ["AI_ASSISTANCE_ENGINE_CONTRACT"],
        False,
        False,
        True,
        True,
        True,
        MAX_SCOPE_ITEMS,
    ),
    (
        "ai.scope-summary.ingest",
        "ai.scope-summary.ingest",
        "tool.ai.scope_summary.ingest",
        "ai-scope-summary.schema.json",
        "ai-scope-summary.schema.json",
        ["AI_ASSISTANCE_ENGINE_CONTRACT"],
        True,
        False,
        False,
        True,
        True,
        1,
    ),
    (
        "ai.scope-summary.get",
        "ai.scope-summary.get",
        "tool.ai.scope_summary.get",
        "ai-scope-summary.schema.json",
        "ai-scope-summary.schema.json",
        ["AI_ASSISTANCE_ENGINE_CONTRACT"],
        False,
        False,
        False,
        True,
        True,
        1,
    ),
    (
        "ai.scope-summary.list",
        "ai.scope-summary.list",
        "tool.ai.scope_summary.list",
        "ai-scope-summary.schema.json",
        "ai-scope-summary.schema.json",
        ["AI_ASSISTANCE_ENGINE_CONTRACT"],
        False,
        False,
        True,
        True,
        True,
        MAX_SCOPE_ITEMS,
    ),
    (
        "ai.keyword-recommendation.review",
        "ai.keyword-recommendation.review",
        "tool.ai.keyword_recommendation.review",
        "ai-verification-event.schema.json",
        "ai-verification-event.schema.json",
        ["AI_ASSISTANCE_ENGINE_CONTRACT"],
        True,
        True,
        False,
        True,
        True,
        1,
    ),
    (
        "ai.scope-summary.review",
        "ai.scope-summary.review",
        "tool.ai.scope_summary.review",
        "ai-verification-event.schema.json",
        "ai-verification-event.schema.json",
        ["AI_ASSISTANCE_ENGINE_CONTRACT"],
        True,
        True,
        False,
        True,
        True,
        1,
    ),
    (
        "ai.verification.history",
        "ai.verification.history",
        "tool.ai.verification.history",
        "ai-verification-event.schema.json",
        "ai-verification-event.schema.json",
        ["AI_ASSISTANCE_ENGINE_CONTRACT"],
        False,
        False,
        True,
        True,
        True,
        MAX_SCOPE_ITEMS,
    ),
    (
        "ai.promotion.preview",
        "ai.promotion.preview",
        "tool.ai.promotion.preview",
        "ai-keyword-promotion.schema.json",
        "ai-keyword-promotion.schema.json",
        ["AI_ASSISTANCE_ENGINE_CONTRACT"],
        False,
        True,
        False,
        True,
        True,
        1,
    ),
    (
        "ai.keyword-recommendation.promote",
        "ai.keyword-recommendation.promote",
        "tool.ai.keyword_recommendation.promote",
        "ai-keyword-promotion.schema.json",
        "ai-keyword-promotion.schema.json",
        ["AI_ASSISTANCE_ENGINE_CONTRACT"],
        True,
        True,
        False,
        True,
        True,
        1,
    ),
    (
        "ai.capabilities",
        "ai.capabilities",
        "tool.ai.capabilities",
        "ai-provider-capability.schema.json",
        "ai-provider-capability.schema.json",
        ["AI_ASSISTANCE_ENGINE_CONTRACT"],
        False,
        False,
        False,
        True,
        False,
        1,
    ),
)



def _enum_value(value: Any) -> str:
    return str(value.value if hasattr(value, "value") else value)


def _dedupe(values: Iterable[str]) -> list[str]:
    return sorted({str(item) for item in values if str(item)})


def _json_clone(value: Any) -> Any:
    return json.loads(json.dumps(value, ensure_ascii=False))


def _cursor(payload: Mapping[str, Any]) -> str:
    raw = json.dumps(dict(payload), ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return base64.urlsafe_b64encode(raw.encode("utf-8")).decode("ascii")


def _decode_cursor(value: str | None) -> dict[str, Any] | None:
    if value is None:
        return None
    try:
        return dict(json.loads(base64.urlsafe_b64decode(value.encode("ascii")).decode("utf-8")))
    except Exception as error:
        raise CursorInvalidError("Cursor is not a valid Phase 6 opaque cursor.") from error


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


def _reject_forbidden_json(value: Any, *, target: str) -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            normalized = str(key).casefold().replace("-", "_")
            if any(part in normalized for part in _SECRET_KEY_PARTS):
                raise ValidationError(
                    "Context data cannot store secrets, prompts, or credentials.", target=target
                )
            if any(part == normalized for part in _RAW_BLOB_KEYS):
                raise ValidationError("Context data cannot store raw binary blobs.", target=target)
            _reject_forbidden_json(item, target=target)
    elif isinstance(value, list):
        for item in value:
            _reject_forbidden_json(item, target=target)


def _validate_json_budget(value: Any, *, target: str) -> None:
    _reject_forbidden_json(value, target=target)
    if _depth(value) > MAX_JSON_DEPTH:
        raise ContextFilterLimitExceededError(
            "Context JSON exceeds the maximum depth.", target=target
        )
    if len(canonical_json_bytes(value)) > MAX_FILTER_BYTES:
        raise ContextFilterLimitExceededError(
            "Context JSON exceeds the maximum serialized size.", target=target
        )


def _redact(value: Any) -> Any:
    if isinstance(value, Mapping):
        redacted: dict[str, Any] = {}
        for key, item in value.items():
            normalized = str(key).casefold().replace("-", "_")
            if any(part in normalized for part in _SECRET_KEY_PARTS):
                redacted[str(key)] = "[REDACTED]"
            elif any(part == normalized for part in _RAW_BLOB_KEYS):
                redacted[str(key)] = "[REDACTED_BLOB]"
            else:
                redacted[str(key)] = _redact(item)
        return redacted
    if isinstance(value, list):
        return [_redact(item) for item in value]
    if isinstance(value, bytes):
        return "[REDACTED_BYTES]"
    return value


def _resource_error(resource_type: str, resource_id: str) -> NotFoundError:
    return NotFoundError(
        "RESOURCE_NOT_FOUND",
        f"Resource not found: {resource_type}:{resource_id}",
        target="resource_id",
    )


def _stable_revision_states(states: list[RevisionState]) -> list[dict[str, Any]]:
    return [
        {
            "resource_type": _enum_value(state.resource_type),
            "resource_id": state.resource_id,
            "expected_revision": state.expected_revision,
            "current_revision": state.current_revision,
            "status": _enum_value(state.status),
            "reason": state.reason,
        }
        for state in sorted(
            states, key=lambda item: (_enum_value(item.resource_type), item.resource_id)
        )
    ]


class ContextService:
    """Coordinates Phase 6 live contexts, immutable snapshots, and scope pages."""

    def __init__(
        self,
        *,
        repository: Any,
        clock: Clock,
        id_generator: IdGenerator,
        ttl_seconds: int = DEFAULT_CONTEXT_TTL_SECONDS,
    ) -> None:
        self._repository = repository
        self._clock = clock
        self._id_generator = id_generator
        self._ttl_seconds = ttl_seconds

    def create(
        self,
        *,
        session_id: str,
        case_id: str,
        actor_id: str | None = None,
        locale: str = "ko-KR",
        timezone: str = "Asia/Seoul",
        current_route: GuiRoute | str = GuiRoute.CASE_OVERVIEW,
        current_panel: str | None = None,
        active_evidence_id: str | None = None,
        selected_file_node_ids: list[str] | None = None,
        selected_artifact_ids: list[str] | None = None,
        selected_timeline_event_ids: list[str] | None = None,
        selected_search_result_ids: list[str] | None = None,
        selected_media_artifact_ids: list[str] | None = None,
        selected_browser_artifact_ids: list[str] | None = None,
        selected_candidate_ids: list[str] | None = None,
        active_filters: dict[str, Any] | None = None,
        active_sort: dict[str, Any] | None = None,
        active_time_range: dict[str, Any] | None = None,
        active_keyword_set_id: str | None = None,
        active_keyword_set_version: int | None = None,
        active_search_execution_id: str | None = None,
        active_timeline_revision: int | None = None,
        active_context_scope: AnalysisScopeType | str = AnalysisScopeType.CASE,
        ui_preferences: dict[str, Any] | None = None,
        expires_at: str | None = None,
    ) -> GuiSessionContext:
        self._require_case(case_id)
        if active_evidence_id is not None:
            self._require_evidence_for_case(case_id, active_evidence_id)
        now = self._clock.now()
        expiration = (
            parse_timestamp(expires_at)
            if expires_at is not None
            else now + timedelta(seconds=self._ttl_seconds)
        )
        context = GuiSessionContext(
            session_context_id=self._id_generator.new_id(),
            session_id=session_id,
            case_id=case_id,
            actor_id=actor_id,
            locale=locale,
            timezone=timezone,
            current_route=GuiRoute(_enum_value(current_route)),
            current_panel=current_panel,
            active_evidence_id=active_evidence_id,
            selected_file_node_ids=_dedupe(selected_file_node_ids or []),
            selected_artifact_ids=_dedupe(selected_artifact_ids or []),
            selected_timeline_event_ids=_dedupe(selected_timeline_event_ids or []),
            selected_search_result_ids=_dedupe(selected_search_result_ids or []),
            selected_media_artifact_ids=_dedupe(selected_media_artifact_ids or []),
            selected_browser_artifact_ids=_dedupe(selected_browser_artifact_ids or []),
            selected_candidate_ids=_dedupe(selected_candidate_ids or []),
            active_filters=active_filters or {},
            active_sort=active_sort or {},
            active_time_range=active_time_range or {},
            active_keyword_set_id=active_keyword_set_id,
            active_keyword_set_version=active_keyword_set_version,
            active_search_execution_id=active_search_execution_id,
            active_timeline_revision=active_timeline_revision,
            active_context_scope=AnalysisScopeType(_enum_value(active_context_scope)),
            ui_preferences=ui_preferences or {},
            context_revision=1,
            created_at=now,
            updated_at=now,
            expires_at=expiration,
        )
        states = self.validate_source_revisions(context)
        context.is_partial = any(state.status == RevisionStatus.PARTIAL for state in states)
        context.stale_reasons = _dedupe(
            state.reason or "UNKNOWN" for state in states if state.status != RevisionStatus.CURRENT
        )
        context.source_revision_fingerprint = self._source_revision_fingerprint(states)
        self._validate_context_payload(context)
        self._repository.save_gui_session_context(context)
        return context

    def get(self, session_context_id: str) -> GuiSessionContext:
        context = cast(
            GuiSessionContext | None,
            self._repository.get_gui_session_context(session_context_id),
        )
        if context is None:
            raise NotFoundError(
                "RESOURCE_NOT_FOUND", "GUI session context not found.", target="session_context_id"
            )
        return context

    def update(
        self, session_context_id: str, *, expected_revision: int, **updates: Any
    ) -> GuiSessionContext:
        context = self.get(session_context_id)
        self._ensure_live(context)
        if context.context_revision != expected_revision:
            raise ContextRevisionConflictError(
                "GUI session context revision conflict.", target="expected_revision"
            )
        updated = self._apply_updates(context, updates)
        return self._persist_context_update(updated, expected_revision=expected_revision)

    def patch(
        self, session_context_id: str, *, expected_revision: int, patch: dict[str, Any]
    ) -> GuiSessionContext:
        return self.update(session_context_id, expected_revision=expected_revision, **patch)

    def select_items(
        self,
        session_context_id: str,
        *,
        expected_revision: int,
        resource_type: ResourceType | str,
        resource_ids: list[str],
        mode: str = "replace",
    ) -> GuiSessionContext:
        context = self.get(session_context_id)
        self._ensure_live(context)
        if context.context_revision != expected_revision:
            raise ContextRevisionConflictError(
                "GUI session context revision conflict.", target="expected_revision"
            )
        field = self._selection_field(resource_type)
        existing = list(getattr(context, field))
        if mode == "append":
            values = _dedupe(existing + resource_ids)
        elif mode == "remove":
            remove = set(resource_ids)
            values = [item for item in existing if item not in remove]
        elif mode == "replace":
            values = _dedupe(resource_ids)
        else:
            raise ValidationError(
                "Selection mode must be replace, append, or remove.", target="mode"
            )
        return self.update(
            session_context_id, expected_revision=expected_revision, **{field: values}
        )

    def clear_selection(
        self, session_context_id: str, *, expected_revision: int
    ) -> GuiSessionContext:
        return self.update(
            session_context_id,
            expected_revision=expected_revision,
            selected_file_node_ids=[],
            selected_artifact_ids=[],
            selected_timeline_event_ids=[],
            selected_search_result_ids=[],
            selected_media_artifact_ids=[],
            selected_browser_artifact_ids=[],
            selected_candidate_ids=[],
        )

    def set_filters(
        self, session_context_id: str, *, expected_revision: int, filters: dict[str, Any]
    ) -> GuiSessionContext:
        return self.update(
            session_context_id, expected_revision=expected_revision, active_filters=filters
        )

    def set_time_range(
        self,
        session_context_id: str,
        *,
        expected_revision: int,
        time_range: dict[str, Any],
    ) -> GuiSessionContext:
        return self.update(
            session_context_id, expected_revision=expected_revision, active_time_range=time_range
        )

    def set_keyword_set(
        self,
        session_context_id: str,
        *,
        expected_revision: int,
        keyword_set_id: str | None,
        keyword_set_version: int | None,
    ) -> GuiSessionContext:
        return self.update(
            session_context_id,
            expected_revision=expected_revision,
            active_keyword_set_id=keyword_set_id,
            active_keyword_set_version=keyword_set_version,
        )

    def set_search_execution(
        self,
        session_context_id: str,
        *,
        expected_revision: int,
        search_execution_id: str | None,
    ) -> GuiSessionContext:
        return self.update(
            session_context_id,
            expected_revision=expected_revision,
            active_search_execution_id=search_execution_id,
        )

    def set_timeline_revision(
        self,
        session_context_id: str,
        *,
        expected_revision: int,
        timeline_revision: int | None,
    ) -> GuiSessionContext:
        return self.update(
            session_context_id,
            expected_revision=expected_revision,
            active_timeline_revision=timeline_revision,
        )

    def refresh_revision_state(
        self, session_context_id: str, *, expected_revision: int | None = None
    ) -> dict[str, Any]:
        context = self.get(session_context_id)
        self._ensure_live(context)
        if expected_revision is not None and context.context_revision != expected_revision:
            raise ContextRevisionConflictError(
                "GUI session context revision conflict.", target="expected_revision"
            )
        states = self.validate_source_revisions(context)
        current_fingerprint = self._source_revision_fingerprint(states)
        stale_reasons = list(context.stale_reasons)
        if current_fingerprint != context.source_revision_fingerprint:
            stale_reasons = _dedupe(
                stale_reasons
                + [
                    state.reason or StaleReason.UNKNOWN.value
                    for state in states
                    if state.status != RevisionStatus.CURRENT
                ]
            )
            if not stale_reasons:
                stale_reasons = [StaleReason.UNKNOWN.value]
        refreshed = replace(
            context,
            is_partial=any(state.status == RevisionStatus.PARTIAL for state in states),
            stale_reasons=stale_reasons,
            updated_at=self._clock.now(),
        )
        if refreshed.to_schema_dict() != context.to_schema_dict():
            refreshed.context_revision = context.context_revision + 1
            self._repository.save_gui_session_context(refreshed)
        return {
            "session_context": refreshed.to_schema_dict(),
            "source_revision_fingerprint": context.source_revision_fingerprint,
            "current_source_revision_fingerprint": current_fingerprint,
            "revision_states": [state.to_schema_dict() for state in states],
            "stale": bool(stale_reasons),
        }

    def clone(
        self,
        session_context_id: str,
        *,
        session_id: str | None = None,
        actor_id: str | None = None,
    ) -> GuiSessionContext:
        context = self.get(session_context_id)
        return self.create(
            session_id=session_id or self._id_generator.new_id(),
            case_id=context.case_id,
            actor_id=actor_id if actor_id is not None else context.actor_id,
            locale=context.locale,
            timezone=context.timezone,
            current_route=context.current_route,
            current_panel=context.current_panel,
            active_evidence_id=context.active_evidence_id,
            selected_file_node_ids=context.selected_file_node_ids,
            selected_artifact_ids=context.selected_artifact_ids,
            selected_timeline_event_ids=context.selected_timeline_event_ids,
            selected_search_result_ids=context.selected_search_result_ids,
            selected_media_artifact_ids=context.selected_media_artifact_ids,
            selected_browser_artifact_ids=context.selected_browser_artifact_ids,
            selected_candidate_ids=context.selected_candidate_ids,
            active_filters=context.active_filters,
            active_sort=context.active_sort,
            active_time_range=context.active_time_range,
            active_keyword_set_id=context.active_keyword_set_id,
            active_keyword_set_version=context.active_keyword_set_version,
            active_search_execution_id=context.active_search_execution_id,
            active_timeline_revision=context.active_timeline_revision,
            active_context_scope=context.active_context_scope,
            ui_preferences=context.ui_preferences,
        )

    def expire(
        self, session_context_id: str, *, expected_revision: int | None = None
    ) -> GuiSessionContext:
        context = self.get(session_context_id)
        if expected_revision is not None and context.context_revision != expected_revision:
            raise ContextRevisionConflictError(
                "GUI session context revision conflict.", target="expected_revision"
            )
        expired = replace(
            context,
            context_revision=context.context_revision + 1,
            expires_at=self._clock.now(),
            updated_at=self._clock.now(),
        )
        self._repository.save_gui_session_context(expired)
        return expired

    def list_by_case(self, case_id: str) -> list[GuiSessionContext]:
        self._require_case(case_id)
        return cast(
            list[GuiSessionContext],
            self._repository.list_gui_session_contexts(case_id),
        )

    def compare_revisions(
        self, session_context_id: str, left_revision: int, right_revision: int
    ) -> dict[str, Any]:
        left = self._repository.get_gui_session_context_revision(session_context_id, left_revision)
        right = self._repository.get_gui_session_context_revision(
            session_context_id, right_revision
        )
        if left is None or right is None:
            raise NotFoundError(
                "RESOURCE_NOT_FOUND", "Context revision not found.", target="context_revision"
            )
        left_dict = left.to_schema_dict()
        right_dict = right.to_schema_dict()
        return {
            "session_context_id": session_context_id,
            "left_revision": left_revision,
            "right_revision": right_revision,
            "changed_fields": [
                key
                for key in sorted(set(left_dict) | set(right_dict))
                if left_dict.get(key) != right_dict.get(key)
            ],
            "left": left_dict,
            "right": right_dict,
        }

    def build_from_session(
        self,
        session_context_id: str,
        *,
        purpose: AnalysisContextPurpose | str,
        scopes: list[str] | None = None,
        previous_snapshot_id: str | None = None,
        cancellation_token: CancellationToken | None = None,
    ) -> AnalysisContextSnapshot:
        context = self.get(session_context_id)
        self._check_cancel(cancellation_token)
        states = self.validate_source_revisions(context)
        included = self._context_included_resources(context)
        snapshot_scopes = scopes or self._scopes_from_included(included)
        return self._create_snapshot(
            case_id=context.case_id,
            session_context_id=context.session_context_id,
            session_context_revision=context.context_revision,
            actor_id=context.actor_id,
            purpose=purpose,
            scopes=snapshot_scopes,
            included_resource_ids=included,
            excluded_resource_ids={},
            filters=context.active_filters,
            time_range=context.active_time_range,
            source_revisions=states,
            keyword_set_id=context.active_keyword_set_id,
            keyword_set_version=context.active_keyword_set_version,
            search_execution_id=context.active_search_execution_id,
            search_index_revision=self._search_index_revision(context.active_search_execution_id),
            timeline_revision=context.active_timeline_revision,
            previous_snapshot_id=previous_snapshot_id,
            cancellation_token=cancellation_token,
        )

    def snapshot(self, session_context_id: str, **kwargs: Any) -> AnalysisContextSnapshot:
        return self.build_from_session(session_context_id, **kwargs)

    def build_from_selection(
        self,
        *,
        case_id: str,
        actor_id: str | None,
        purpose: AnalysisContextPurpose | str,
        resources: dict[str, list[str]],
        scopes: list[str] | None = None,
        filters: dict[str, Any] | None = None,
        time_range: dict[str, Any] | None = None,
        previous_snapshot_id: str | None = None,
        cancellation_token: CancellationToken | None = None,
    ) -> AnalysisContextSnapshot:
        self._require_case(case_id)
        included_resources = {key: _dedupe(value) for key, value in resources.items() if value}
        states = self._revision_states_for_resources(case_id, included_resources)
        return self._create_snapshot(
            case_id=case_id,
            session_context_id=None,
            session_context_revision=None,
            actor_id=actor_id,
            purpose=purpose,
            scopes=scopes or self._scopes_from_included(included_resources),
            included_resource_ids=included_resources,
            excluded_resource_ids={},
            filters=filters or {},
            time_range=time_range or {},
            source_revisions=states,
            keyword_set_id=None,
            keyword_set_version=None,
            search_execution_id=None,
            search_index_revision=None,
            timeline_revision=None,
            previous_snapshot_id=previous_snapshot_id,
            cancellation_token=cancellation_token,
        )

    def build_by_scope(
        self,
        *,
        case_id: str,
        actor_id: str | None,
        purpose: AnalysisContextPurpose | str,
        scope: AnalysisScopeType | str,
        limit: int = MAX_SCOPE_ITEMS,
        previous_snapshot_id: str | None = None,
    ) -> AnalysisContextSnapshot:
        self._require_case(case_id)
        scope_value = _enum_value(scope)
        resources = self._resource_ids_for_scope(case_id=case_id, scope=scope_value, limit=limit)
        return self.build_from_selection(
            case_id=case_id,
            actor_id=actor_id,
            purpose=purpose,
            scopes=[scope_value],
            resources=resources,
            previous_snapshot_id=previous_snapshot_id,
        )

    def get_snapshot(self, context_snapshot_id: str) -> AnalysisContextSnapshot:
        snapshot = cast(
            AnalysisContextSnapshot | None,
            self._repository.get_analysis_context_snapshot(context_snapshot_id),
        )
        if snapshot is None:
            raise NotFoundError(
                "RESOURCE_NOT_FOUND",
                "Analysis context snapshot not found.",
                target="context_snapshot_id",
            )
        return snapshot

    def add_scope(
        self,
        context_snapshot_id: str,
        scope: AnalysisScopeType | str,
        *,
        limit: int = MAX_SCOPE_ITEMS,
    ) -> AnalysisContextSnapshot:
        snapshot = self.get_snapshot(context_snapshot_id)
        scope_value = _enum_value(scope)
        if scope_value in snapshot.scopes:
            return snapshot
        resources = _json_clone(snapshot.included_resource_ids)
        for key, values in self._resource_ids_for_scope(
            case_id=snapshot.case_id, scope=scope_value, limit=limit
        ).items():
            resources[key] = _dedupe(resources.get(key, []) + values)
        return self.build_from_selection(
            case_id=snapshot.case_id,
            actor_id=snapshot.actor_id,
            purpose=snapshot.purpose,
            scopes=[*snapshot.scopes, scope_value],
            resources=resources,
            filters=snapshot.filters,
            time_range=snapshot.time_range,
            previous_snapshot_id=snapshot.context_snapshot_id,
        )

    def remove_scope(
        self, context_snapshot_id: str, scope: AnalysisScopeType | str
    ) -> AnalysisContextSnapshot:
        snapshot = self.get_snapshot(context_snapshot_id)
        scope_value = _enum_value(scope)
        remaining = [item for item in snapshot.scopes if item != scope_value]
        resources = {
            key: values
            for key, values in snapshot.included_resource_ids.items()
            if key not in _SCOPE_RESOURCE_TYPES.get(scope_value, ())
        }
        return self.build_from_selection(
            case_id=snapshot.case_id,
            actor_id=snapshot.actor_id,
            purpose=snapshot.purpose,
            scopes=remaining,
            resources=resources,
            filters=snapshot.filters,
            time_range=snapshot.time_range,
            previous_snapshot_id=snapshot.context_snapshot_id,
        )

    def refresh(self, context_snapshot_id: str) -> AnalysisContextSnapshot:
        snapshot = self.get_snapshot(context_snapshot_id)
        source_revisions = self._refresh_snapshot_source_revisions(snapshot)
        return self._create_snapshot(
            case_id=snapshot.case_id,
            session_context_id=snapshot.session_context_id,
            session_context_revision=snapshot.session_context_revision,
            actor_id=snapshot.actor_id,
            purpose=snapshot.purpose,
            scopes=snapshot.scopes,
            included_resource_ids=snapshot.included_resource_ids,
            excluded_resource_ids=snapshot.excluded_resource_ids,
            filters=snapshot.filters,
            time_range=snapshot.time_range,
            source_revisions=source_revisions,
            keyword_set_id=snapshot.keyword_set_id,
            keyword_set_version=snapshot.keyword_set_version,
            search_execution_id=snapshot.search_execution_id,
            search_index_revision=snapshot.search_index_revision,
            timeline_revision=snapshot.timeline_revision,
            previous_snapshot_id=snapshot.context_snapshot_id,
            cancellation_token=None,
        )

    def compare(self, left_snapshot_id: str, right_snapshot_id: str) -> dict[str, Any]:
        left = self.get_snapshot(left_snapshot_id)
        right = self.get_snapshot(right_snapshot_id)
        left_dict = left.to_schema_dict()
        right_dict = right.to_schema_dict()
        return {
            "left_snapshot_id": left_snapshot_id,
            "right_snapshot_id": right_snapshot_id,
            "same_fingerprint": left.context_fingerprint == right.context_fingerprint,
            "changed_fields": [
                key
                for key in sorted(set(left_dict) | set(right_dict))
                if left_dict.get(key) != right_dict.get(key)
            ],
            "left_source_revisions": left_dict["source_revisions"],
            "right_source_revisions": right_dict["source_revisions"],
        }

    def list_scopes(self, context_snapshot_id: str) -> list[AnalysisScopeContext]:
        self.get_snapshot(context_snapshot_id)
        return cast(
            list[AnalysisScopeContext],
            self._repository.list_analysis_scope_contexts(context_snapshot_id),
        )

    def paginate_scope(
        self,
        context_snapshot_id: str,
        scope: AnalysisScopeType | str,
        *,
        cursor: str | None = None,
        limit: int = 100,
    ) -> dict[str, Any]:
        if limit < 1 or limit > MAX_SCOPE_ITEMS:
            raise ValidationError("Scope page limit must be between 1 and 1000.", target="limit")
        scope_value = _enum_value(scope)
        decoded = _decode_cursor(cursor)
        offset = 0
        if decoded is not None:
            if (
                decoded.get("snapshot_id") != context_snapshot_id
                or decoded.get("scope") != scope_value
            ):
                raise CursorInvalidError(
                    "Cursor does not belong to this snapshot scope.", target="cursor"
                )
            offset = int(decoded.get("offset", 0))
        scope_context = self._repository.get_analysis_scope_context(
            context_snapshot_id, scope_value
        )
        if scope_context is None:
            raise NotFoundError(
                "RESOURCE_NOT_FOUND", "Analysis scope context not found.", target="scope"
            )
        ids = scope_context.resource_ids
        items = ids[offset : offset + limit]
        next_offset = offset + len(items)
        next_cursor = None
        if next_offset < len(ids):
            next_cursor = _cursor(
                {"snapshot_id": context_snapshot_id, "scope": scope_value, "offset": next_offset}
            )
        return {
            "context_snapshot_id": context_snapshot_id,
            "scope_type": scope_value,
            "items": [
                self.resolve_resource(
                    resource_type=self._resource_type_for_scope_item(
                        self.get_snapshot(context_snapshot_id), scope_value, item
                    ),
                    resource_id=item,
                )
                for item in items
            ],
            "page": {
                "next_cursor": next_cursor,
                "has_more": next_cursor is not None,
                "returned": len(items),
            },
            "scope": scope_context.to_schema_dict(),
        }

    def resolve_resource(
        self, *, resource_type: ResourceType | str, resource_id: str
    ) -> dict[str, Any]:
        return self._resource_info(_enum_value(resource_type), resource_id)

    def validate_source_revisions(self, context: GuiSessionContext) -> list[RevisionState]:
        states = self._revision_states_for_resources(
            context.case_id, self._context_included_resources(context)
        )
        if context.active_search_execution_id is not None:
            execution = self._repository.get_search_execution(context.active_search_execution_id)
            if execution is None:
                states.append(
                    self._missing_state(
                        ResourceType.SEARCH_RESULT.value,
                        context.active_search_execution_id,
                        StaleReason.SEARCH_EXECUTION_STALE.value,
                    )
                )
            elif execution.case_id != context.case_id:
                raise ContextScopeMismatchError(
                    "Search execution belongs to another case.", target="active_search_execution_id"
                )
            else:
                states.append(
                    RevisionState(
                        ResourceType.SEARCH_RESULT.value,
                        execution.execution_id,
                        context.active_search_execution_id,
                        execution.execution_revision,
                        RevisionStatus.CURRENT,
                        None,
                        self._clock.now(),
                    )
                )
        return states

    def _revision_states_for_resources(
        self, case_id: str, included_resources: dict[str, list[str]]
    ) -> list[RevisionState]:
        states: list[RevisionState] = []
        for resource_type, resource_ids in included_resources.items():
            for resource_id in resource_ids:
                info = self._resource_info(resource_type, resource_id)
                if info["case_id"] != case_id:
                    raise ContextScopeMismatchError(
                        "Selected resource belongs to another case.",
                        target="resource_id",
                        details={"resource_type": resource_type, "resource_id": resource_id},
                    )
                state_status = (
                    RevisionStatus.PARTIAL if info["is_partial"] else RevisionStatus.CURRENT
                )
                reason = (
                    StaleReason.UNKNOWN.value if state_status == RevisionStatus.PARTIAL else None
                )
                states.append(
                    RevisionState(
                        resource_type=resource_type,
                        resource_id=resource_id,
                        expected_revision=info["source_revision"],
                        current_revision=info["source_revision"],
                        status=state_status,
                        reason=reason,
                        detected_at=self._clock.now(),
                    )
                )
        return states

    def summarize_coverage_metadata(self, snapshot_id: str) -> dict[str, Any]:
        scopes = self.list_scopes(snapshot_id)
        return {
            "context_snapshot_id": snapshot_id,
            "scope_count": len(scopes),
            "result_count": sum(scope.result_count for scope in scopes),
            "included_count": sum(scope.included_count for scope in scopes),
            "partial_scopes": [scope.scope_type for scope in scopes if scope.is_partial],
            "stale_reasons": _dedupe(reason for scope in scopes for reason in scope.stale_reasons),
        }

    def _persist_context_update(
        self, context: GuiSessionContext, *, expected_revision: int
    ) -> GuiSessionContext:
        states = self.validate_source_revisions(context)
        context.context_revision = expected_revision + 1
        context.updated_at = self._clock.now()
        context.is_partial = any(state.status == RevisionStatus.PARTIAL for state in states)
        context.source_revision_fingerprint = self._source_revision_fingerprint(states)
        context.stale_reasons = _dedupe(
            state.reason or "UNKNOWN" for state in states if state.status != RevisionStatus.CURRENT
        )
        self._validate_context_payload(context)
        self._repository.save_gui_session_context(context)
        return context

    def _apply_updates(
        self, context: GuiSessionContext, updates: dict[str, Any]
    ) -> GuiSessionContext:
        allowed = set(context.to_schema_dict()) - {
            "session_context_id",
            "case_id",
            "context_revision",
            "created_at",
            "updated_at",
            "source_revision_fingerprint",
            "is_partial",
            "stale_reasons",
        }
        unknown = sorted(set(updates) - allowed)
        if unknown:
            raise ValidationError("Context update contains unsupported fields.", target=unknown[0])
        data = context.to_schema_dict()
        data.update(updates)
        data["selected_file_node_ids"] = _dedupe(data["selected_file_node_ids"])
        data["selected_artifact_ids"] = _dedupe(data["selected_artifact_ids"])
        data["selected_timeline_event_ids"] = _dedupe(data["selected_timeline_event_ids"])
        data["selected_search_result_ids"] = _dedupe(data["selected_search_result_ids"])
        data["selected_media_artifact_ids"] = _dedupe(data["selected_media_artifact_ids"])
        data["selected_browser_artifact_ids"] = _dedupe(data["selected_browser_artifact_ids"])
        data["selected_candidate_ids"] = _dedupe(data["selected_candidate_ids"])
        expires_at = data.get("expires_at")
        return GuiSessionContext(
            session_context_id=context.session_context_id,
            session_id=str(data["session_id"]),
            case_id=context.case_id,
            actor_id=data.get("actor_id"),
            locale=str(data["locale"]),
            timezone=str(data["timezone"]),
            current_route=GuiRoute(str(data["current_route"])),
            current_panel=data.get("current_panel"),
            active_evidence_id=data.get("active_evidence_id"),
            selected_file_node_ids=list(data["selected_file_node_ids"]),
            selected_artifact_ids=list(data["selected_artifact_ids"]),
            selected_timeline_event_ids=list(data["selected_timeline_event_ids"]),
            selected_search_result_ids=list(data["selected_search_result_ids"]),
            selected_media_artifact_ids=list(data["selected_media_artifact_ids"]),
            selected_browser_artifact_ids=list(data["selected_browser_artifact_ids"]),
            selected_candidate_ids=list(data["selected_candidate_ids"]),
            active_filters=dict(data["active_filters"]),
            active_sort=dict(data["active_sort"]),
            active_time_range=dict(data["active_time_range"]),
            active_keyword_set_id=data.get("active_keyword_set_id"),
            active_keyword_set_version=data.get("active_keyword_set_version"),
            active_search_execution_id=data.get("active_search_execution_id"),
            active_timeline_revision=data.get("active_timeline_revision"),
            active_context_scope=AnalysisScopeType(str(data["active_context_scope"])),
            ui_preferences=dict(data["ui_preferences"]),
            context_revision=context.context_revision,
            source_revision_fingerprint=context.source_revision_fingerprint,
            is_partial=context.is_partial,
            stale_reasons=list(context.stale_reasons),
            created_at=context.created_at,
            updated_at=context.updated_at,
            expires_at=parse_timestamp(str(expires_at))
            if isinstance(expires_at, str)
            else context.expires_at,
        )

    def _validate_context_payload(self, context: GuiSessionContext) -> None:
        selections = [ids for _, ids in self._context_resource_pairs(context)]
        if sum(len(ids) for ids in selections) > MAX_SELECTION_IDS:
            raise ContextSelectionLimitExceededError(
                "Context selection exceeds the maximum item count.", target="selection"
            )
        for target, value in (
            ("active_filters", context.active_filters),
            ("active_sort", context.active_sort),
            ("active_time_range", context.active_time_range),
            ("ui_preferences", context.ui_preferences),
        ):
            _validate_json_budget(value, target=target)
        if len(canonical_json_bytes(context.to_schema_dict())) > MAX_CONTEXT_PAYLOAD_BYTES:
            raise ContextFilterLimitExceededError(
                "Context payload exceeds the maximum size.", target="context"
            )

    def _create_snapshot(
        self,
        *,
        case_id: str,
        session_context_id: str | None,
        session_context_revision: int | None,
        actor_id: str | None,
        purpose: AnalysisContextPurpose | str,
        scopes: list[str],
        included_resource_ids: dict[str, list[str]],
        excluded_resource_ids: dict[str, list[str]],
        filters: dict[str, Any],
        time_range: dict[str, Any],
        source_revisions: list[RevisionState],
        keyword_set_id: str | None,
        keyword_set_version: int | None,
        search_execution_id: str | None,
        search_index_revision: int | None,
        timeline_revision: int | None,
        previous_snapshot_id: str | None,
        cancellation_token: CancellationToken | None,
    ) -> AnalysisContextSnapshot:
        self._check_cancel(cancellation_token)
        _validate_json_budget(filters, target="filters")
        _validate_json_budget(time_range, target="time_range")
        included = {key: _dedupe(value) for key, value in included_resource_ids.items() if value}
        excluded = {key: _dedupe(value) for key, value in excluded_resource_ids.items() if value}
        citations = self._collect_citations(included)[:MAX_CITATIONS]
        partial_state = {
            "is_partial": any(state.status == RevisionStatus.PARTIAL for state in source_revisions),
            "partial_resource_ids": [
                state.resource_id
                for state in source_revisions
                if state.status == RevisionStatus.PARTIAL
            ],
        }
        stale_state = {
            "is_stale": any(
                _enum_value(state.status)
                not in {RevisionStatus.CURRENT.value, RevisionStatus.PARTIAL.value}
                for state in source_revisions
            ),
            "stale_reasons": _dedupe(
                state.reason or "UNKNOWN"
                for state in source_revisions
                if _enum_value(state.status)
                not in {RevisionStatus.CURRENT.value, RevisionStatus.PARTIAL.value}
            ),
        }
        analyzer_versions = self._collect_analyzer_versions(included)
        fingerprint_payload = {
            "case_id": case_id,
            "purpose": _enum_value(purpose),
            "scopes": sorted(scopes),
            "included_resource_ids": included,
            "excluded_resource_ids": excluded,
            "filters": filters,
            "time_range": time_range,
            "source_revisions": _stable_revision_states(source_revisions),
            "analyzer_versions": analyzer_versions,
            "search_index_revision": search_index_revision,
            "timeline_revision": timeline_revision,
            "keyword_set_id": keyword_set_id,
            "keyword_set_version": keyword_set_version,
            "search_execution_id": search_execution_id,
            "partial_state": partial_state,
            "stale_state": stale_state,
            "citations": citations,
        }
        snapshot = AnalysisContextSnapshot(
            context_snapshot_id=self._id_generator.new_id(),
            case_id=case_id,
            session_context_id=session_context_id,
            session_context_revision=session_context_revision,
            actor_id=actor_id,
            purpose=AnalysisContextPurpose(_enum_value(purpose)),
            scopes=sorted(set(scopes)),
            included_resource_ids=included,
            excluded_resource_ids=excluded,
            filters=_redact(filters),
            time_range=time_range,
            source_revisions=source_revisions,
            analyzer_versions=analyzer_versions,
            search_index_revision=search_index_revision,
            timeline_revision=timeline_revision,
            keyword_set_id=keyword_set_id,
            keyword_set_version=keyword_set_version,
            search_execution_id=search_execution_id,
            partial_state=partial_state,
            stale_state=stale_state,
            warnings=[],
            citations=citations,
            context_fingerprint=canonical_sha256(fingerprint_payload),
            previous_snapshot_id=previous_snapshot_id,
            created_at=self._clock.now(),
        )
        self._repository.save_analysis_context_snapshot(snapshot)
        self._repository.save_context_revision_states(
            snapshot.context_snapshot_id, source_revisions
        )
        self._save_scope_contexts(snapshot, cancellation_token=cancellation_token)
        return snapshot

    def _save_scope_contexts(
        self, snapshot: AnalysisContextSnapshot, *, cancellation_token: CancellationToken | None
    ) -> None:
        for scope in snapshot.scopes:
            self._check_cancel(cancellation_token)
            included = self._included_resources_for_scope(snapshot, scope)
            resource_ids = _dedupe(
                resource_id for ids in included.values() for resource_id in ids
            )
            resource_pairs = {
                (resource_type, resource_id)
                for resource_type, ids in included.items()
                for resource_id in ids
            }
            states = [
                state
                for state in snapshot.source_revisions
                if (_enum_value(state.resource_type), state.resource_id) in resource_pairs
            ]
            continuation = None
            if len(resource_ids) > MAX_SCOPE_ITEMS:
                continuation = _cursor(
                    {
                        "snapshot_id": snapshot.context_snapshot_id,
                        "scope": scope,
                        "offset": MAX_SCOPE_ITEMS,
                    }
                )
            scope_payload = {
                "snapshot": snapshot.context_snapshot_id,
                "scope": scope,
                "resources": resource_ids,
                "included_resource_ids": included,
                "source_revisions": _stable_revision_states(states),
                "filters": snapshot.filters,
                "time_range": snapshot.time_range,
            }
            scope_context = AnalysisScopeContext(
                scope_context_id=self._id_generator.new_id(),
                context_snapshot_id=snapshot.context_snapshot_id,
                scope_type=scope,
                case_id=snapshot.case_id,
                evidence_ids=self._evidence_ids_for_included(included),
                resource_ids=resource_ids,
                source_revisions=states,
                analyzer_versions=self._collect_analyzer_versions(included),
                filters=snapshot.filters,
                sort={},
                time_range=snapshot.time_range,
                result_count=len(resource_ids),
                included_count=min(len(resource_ids), MAX_SCOPE_ITEMS),
                excluded_count=0,
                is_partial=len(resource_ids) > MAX_SCOPE_ITEMS
                or any(state.status == RevisionStatus.PARTIAL for state in states),
                coverage=self._coverage_for_scope(snapshot.case_id, scope),
                stale_reasons=_dedupe(
                    state.reason or "UNKNOWN"
                    for state in states
                    if state.status != RevisionStatus.CURRENT
                ),
                warnings=[],
                citations=self._collect_citations(included)[:MAX_CITATIONS],
                continuation_cursor=continuation,
                scope_fingerprint=canonical_sha256(scope_payload),
                created_at=self._clock.now(),
            )
            self._repository.save_analysis_scope_context(scope_context)

    def _resource_ids_for_scope(
        self, *, case_id: str, scope: str, limit: int
    ) -> dict[str, list[str]]:
        if scope == AnalysisScopeType.EVIDENCE.value:
            return {
                ResourceType.EVIDENCE.value: self._repository.list_resource_ids(
                    "evidence", "evidence_id", case_id, limit
                )
            }
        if scope == AnalysisScopeType.FILESYSTEM.value:
            return {
                ResourceType.FILE_SYSTEM_NODE.value: self._repository.list_resource_ids(
                    "fs_nodes", "node_id", case_id, limit
                )
            }
        if scope in _ARTIFACT_RESOURCE_TYPE_BY_SCOPE:
            artifact_types = {
                AnalysisScopeType.REGISTRY.value: [
                    ArtifactType.REGISTRY_KEY.value,
                    ArtifactType.REGISTRY_VALUE.value,
                    ArtifactType.REGISTRY_AUTORUN.value,
                    ArtifactType.REGISTRY_USB_DEVICE.value,
                    ArtifactType.REGISTRY_TIMEZONE.value,
                    ArtifactType.REGISTRY_USERASSIST.value,
                ],
                AnalysisScopeType.EVENTLOG.value: [ArtifactType.EVENT_LOG_RECORD.value],
                AnalysisScopeType.PREFETCH.value: [ArtifactType.PREFETCH_EXECUTION.value],
                AnalysisScopeType.BROWSER.value: [
                    ArtifactType.BROWSER_PROFILE.value,
                    ArtifactType.BROWSER_VISIT.value,
                    ArtifactType.BROWSER_SEARCH.value,
                    ArtifactType.BROWSER_DOWNLOAD.value,
                ],
                AnalysisScopeType.MEDIA.value: [
                    ArtifactType.MEDIA_IMAGE.value,
                    ArtifactType.MEDIA_VIDEO.value,
                    ArtifactType.MEDIA_AUDIO.value,
                ],
            }[scope]
            artifact_resource_type = _ARTIFACT_RESOURCE_TYPE_BY_SCOPE[scope]
            artifact_ids = self._repository.list_artifact_ids_for_types(
                case_id, artifact_types, limit
            )
            return {artifact_resource_type: artifact_ids}
        if scope == AnalysisScopeType.TIMELINE.value:
            return {
                ResourceType.TIMELINE_EVENT.value: self._repository.list_resource_ids(
                    "timeline_events", "timeline_event_id", case_id, limit
                )
            }
        if scope == AnalysisScopeType.KEYWORD_SEARCH.value:
            return {
                ResourceType.SEARCH_RESULT.value: self._repository.list_search_result_ids_for_case(
                    case_id, limit
                )
            }
        if scope == AnalysisScopeType.MACHINE_CANDIDATE.value:
            return {
                ResourceType.MACHINE_CANDIDATE.value: self._repository.list_resource_ids(
                    "machine_extracted_candidates", "candidate_id", case_id, limit
                )
            }
        if scope == AnalysisScopeType.CHAIN_OF_CUSTODY.value:
            return {
                ResourceType.CUSTODY_EVENT.value: self._repository.list_resource_ids(
                    "custody_events", "event_id", case_id, limit
                )
            }
        return {}

    def _resource_info(self, resource_type: str, resource_id: str) -> dict[str, Any]:
        if resource_type == ResourceType.FILE_SYSTEM_NODE.value:
            node = self._repository.get_fs_node(resource_id)
            if node is None:
                raise _resource_error(resource_type, resource_id)
            return {
                "resource_type": resource_type,
                "resource_id": resource_id,
                "case_id": node.case_id,
                "evidence_id": node.evidence_id,
                "source_revision": node.index_revision,
                "is_partial": node.is_partial,
                "title": node.display_path or node.original_name,
                "summary": node.node_type.value,
                "raw_locator": node.raw_locator,
                "citations": [],
                "fields": node.to_schema_dict(),
                "analyzer_id": node.provider_id,
                "analyzer_version": node.provider_version,
            }
        if resource_type == ResourceType.EVIDENCE.value:
            evidence = self._repository.get_evidence(resource_id)
            if evidence is None:
                raise _resource_error(resource_type, resource_id)
            fingerprint = evidence.fingerprint.value if evidence.fingerprint is not None else None
            return {
                "resource_type": resource_type,
                "resource_id": resource_id,
                "case_id": evidence.case_id,
                "evidence_id": evidence.evidence_id,
                "source_revision": fingerprint or to_json_timestamp(evidence.updated_at),
                "is_partial": False,
                "title": evidence.display_name,
                "summary": evidence.status.value,
                "raw_locator": None,
                "citations": [],
                "fields": evidence.to_schema_dict(),
                "analyzer_id": "evidence.manager",
                "analyzer_version": ENGINE_VERSION,
            }
        if resource_type in {
            ResourceType.ARTIFACT.value,
            ResourceType.REGISTRY.value,
            ResourceType.EVENT_LOG.value,
            ResourceType.PREFETCH.value,
            ResourceType.BROWSER.value,
            ResourceType.MEDIA.value,
        }:
            artifact = self._repository.get_artifact(resource_id)
            if artifact is None:
                raise _resource_error(resource_type, resource_id)
            artifact_scope = self._scope_for_artifact_type(artifact.artifact_type.value)
            requested_scope = _RESOURCE_SCOPE_BY_TYPE.get(resource_type)
            if (
                requested_scope in _ARTIFACT_RESOURCE_TYPE_BY_SCOPE
                and artifact_scope != requested_scope
            ):
                raise ContextScopeMismatchError(
                    "Artifact is outside the requested analysis scope.",
                    target="resource_id",
                    details={
                        "resource_type": resource_type,
                        "resource_id": resource_id,
                        "artifact_type": artifact.artifact_type.value,
                    },
                )
            return {
                "resource_type": resource_type,
                "resource_id": resource_id,
                "case_id": artifact.case_id,
                "evidence_id": artifact.evidence_id,
                "source_revision": artifact.index_revision,
                "is_partial": artifact.is_partial,
                "title": artifact.title,
                "summary": artifact.summary,
                "raw_locator": artifact.raw_locator,
                "citations": artifact.citations,
                "fields": artifact.to_schema_dict(),
                "analyzer_id": artifact.analyzer_id,
                "analyzer_version": artifact.analyzer_version,
                "warnings": artifact.warnings,
                "confidence": artifact.confidence,
            }
        if resource_type == ResourceType.TIMELINE_EVENT.value:
            event = self._repository.get_timeline_event(resource_id)
            if event is None:
                raise _resource_error(resource_type, resource_id)
            return {
                "resource_type": resource_type,
                "resource_id": resource_id,
                "case_id": event.case_id,
                "evidence_id": event.evidence_id,
                "source_revision": event.timeline_revision,
                "is_partial": event.is_partial,
                "title": event.title,
                "summary": event.description,
                "raw_locator": event.raw_locator,
                "citations": event.citations,
                "fields": event.to_schema_dict(),
                "analyzer_id": event.analyzer_id,
                "analyzer_version": event.analyzer_version,
            }
        if resource_type == ResourceType.SEARCH_RESULT.value:
            result = self._repository.get_search_result(resource_id)
            if result is None:
                raise _resource_error(resource_type, resource_id)
            query = self._repository.get_search_query(result.query_id)
            case_id = (
                query.case_id
                if query is not None
                else self._repository.case_id_for_search_result(resource_id)
            )
            return {
                "resource_type": resource_type,
                "resource_id": resource_id,
                "case_id": case_id,
                "evidence_id": None,
                "source_revision": result.index_revision,
                "is_partial": result.is_partial,
                "title": result.snippet[:120] or result.source_id,
                "summary": ", ".join(result.matched_fields),
                "raw_locator": result.raw_locator,
                "citations": result.citations,
                "fields": result.to_schema_dict(),
                "analyzer_id": "sqlite-fts5",
                "analyzer_version": None,
            }
        if resource_type == ResourceType.MACHINE_CANDIDATE.value:
            candidate = self._repository.get_machine_candidate(resource_id)
            if candidate is None:
                raise _resource_error(resource_type, resource_id)
            return {
                "resource_type": resource_type,
                "resource_id": resource_id,
                "case_id": candidate.case_id,
                "evidence_id": candidate.evidence_id,
                "source_revision": candidate.source_revision,
                "is_partial": candidate.is_partial,
                "title": candidate.text[:120],
                "summary": candidate.extraction_type,
                "raw_locator": candidate.raw_locator,
                "citations": candidate.citations,
                "fields": candidate.to_schema_dict(),
                "analyzer_id": candidate.provider_id,
                "analyzer_version": candidate.provider_version,
                "confidence": candidate.confidence,
            }
        if resource_type == ResourceType.CUSTODY_EVENT.value:
            event = self._repository.get_custody_event(resource_id)
            if event is None:
                raise _resource_error(resource_type, resource_id)
            return {
                "resource_type": resource_type,
                "resource_id": resource_id,
                "case_id": event.case_id,
                "evidence_id": event.evidence_id,
                "source_revision": event.immutable_revision,
                "is_partial": False,
                "title": event.event_type.value,
                "summary": event.action,
                "raw_locator": None,
                "citations": [],
                "fields": event.to_schema_dict(),
                "analyzer_id": "custody.ledger",
                "analyzer_version": ENGINE_VERSION,
            }
        raise UnsupportedCapabilityError(
            "Unsupported resource type.", target="resource_type", required_capability=resource_type
        )

    def _context_resource_pairs(self, context: GuiSessionContext) -> list[tuple[str, list[str]]]:
        return [
            (
                ResourceType.EVIDENCE.value,
                [context.active_evidence_id] if context.active_evidence_id is not None else [],
            ),
            (ResourceType.FILE_SYSTEM_NODE.value, context.selected_file_node_ids),
            (ResourceType.ARTIFACT.value, context.selected_artifact_ids),
            (ResourceType.TIMELINE_EVENT.value, context.selected_timeline_event_ids),
            (ResourceType.SEARCH_RESULT.value, context.selected_search_result_ids),
            (ResourceType.MEDIA.value, context.selected_media_artifact_ids),
            (ResourceType.BROWSER.value, context.selected_browser_artifact_ids),
            (ResourceType.MACHINE_CANDIDATE.value, context.selected_candidate_ids),
        ]

    def _context_included_resources(self, context: GuiSessionContext) -> dict[str, list[str]]:
        return {
            resource_type: list(ids)
            for resource_type, ids in self._context_resource_pairs(context)
            if ids
        }

    def _selection_field(self, resource_type: ResourceType | str) -> str:
        resource_value = _enum_value(resource_type)
        try:
            return _RESOURCE_SELECTION_FIELDS[resource_value]
        except KeyError as error:
            raise UnsupportedCapabilityError(
                "Unsupported selection resource type.",
                target="resource_type",
                required_capability=resource_value,
            ) from error

    def _require_case(self, case_id: str) -> Any:
        case = self._repository.get_case(case_id)
        if case is None:
            raise NotFoundError("CASE_NOT_FOUND", "Case not found.", target="case_id")
        return case

    def _require_evidence_for_case(self, case_id: str, evidence_id: str) -> Any:
        evidence = self._repository.get_evidence(evidence_id)
        if evidence is None:
            raise NotFoundError("EVIDENCE_NOT_FOUND", "Evidence not found.", target="evidence_id")
        if evidence.case_id != case_id:
            raise ContextScopeMismatchError(
                "Evidence belongs to another case.", target="evidence_id"
            )
        return evidence

    def _ensure_live(self, context: GuiSessionContext) -> None:
        if context.expires_at is not None and context.expires_at <= self._clock.now():
            raise ContextExpiredError(
                "Expired GUI session contexts cannot be modified.", target="session_context_id"
            )

    def _refresh_snapshot_source_revisions(
        self, snapshot: AnalysisContextSnapshot
    ) -> list[RevisionState]:
        refreshed: list[RevisionState] = []
        seen: set[tuple[str, str]] = set()
        for previous in snapshot.source_revisions:
            refreshed.append(self._refresh_revision_state(snapshot, previous))
            seen.add((_enum_value(previous.resource_type), previous.resource_id))
        for resource_type, resource_ids in snapshot.included_resource_ids.items():
            for resource_id in resource_ids:
                pair = (resource_type, resource_id)
                if pair in seen:
                    continue
                refreshed.append(
                    self._current_revision_state(snapshot.case_id, resource_type, resource_id)
                )
                seen.add(pair)
        return refreshed

    def _refresh_revision_state(
        self, snapshot: AnalysisContextSnapshot, previous: RevisionState
    ) -> RevisionState:
        resource_type = _enum_value(previous.resource_type)
        if (
            resource_type == ResourceType.SEARCH_RESULT.value
            and previous.resource_id == snapshot.search_execution_id
        ):
            return self._refresh_search_execution_state(snapshot, previous)
        baseline_revision = previous.current_revision or previous.expected_revision
        try:
            current = self._current_revision_state(
                snapshot.case_id, resource_type, previous.resource_id
            )
        except ApexError:
            return RevisionState(
                resource_type,
                previous.resource_id,
                previous.expected_revision,
                None,
                RevisionStatus.MISSING,
                StaleReason.RESOURCE_MISSING.value,
                self._clock.now(),
            )
        status = RevisionStatus.CURRENT
        reason = None
        if (
            baseline_revision is not None
            and str(current.current_revision) != str(baseline_revision)
        ):
            status = RevisionStatus.STALE
            reason = self._stale_reason_for_resource_type(resource_type)
        elif current.status == RevisionStatus.PARTIAL:
            status = RevisionStatus.PARTIAL
            reason = current.reason
        return RevisionState(
            resource_type,
            previous.resource_id,
            previous.expected_revision,
            current.current_revision,
            status,
            reason,
            self._clock.now(),
        )

    def _refresh_search_execution_state(
        self, snapshot: AnalysisContextSnapshot, previous: RevisionState
    ) -> RevisionState:
        baseline_revision = previous.current_revision or previous.expected_revision
        execution = self._repository.get_search_execution(previous.resource_id)
        if execution is None or execution.case_id != snapshot.case_id:
            return RevisionState(
                ResourceType.SEARCH_RESULT.value,
                previous.resource_id,
                previous.expected_revision,
                None,
                RevisionStatus.MISSING,
                StaleReason.SEARCH_EXECUTION_STALE.value,
                self._clock.now(),
            )
        status = RevisionStatus.CURRENT
        reason = None
        if (
            baseline_revision is not None
            and str(execution.execution_revision) != str(baseline_revision)
        ):
            status = RevisionStatus.STALE
            reason = StaleReason.SEARCH_EXECUTION_STALE.value
        return RevisionState(
            ResourceType.SEARCH_RESULT.value,
            previous.resource_id,
            previous.expected_revision,
            execution.execution_revision,
            status,
            reason,
            self._clock.now(),
        )

    def _current_revision_state(
        self, case_id: str, resource_type: str, resource_id: str
    ) -> RevisionState:
        info = self._resource_info(resource_type, resource_id)
        if info["case_id"] != case_id:
            raise ContextScopeMismatchError(
                "Selected resource belongs to another case.", target="resource_id"
            )
        status = RevisionStatus.PARTIAL if info["is_partial"] else RevisionStatus.CURRENT
        reason = StaleReason.UNKNOWN.value if status == RevisionStatus.PARTIAL else None
        return RevisionState(
            resource_type,
            resource_id,
            info["source_revision"],
            info["source_revision"],
            status,
            reason,
            self._clock.now(),
        )

    @staticmethod
    def _stale_reason_for_resource_type(resource_type: str) -> str:
        if resource_type == ResourceType.EVIDENCE.value:
            return StaleReason.EVIDENCE_REVISION_CHANGED.value
        if resource_type == ResourceType.FILE_SYSTEM_NODE.value:
            return StaleReason.FILESYSTEM_INDEX_CHANGED.value
        if resource_type == ResourceType.SEARCH_RESULT.value:
            return StaleReason.SEARCH_INDEX_CHANGED.value
        if resource_type == ResourceType.TIMELINE_EVENT.value:
            return StaleReason.TIMELINE_REVISION_CHANGED.value
        if resource_type == ResourceType.MACHINE_CANDIDATE.value:
            return StaleReason.CANDIDATE_REVIEW_CHANGED.value
        return StaleReason.ARTIFACT_SOURCE_CHANGED.value

    def _source_revision_fingerprint(self, states: list[RevisionState]) -> str:
        return canonical_sha256(_stable_revision_states(states))

    def _missing_state(self, resource_type: str, resource_id: str, reason: str) -> RevisionState:
        return RevisionState(
            resource_type,
            resource_id,
            None,
            None,
            RevisionStatus.MISSING,
            reason,
            self._clock.now(),
        )

    def _scopes_from_included(self, included: dict[str, list[str]]) -> list[str]:
        scopes: set[str] = set()
        has_selection = False
        for resource_type, resource_ids in included.items():
            if not resource_ids:
                continue
            has_selection = True
            if resource_type == ResourceType.ARTIFACT.value:
                for resource_id in resource_ids:
                    artifact_scope = self._artifact_scope_for_id(resource_id)
                    if artifact_scope is not None:
                        scopes.add(artifact_scope)
                continue
            scope = _RESOURCE_SCOPE_BY_TYPE.get(resource_type)
            if scope is not None:
                scopes.add(scope)
        if has_selection:
            scopes.add(AnalysisScopeType.SELECTION.value)
        if not scopes:
            return [AnalysisScopeType.CASE.value]
        return [scope for scope in _SCOPE_RESOURCE_TYPES if scope in scopes]

    def _resource_type_for_scope(self, scope: str) -> str:
        resource_types = _SCOPE_RESOURCE_TYPES.get(scope, ())
        return resource_types[0] if resource_types else ResourceType.OTHER.value

    def _resource_type_for_scope_item(
        self, snapshot: AnalysisContextSnapshot, scope: str, resource_id: str
    ) -> str:
        if scope == AnalysisScopeType.SELECTION.value:
            for resource_type in _SCOPE_RESOURCE_TYPES[AnalysisScopeType.SELECTION.value]:
                if resource_id in snapshot.included_resource_ids.get(resource_type, []):
                    return resource_type
            return ResourceType.OTHER.value
        if scope in _ARTIFACT_RESOURCE_TYPE_BY_SCOPE:
            resource_type = _ARTIFACT_RESOURCE_TYPE_BY_SCOPE[scope]
            if resource_id in snapshot.included_resource_ids.get(resource_type, []):
                return resource_type
            if resource_id in snapshot.included_resource_ids.get(ResourceType.ARTIFACT.value, []):
                artifact_scope = self._artifact_scope_for_id(resource_id)
                if artifact_scope == scope:
                    return resource_type
        return self._resource_type_for_scope(scope)

    def _included_resources_for_scope(
        self, snapshot: AnalysisContextSnapshot, scope: str
    ) -> dict[str, list[str]]:
        if scope == AnalysisScopeType.SELECTION.value:
            return {
                resource_type: list(snapshot.included_resource_ids.get(resource_type, []))
                for resource_type in _SCOPE_RESOURCE_TYPES[AnalysisScopeType.SELECTION.value]
                if snapshot.included_resource_ids.get(resource_type)
            }
        if scope in _ARTIFACT_RESOURCE_TYPE_BY_SCOPE:
            resource_type = _ARTIFACT_RESOURCE_TYPE_BY_SCOPE[scope]
            ids = list(snapshot.included_resource_ids.get(resource_type, []))
            ids.extend(
                self._artifact_ids_matching_scope(
                    snapshot.included_resource_ids.get(ResourceType.ARTIFACT.value, []), scope
                )
            )
            deduped = _dedupe(ids)
            return {resource_type: deduped} if deduped else {}
        return {
            resource_type: list(snapshot.included_resource_ids.get(resource_type, []))
            for resource_type in _SCOPE_RESOURCE_TYPES.get(scope, ())
            if snapshot.included_resource_ids.get(resource_type)
        }

    def _artifact_scope_for_id(self, artifact_id: str) -> str | None:
        artifact = self._repository.get_artifact(artifact_id)
        if artifact is None:
            return None
        return self._scope_for_artifact_type(artifact.artifact_type.value)

    @staticmethod
    def _scope_for_artifact_type(artifact_type: str) -> str | None:
        return _ARTIFACT_SCOPE_BY_TYPE.get(artifact_type)

    def _artifact_ids_matching_scope(self, artifact_ids: list[str], scope: str) -> list[str]:
        return [
            artifact_id
            for artifact_id in artifact_ids
            if self._artifact_scope_for_id(artifact_id) == scope
        ]

    def _collect_citations(self, included: dict[str, list[str]]) -> list[dict[str, Any]]:
        citations: list[dict[str, Any]] = []
        for resource_type, resource_ids in included.items():
            for resource_id in resource_ids:
                try:
                    citations.extend(
                        self._resource_info(resource_type, resource_id).get("citations", [])
                    )
                except ApexError:
                    continue
        return citations

    def _collect_analyzer_versions(self, included: dict[str, list[str]]) -> dict[str, str]:
        versions: dict[str, str] = {}
        for resource_type, resource_ids in included.items():
            for resource_id in resource_ids:
                try:
                    info = self._resource_info(resource_type, resource_id)
                except ApexError:
                    continue
                analyzer_id = info.get("analyzer_id")
                analyzer_version = info.get("analyzer_version")
                if analyzer_id is not None and analyzer_version is not None:
                    versions[str(analyzer_id)] = str(analyzer_version)
        return versions

    def _coverage_for_scope(self, case_id: str, scope: str) -> dict[str, Any]:
        return cast(dict[str, Any], self._repository.coverage_summary_for_scope(case_id, scope))

    def _evidence_ids(self, resource_ids: list[str], resource_types: Iterable[str]) -> list[str]:
        included = dict.fromkeys(resource_types, resource_ids)
        return self._evidence_ids_for_included(included)

    def _evidence_ids_for_included(self, included: dict[str, list[str]]) -> list[str]:
        evidence_ids: list[str] = []
        for resource_type, resource_ids in included.items():
            for resource_id in resource_ids:
                if resource_type == ResourceType.EVIDENCE.value:
                    evidence_ids.append(resource_id)
                    continue
                try:
                    evidence_id = self._resource_info(resource_type, resource_id).get("evidence_id")
                except ApexError:
                    continue
                if evidence_id is not None:
                    evidence_ids.append(str(evidence_id))
        return _dedupe(evidence_ids)

    def _search_index_revision(self, search_execution_id: str | None) -> int | None:
        if search_execution_id is None:
            return None
        execution = self._repository.get_search_execution(search_execution_id)
        return None if execution is None else execution.index_revision

    @staticmethod
    def _check_cancel(cancellation_token: CancellationToken | None) -> None:
        if cancellation_token is not None and cancellation_token.is_cancelled:
            from apex_forensic.domain.errors import OperationCancelledError

            raise OperationCancelledError()


class ViewProjectionService:
    """Builds Simple/Detailed/Raw projections without mutating source facts."""

    def __init__(
        self, *, repository: Any, contexts: ContextService, clock: Clock, id_generator: IdGenerator
    ) -> None:
        self._repository = repository
        self._contexts = contexts
        self._clock = clock
        self._id_generator = id_generator

    def simple(
        self,
        *,
        case_id: str,
        resource_type: ResourceType | str,
        resource_id: str,
        redaction_policy: str = "DEFAULT",
    ) -> ViewProjection:
        return self.project(
            case_id=case_id,
            resource_type=resource_type,
            resource_id=resource_id,
            view_mode=ViewMode.SIMPLE,
            redaction_policy=redaction_policy,
        )

    def detailed(
        self,
        *,
        case_id: str,
        resource_type: ResourceType | str,
        resource_id: str,
        redaction_policy: str = "DEFAULT",
    ) -> ViewProjection:
        return self.project(
            case_id=case_id,
            resource_type=resource_type,
            resource_id=resource_id,
            view_mode=ViewMode.DETAILED,
            redaction_policy=redaction_policy,
        )

    def raw(
        self,
        *,
        case_id: str,
        resource_type: ResourceType | str,
        resource_id: str,
        redaction_policy: str = "DEFAULT",
    ) -> ViewProjection:
        return self.project(
            case_id=case_id,
            resource_type=resource_type,
            resource_id=resource_id,
            view_mode=ViewMode.RAW,
            redaction_policy=redaction_policy,
        )

    def project(
        self,
        *,
        case_id: str,
        resource_type: ResourceType | str,
        resource_id: str,
        view_mode: ViewMode | str,
        redaction_policy: str = "DEFAULT",
    ) -> ViewProjection:
        del redaction_policy
        resource_value = _enum_value(resource_type)
        mode_value = _enum_value(view_mode)
        info = self._contexts.resolve_resource(
            resource_type=resource_value, resource_id=resource_id
        )
        if info["case_id"] != case_id:
            raise ContextScopeMismatchError(
                "Resource belongs to another case.", target="resource_id"
            )
        fields = _redact(info.get("fields", {}))
        primary = self._primary_fields(info, mode_value)
        secondary = {} if mode_value == ViewMode.SIMPLE.value else self._secondary_fields(fields)
        technical = (
            {} if mode_value == ViewMode.SIMPLE.value else self._technical_fields(info, fields)
        )
        raw_fields = {}
        if mode_value == ViewMode.RAW.value:
            raw_fields = self._raw_fields(info, fields)
        projection = ViewProjection(
            projection_id=self._id_generator.new_id(),
            case_id=case_id,
            resource_type=resource_value,
            resource_id=resource_id,
            view_mode=mode_value,
            title=str(info.get("title") or resource_id),
            subtitle=str(info.get("summary") or "")[:200] or None,
            summary=str(info.get("summary") or "")[:500] or None,
            severity=None,
            badges=self._badges(info),
            primary_fields=primary,
            secondary_fields=secondary,
            technical_fields=technical,
            raw_fields=raw_fields,
            timestamps=self._timestamps(fields),
            timezone=str(fields.get("case_timezone"))
            if isinstance(fields, dict) and fields.get("case_timezone") is not None
            else None,
            confidence=float(info["confidence"]) if info.get("confidence") is not None else None,
            partial_state={"is_partial": bool(info.get("is_partial"))},
            stale_state={"is_stale": False, "stale_reasons": []},
            warnings=list(info.get("warnings", [])),
            citations=list(info.get("citations", [])),
            raw_locator=info.get("raw_locator"),
            available_actions=self._available_actions(resource_value, info),
            source_revision=info.get("source_revision"),
            analyzer_id=info.get("analyzer_id"),
            analyzer_version=info.get("analyzer_version"),
            projection_version=PROJECTION_VERSION,
            created_at=self._clock.now(),
        )
        self._repository.save_view_projection(projection)
        return projection

    def raw_read(
        self,
        *,
        case_id: str,
        resource_type: ResourceType | str,
        resource_id: str,
        offset: int = 0,
        length: int | None = None,
        correlation_id: str | None = None,
        cancellation_token: CancellationToken | None = None,
    ) -> RawViewProjection:
        reader = SafeRawRangeReader(
            repository=self._repository, clock=self._clock, id_generator=self._id_generator
        )
        return reader.read_resource(
            case_id=case_id,
            resource_type=resource_type,
            resource_id=resource_id,
            offset=offset,
            length=length,
            correlation_id=correlation_id,
            cancellation_token=cancellation_token,
        )

    def capabilities(self) -> dict[str, Any]:
        reader = SafeRawRangeReader(
            repository=self._repository, clock=self._clock, id_generator=self._id_generator
        )
        return {"view_modes": [item.value for item in ViewMode], "raw_reader": reader.capability()}

    def _primary_fields(self, info: dict[str, Any], view_mode: str) -> dict[str, Any]:
        fields = info.get("fields", {})
        if not isinstance(fields, Mapping):
            return {}
        keys = [
            "display_path",
            "source_path",
            "artifact_type",
            "url",
            "path",
            "event_type",
            "review_status",
            "source_revision",
        ]
        limit = 8 if view_mode == ViewMode.SIMPLE.value else 30
        result = {key: fields[key] for key in keys if key in fields and fields[key] is not None}
        if view_mode == ViewMode.SIMPLE.value:
            result["label_resource_key"] = f"resource.{str(info['resource_type']).casefold()}"
            result["citation_count"] = len(info.get("citations", []))
            result["next_recommended_view"] = ViewMode.DETAILED.value
        return dict(list(result.items())[:limit])

    @staticmethod
    def _secondary_fields(fields: Any) -> dict[str, Any]:
        if not isinstance(fields, Mapping):
            return {}
        omitted = {"raw_locator", "citations", "fields", "payload"}
        return {
            str(key): value
            for key, value in fields.items()
            if key not in omitted and value is not None
        }

    @staticmethod
    def _technical_fields(info: dict[str, Any], fields: Any) -> dict[str, Any]:
        technical = {
            "source_revision": info.get("source_revision"),
            "analyzer_id": info.get("analyzer_id"),
            "analyzer_version": info.get("analyzer_version"),
            "resource_semantics": "observed_fact"
            if info.get("resource_type") != ResourceType.MACHINE_CANDIDATE.value
            else "candidate_not_observed_fact",
            "parse_status": fields.get("parse_status") if isinstance(fields, Mapping) else None,
            "coverage": fields.get("coverage") if isinstance(fields, Mapping) else None,
        }
        return {key: value for key, value in technical.items() if value is not None}

    @staticmethod
    def _raw_fields(info: dict[str, Any], fields: Any) -> dict[str, Any]:
        return {
            "raw_locator": info.get("raw_locator"),
            "structured_fields": fields,
            "raw_included": False,
            "raw_access": "use raw-read for bounded chunks",
        }

    @staticmethod
    def _timestamps(fields: Any) -> dict[str, Any]:
        if not isinstance(fields, Mapping):
            return {}
        result: dict[str, Any] = {}
        for key, value in fields.items():
            if "time" in str(key).casefold() or str(key).endswith("_at"):
                result[str(key)] = value
        return result

    @staticmethod
    def _badges(info: dict[str, Any]) -> list[str]:
        badges = [str(info.get("resource_type"))]
        if info.get("is_partial"):
            badges.append("PARTIAL")
        if info.get("citations"):
            badges.append("CITED")
        return badges

    @staticmethod
    def _available_actions(resource_type: str, info: dict[str, Any]) -> list[str]:
        actions = ["view.simple", "view.detailed", "view.raw"]
        if info.get("raw_locator") is not None:
            actions.append("view.raw-read")
        if resource_type == ResourceType.MACHINE_CANDIDATE.value:
            actions.append("candidate.review")
        return actions


class SafeRawRangeReader:
    """Provider-neutral bounded raw range reader with evidence-root validation."""

    backend_id = "apex.safe_raw_range_reader"
    backend_version = ENGINE_VERSION

    def __init__(self, *, repository: Any, clock: Clock, id_generator: IdGenerator) -> None:
        self._repository = repository
        self._clock = clock
        self._id_generator = id_generator

    def capability(self) -> dict[str, Any]:
        return {
            "backend_id": self.backend_id,
            "backend_version": self.backend_version,
            "default_read_limit": DEFAULT_RAW_READ_LENGTH,
            "maximum_read_limit": MAX_RAW_READ_LENGTH,
            "supports_directory_evidence": True,
            "supports_logical_file_evidence": True,
            "supports_disk_image_raw_offsets": False,
            "supports_logical_fields": True,
        }

    def validate_locator(self, *, case_id: str, raw_locator: dict[str, Any]) -> dict[str, Any]:
        evidence_id = raw_locator.get("evidence_id")
        source_id = raw_locator.get("source_id") or raw_locator.get("source_file_node_id")
        if evidence_id is None or source_id is None:
            raise RawReadError(
                "RAW_RESOURCE_NOT_FOUND",
                "Raw locator is missing evidence_id or source_id.",
                target="raw_locator",
            )
        evidence = self._repository.get_evidence(str(evidence_id))
        if evidence is None:
            raise RawReadError(
                "RAW_RESOURCE_NOT_FOUND", "Raw evidence was not found.", target="evidence_id"
            )
        if evidence.case_id != case_id:
            raise RawReadError(
                "RAW_SOURCE_OUTSIDE_EVIDENCE",
                "Raw evidence belongs to another case.",
                target="case_id",
            )
        node = self._repository.get_fs_node(str(source_id))
        if node is None:
            raise RawReadError(
                "RAW_RESOURCE_NOT_FOUND",
                "Raw locator source node was not found.",
                target="source_id",
            )
        if node.case_id != case_id or node.evidence_id != evidence.evidence_id:
            raise RawReadError(
                "RAW_SOURCE_OUTSIDE_EVIDENCE",
                "Raw locator source does not belong to the evidence.",
                target="source_id",
            )
        indexed_relative_path = self._clean_relative_path(node.original_relative_path)
        requested_relative_path = raw_locator.get("relative_path")
        if requested_relative_path is not None:
            requested = self._clean_relative_path(str(requested_relative_path))
            if requested != indexed_relative_path:
                raise RawReadError(
                    "RAW_SOURCE_OUTSIDE_EVIDENCE",
                    "Raw locator path does not match the indexed source node.",
                    target="raw_locator",
                )
        root = Path(evidence.source_path).resolve(strict=True)
        base = root if root.is_dir() else root.parent
        candidate = root if indexed_relative_path == "." else root.joinpath(
            *PurePosixPath(indexed_relative_path).parts
        )
        try:
            candidate.resolve(strict=False).relative_to(base)
        except ValueError as error:
            raise RawReadError(
                "RAW_SOURCE_OUTSIDE_EVIDENCE",
                "Raw source resolves outside evidence root.",
                target="raw_locator",
            ) from error
        return {"evidence": evidence, "node": node, "raw_locator": raw_locator}

    def read_resource(
        self,
        *,
        case_id: str,
        resource_type: ResourceType | str,
        resource_id: str,
        offset: int = 0,
        length: int | None = None,
        correlation_id: str | None = None,
        cancellation_token: CancellationToken | None = None,
    ) -> RawViewProjection:
        context = ContextService(
            repository=self._repository, clock=self._clock, id_generator=self._id_generator
        )
        info = context.resolve_resource(resource_type=resource_type, resource_id=resource_id)
        if info["case_id"] != case_id:
            raise RawReadError(
                "RAW_SOURCE_OUTSIDE_EVIDENCE",
                "Raw resource belongs to another case.",
                target="resource_id",
            )
        locator = info.get("raw_locator")
        if not isinstance(locator, dict):
            raise RawReadError(
                "RAW_LOCATOR_UNSUPPORTED", "Resource has no raw locator.", target="resource_id"
            )
        locator = dict(locator)
        locator.setdefault("evidence_id", info.get("evidence_id"))
        locator.setdefault("source_id", resource_id)
        if _enum_value(resource_type) == ResourceType.FILE_SYSTEM_NODE.value:
            locator.setdefault("offset", 0)
            fields = info.get("fields", {})
            if isinstance(fields, Mapping) and fields.get("file_size") is not None:
                locator.setdefault("length", int(fields["file_size"]))
        return self.read_locator(
            case_id=case_id,
            resource_type=_enum_value(resource_type),
            resource_id=resource_id,
            raw_locator=locator,
            source_revision=info.get("source_revision"),
            citations=list(info.get("citations", [])),
            structured_fields=dict(info.get("fields", {})),
            offset=offset,
            length=length,
            correlation_id=correlation_id,
            cancellation_token=cancellation_token,
        )

    def read_locator(
        self,
        *,
        case_id: str,
        resource_type: ResourceType | str,
        resource_id: str,
        raw_locator: dict[str, Any],
        source_revision: str | int | None = None,
        citations: list[dict[str, Any]] | None = None,
        structured_fields: dict[str, Any] | None = None,
        offset: int = 0,
        length: int | None = None,
        correlation_id: str | None = None,
        cancellation_token: CancellationToken | None = None,
    ) -> RawViewProjection:
        self._check_cancel(cancellation_token)
        if offset < 0:
            raise RawReadError(
                "RAW_RANGE_INVALID", "Raw read offset cannot be negative.", target="offset"
            )
        requested_length = DEFAULT_RAW_READ_LENGTH if length is None else int(length)
        if requested_length < 1:
            raise RawReadError(
                "RAW_RANGE_INVALID", "Raw read length must be positive.", target="length"
            )
        if requested_length > MAX_RAW_READ_LENGTH:
            raise RawReadError(
                "RAW_READ_LIMIT_EXCEEDED",
                "Raw read length exceeds maximum policy.",
                target="length",
                details={"maximum": MAX_RAW_READ_LENGTH},
            )
        validation = self.validate_locator(case_id=case_id, raw_locator=raw_locator)
        locator_type = self._locator_type(raw_locator)
        locator_offset = raw_locator.get("offset")
        locator_length = raw_locator.get("length")
        if locator_offset is None:
            return self.read_logical_field(
                case_id=case_id,
                resource_type=resource_type,
                resource_id=resource_id,
                raw_locator=raw_locator,
                source_revision=source_revision,
                citations=citations or [],
                structured_fields=structured_fields or {},
                requested_offset=offset,
                requested_length=requested_length,
            )
        base_offset = int(locator_offset)
        allowed_length = int(locator_length) if locator_length is not None else requested_length
        if offset > allowed_length:
            raise RawReadError(
                "RAW_RANGE_INVALID", "Raw read offset is beyond the locator range.", target="offset"
            )
        read_length = min(requested_length, allowed_length - offset)
        path = self._path_for_locator(validation["evidence"], validation["node"], raw_locator)
        total_length = path.stat().st_size
        absolute_offset = base_offset + offset
        if absolute_offset > total_length:
            raise RawReadError(
                "RAW_RANGE_INVALID", "Raw read offset is beyond EOF.", target="offset"
            )
        with path.open("rb") as handle:
            handle.seek(absolute_offset)
            data = handle.read(read_length)
        self._check_cancel(cancellation_token)
        returned_length = len(data)
        hash_data = hashlib.sha256(data).hexdigest()
        text_preview, content_type = self._text_preview(data, raw_locator.get("encoding"))
        projection = RawViewProjection(
            projection_id=self._id_generator.new_id(),
            case_id=case_id,
            evidence_id=str(raw_locator.get("evidence_id")),
            resource_type=_enum_value(resource_type),
            resource_id=resource_id,
            source_path=str(path),
            raw_locator=raw_locator,
            locator_type=locator_type,
            requested_offset=offset,
            requested_length=requested_length,
            returned_offset=offset,
            returned_length=returned_length,
            total_length=total_length,
            encoding=raw_locator.get("encoding"),
            content_type=content_type,
            hex_preview=data[:RAW_PREVIEW_BYTES].hex(),
            text_preview=text_preview,
            structured_raw_fields={},
            truncated=returned_length < requested_length or returned_length > RAW_PREVIEW_BYTES,
            hash={
                "algorithm": "SHA256",
                "range_sha256": hash_data,
                "source_content_sha256": raw_locator.get("content_sha256"),
            },
            citations=citations or [],
            warnings=[],
            source_revision=source_revision,
            created_at=self._clock.now(),
        )
        self._audit(projection, correlation_id=correlation_id)
        return projection

    def read_range(self, **kwargs: Any) -> RawViewProjection:
        return self.read_locator(**kwargs)

    def read_logical_field(
        self,
        *,
        case_id: str,
        resource_type: ResourceType | str,
        resource_id: str,
        raw_locator: dict[str, Any],
        source_revision: str | int | None,
        citations: list[dict[str, Any]],
        structured_fields: dict[str, Any],
        requested_offset: int = 0,
        requested_length: int | None = None,
    ) -> RawViewProjection:
        locator_type = self._locator_type(raw_locator)
        allowed = {
            RawLocatorType.SQLITE_ROW.value,
            RawLocatorType.SQLITE_TABLE_ROW_COLUMN.value,
            RawLocatorType.REGISTRY_KEY.value,
            RawLocatorType.REGISTRY_VALUE.value,
            RawLocatorType.EVENT_RECORD.value,
            RawLocatorType.PREFETCH_FIELD.value,
            RawLocatorType.EXIF_TAG.value,
            RawLocatorType.MEDIA_METADATA_FIELD.value,
            RawLocatorType.FILE_LOGICAL_FIELD.value,
        }
        if locator_type not in allowed and raw_locator.get("locator_type") not in {
            "SQLITE_ROW",
            "LOGICAL_REGISTRY",
            "LOGICAL_EVENT_RECORD",
            "PREFETCH_FIELD",
            "MEDIA_METADATA",
        }:
            raise RawReadError(
                "RAW_LOCATOR_UNSUPPORTED",
                "Raw locator has no byte range and is not a supported logical field.",
                target="raw_locator",
            )
        projection = RawViewProjection(
            projection_id=self._id_generator.new_id(),
            case_id=case_id,
            evidence_id=raw_locator.get("evidence_id"),
            resource_type=_enum_value(resource_type),
            resource_id=resource_id,
            source_path=raw_locator.get("source_path"),
            raw_locator=raw_locator,
            locator_type=locator_type,
            requested_offset=requested_offset,
            requested_length=requested_length,
            returned_offset=None,
            returned_length=None,
            total_length=None,
            encoding=raw_locator.get("encoding"),
            content_type="application/json",
            hex_preview=None,
            text_preview=json.dumps(_redact(structured_fields), ensure_ascii=False, sort_keys=True)[
                :RAW_PREVIEW_BYTES
            ],
            structured_raw_fields=_redact(structured_fields),
            truncated=len(json.dumps(structured_fields, ensure_ascii=False)) > RAW_PREVIEW_BYTES,
            hash={
                "algorithm": "SHA256",
                "range_sha256": canonical_sha256(structured_fields),
                "source_content_sha256": raw_locator.get("content_sha256"),
            },
            citations=citations,
            warnings=[
                {
                    "code": "LOGICAL_LOCATOR_NO_BYTE_OFFSET",
                    "message_key": "warning.raw.logical_locator_no_byte_offset",
                    "developer_message": "Logical locators do not invent byte offsets.",
                    "details": {},
                }
            ],
            source_revision=source_revision,
            created_at=self._clock.now(),
        )
        self._audit(projection, correlation_id=None)
        return projection

    def preview(self, **kwargs: Any) -> RawViewProjection:
        return self.read_locator(**kwargs)

    def hash_range(self, **kwargs: Any) -> dict[str, Any]:
        projection = self.read_locator(**kwargs)
        return projection.hash

    def _path_for_locator(self, evidence: Any, node: Any, raw_locator: dict[str, Any]) -> Path:
        if node is None:
            raise RawReadError(
                "RAW_RESOURCE_NOT_FOUND",
                "Raw locator source node was not found.",
                target="source_id",
            )
        if getattr(node, "is_link", False):
            raise RawReadError(
                "RAW_LOCATOR_UNSUPPORTED",
                "Symlink raw reads are not supported by policy.",
                target="resource_id",
            )
        root = Path(evidence.source_path).resolve(strict=True)
        base = root if root.is_dir() else root.parent
        relative = self._clean_relative_path(node.original_relative_path)
        candidate = root if relative == "." else root.joinpath(*PurePosixPath(relative).parts)
        resolved = candidate.resolve(strict=True)
        try:
            resolved.relative_to(base)
        except ValueError as error:
            raise RawReadError(
                "RAW_SOURCE_OUTSIDE_EVIDENCE",
                "Raw source resolves outside evidence root.",
                target="raw_locator",
            ) from error
        if resolved.is_dir():
            raise RawReadError(
                "RAW_LOCATOR_UNSUPPORTED",
                "Raw byte reads require a file source.",
                target="raw_locator",
            )
        if resolved.is_symlink():
            raise RawReadError(
                "RAW_LOCATOR_UNSUPPORTED",
                "Symlink raw reads are not supported by policy.",
                target="raw_locator",
            )
        return resolved

    @staticmethod
    def _clean_relative_path(relative_path: str) -> str:
        pure = PurePosixPath(relative_path.replace("\\", "/"))
        if pure.is_absolute() or any(part == ".." for part in pure.parts):
            raise RawReadError(
                "RAW_SOURCE_OUTSIDE_EVIDENCE",
                "Raw locator path escapes the evidence root.",
                target="raw_locator",
            )
        cleaned = pure.as_posix()
        if cleaned in {"", "."}:
            return "."
        return cleaned.lstrip("./")

    @staticmethod
    def _locator_type(raw_locator: dict[str, Any]) -> str:
        raw_type = str(raw_locator.get("locator_type") or "UNKNOWN")
        aliases = {
            "BYTE_RANGE": RawLocatorType.FILE_BYTE_RANGE.value,
            "LOGICAL_PATH": RawLocatorType.FILE_BYTE_RANGE.value,
            "SQLITE_ROW": RawLocatorType.SQLITE_ROW.value,
            "LOGICAL_REGISTRY": RawLocatorType.REGISTRY_VALUE.value,
            "LOGICAL_EVENT_RECORD": RawLocatorType.EVENT_RECORD.value,
            "PREFETCH_FIELD": RawLocatorType.PREFETCH_FIELD.value,
            "MEDIA_METADATA": RawLocatorType.MEDIA_METADATA_FIELD.value,
        }
        return aliases.get(
            raw_type,
            raw_type
            if raw_type in {item.value for item in RawLocatorType}
            else RawLocatorType.UNKNOWN.value,
        )

    @staticmethod
    def _text_preview(data: bytes, encoding: Any) -> tuple[str | None, str]:
        if b"\\x00" in data:
            return None, "application/octet-stream"
        candidates = [str(encoding)] if encoding else ["utf-8"]
        for candidate in candidates:
            try:
                return data[:RAW_PREVIEW_BYTES].decode(candidate, errors="strict"), "text/plain"
            except (LookupError, UnicodeDecodeError):
                continue
        return None, "application/octet-stream"

    def _audit(self, projection: RawViewProjection, *, correlation_id: str | None) -> None:
        self._repository.save_raw_read_audit(
            {
                "audit_id": self._id_generator.new_id(),
                "case_id": projection.case_id,
                "evidence_id": projection.evidence_id,
                "resource_type": _enum_value(projection.resource_type),
                "resource_id": projection.resource_id,
                "raw_locator": projection.raw_locator,
                "requested_offset": projection.requested_offset,
                "requested_length": projection.requested_length,
                "returned_offset": projection.returned_offset,
                "returned_length": projection.returned_length,
                "range_hash": projection.hash.get("range_sha256"),
                "correlation_id": correlation_id,
                "created_at": to_json_timestamp(projection.created_at),
            }
        )

    @staticmethod
    def _check_cancel(cancellation_token: CancellationToken | None) -> None:
        if cancellation_token is not None and cancellation_token.is_cancelled:
            from apex_forensic.domain.errors import OperationCancelledError

            raise OperationCancelledError()


class EngineInterfaceService:
    """Public JSON-friendly engine interface used by CLI, GUI, and future MCP adapters."""

    def __init__(
        self,
        *,
        repository: Any,
        contexts: ContextService,
        views: ViewProjectionService,
        ai: Any | None = None,
        clock: Clock,
        id_generator: IdGenerator,
    ) -> None:
        self._repository = repository
        self._contexts = contexts
        self._views = views
        self._ai = ai
        self._clock = clock
        self._id_generator = id_generator
        self._register_default_tool_descriptors()

    def version(self) -> EngineInterfaceVersion:
        version = EngineInterfaceVersion(
            interface_name="apex.engine.public",
            interface_version=INTERFACE_VERSION,
            engine_version=ENGINE_VERSION,
            schema_version=SCHEMA_VERSION,
            capabilities=[
                "CASE_EVIDENCE_READ",
                "FILESYSTEM_VIEW",
                "SAFE_RAW_READ",
                "ARTIFACT_VIEW",
                "BROWSER_MEDIA_VIEW",
                "SEARCH_TIMELINE_VIEW",
                "CONTEXT_SNAPSHOT",
                "SIMPLE_DETAILED_RAW_VIEW",
                "MCP_ADAPTER_DESCRIPTOR",
                "AI_ASSISTANCE_ENGINE_CONTRACT",
                "AI_RESULT_VALIDATION",
                "AI_HUMAN_VERIFICATION",
                "AI_KEYWORD_PROMOTION",
            ],
            unavailable_capabilities=[
                "REST_SERVER",
                "MCP_SERVER",
                "LLM_PROVIDER",
                "RUNTIME_AI_PROVIDER",
                "PROMPT_TEMPLATE",
                "DISK_IMAGE_RAW_OFFSET",
            ],
            generated_at=self._clock.now(),
        )
        self._repository.save_engine_interface_version(version)
        return version

    def tools(self) -> list[EngineToolDescriptor]:
        self._register_default_tool_descriptors()
        return cast(
            list[EngineToolDescriptor],
            self._repository.list_engine_tool_descriptors(),
        )

    def capability(self, capability: str | None = None) -> dict[str, Any]:
        version = self.version()
        all_capabilities = version.capabilities
        unavailable = version.unavailable_capabilities
        if capability is None:
            return {"capabilities": all_capabilities, "unavailable_capabilities": unavailable}
        return {
            "capability": capability,
            "is_available": capability in all_capabilities,
            "unavailable_reason": None
            if capability in all_capabilities
            else "CAPABILITY_UNAVAILABLE",
        }

    def success(
        self,
        data: Any,
        *,
        request_id: str | None = None,
        correlation_id: str | None = None,
        warnings: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "interface_version": INTERFACE_VERSION,
            "request_id": request_id or self._id_generator.new_id(),
            "correlation_id": correlation_id,
            "status": "OK",
            "data": data,
            "warnings": warnings or [],
            "errors": [],
        }

    def error(
        self, error: ApexError, *, request_id: str | None = None, correlation_id: str | None = None
    ) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "interface_version": INTERFACE_VERSION,
            "request_id": request_id or self._id_generator.new_id(),
            "correlation_id": correlation_id,
            "status": "ERROR",
            "data": None,
            "warnings": [],
            "errors": [error.to_api_error()],
        }

    def invoke_read(
        self,
        operation: str,
        payload: Mapping[str, Any],
        *,
        request_id: str | None = None,
        correlation_id: str | None = None,
    ) -> dict[str, Any]:
        try:
            request = self._request_payload(payload)
            canonical_operation = self._canonical_operation(operation)
            if canonical_operation == "context.get":
                return self.success(
                    self._contexts.get(
                        self._required_string(request, "session_context_id")
                    ).to_schema_dict(),
                    request_id=request_id,
                    correlation_id=correlation_id,
                )
            if canonical_operation == "context.snapshot":
                snapshot = self._contexts.build_from_session(
                    self._required_string(request, "session_context_id"),
                    purpose=self._optional_enum(
                        request,
                        "purpose",
                        AnalysisContextPurpose,
                        AnalysisContextPurpose.MCP_REQUEST,
                    ),
                    scopes=self._optional_scope_list(request, "scopes"),
                    previous_snapshot_id=self._optional_string(request, "previous_snapshot_id"),
                )
                return self.success(
                    snapshot.to_schema_dict(),
                    request_id=request_id,
                    correlation_id=correlation_id,
                )
            if canonical_operation == "context.snapshot-show":
                return self.success(
                    self._contexts.get_snapshot(
                        self._required_string(request, "context_snapshot_id")
                    ).to_schema_dict(),
                    request_id=request_id,
                    correlation_id=correlation_id,
                )
            if canonical_operation == "context.scope-page":
                page = self._contexts.paginate_scope(
                    self._required_string(request, "context_snapshot_id"),
                    self._required_enum(request, "scope", AnalysisScopeType).value,
                    cursor=self._optional_string(request, "cursor"),
                    limit=self._optional_integer(
                        request, "limit", 100, minimum=1, maximum=MAX_SCOPE_ITEMS
                    ),
                )
                return self.success(page, request_id=request_id, correlation_id=correlation_id)
            if canonical_operation == "view.simple":
                projection = self._views.simple(
                    case_id=self._required_string(request, "case_id"),
                    resource_type=self._required_enum(request, "resource_type", ResourceType).value,
                    resource_id=self._required_string(request, "resource_id"),
                )
                return self.success(
                    projection.to_schema_dict(),
                    request_id=request_id,
                    correlation_id=correlation_id,
                )
            if canonical_operation == "view.detailed":
                projection = self._views.detailed(
                    case_id=self._required_string(request, "case_id"),
                    resource_type=self._required_enum(request, "resource_type", ResourceType).value,
                    resource_id=self._required_string(request, "resource_id"),
                )
                return self.success(
                    projection.to_schema_dict(),
                    request_id=request_id,
                    correlation_id=correlation_id,
                )
            if canonical_operation == "view.raw":
                projection = self._views.raw(
                    case_id=self._required_string(request, "case_id"),
                    resource_type=self._required_enum(request, "resource_type", ResourceType).value,
                    resource_id=self._required_string(request, "resource_id"),
                )
                return self.success(
                    projection.to_schema_dict(),
                    request_id=request_id,
                    correlation_id=correlation_id,
                )
            if canonical_operation == "view.raw-read":
                raw_projection = self._views.raw_read(
                    case_id=self._required_string(request, "case_id"),
                    resource_type=self._required_enum(request, "resource_type", ResourceType).value,
                    resource_id=self._required_string(request, "resource_id"),
                    offset=self._optional_integer(request, "offset", 0, minimum=0),
                    length=self._optional_integer(
                        request,
                        "length",
                        DEFAULT_RAW_READ_LENGTH,
                        minimum=1,
                        maximum=MAX_RAW_READ_LENGTH,
                    ),
                    correlation_id=correlation_id,
                )
                return self.success(
                    raw_projection.to_schema_dict(),
                    request_id=request_id,
                    correlation_id=correlation_id,
                )
            if canonical_operation.startswith("ai."):
                ai = self._require_ai_service()
                if canonical_operation == "ai.capabilities":
                    return self.success(
                        ai.capabilities(),
                        request_id=request_id,
                        correlation_id=correlation_id,
                    )
                if canonical_operation == "ai.request.create":
                    ai_request = ai.create_request_from_context_snapshot(
                        case_id=self._required_string(request, "case_id"),
                        context_snapshot_id=self._required_string(
                            request, "context_snapshot_id"
                        ),
                        purpose=self._optional_enum(
                            request,
                            "purpose",
                            AiAssistancePurpose,
                            AiAssistancePurpose.INVESTIGATION_ASSISTANCE,
                        ),
                        requested_operations=self._optional_string_list(
                            request, "requested_operations"
                        ),
                        requested_scopes=self._optional_string_list(
                            request, "requested_scopes"
                        ),
                        scope_context_ids=self._optional_string_list(
                            request, "scope_context_ids"
                        ),
                        locale=self._optional_string(request, "locale"),
                        timezone=self._optional_string(request, "timezone"),
                        max_keyword_candidates=self._optional_integer(
                            request, "max_keyword_candidates", 100, minimum=1
                        ),
                        max_summary_length=self._optional_integer(
                            request, "max_summary_length", 4000, minimum=1
                        ),
                        correlation_id=correlation_id
                        or self._optional_string(request, "correlation_id"),
                    )
                    return self.success(
                        ai_request.to_schema_dict(),
                        request_id=request_id,
                        correlation_id=correlation_id,
                    )
                if canonical_operation == "ai.request.get":
                    return self.success(
                        ai.get_request(
                            self._required_string(request, "assistance_request_id")
                        ).to_schema_dict(),
                        request_id=request_id,
                        correlation_id=correlation_id,
                    )
                if canonical_operation == "ai.request.list":
                    return self.success(
                        [
                            item.to_schema_dict()
                            for item in ai.list_requests_by_case(
                                self._required_string(request, "case_id"),
                                limit=self._optional_integer(
                                    request, "limit", 100, minimum=1
                                ),
                            )
                        ],
                        request_id=request_id,
                        correlation_id=correlation_id,
                    )
                if canonical_operation == "ai.keyword-batch.ingest":
                    return self.success(
                        ai.ingest_keyword_batch(
                            assistance_request_id=self._required_string(
                                request, "assistance_request_id"
                            ),
                            payload=self._object_payload(request),
                        ),
                        request_id=request_id,
                        correlation_id=correlation_id,
                    )
                if canonical_operation == "ai.keyword-batch.get":
                    return self.success(
                        ai.get_keyword_batch(
                            self._required_string(request, "recommendation_batch_id")
                        ),
                        request_id=request_id,
                        correlation_id=correlation_id,
                    )
                if canonical_operation == "ai.keyword-recommendation.get":
                    return self.success(
                        ai.get_keyword_recommendation(
                            self._required_string(request, "recommendation_id")
                        ).to_schema_dict(),
                        request_id=request_id,
                        correlation_id=correlation_id,
                    )
                if canonical_operation == "ai.keyword-recommendation.list":
                    return self.success(
                        ai.list_keyword_recommendations(
                            case_id=self._required_string(request, "case_id"),
                            recommendation_batch_id=self._optional_string(
                                request, "recommendation_batch_id"
                            ),
                            cursor=self._optional_string(request, "cursor"),
                            limit=self._optional_integer(request, "limit", 100, minimum=1),
                        ),
                        request_id=request_id,
                        correlation_id=correlation_id,
                    )
                if canonical_operation == "ai.scope-summary.ingest":
                    return self.success(
                        ai.ingest_scope_summary(
                            assistance_request_id=self._required_string(
                                request, "assistance_request_id"
                            ),
                            payload=self._object_payload(request),
                        ).to_schema_dict(),
                        request_id=request_id,
                        correlation_id=correlation_id,
                    )
                if canonical_operation == "ai.scope-summary.get":
                    return self.success(
                        ai.get_scope_summary(
                            self._required_string(request, "scope_summary_id")
                        ).to_schema_dict(),
                        request_id=request_id,
                        correlation_id=correlation_id,
                    )
                if canonical_operation == "ai.scope-summary.list":
                    return self.success(
                        [
                            item.to_schema_dict()
                            for item in ai.list_scope_summaries(
                                case_id=self._required_string(request, "case_id"),
                                context_snapshot_id=self._optional_string(
                                    request, "context_snapshot_id"
                                ),
                                scope_context_id=self._optional_string(
                                    request, "scope_context_id"
                                ),
                                limit=self._optional_integer(
                                    request, "limit", 100, minimum=1
                                ),
                            )
                        ],
                        request_id=request_id,
                        correlation_id=correlation_id,
                    )
                if canonical_operation == "ai.keyword-recommendation.review":
                    return self.success(
                        ai.review_keyword_recommendation(
                            recommendation_id=self._required_string(
                                request, "recommendation_id"
                            ),
                            action=self._required_enum(
                                request, "action", AiVerificationAction
                            ),
                            actor_id=self._required_string(request, "actor_id"),
                            reason=self._required_string(request, "reason"),
                            expected_review_revision=self._optional_integer_or_none(
                                request, "expected_review_revision", minimum=0
                            ),
                            corrected_value=self._optional_string(
                                request, "corrected_value"
                            ),
                            corrected_reason=self._optional_string(
                                request, "corrected_reason"
                            ),
                        ).to_schema_dict(),
                        request_id=request_id,
                        correlation_id=correlation_id,
                    )
                if canonical_operation == "ai.scope-summary.review":
                    return self.success(
                        ai.review_scope_summary(
                            scope_summary_id=self._required_string(
                                request, "scope_summary_id"
                            ),
                            action=self._required_enum(
                                request, "action", AiVerificationAction
                            ),
                            actor_id=self._required_string(request, "actor_id"),
                            reason=self._required_string(request, "reason"),
                            expected_review_revision=self._optional_integer_or_none(
                                request, "expected_review_revision", minimum=0
                            ),
                            corrected_value=self._optional_string(
                                request, "corrected_value"
                            ),
                            corrected_reason=self._optional_string(
                                request, "corrected_reason"
                            ),
                        ).to_schema_dict(),
                        request_id=request_id,
                        correlation_id=correlation_id,
                    )
                if canonical_operation == "ai.verification.history":
                    return self.success(
                        [
                            item.to_schema_dict()
                            for item in ai.review_history(
                                target_type=self._required_string(request, "target_type"),
                                target_id=self._required_string(request, "target_id"),
                            )
                        ],
                        request_id=request_id,
                        correlation_id=correlation_id,
                    )
                if canonical_operation == "ai.promotion.preview":
                    return self.success(
                        ai.preview_keyword_promotion(
                            recommendation_id=self._required_string(
                                request, "recommendation_id"
                            ),
                            keyword_set_id=self._required_string(
                                request, "keyword_set_id"
                            ),
                            regex_confirmed=bool(request.get("regex_confirmed", False)),
                        ),
                        request_id=request_id,
                        correlation_id=correlation_id,
                    )
                if canonical_operation == "ai.keyword-recommendation.promote":
                    return self.success(
                        ai.promote_accepted_keyword(
                            recommendation_id=self._required_string(
                                request, "recommendation_id"
                            ),
                            keyword_set_id=self._required_string(
                                request, "keyword_set_id"
                            ),
                            actor_id=self._required_string(request, "actor_id"),
                            reason=self._required_string(request, "reason"),
                            expected_review_revision=self._optional_integer_or_none(
                                request, "expected_review_revision", minimum=0
                            ),
                            regex_confirmed=bool(request.get("regex_confirmed", False)),
                            confirmation_metadata=self._optional_object_payload(
                                request, "confirmation_metadata"
                            ),
                        ).to_schema_dict(),
                        request_id=request_id,
                        correlation_id=correlation_id,
                    )
            raise UnsupportedCapabilityError(
                "Unknown public read operation.", target="operation", required_capability=operation
            )
        except ApexError as apex_error:
            return self.error(apex_error, request_id=request_id, correlation_id=correlation_id)

    def invoke_mutation(
        self,
        operation: str,
        payload: Mapping[str, Any],
        *,
        request_id: str | None = None,
        correlation_id: str | None = None,
    ) -> dict[str, Any]:
        return self.invoke_read(
            operation,
            payload,
            request_id=request_id,
            correlation_id=correlation_id,
        )

    @staticmethod
    def _request_payload(payload: Mapping[str, Any]) -> Mapping[str, Any]:
        if not isinstance(payload, Mapping):
            raise ValidationError(
                "Invocation payload must be a JSON object.",
                target="payload",
                details={"payload_type": type(payload).__name__},
            )
        return payload

    def _object_payload(self, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        nested = payload.get("payload")
        if nested is None:
            return payload
        if not isinstance(nested, Mapping):
            raise ValidationError(
                "Invocation payload field must be a JSON object.",
                target="payload",
        )
        return nested

    def _optional_object_payload(
        self, payload: Mapping[str, Any], field: str
    ) -> dict[str, Any]:
        nested = payload.get(field)
        if nested is None:
            return {}
        if not isinstance(nested, Mapping):
            raise ValidationError(
                f"Invocation {field} field must be a JSON object.",
                target=field,
            )
        return dict(nested)

    @staticmethod
    def _canonical_operation(operation: str) -> str:
        canonical = _OPERATION_ALIASES.get(operation)
        if canonical is None:
            canonical = _OPERATION_ALIASES.get(operation.replace("_", "-"))
        if canonical is None:
            raise UnsupportedCapabilityError(
                "Unknown public read operation.", target="operation", required_capability=operation
            )
        return canonical

    @staticmethod
    def _required_value(payload: Mapping[str, Any], field: str) -> Any:
        if field not in payload or payload[field] is None:
            raise ValidationError(
                "Invocation payload is missing a required field.", target=field
            )
        return payload[field]

    @classmethod
    def _required_string(cls, payload: Mapping[str, Any], field: str) -> str:
        value = cls._required_value(payload, field)
        if not isinstance(value, str) or value == "":
            raise ValidationError(
                "Invocation payload field must be a non-empty string.",
                target=field,
                details={"value": value},
            )
        return value

    @staticmethod
    def _optional_string(payload: Mapping[str, Any], field: str) -> str | None:
        value = payload.get(field)
        if value is None:
            return None
        if not isinstance(value, str) or value == "":
            raise ValidationError(
                "Invocation payload field must be a non-empty string.",
                target=field,
                details={"value": value},
            )
        return value

    @staticmethod
    def _optional_integer(
        payload: Mapping[str, Any],
        field: str,
        default: int,
        *,
        minimum: int,
        maximum: int | None = None,
    ) -> int:
        value = payload.get(field, default)
        if isinstance(value, bool):
            raise ValidationError(
                "Invocation payload field must be an integer.",
                target=field,
                details={"value": value},
            )
        try:
            parsed = int(value)
        except (TypeError, ValueError) as error:
            raise ValidationError(
                "Invocation payload field must be an integer.",
                target=field,
                details={"value": value},
            ) from error
        if parsed < minimum or (maximum is not None and parsed > maximum):
            raise ValidationError(
                "Invocation payload integer is outside the allowed range.",
                target=field,
                details={"value": parsed, "minimum": minimum, "maximum": maximum},
            )
        return parsed

    @staticmethod
    def _optional_integer_or_none(
        payload: Mapping[str, Any],
        field: str,
        *,
        minimum: int,
        maximum: int | None = None,
    ) -> int | None:
        if field not in payload or payload[field] is None:
            return None
        value = payload[field]
        if isinstance(value, bool):
            raise ValidationError(
                "Invocation payload field must be an integer.",
                target=field,
                details={"value": value},
            )
        try:
            parsed = int(value)
        except (TypeError, ValueError) as error:
            raise ValidationError(
                "Invocation payload field must be an integer.",
                target=field,
                details={"value": value},
            ) from error
        if parsed < minimum or (maximum is not None and parsed > maximum):
            raise ValidationError(
                "Invocation payload integer is outside the allowed range.",
                target=field,
                details={"value": parsed, "minimum": minimum, "maximum": maximum},
            )
        return parsed

    @classmethod
    def _required_enum(cls, payload: Mapping[str, Any], field: str, enum_type: Any) -> Any:
        value = cls._required_string(payload, field)
        try:
            return enum_type(value)
        except ValueError as error:
            raise ValidationError(
                "Invocation payload field has an unsupported enum value.",
                target=field,
                details={"value": value},
            ) from error

    @staticmethod
    def _optional_enum(
        payload: Mapping[str, Any], field: str, enum_type: Any, default: Any
    ) -> Any:
        value = payload.get(field)
        if value is None:
            return default
        if not isinstance(value, str) or value == "":
            raise ValidationError(
                "Invocation payload field must be a non-empty string.",
                target=field,
                details={"value": value},
            )
        try:
            return enum_type(value)
        except ValueError as error:
            raise ValidationError(
                "Invocation payload field has an unsupported enum value.",
                target=field,
                details={"value": value},
            ) from error

    @staticmethod
    def _optional_scope_list(payload: Mapping[str, Any], field: str) -> list[str] | None:
        value = payload.get(field)
        if value is None:
            return None
        if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
            raise ValidationError(
                "Invocation payload field must be a list of strings.",
                target=field,
                details={"value": value},
            )
        scopes: list[str] = []
        for item in value:
            try:
                scopes.append(AnalysisScopeType(item).value)
            except ValueError as error:
                raise ValidationError(
                    "Invocation payload field has an unsupported enum value.",
                    target=field,
                    details={"value": item},
                ) from error
        return scopes

    @staticmethod
    def _optional_string_list(payload: Mapping[str, Any], field: str) -> list[str] | None:
        value = payload.get(field)
        if value is None:
            return None
        if not isinstance(value, list) or any(
            not isinstance(item, str) or not item for item in value
        ):
            raise ValidationError(
                "Invocation payload field must be a list of non-empty strings.",
                target=field,
                details={"value": value},
            )
        return list(dict.fromkeys(value))

    def _require_ai_service(self) -> Any:
        if self._ai is None:
            raise UnsupportedCapabilityError(
                "AI assistance service is not available.",
                target="operation",
                required_capability="AI_ASSISTANCE_ENGINE_CONTRACT",
            )
        return self._ai

    def _register_default_tool_descriptors(self) -> None:
        for spec in _TOOL_DESCRIPTOR_SPECS:
            (
                tool_name,
                _operation_name,
                description_key,
                input_schema_ref,
                output_schema_ref,
                required_capabilities,
                mutates_state,
                requires_confirmation,
                supports_pagination,
                supports_partial,
                supports_citation,
                max_result_items,
            ) = spec
            descriptor = EngineToolDescriptor(
                tool_name,
                INTERFACE_VERSION,
                description_key,
                input_schema_ref,
                output_schema_ref,
                required_capabilities,
                mutates_state,
                requires_confirmation,
                supports_pagination,
                supports_partial,
                supports_citation,
                max_result_items,
            )
            self._repository.save_engine_tool_descriptor(descriptor)
