"""Phase 7 AI assistance contract domain models."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from apex_forensic._time import to_json_timestamp
from apex_forensic.constants import SCHEMA_VERSION


def _value(value: Any) -> Any:
    return value.value if hasattr(value, "value") else value


def _timestamp(value: datetime | None) -> str | None:
    return None if value is None else to_json_timestamp(value)


@dataclass(slots=True)
class AiProviderCapability:
    """Provider-neutral capability statement for an external AI layer."""

    provider_id: str
    provider_version: str
    supported_operations: list[str]
    max_request_items: int
    max_result_items: int
    max_summary_length: int
    is_available: bool
    unavailable_reason: str | None = None
    warnings: list[dict[str, Any]] = field(default_factory=list)
    generated_at: datetime | None = None
    capability_version: str = SCHEMA_VERSION

    def to_schema_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.capability_version,
            "provider_id": self.provider_id,
            "provider_version": self.provider_version,
            "supported_operations": self.supported_operations,
            "max_request_items": self.max_request_items,
            "max_result_items": self.max_result_items,
            "max_summary_length": self.max_summary_length,
            "is_available": self.is_available,
            "unavailable_reason": self.unavailable_reason,
            "warnings": self.warnings,
            "generated_at": _timestamp(self.generated_at),
        }


@dataclass(slots=True)
class AiAssistanceRequest:
    """Immutable request DTO created from an analysis context snapshot."""

    assistance_request_id: str
    case_id: str
    context_snapshot_id: str
    purpose: str
    requested_operations: list[str]
    requested_scopes: list[str]
    scope_context_ids: list[str]
    locale: str
    timezone: str
    context_fingerprint: str
    source_revision_fingerprint: str
    is_partial: bool
    is_stale: bool
    coverage_summary: dict[str, Any]
    warnings: list[dict[str, Any]]
    citations: list[dict[str, Any]]
    max_keyword_candidates: int
    max_summary_length: int
    requested_at: datetime
    expires_at: datetime
    request_version: str
    correlation_id: str | None
    request_fingerprint: str
    resource_count: int

    def to_schema_dict(self) -> dict[str, Any]:
        return {
            "assistance_request_id": self.assistance_request_id,
            "case_id": self.case_id,
            "context_snapshot_id": self.context_snapshot_id,
            "purpose": _value(self.purpose),
            "requested_operations": [_value(item) for item in self.requested_operations],
            "requested_scopes": self.requested_scopes,
            "scope_context_ids": self.scope_context_ids,
            "locale": self.locale,
            "timezone": self.timezone,
            "context_fingerprint": self.context_fingerprint,
            "source_revision_fingerprint": self.source_revision_fingerprint,
            "is_partial": self.is_partial,
            "is_stale": self.is_stale,
            "coverage_summary": self.coverage_summary,
            "warnings": self.warnings,
            "citations": self.citations,
            "max_keyword_candidates": self.max_keyword_candidates,
            "max_summary_length": self.max_summary_length,
            "requested_at": to_json_timestamp(self.requested_at),
            "expires_at": to_json_timestamp(self.expires_at),
            "request_version": self.request_version,
            "correlation_id": self.correlation_id,
            "request_fingerprint": self.request_fingerprint,
            "resource_count": self.resource_count,
        }


@dataclass(slots=True)
class AiKeywordRecommendationBatch:
    """One externally generated keyword recommendation result batch."""

    recommendation_batch_id: str
    assistance_request_id: str
    case_id: str
    context_snapshot_id: str
    provider_id: str
    provider_version: str
    model_id: str
    external_request_id: str | None
    generation_started_at: datetime
    generation_completed_at: datetime
    result_hash: str
    recommendation_count: int
    partial_state: dict[str, Any]
    stale_state: dict[str, Any]
    warnings: list[dict[str, Any]]
    created_at: datetime
    batch_version: str

    def to_schema_dict(self) -> dict[str, Any]:
        return {
            "recommendation_batch_id": self.recommendation_batch_id,
            "assistance_request_id": self.assistance_request_id,
            "case_id": self.case_id,
            "context_snapshot_id": self.context_snapshot_id,
            "provider_id": self.provider_id,
            "provider_version": self.provider_version,
            "model_id": self.model_id,
            "external_request_id": self.external_request_id,
            "generation_started_at": to_json_timestamp(self.generation_started_at),
            "generation_completed_at": to_json_timestamp(self.generation_completed_at),
            "result_hash": self.result_hash,
            "recommendation_count": self.recommendation_count,
            "partial_state": self.partial_state,
            "stale_state": self.stale_state,
            "warnings": self.warnings,
            "created_at": to_json_timestamp(self.created_at),
            "batch_version": self.batch_version,
        }


@dataclass(slots=True)
class AiKeywordRecommendation:
    """One AI keyword candidate that is not an observed forensic fact."""

    recommendation_id: str
    recommendation_batch_id: str
    case_id: str
    context_snapshot_id: str
    keyword_type: str
    value: str
    normalized_value: str
    display_value: str
    reason: str
    confidence: str
    recommended_scope: str
    evidence_ids: list[str]
    source_resource_ids: list[str]
    citations: list[dict[str, Any]]
    is_partial: bool
    stale_reasons: list[str]
    risk_flags: list[str]
    review_status: str
    current_review_revision: int
    content_fingerprint: str
    created_at: datetime
    effective_value: str | None = None
    effective_reason: str | None = None
    corrected_reason: str | None = None

    def to_schema_dict(self) -> dict[str, Any]:
        return {
            "recommendation_id": self.recommendation_id,
            "recommendation_batch_id": self.recommendation_batch_id,
            "case_id": self.case_id,
            "context_snapshot_id": self.context_snapshot_id,
            "keyword_type": _value(self.keyword_type),
            "value": self.value,
            "normalized_value": self.normalized_value,
            "display_value": self.display_value,
            "reason": self.reason,
            "confidence": _value(self.confidence),
            "recommended_scope": self.recommended_scope,
            "evidence_ids": self.evidence_ids,
            "source_resource_ids": self.source_resource_ids,
            "citations": self.citations,
            "is_partial": self.is_partial,
            "stale_reasons": self.stale_reasons,
            "risk_flags": self.risk_flags,
            "review_status": _value(self.review_status),
            "current_review_revision": self.current_review_revision,
            "content_fingerprint": self.content_fingerprint,
            "created_at": to_json_timestamp(self.created_at),
            "result_kind": "AI_RECOMMENDATION",
            "observed_fact_status": "NOT_OBSERVED_FACT",
            "effective_value": self.effective_value or self.value,
            "effective_reason": self.effective_reason or self.reason,
            "corrected_reason": self.corrected_reason,
        }


@dataclass(slots=True)
class AiScopeSummaryRecord:
    """One externally generated scope summary result."""

    scope_summary_id: str
    assistance_request_id: str
    case_id: str
    context_snapshot_id: str
    scope_context_id: str
    scope_type: str
    provider_id: str
    provider_version: str
    model_id: str
    external_request_id: str | None
    title: str
    summary_text: str
    key_points: list[str]
    referenced_resource_ids: list[str]
    citations: list[dict[str, Any]]
    partial_state: dict[str, Any]
    stale_state: dict[str, Any]
    coverage: dict[str, Any]
    warnings: list[dict[str, Any]]
    review_status: str
    current_review_revision: int
    content_fingerprint: str
    created_at: datetime
    summary_version: str
    effective_title: str | None = None
    effective_summary_text: str | None = None
    effective_key_points: list[str] | None = None
    corrected_reason: str | None = None

    def to_schema_dict(self) -> dict[str, Any]:
        return {
            "scope_summary_id": self.scope_summary_id,
            "assistance_request_id": self.assistance_request_id,
            "case_id": self.case_id,
            "context_snapshot_id": self.context_snapshot_id,
            "scope_context_id": self.scope_context_id,
            "scope_type": self.scope_type,
            "provider_id": self.provider_id,
            "provider_version": self.provider_version,
            "model_id": self.model_id,
            "external_request_id": self.external_request_id,
            "title": self.title,
            "summary_text": self.summary_text,
            "key_points": self.key_points,
            "referenced_resource_ids": self.referenced_resource_ids,
            "citations": self.citations,
            "partial_state": self.partial_state,
            "stale_state": self.stale_state,
            "coverage": self.coverage,
            "warnings": self.warnings,
            "review_status": _value(self.review_status),
            "current_review_revision": self.current_review_revision,
            "content_fingerprint": self.content_fingerprint,
            "created_at": to_json_timestamp(self.created_at),
            "summary_version": self.summary_version,
            "result_kind": "AI_SUMMARY",
            "observed_fact_status": "NOT_OBSERVED_FACT",
            "effective_title": self.effective_title or self.title,
            "effective_summary_text": self.effective_summary_text or self.summary_text,
            "effective_key_points": self.effective_key_points or self.key_points,
            "corrected_reason": self.corrected_reason,
        }


@dataclass(slots=True)
class AiVerificationEvent:
    """Append-only human verification event for a Phase 7 AI result."""

    verification_event_id: str
    case_id: str
    target_type: str
    target_id: str
    action: str
    previous_status: str
    new_status: str
    actor_id: str
    reason: str
    corrected_value: str | None
    corrected_reason: str | None
    review_revision: int
    previous_event_hash: str | None
    event_hash: str
    created_at: datetime

    def to_schema_dict(self) -> dict[str, Any]:
        return {
            "verification_event_id": self.verification_event_id,
            "case_id": self.case_id,
            "target_type": _value(self.target_type),
            "target_id": self.target_id,
            "action": _value(self.action),
            "previous_status": _value(self.previous_status),
            "new_status": _value(self.new_status),
            "actor_id": self.actor_id,
            "reason": self.reason,
            "corrected_value": self.corrected_value,
            "corrected_reason": self.corrected_reason,
            "review_revision": self.review_revision,
            "previous_event_hash": self.previous_event_hash,
            "event_hash": self.event_hash,
            "created_at": to_json_timestamp(self.created_at),
        }


@dataclass(slots=True)
class AiKeywordPromotion:
    """Idempotent promotion record linking an accepted candidate to a keyword set."""

    promotion_id: str
    case_id: str
    recommendation_id: str
    review_revision: int
    keyword_set_id: str
    keyword_set_version_id: str | None
    keyword_set_version: int | None
    promoted_keyword_id: str | None
    promoted_value: str
    status: str
    duplicate: bool
    source_context_snapshot_id: str
    actor_id: str
    reason: str
    promotion_fingerprint: str
    metadata: dict[str, Any]
    created_at: datetime

    def to_schema_dict(self) -> dict[str, Any]:
        return {
            "promotion_id": self.promotion_id,
            "case_id": self.case_id,
            "recommendation_id": self.recommendation_id,
            "review_revision": self.review_revision,
            "keyword_set_id": self.keyword_set_id,
            "keyword_set_version_id": self.keyword_set_version_id,
            "keyword_set_version": self.keyword_set_version,
            "promoted_keyword_id": self.promoted_keyword_id,
            "promoted_value": self.promoted_value,
            "status": self.status,
            "duplicate": self.duplicate,
            "source_context_snapshot_id": self.source_context_snapshot_id,
            "actor_id": self.actor_id,
            "reason": self.reason,
            "promotion_fingerprint": self.promotion_fingerprint,
            "metadata": self.metadata,
            "created_at": to_json_timestamp(self.created_at),
        }
