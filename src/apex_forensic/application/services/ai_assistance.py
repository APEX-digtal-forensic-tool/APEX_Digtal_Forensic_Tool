"""Phase 7 AI assistance request/result contract service."""

from __future__ import annotations

import base64
import ipaddress
import json
import re
from collections.abc import Iterable, Mapping
from datetime import datetime, timedelta
from typing import Any, cast
from urllib.parse import urlparse

from apex_forensic._time import parse_timestamp, to_json_timestamp
from apex_forensic.constants import DEFAULT_LOCALE, DEFAULT_TIMEZONE, SCHEMA_VERSION
from apex_forensic.domain.enums import (
    AiAssistancePurpose,
    AiKeywordConfidence,
    AiRequestedOperation,
    AiReviewStatus,
    AiVerificationAction,
    AiVerificationTargetType,
    AnalysisScopeType,
    KeywordMatchMode,
    KeywordType,
)
from apex_forensic.domain.errors import (
    AiAssistanceError,
    ApexError,
    NotFoundError,
    ValidationError,
)
from apex_forensic.domain.models import (
    AiAssistanceRequest,
    AiKeywordPromotion,
    AiKeywordRecommendation,
    AiKeywordRecommendationBatch,
    AiScopeSummaryRecord,
    AiVerificationEvent,
    AnalysisContextSnapshot,
    AnalysisScopeContext,
    KeywordSet,
)
from apex_forensic.domain.services.canonical import canonical_json_bytes, canonical_sha256
from apex_forensic.ports.ai_assistance import (
    AiAssistanceProviderPort,
    UnavailableAiAssistanceProvider,
)
from apex_forensic.ports.clock import Clock
from apex_forensic.ports.id_generator import IdGenerator

AI_REQUEST_VERSION = "ai-assistance-request-v1"
AI_KEYWORD_BATCH_VERSION = "ai-keyword-recommendation-batch-v1"
AI_SUMMARY_VERSION = "ai-scope-summary-v1"
DEFAULT_REQUEST_TTL_SECONDS = 60 * 60
MAX_REQUEST_SCOPES = 32
MAX_REQUEST_ITEMS = 10_000
MAX_REQUEST_CITATIONS = 200
MAX_KEYWORD_CANDIDATES = 1000
MAX_SUMMARY_LENGTH = 20_000
MAX_KEY_POINTS = 20
MAX_KEY_POINT_LENGTH = 500
MAX_WARNING_COUNT = 200
MAX_REASON_LENGTH = 4000
MAX_PROVIDER_METADATA_LENGTH = 256
MAX_SCOPE_TITLE_LENGTH = 300
MAX_KEYWORD_TEXT_LENGTH = 4096
MAX_ACTOR_ID_LENGTH = 256
MAX_JSON_DEPTH = 8
MAX_JSON_BYTES = 512 * 1024
NO_DIRECT_CITATION = "NO_DIRECT_CITATION"
PARTIAL_WARNING = "AI_RESULT_FROM_PARTIAL_SNAPSHOT"
STALE_WARNING = "AI_RESULT_FROM_STALE_SNAPSHOT"
_FORBIDDEN_KEY_PARTS = (
    "api_key",
    "apikey",
    "secret",
    "credential",
    "password",
    "prompt",
    "chain_of_thought",
    "chain-of-thought",
    "reasoning_trace",
    "raw_body",
)
_RAW_BLOB_KEYS = ("raw_blob", "blob", "binary", "bytes", "base64")
_DANGEROUS_TEXT = re.compile(r"<\s*(script|iframe|object|embed|img|svg|html)\b", re.IGNORECASE)
_BASE64_DATA = re.compile(r"data\s*:\s*[^;]+;\s*base64\s*,", re.IGNORECASE)
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)
_HASH_RE = re.compile(
    r"^(?:(?:md5:)?[0-9a-fA-F]{32}|(?:sha1:)?[0-9a-fA-F]{40}|"
    r"(?:sha256:)?[0-9a-fA-F]{64})$"
)


class AiAssistanceService:
    """Validates and persists Phase 7 AI assistance contracts.

    The service never calls a runtime LLM unless an external test/provider object is explicitly
    supplied, and provider output always re-enters through the same validation methods.
    """

    def __init__(
        self,
        *,
        repository: Any,
        contexts: Any,
        search: Any,
        clock: Clock,
        id_generator: IdGenerator,
        provider: AiAssistanceProviderPort | None = None,
    ) -> None:
        self._repository = repository
        self._contexts = contexts
        self._search = search
        self._clock = clock
        self._id_generator = id_generator
        self._provider = provider or UnavailableAiAssistanceProvider()

    def capabilities(self) -> dict[str, Any]:
        provider_capability = self._provider.capabilities()
        provider_capability.generated_at = provider_capability.generated_at or self._clock.now()
        engine_capabilities = [
            "AI_ASSISTANCE_REQUEST_CONTRACT",
            "AI_RESULT_VALIDATION",
            "AI_CITATION_VALIDATION",
            "AI_HUMAN_VERIFICATION",
            "AI_KEYWORD_PROMOTION",
        ]
        unavailable_capabilities = [
            "PROMPT_TEMPLATE",
            "MCP_SERVER",
            "AI_OBSERVED_FACT_PROMOTION",
        ]
        if provider_capability.is_available:
            engine_capabilities.append("RUNTIME_LLM_PROVIDER")
        else:
            unavailable_capabilities.append("RUNTIME_LLM_PROVIDER")
        return {
            "schema_version": SCHEMA_VERSION,
            "engine_capabilities": engine_capabilities,
            "unavailable_capabilities": unavailable_capabilities,
            "runtime_capability": provider_capability.to_schema_dict(),
        }

    def create_request_from_context_snapshot(
        self,
        *,
        case_id: str,
        context_snapshot_id: str,
        purpose: AiAssistancePurpose | str = AiAssistancePurpose.INVESTIGATION_ASSISTANCE,
        requested_operations: list[str] | None = None,
        requested_scopes: list[str] | None = None,
        scope_context_ids: list[str] | None = None,
        locale: str | None = None,
        timezone: str | None = None,
        max_keyword_candidates: int = 100,
        max_summary_length: int = 4000,
        ttl_seconds: int = DEFAULT_REQUEST_TTL_SECONDS,
        correlation_id: str | None = None,
    ) -> AiAssistanceRequest:
        correlation_id = _optional_non_empty(correlation_id, "correlation_id")
        self._require_case(case_id)
        snapshot = self._require_snapshot(context_snapshot_id)
        if snapshot.case_id != case_id:
            raise AiAssistanceError(
                "AI_REQUEST_CASE_MISMATCH",
                "Context snapshot belongs to another case.",
                target="context_snapshot_id",
            )
        purpose_value = _enum_value(AiAssistancePurpose, purpose, "purpose")
        operations = self._requested_operations(purpose_value, requested_operations)
        scopes = self._requested_scopes(snapshot, requested_scopes)
        scope_contexts = self._scope_contexts_for_request(snapshot, scopes, scope_context_ids)
        max_keyword_candidates = self._limit(
            max_keyword_candidates,
            minimum=1,
            maximum=MAX_KEYWORD_CANDIDATES,
            code="AI_REQUEST_LIMIT_EXCEEDED",
            target="max_keyword_candidates",
        )
        max_summary_length = self._limit(
            max_summary_length,
            minimum=1,
            maximum=MAX_SUMMARY_LENGTH,
            code="AI_REQUEST_LIMIT_EXCEEDED",
            target="max_summary_length",
        )
        if ttl_seconds <= 0:
            raise AiAssistanceError(
                "AI_REQUEST_LIMIT_EXCEEDED",
                "Request TTL must be positive.",
                target="ttl_seconds",
            )
        resource_count = sum(scope.result_count for scope in scope_contexts)
        if resource_count > MAX_REQUEST_ITEMS:
            raise AiAssistanceError(
                "AI_REQUEST_LIMIT_EXCEEDED",
                "AI assistance request exceeds the maximum resource count.",
                target="context_snapshot_id",
                details={"resource_count": resource_count, "maximum": MAX_REQUEST_ITEMS},
            )
        if len(snapshot.citations) > MAX_REQUEST_CITATIONS:
            raise AiAssistanceError(
                "AI_REQUEST_LIMIT_EXCEEDED",
                "AI assistance request exceeds the maximum citation count.",
                target="citations",
            )
        citations = _stable_citations(list(snapshot.citations))
        warnings = _bounded_warnings(
            [
                *snapshot.warnings,
                *[warning for scope in scope_contexts for warning in scope.warnings],
                *_state_warnings(snapshot),
            ],
            "warnings",
        )
        coverage_summary = {
            scope.scope_context_id: {
                "scope_type": scope.scope_type.value
                if hasattr(scope.scope_type, "value")
                else str(scope.scope_type),
                "coverage": scope.coverage,
                "result_count": scope.result_count,
                "included_count": scope.included_count,
                "is_partial": scope.is_partial,
                "stale_reasons": scope.stale_reasons,
            }
            for scope in sorted(scope_contexts, key=lambda item: item.scope_context_id)
        }
        source_revision_fingerprint = canonical_sha256(
            [
                {
                    "resource_type": state.resource_type.value
                    if hasattr(state.resource_type, "value")
                    else str(state.resource_type),
                    "resource_id": state.resource_id,
                    "expected_revision": state.expected_revision,
                    "current_revision": state.current_revision,
                    "status": state.status.value
                    if hasattr(state.status, "value")
                    else str(state.status),
                    "reason": state.reason,
                }
                for state in sorted(
                    snapshot.source_revisions,
                    key=lambda item: (
                        item.resource_type.value
                        if hasattr(item.resource_type, "value")
                        else str(item.resource_type),
                        item.resource_id,
                    ),
                )
            ]
        )
        now = self._clock.now()
        expires_at = now + timedelta(seconds=ttl_seconds)
        fingerprint_payload = {
            "case_id": case_id,
            "context_snapshot_id": context_snapshot_id,
            "purpose": purpose_value,
            "requested_operations": operations,
            "requested_scopes": scopes,
            "scope_context_ids": [scope.scope_context_id for scope in scope_contexts],
            "locale": locale or DEFAULT_LOCALE,
            "timezone": timezone or DEFAULT_TIMEZONE,
            "context_fingerprint": snapshot.context_fingerprint,
            "source_revision_fingerprint": source_revision_fingerprint,
            "max_keyword_candidates": max_keyword_candidates,
            "max_summary_length": max_summary_length,
            "request_version": AI_REQUEST_VERSION,
        }
        request_fingerprint = canonical_sha256(fingerprint_payload)
        existing = self._repository.get_ai_assistance_request_by_fingerprint(
            request_fingerprint
        )
        if existing is not None:
            return cast(AiAssistanceRequest, existing)
        request = AiAssistanceRequest(
            assistance_request_id=self._id_generator.new_id(),
            case_id=case_id,
            context_snapshot_id=context_snapshot_id,
            purpose=purpose_value,
            requested_operations=operations,
            requested_scopes=scopes,
            scope_context_ids=[scope.scope_context_id for scope in scope_contexts],
            locale=locale or DEFAULT_LOCALE,
            timezone=timezone or DEFAULT_TIMEZONE,
            context_fingerprint=snapshot.context_fingerprint,
            source_revision_fingerprint=source_revision_fingerprint,
            is_partial=bool(snapshot.partial_state.get("is_partial", False))
            or any(scope.is_partial for scope in scope_contexts),
            is_stale=bool(snapshot.stale_state.get("is_stale", False)),
            coverage_summary=coverage_summary,
            warnings=warnings,
            citations=citations,
            max_keyword_candidates=max_keyword_candidates,
            max_summary_length=max_summary_length,
            requested_at=now,
            expires_at=expires_at,
            request_version=AI_REQUEST_VERSION,
            correlation_id=correlation_id,
            request_fingerprint=request_fingerprint,
            resource_count=resource_count,
        )
        self._repository.save_ai_assistance_request(request)
        return request

    def get_request(self, assistance_request_id: str) -> AiAssistanceRequest:
        request = self._repository.get_ai_assistance_request(assistance_request_id)
        if request is None:
            raise AiAssistanceError(
                "AI_REQUEST_NOT_FOUND",
                "AI assistance request not found.",
                target="assistance_request_id",
            )
        return cast(AiAssistanceRequest, request)

    def list_requests_by_case(
        self, case_id: str, *, limit: int = 100
    ) -> list[AiAssistanceRequest]:
        self._require_case(case_id)
        return cast(
            list[AiAssistanceRequest],
            self._repository.list_ai_assistance_requests(
                case_id=case_id,
                limit=self._limit(limit, minimum=1, maximum=MAX_KEYWORD_CANDIDATES),
            ),
        )

    def expire_request(self, assistance_request_id: str) -> AiAssistanceRequest:
        request = self.get_request(assistance_request_id)
        self._repository.expire_ai_assistance_request(
            assistance_request_id,
            expires_at=self._clock.now(),
        )
        return self.get_request(request.assistance_request_id)

    def compare_requests(self, left_request_id: str, right_request_id: str) -> dict[str, Any]:
        left = self.get_request(left_request_id)
        right = self.get_request(right_request_id)
        return {
            "left_assistance_request_id": left.assistance_request_id,
            "right_assistance_request_id": right.assistance_request_id,
            "same_fingerprint": left.request_fingerprint == right.request_fingerprint,
            "left_request_fingerprint": left.request_fingerprint,
            "right_request_fingerprint": right.request_fingerprint,
            "changed_fields": [
                key
                for key in left.to_schema_dict()
                if left.to_schema_dict().get(key) != right.to_schema_dict().get(key)
                and key
                not in {
                    "assistance_request_id",
                    "requested_at",
                    "expires_at",
                    "correlation_id",
                }
            ],
        }

    def validate_current_revisions(self, assistance_request_id: str) -> dict[str, Any]:
        request = self.get_request(assistance_request_id)
        snapshot = self._require_snapshot(request.context_snapshot_id)
        states = []
        for state in snapshot.source_revisions:
            resource_type = (
                state.resource_type.value
                if hasattr(state.resource_type, "value")
                else str(state.resource_type)
            )
            try:
                info = self._contexts.resolve_resource(
                    resource_type=resource_type,
                    resource_id=state.resource_id,
                )
            except ApexError:
                states.append(
                    {
                        "resource_type": resource_type,
                        "resource_id": state.resource_id,
                        "status": "MISSING",
                        "reason": "RESOURCE_MISSING",
                    }
                )
                continue
            current_revision = info.get("source_revision")
            expected_revision = state.expected_revision
            status = "CURRENT" if str(current_revision) == str(expected_revision) else "STALE"
            states.append(
                {
                    "resource_type": resource_type,
                    "resource_id": state.resource_id,
                    "expected_revision": expected_revision,
                    "current_revision": current_revision,
                    "status": status,
                    "reason": None if status == "CURRENT" else "SOURCE_REVISION_CHANGED",
                }
            )
        return {
            "assistance_request_id": assistance_request_id,
            "context_snapshot_id": request.context_snapshot_id,
            "is_current": all(item["status"] == "CURRENT" for item in states),
            "states": states,
        }

    def ingest_keyword_batch(
        self,
        *,
        assistance_request_id: str,
        payload: Mapping[str, Any],
    ) -> dict[str, Any]:
        request = self._request_for_ingest(assistance_request_id)
        _validate_contract_payload(payload, target="keyword_batch")
        recommendations_input = _required_list(payload, "recommendations")
        if len(recommendations_input) > request.max_keyword_candidates:
            raise AiAssistanceError(
                "AI_REQUEST_LIMIT_EXCEEDED",
                "Keyword recommendation result exceeds the request limit.",
                target="recommendations",
            )
        now = self._clock.now()
        provider_id = _metadata_string(payload.get("provider_id", "UNKNOWN"), "provider_id")
        provider_version = _metadata_string(
            payload.get("provider_version", "UNKNOWN"), "provider_version"
        )
        model_id = _metadata_string(payload.get("model_id", "UNKNOWN"), "model_id")
        generation_started_at = _optional_timestamp(
            payload.get("generation_started_at"), default=now, target="generation_started_at"
        )
        generation_completed_at = _optional_timestamp(
            payload.get("generation_completed_at"),
            default=now,
            target="generation_completed_at",
        )
        warnings = _bounded_warnings(payload.get("warnings", []), "warnings")
        external_request_id = _optional_non_empty(
            payload.get("external_request_id"),
            "external_request_id",
        )
        snapshot = self._require_snapshot(request.context_snapshot_id)
        batch_id = self._id_generator.new_id()
        recommendations = self._keyword_recommendations_from_input(
            request=request,
            snapshot=snapshot,
            batch_id=batch_id,
            recommendations_input=recommendations_input,
        )
        result_hash = canonical_sha256(
            {
                "provider_id": provider_id,
                "provider_version": provider_version,
                "model_id": model_id,
                "external_request_id": external_request_id,
                "recommendations": [
                    _without_generated_fields(item.to_schema_dict())
                    for item in recommendations
                ],
                "warnings": warnings,
            }
        )
        batch = AiKeywordRecommendationBatch(
            recommendation_batch_id=batch_id,
            assistance_request_id=request.assistance_request_id,
            case_id=request.case_id,
            context_snapshot_id=request.context_snapshot_id,
            provider_id=provider_id,
            provider_version=provider_version,
            model_id=model_id,
            external_request_id=external_request_id,
            generation_started_at=generation_started_at,
            generation_completed_at=generation_completed_at,
            result_hash=result_hash,
            recommendation_count=len(recommendations),
            partial_state=_partial_state(request),
            stale_state=_stale_state(request),
            warnings=_bounded_warnings(
                [*warnings, *_state_warnings_for_request(request)],
                "warnings",
            ),
            created_at=now,
            batch_version=AI_KEYWORD_BATCH_VERSION,
        )
        self._repository.save_ai_keyword_batch(batch, recommendations)
        return {
            "batch": batch.to_schema_dict(),
            "recommendations": [item.to_schema_dict() for item in recommendations],
        }

    def get_keyword_batch(self, recommendation_batch_id: str) -> dict[str, Any]:
        batch = self._repository.get_ai_keyword_batch(recommendation_batch_id)
        if batch is None:
            raise NotFoundError(
                "AI_KEYWORD_BATCH_NOT_FOUND",
                "AI keyword recommendation batch not found.",
                target="recommendation_batch_id",
            )
        recommendations = self._repository.list_ai_keyword_recommendations(
            case_id=batch.case_id,
            recommendation_batch_id=batch.recommendation_batch_id,
            after_recommendation_id=None,
            limit=MAX_KEYWORD_CANDIDATES,
        )
        return {
            "batch": batch.to_schema_dict(),
            "recommendations": [
                self._effective_keyword(item).to_schema_dict() for item in recommendations
            ],
        }

    def get_keyword_recommendation(self, recommendation_id: str) -> AiKeywordRecommendation:
        recommendation = self._repository.get_ai_keyword_recommendation(recommendation_id)
        if recommendation is None:
            raise NotFoundError(
                "AI_KEYWORD_RECOMMENDATION_NOT_FOUND",
                "AI keyword recommendation not found.",
                target="recommendation_id",
            )
        return self._effective_keyword(recommendation)

    def list_keyword_recommendations(
        self,
        *,
        case_id: str,
        recommendation_batch_id: str | None = None,
        cursor: str | None = None,
        limit: int = 100,
    ) -> dict[str, Any]:
        self._require_case(case_id)
        limit = self._limit(limit, minimum=1, maximum=MAX_KEYWORD_CANDIDATES)
        after = _decode_cursor(cursor, field="recommendation_id")
        rows = self._repository.list_ai_keyword_recommendations(
            case_id=case_id,
            recommendation_batch_id=recommendation_batch_id,
            after_recommendation_id=after,
            limit=limit + 1,
        )
        has_more = len(rows) > limit
        items = [self._effective_keyword(item).to_schema_dict() for item in rows[:limit]]
        next_cursor = (
            _encode_cursor("recommendation_id", items[-1]["recommendation_id"])
            if has_more and items
            else None
        )
        return {
            "items": items,
            "page": {"next_cursor": next_cursor, "has_more": has_more, "returned": len(items)},
        }

    def ingest_scope_summary(
        self,
        *,
        assistance_request_id: str,
        payload: Mapping[str, Any],
    ) -> AiScopeSummaryRecord:
        request = self._request_for_ingest(assistance_request_id)
        _validate_contract_payload(payload, target="scope_summary")
        snapshot = self._require_snapshot(request.context_snapshot_id)
        scope_context = self._scope_context_for_summary(request, payload)
        summary_text = _required_string(payload, "summary_text")
        if len(summary_text) > request.max_summary_length:
            raise AiAssistanceError(
                "AI_REQUEST_LIMIT_EXCEEDED",
                "Scope summary exceeds the request summary length limit.",
                target="summary_text",
            )
        _validate_safe_text(summary_text, "summary_text")
        title = _bounded_non_empty(
            _required_string(payload, "title"),
            "title",
            MAX_SCOPE_TITLE_LENGTH,
        )
        _validate_safe_text(title, "title")
        key_points = _string_list(payload.get("key_points", []), "key_points")
        if len(key_points) > MAX_KEY_POINTS:
            raise AiAssistanceError(
                "AI_REQUEST_LIMIT_EXCEEDED",
                "Scope summary has too many key points.",
                target="key_points",
            )
        for point in key_points:
            if len(point) > MAX_KEY_POINT_LENGTH:
                raise AiAssistanceError(
                    "AI_REQUEST_LIMIT_EXCEEDED",
                    "Scope summary key point is too long.",
                    target="key_points",
                )
            _validate_safe_text(point, "key_points")
        citations = self._validate_citations(
            case_id=request.case_id,
            snapshot=snapshot,
            citations=_required_list(payload, "citations"),
            target="citations",
            require_direct=True,
        )
        referenced_resource_ids = _string_list(
            payload.get("referenced_resource_ids", []),
            "referenced_resource_ids",
        )
        self._validate_resource_ids_in_scope(scope_context, referenced_resource_ids)
        now = self._clock.now()
        warnings = _bounded_warnings(
            [
                *_required_optional_list(payload.get("warnings", []), "warnings"),
                *_state_warnings_for_request(request),
            ],
            "warnings",
        )
        external_request_id = _optional_non_empty(
            payload.get("external_request_id"),
            "external_request_id",
        )
        content_payload = {
            "assistance_request_id": request.assistance_request_id,
            "case_id": request.case_id,
            "context_snapshot_id": request.context_snapshot_id,
            "scope_context_id": scope_context.scope_context_id,
            "title": title,
            "summary_text": summary_text,
            "key_points": key_points,
            "referenced_resource_ids": sorted(referenced_resource_ids),
            "citations": citations,
            "partial_state": _partial_state(request, scope_context),
            "stale_state": _stale_state(request, scope_context),
            "coverage": payload.get("coverage") or scope_context.coverage,
        }
        record = AiScopeSummaryRecord(
            scope_summary_id=self._id_generator.new_id(),
            assistance_request_id=request.assistance_request_id,
            case_id=request.case_id,
            context_snapshot_id=request.context_snapshot_id,
            scope_context_id=scope_context.scope_context_id,
            scope_type=scope_context.scope_type.value
            if hasattr(scope_context.scope_type, "value")
            else str(scope_context.scope_type),
            provider_id=_metadata_string(payload.get("provider_id", "UNKNOWN"), "provider_id"),
            provider_version=_metadata_string(
                payload.get("provider_version", "UNKNOWN"), "provider_version"
            ),
            model_id=_metadata_string(payload.get("model_id", "UNKNOWN"), "model_id"),
            external_request_id=external_request_id,
            title=title,
            summary_text=summary_text,
            key_points=key_points,
            referenced_resource_ids=sorted(referenced_resource_ids),
            citations=citations,
            partial_state=_partial_state(request, scope_context),
            stale_state=_stale_state(request, scope_context),
            coverage=dict(payload.get("coverage") or scope_context.coverage),
            warnings=warnings,
            review_status=AiReviewStatus.UNREVIEWED.value,
            current_review_revision=0,
            content_fingerprint=canonical_sha256(content_payload),
            created_at=now,
            summary_version=AI_SUMMARY_VERSION,
        )
        self._repository.save_ai_scope_summary(record)
        return record

    def get_scope_summary(self, scope_summary_id: str) -> AiScopeSummaryRecord:
        summary = self._repository.get_ai_scope_summary(scope_summary_id)
        if summary is None:
            raise NotFoundError(
                "AI_SCOPE_SUMMARY_NOT_FOUND",
                "AI scope summary not found.",
                target="scope_summary_id",
            )
        return self._effective_summary(summary)

    def list_scope_summaries(
        self,
        *,
        case_id: str,
        context_snapshot_id: str | None = None,
        scope_context_id: str | None = None,
        limit: int = 100,
    ) -> list[AiScopeSummaryRecord]:
        self._require_case(case_id)
        return [
            self._effective_summary(item)
            for item in self._repository.list_ai_scope_summaries(
                case_id=case_id,
                context_snapshot_id=context_snapshot_id,
                scope_context_id=scope_context_id,
                limit=self._limit(limit, minimum=1, maximum=MAX_KEYWORD_CANDIDATES),
            )
        ]

    def review_keyword_recommendation(
        self,
        *,
        recommendation_id: str,
        action: AiVerificationAction | str,
        actor_id: str,
        reason: str,
        expected_case_id: str | None = None,
        expected_review_revision: int | None = None,
        corrected_value: str | None = None,
        corrected_reason: str | None = None,
    ) -> AiVerificationEvent:
        recommendation = self.get_keyword_recommendation(recommendation_id)
        self._require_target_case(recommendation.case_id, expected_case_id)
        if corrected_value is not None:
            corrected_value = _validate_keyword_value(
                corrected_value,
                KeywordType(recommendation.keyword_type),
                "corrected_value",
            )
        return self._append_review_event(
            case_id=recommendation.case_id,
            target_type=AiVerificationTargetType.KEYWORD_RECOMMENDATION.value,
            target_id=recommendation.recommendation_id,
            previous_status=recommendation.review_status,
            action=action,
            actor_id=actor_id,
            reason=reason,
            expected_review_revision=expected_review_revision,
            corrected_value=corrected_value,
            corrected_reason=corrected_reason,
        )

    def review_scope_summary(
        self,
        *,
        scope_summary_id: str,
        action: AiVerificationAction | str,
        actor_id: str,
        reason: str,
        expected_case_id: str | None = None,
        expected_review_revision: int | None = None,
        corrected_value: str | None = None,
        corrected_reason: str | None = None,
    ) -> AiVerificationEvent:
        summary = self.get_scope_summary(scope_summary_id)
        self._require_target_case(summary.case_id, expected_case_id)
        if corrected_value is not None:
            if len(corrected_value) > MAX_SUMMARY_LENGTH:
                raise AiAssistanceError(
                    "AI_REVIEW_CORRECTION_REQUIRED",
                    "Corrected summary is too long.",
                    target="corrected_value",
                )
            _validate_safe_text(corrected_value, "corrected_value")
        return self._append_review_event(
            case_id=summary.case_id,
            target_type=AiVerificationTargetType.SCOPE_SUMMARY.value,
            target_id=summary.scope_summary_id,
            previous_status=summary.review_status,
            action=action,
            actor_id=actor_id,
            reason=reason,
            expected_review_revision=expected_review_revision,
            corrected_value=corrected_value,
            corrected_reason=corrected_reason,
        )

    def review_history(
        self,
        *,
        target_type: str,
        target_id: str,
        expected_case_id: str | None = None,
    ) -> list[AiVerificationEvent]:
        target_value = _enum_value(AiVerificationTargetType, target_type, "target_type")
        target = self._require_review_target(target_value, target_id)
        self._require_target_case(target.case_id, expected_case_id)
        return cast(
            list[AiVerificationEvent],
            self._repository.list_ai_verification_events(
                target_type=target_value,
                target_id=target_id,
            ),
        )

    def preview_keyword_promotion(
        self,
        *,
        recommendation_id: str,
        keyword_set_id: str,
        expected_case_id: str | None = None,
        regex_confirmed: bool = False,
    ) -> dict[str, Any]:
        recommendation = self.get_keyword_recommendation(recommendation_id)
        self._require_target_case(recommendation.case_id, expected_case_id)
        keyword_set = self._search.get_keyword_set(keyword_set_id)
        self._validate_keyword_set_case(recommendation, keyword_set)
        self._require_promotable_recommendation(recommendation)
        effective_value = recommendation.effective_value or recommendation.value
        duplicate = _keyword_set_duplicate(
            keyword_set,
            term=effective_value,
            match_mode=_promotion_match_mode(recommendation.keyword_type),
            case_sensitive=False,
        )
        regex_requires_confirmation = recommendation.keyword_type == KeywordType.REGEX.value
        promotable = not regex_requires_confirmation or regex_confirmed
        return {
            "recommendation_id": recommendation.recommendation_id,
            "keyword_set_id": keyword_set.keyword_set_id,
            "case_id": recommendation.case_id,
            "review_status": recommendation.review_status,
            "review_revision": recommendation.current_review_revision,
            "effective_value": effective_value,
            "keyword_type": recommendation.keyword_type,
            "match_mode": _promotion_match_mode(recommendation.keyword_type),
            "duplicate": duplicate is not None,
            "duplicate_keyword_id": None if duplicate is None else duplicate.keyword_id,
            "regex_requires_confirmation": regex_requires_confirmation,
            "promotable": promotable,
            "will_run_search": False,
            "will_activate_keyword_set": False,
        }

    def promote_accepted_keyword(
        self,
        *,
        recommendation_id: str,
        keyword_set_id: str,
        actor_id: str,
        reason: str,
        expected_case_id: str | None = None,
        expected_review_revision: int | None = None,
        regex_confirmed: bool = False,
        confirmation_metadata: Mapping[str, Any] | None = None,
    ) -> AiKeywordPromotion:
        actor_id = _bounded_non_empty(actor_id, "actor_id", MAX_ACTOR_ID_LENGTH)
        reason = _required_reason(reason)
        recommendation = self.get_keyword_recommendation(recommendation_id)
        self._require_target_case(recommendation.case_id, expected_case_id)
        keyword_set = self._search.get_keyword_set(keyword_set_id)
        self._validate_keyword_set_case(recommendation, keyword_set)
        self._require_promotable_recommendation(recommendation)
        if (
            expected_review_revision is not None
            and expected_review_revision != recommendation.current_review_revision
        ):
            raise AiAssistanceError(
                "AI_REVIEW_REVISION_CONFLICT",
                "Keyword recommendation review revision changed.",
                target="expected_review_revision",
            )
        if recommendation.keyword_type == KeywordType.REGEX.value and not regex_confirmed:
            raise AiAssistanceError(
                "AI_REVIEW_TRANSITION_INVALID",
                "Regex keyword promotion requires explicit confirmation metadata.",
                target="regex_confirmed",
            )
        if confirmation_metadata is not None:
            _validate_contract_payload(confirmation_metadata, target="confirmation_metadata")
        effective_value = recommendation.effective_value or recommendation.value
        match_mode = _promotion_match_mode(recommendation.keyword_type)
        promotion_fingerprint = canonical_sha256(
            {
                "case_id": recommendation.case_id,
                "recommendation_id": recommendation.recommendation_id,
                "review_revision": recommendation.current_review_revision,
                "keyword_set_id": keyword_set.keyword_set_id,
                "effective_value": effective_value,
                "keyword_type": recommendation.keyword_type,
                "match_mode": match_mode,
            }
        )
        existing = self._repository.get_ai_keyword_promotion_by_fingerprint(
            promotion_fingerprint
        )
        if existing is not None:
            return cast(AiKeywordPromotion, existing)
        duplicate = _keyword_set_duplicate(
            keyword_set,
            term=effective_value,
            match_mode=match_mode,
            case_sensitive=False,
        )
        promoted_keyword_id = None
        keyword_set_version_id = keyword_set.keyword_set_version_id
        keyword_set_version = keyword_set.version
        status = "SKIPPED_DUPLICATE"
        if duplicate is None:
            before_ids = {keyword.keyword_id for keyword in keyword_set.keywords}
            updated = self._search.add_keyword(
                keyword_set.keyword_set_id,
                term=effective_value,
                keyword_type=KeywordType(recommendation.keyword_type),
                match_mode=KeywordMatchMode(match_mode),
                case_sensitive=False,
                enabled=True,
                notes=json.dumps(
                    {
                        "promotion_source": "AI_KEYWORD_RECOMMENDATION",
                        "recommendation_id": recommendation.recommendation_id,
                        "review_revision": recommendation.current_review_revision,
                        "context_snapshot_id": recommendation.context_snapshot_id,
                    },
                    ensure_ascii=False,
                    sort_keys=True,
                ),
                source="AI_RECOMMENDATION",
            )
            after_ids = {keyword.keyword_id for keyword in updated.keywords}
            new_ids = sorted(after_ids - before_ids)
            promoted_keyword_id = new_ids[0] if new_ids else None
            keyword_set_version_id = updated.keyword_set_version_id
            keyword_set_version = updated.version
            status = "PROMOTED"
        else:
            promoted_keyword_id = duplicate.keyword_id
        promotion = AiKeywordPromotion(
            promotion_id=self._id_generator.new_id(),
            case_id=recommendation.case_id,
            recommendation_id=recommendation.recommendation_id,
            review_revision=recommendation.current_review_revision,
            keyword_set_id=keyword_set.keyword_set_id,
            keyword_set_version_id=keyword_set_version_id,
            keyword_set_version=keyword_set_version,
            promoted_keyword_id=promoted_keyword_id,
            promoted_value=effective_value,
            status=status,
            duplicate=duplicate is not None,
            source_context_snapshot_id=recommendation.context_snapshot_id,
            actor_id=actor_id,
            reason=reason,
            promotion_fingerprint=promotion_fingerprint,
            metadata={
                "will_run_search": False,
                "will_activate_keyword_set": False,
                "keyword_type": recommendation.keyword_type,
                "match_mode": match_mode,
                "regex_confirmed": regex_confirmed,
                "confirmation_metadata": dict(confirmation_metadata or {}),
            },
            created_at=self._clock.now(),
        )
        self._repository.save_ai_keyword_promotion(promotion)
        return promotion

    def promotion_history(
        self,
        *,
        recommendation_id: str | None = None,
        keyword_set_id: str | None = None,
    ) -> list[AiKeywordPromotion]:
        return cast(
            list[AiKeywordPromotion],
            self._repository.list_ai_keyword_promotions(
                recommendation_id=recommendation_id,
                keyword_set_id=keyword_set_id,
            ),
        )

    def generate_keyword_recommendations(
        self,
        *,
        assistance_request_id: str,
        provider: AiAssistanceProviderPort | None = None,
    ) -> dict[str, Any]:
        request = self._request_for_ingest(assistance_request_id)
        active_provider = provider or self._provider
        payload = active_provider.generate_keyword_recommendations(request)
        return self.ingest_keyword_batch(
            assistance_request_id=assistance_request_id,
            payload=payload,
        )

    def generate_scope_summary(
        self,
        *,
        assistance_request_id: str,
        provider: AiAssistanceProviderPort | None = None,
    ) -> AiScopeSummaryRecord:
        request = self._request_for_ingest(assistance_request_id)
        active_provider = provider or self._provider
        payload = active_provider.generate_scope_summary(request)
        return self.ingest_scope_summary(
            assistance_request_id=assistance_request_id,
            payload=payload,
        )

    def execute_request(
        self,
        *,
        assistance_request_id: str,
        operation: AiRequestedOperation | str,
    ) -> dict[str, Any]:
        """Execute one approved provider operation and ingest its validated result.

        Completed results are replayed from Core storage. New provider dispatch is allowed only
        while the request is live and all captured source revisions remain current.
        """

        request = self.get_request(assistance_request_id)
        operation_value = _enum_value(AiRequestedOperation, operation, "operation")
        supported_operations = {
            AiRequestedOperation.RECOMMEND_KEYWORDS.value,
            AiRequestedOperation.SUMMARIZE_SCOPE.value,
        }
        if operation_value not in supported_operations:
            raise AiAssistanceError(
                "AI_OPERATION_UNSUPPORTED",
                "The public provider execution contract does not support this operation.",
                target="operation",
                details={"operation": operation_value},
            )
        if operation_value not in request.requested_operations:
            raise AiAssistanceError(
                "AI_OPERATION_NOT_REQUESTED",
                "The operation was not included in the immutable AI assistance request.",
                target="operation",
                details={"operation": operation_value},
            )

        revision_check = self.validate_current_revisions(assistance_request_id)
        existing = self._existing_execution_result(
            assistance_request_id=assistance_request_id,
            operation=operation_value,
        )
        if existing is not None:
            return self._execution_result(
                request=request,
                operation=operation_value,
                revision_check=revision_check,
                result=existing,
                replayed=True,
            )

        self._request_for_ingest(assistance_request_id)
        if not revision_check["is_current"]:
            raise AiAssistanceError(
                "AI_SOURCE_REVISION_STALE",
                "Captured source revisions changed before provider execution.",
                target="context_snapshot_id",
                details={
                    "assistance_request_id": assistance_request_id,
                    "context_snapshot_id": request.context_snapshot_id,
                },
            )

        provider_capability = self._provider.capabilities()
        if (
            not provider_capability.is_available
            or operation_value not in provider_capability.supported_operations
        ):
            raise AiAssistanceError(
                provider_capability.unavailable_reason or "CAPABILITY_UNAVAILABLE",
                "The configured AI provider cannot execute the requested operation.",
                target="provider",
                details={
                    "provider_id": provider_capability.provider_id,
                    "operation": operation_value,
                },
            )

        if operation_value == AiRequestedOperation.RECOMMEND_KEYWORDS.value:
            result: dict[str, Any] = self.generate_keyword_recommendations(
                assistance_request_id=assistance_request_id
            )
        else:
            result = self.generate_scope_summary(
                assistance_request_id=assistance_request_id
            ).to_schema_dict()
        return self._execution_result(
            request=request,
            operation=operation_value,
            revision_check=revision_check,
            result=result,
            replayed=False,
        )

    def _existing_execution_result(
        self,
        *,
        assistance_request_id: str,
        operation: str,
    ) -> dict[str, Any] | None:
        if operation == AiRequestedOperation.RECOMMEND_KEYWORDS.value:
            batch = self._repository.get_ai_keyword_batch_by_request(
                assistance_request_id
            )
            if batch is None:
                return None
            return self.get_keyword_batch(batch.recommendation_batch_id)
        summary = self._repository.get_ai_scope_summary_by_request(
            assistance_request_id
        )
        if summary is None:
            return None
        return self.get_scope_summary(summary.scope_summary_id).to_schema_dict()

    @staticmethod
    def _execution_result(
        *,
        request: AiAssistanceRequest,
        operation: str,
        revision_check: dict[str, Any],
        result: dict[str, Any],
        replayed: bool,
    ) -> dict[str, Any]:
        result_kind = (
            "AI_RECOMMENDATION_BATCH"
            if operation == AiRequestedOperation.RECOMMEND_KEYWORDS.value
            else "AI_SUMMARY"
        )
        return {
            "schema_version": SCHEMA_VERSION,
            "assistance_request_id": request.assistance_request_id,
            "operation": operation,
            "request_fingerprint": request.request_fingerprint,
            "source_revision_check": revision_check,
            "result_kind": result_kind,
            "result": result,
            "replayed": replayed,
            "observed_fact_status": "NOT_OBSERVED_FACT",
        }

    def _keyword_recommendations_from_input(
        self,
        *,
        request: AiAssistanceRequest,
        snapshot: AnalysisContextSnapshot,
        batch_id: str,
        recommendations_input: list[Any],
    ) -> list[AiKeywordRecommendation]:
        rows: list[AiKeywordRecommendation] = []
        seen: set[tuple[str, str, str]] = set()
        now = self._clock.now()
        for raw in recommendations_input:
            if not isinstance(raw, Mapping):
                raise ValidationError(
                    "Recommendation must be a JSON object.",
                    target="recommendations",
                )
            keyword_type = KeywordType(
                _enum_value(
                    KeywordType,
                    raw.get("keyword_type", raw.get("type", KeywordType.OTHER.value)),
                    "keyword_type",
                )
            )
            value = _validate_keyword_value(_required_string(raw, "value"), keyword_type, "value")
            normalized_value = _bounded_non_empty(
                raw.get("normalized_value") or _normalize_keyword(value, keyword_type),
                "normalized_value",
                MAX_KEYWORD_TEXT_LENGTH,
            )
            if "\x00" in normalized_value or not normalized_value:
                raise ValidationError("Normalized keyword is invalid.", target="normalized_value")
            confidence = _enum_value(
                AiKeywordConfidence,
                raw.get("confidence", AiKeywordConfidence.UNKNOWN.value),
                "confidence",
            )
            recommended_scope = _scope_value(
                raw.get("recommended_scope", raw.get("scope", request.requested_scopes[0])),
                "recommended_scope",
            )
            if recommended_scope not in request.requested_scopes:
                raise AiAssistanceError(
                    "AI_REQUEST_SCOPE_INVALID",
                    "Recommendation scope was not requested.",
                    target="recommended_scope",
                )
            evidence_ids = _string_list(raw.get("evidence_ids", []), "evidence_ids")
            self._validate_evidence_ids(request.case_id, evidence_ids)
            source_resource_ids = _string_list(
                raw.get("source_resource_ids", []), "source_resource_ids"
            )
            self._validate_resource_ids_in_snapshot(snapshot, source_resource_ids)
            warnings = list(raw.get("warnings", []))
            citations = self._validate_citations(
                case_id=request.case_id,
                snapshot=snapshot,
                citations=list(raw.get("citations", [])),
                target="citations",
                require_direct=not _has_warning(warnings, NO_DIRECT_CITATION),
            )
            reason = _required_reason(raw.get("reason"), target="reason")
            display_value = _bounded_non_empty(
                raw.get("display_value") or value,
                "display_value",
                MAX_KEYWORD_TEXT_LENGTH,
            )
            _validate_safe_text(display_value, "display_value")
            key = (keyword_type.value, normalized_value, recommended_scope)
            if key in seen:
                continue
            seen.add(key)
            risk_flags = _string_list(raw.get("risk_flags", []), "risk_flags")
            if keyword_type is KeywordType.REGEX and "REGEX_NOT_AUTORUN" not in risk_flags:
                risk_flags.append("REGEX_NOT_AUTORUN")
            stale_reasons = _dedupe(
                [
                    *_string_list(raw.get("stale_reasons", []), "stale_reasons"),
                    *list(request.coverage_summary.get("stale_reasons", [])),
                    *list(_stale_state(request).get("stale_reasons", [])),
                ]
            )
            is_partial = bool(raw.get("is_partial", False)) or request.is_partial
            content_payload = {
                "case_id": request.case_id,
                "context_snapshot_id": request.context_snapshot_id,
                "keyword_type": keyword_type.value,
                "value": value,
                "normalized_value": normalized_value,
                "reason": reason,
                "confidence": confidence,
                "recommended_scope": recommended_scope,
                "evidence_ids": sorted(evidence_ids),
                "source_resource_ids": sorted(source_resource_ids),
                "citations": citations,
                "is_partial": is_partial,
                "stale_reasons": stale_reasons,
                "risk_flags": sorted(risk_flags),
            }
            rows.append(
                AiKeywordRecommendation(
                    recommendation_id=self._id_generator.new_id(),
                    recommendation_batch_id=batch_id,
                    case_id=request.case_id,
                    context_snapshot_id=request.context_snapshot_id,
                    keyword_type=keyword_type.value,
                    value=value,
                    normalized_value=normalized_value,
                    display_value=display_value,
                    reason=reason,
                    confidence=confidence,
                    recommended_scope=recommended_scope,
                    evidence_ids=sorted(evidence_ids),
                    source_resource_ids=sorted(source_resource_ids),
                    citations=citations,
                    is_partial=is_partial,
                    stale_reasons=stale_reasons,
                    risk_flags=sorted(risk_flags),
                    review_status=AiReviewStatus.UNREVIEWED.value,
                    current_review_revision=0,
                    content_fingerprint=canonical_sha256(content_payload),
                    created_at=now,
                )
            )
        rows.sort(
            key=lambda item: (
                item.keyword_type,
                item.normalized_value,
                item.recommended_scope,
            )
        )
        return rows

    def _append_review_event(
        self,
        *,
        case_id: str,
        target_type: str,
        target_id: str,
        previous_status: str,
        action: AiVerificationAction | str,
        actor_id: str,
        reason: str,
        expected_review_revision: int | None,
        corrected_value: str | None,
        corrected_reason: str | None,
    ) -> AiVerificationEvent:
        actor_id = _bounded_non_empty(actor_id, "actor_id", MAX_ACTOR_ID_LENGTH)
        reason = _required_reason(reason)
        corrected_reason = _bounded_optional_text(
            corrected_reason,
            "corrected_reason",
            MAX_REASON_LENGTH,
        )
        action_value = _enum_value(AiVerificationAction, action, "action")
        events = self._repository.list_ai_verification_events(
            target_type=target_type,
            target_id=target_id,
        )
        latest_revision = events[-1].review_revision if events else 0
        latest_status = events[-1].new_status if events else previous_status
        if expected_review_revision is not None and expected_review_revision != latest_revision:
            raise AiAssistanceError(
                "AI_REVIEW_REVISION_CONFLICT",
                "Review revision changed before this verification event.",
                target="expected_review_revision",
                retryable=True,
            )
        new_status = _review_status_for_action(action_value, latest_status)
        if action_value == AiVerificationAction.CORRECT.value and corrected_value is None:
            raise AiAssistanceError(
                "AI_REVIEW_CORRECTION_REQUIRED",
                "Correction review requires a corrected value.",
                target="corrected_value",
            )
        if latest_status == AiReviewStatus.REJECTED.value and action_value in {
            AiVerificationAction.ACCEPT.value,
            AiVerificationAction.CORRECT.value,
        }:
            raise AiAssistanceError(
                "AI_REVIEW_TRANSITION_INVALID",
                "Rejected AI results can only be commented on or rejected again.",
                target="action",
            )
        previous_event_hash = events[-1].event_hash if events else None
        created_at = self._clock.now()
        event_payload = {
            "verification_event_id": None,
            "case_id": case_id,
            "target_type": target_type,
            "target_id": target_id,
            "action": action_value,
            "previous_status": latest_status,
            "new_status": new_status,
            "actor_id": actor_id,
            "reason": reason,
            "corrected_value": corrected_value,
            "corrected_reason": corrected_reason,
            "review_revision": latest_revision + 1,
            "previous_event_hash": previous_event_hash,
            "created_at": created_at.isoformat(),
        }
        event_id = self._id_generator.new_id()
        event_payload["verification_event_id"] = event_id
        event = AiVerificationEvent(
            verification_event_id=event_id,
            case_id=case_id,
            target_type=target_type,
            target_id=target_id,
            action=action_value,
            previous_status=latest_status,
            new_status=new_status,
            actor_id=actor_id,
            reason=reason,
            corrected_value=corrected_value,
            corrected_reason=corrected_reason,
            review_revision=latest_revision + 1,
            previous_event_hash=previous_event_hash,
            event_hash=canonical_sha256(event_payload),
            created_at=created_at,
        )
        self._repository.append_ai_verification_event(event)
        return event

    def _request_for_ingest(self, assistance_request_id: str) -> AiAssistanceRequest:
        request = self.get_request(assistance_request_id)
        if request.expires_at <= self._clock.now():
            raise AiAssistanceError(
                "AI_REQUEST_EXPIRED",
                "Expired AI assistance requests cannot ingest results.",
                target="assistance_request_id",
            )
        return request

    def _effective_keyword(
        self, recommendation: AiKeywordRecommendation
    ) -> AiKeywordRecommendation:
        events = self._repository.list_ai_verification_events(
            target_type=AiVerificationTargetType.KEYWORD_RECOMMENDATION.value,
            target_id=recommendation.recommendation_id,
        )
        if not events:
            return recommendation
        latest = events[-1]
        recommendation.review_status = latest.new_status
        recommendation.current_review_revision = latest.review_revision
        if latest.corrected_value is not None:
            recommendation.effective_value = latest.corrected_value
            recommendation.effective_reason = latest.corrected_reason or recommendation.reason
            recommendation.corrected_reason = latest.corrected_reason
        return recommendation

    def _effective_summary(self, summary: AiScopeSummaryRecord) -> AiScopeSummaryRecord:
        events = self._repository.list_ai_verification_events(
            target_type=AiVerificationTargetType.SCOPE_SUMMARY.value,
            target_id=summary.scope_summary_id,
        )
        if not events:
            return summary
        latest = events[-1]
        summary.review_status = latest.new_status
        summary.current_review_revision = latest.review_revision
        if latest.corrected_value is not None:
            summary.effective_summary_text = latest.corrected_value
            summary.corrected_reason = latest.corrected_reason
        return summary

    def _requested_operations(
        self, purpose: str, requested_operations: list[str] | None
    ) -> list[str]:
        if requested_operations:
            operations = [
                _enum_value(AiRequestedOperation, item, "requested_operations")
                for item in requested_operations
            ]
        elif purpose == AiAssistancePurpose.KEYWORD_RECOMMENDATION.value:
            operations = [AiRequestedOperation.RECOMMEND_KEYWORDS.value]
        elif purpose == AiAssistancePurpose.SCOPE_SUMMARY.value:
            operations = [AiRequestedOperation.SUMMARIZE_SCOPE.value]
        elif purpose == AiAssistancePurpose.REPORT_INPUT.value:
            operations = [AiRequestedOperation.GENERATE_REPORT_DRAFT.value]
        else:
            operations = [
                AiRequestedOperation.RECOMMEND_KEYWORDS.value,
                AiRequestedOperation.SUMMARIZE_SCOPE.value,
            ]
        return _dedupe(operations)

    def _requested_scopes(
        self, snapshot: AnalysisContextSnapshot, requested_scopes: list[str] | None
    ) -> list[str]:
        scopes = [
            _scope_value(item, "requested_scopes")
            for item in (requested_scopes or snapshot.scopes)
        ]
        scopes = _dedupe(scopes)
        if not scopes:
            raise AiAssistanceError(
                "AI_REQUEST_SCOPE_INVALID",
                "At least one AI request scope is required.",
                target="requested_scopes",
            )
        if len(scopes) > MAX_REQUEST_SCOPES:
            raise AiAssistanceError(
                "AI_REQUEST_LIMIT_EXCEEDED",
                "AI request has too many scopes.",
                target="requested_scopes",
            )
        snapshot_scopes = {_scope_value(scope, "snapshot.scopes") for scope in snapshot.scopes}
        if not set(scopes).issubset(snapshot_scopes):
            raise AiAssistanceError(
                "AI_REQUEST_SCOPE_INVALID",
                "Requested scope is not present in the context snapshot.",
                target="requested_scopes",
            )
        return scopes

    def _scope_contexts_for_request(
        self,
        snapshot: AnalysisContextSnapshot,
        scopes: list[str],
        scope_context_ids: list[str] | None,
    ) -> list[AnalysisScopeContext]:
        scope_contexts = self._repository.list_analysis_scope_contexts(snapshot.context_snapshot_id)
        by_scope = {
            (
                scope.scope_type.value
                if hasattr(scope.scope_type, "value")
                else str(scope.scope_type)
            ): scope
            for scope in scope_contexts
        }
        requested = [by_scope[scope] for scope in scopes if scope in by_scope]
        if len(requested) != len(scopes):
            raise AiAssistanceError(
                "AI_REQUEST_SCOPE_INVALID",
                "Requested scope context is missing from the snapshot.",
                target="requested_scopes",
            )
        if scope_context_ids:
            requested_ids = set(_string_list(scope_context_ids, "scope_context_ids"))
            actual_ids = {scope.scope_context_id for scope in requested}
            if not requested_ids.issubset(actual_ids):
                raise AiAssistanceError(
                    "AI_REQUEST_SCOPE_INVALID",
                    "Scope context ID is not allowed for this request.",
                    target="scope_context_ids",
                )
            requested = [scope for scope in requested if scope.scope_context_id in requested_ids]
        return sorted(requested, key=lambda item: item.scope_context_id)

    def _scope_context_for_summary(
        self, request: AiAssistanceRequest, payload: Mapping[str, Any]
    ) -> AnalysisScopeContext:
        scope_context_id = payload.get("scope_context_id")
        if scope_context_id is None:
            if len(request.scope_context_ids) != 1:
                raise AiAssistanceError(
                    "AI_REQUEST_SCOPE_INVALID",
                    "Scope summary ingest requires scope_context_id.",
                    target="scope_context_id",
                )
            scope_context_id = request.scope_context_ids[0]
        if not isinstance(scope_context_id, str) or not scope_context_id:
            raise ValidationError(
                "scope_context_id must be a non-empty string.",
                target="scope_context_id",
            )
        for scope in self._repository.list_analysis_scope_contexts(request.context_snapshot_id):
            if scope.scope_context_id == scope_context_id:
                return cast(AnalysisScopeContext, scope)
        raise AiAssistanceError(
            "AI_REQUEST_SCOPE_INVALID",
            "Scope context does not belong to the request snapshot.",
            target="scope_context_id",
        )

    def _validate_citations(
        self,
        *,
        case_id: str,
        snapshot: AnalysisContextSnapshot,
        citations: list[Any],
        target: str,
        require_direct: bool,
    ) -> list[dict[str, Any]]:
        if not citations:
            if require_direct:
                raise AiAssistanceError(
                    "AI_CITATION_REQUIRED",
                    "AI result requires at least one valid citation.",
                    target=target,
                )
            return []
        if len(citations) > MAX_REQUEST_CITATIONS:
            raise AiAssistanceError(
                "AI_CITATION_LIMIT_EXCEEDED",
                "AI result exceeds the maximum citation count.",
                target=target,
            )
        normalized: list[dict[str, Any]] = []
        for raw in citations:
            if not isinstance(raw, Mapping):
                raise AiAssistanceError(
                    "AI_CITATION_NOT_FOUND",
                    "Citation must be a JSON object.",
                    target=target,
                )
            citation = dict(raw)
            if citation.get("case_id") != case_id:
                raise AiAssistanceError(
                    "AI_CITATION_CASE_MISMATCH",
                    "Citation case_id does not match the AI result case.",
                    target=target,
                )
            evidence_id = citation.get("evidence_id")
            if evidence_id is not None:
                self._validate_evidence_ids(case_id, [str(evidence_id)])
            source_kind = str(citation.get("source_kind", ""))
            source_id = str(citation.get("source_id", ""))
            if not source_kind or not source_id:
                raise AiAssistanceError(
                    "AI_CITATION_NOT_FOUND",
                    "Citation is missing source_kind or source_id.",
                    target=target,
                )
            resource_type = _resource_type_for_citation(source_kind)
            if resource_type is None:
                raise AiAssistanceError(
                    "AI_CITATION_SCOPE_MISMATCH",
                    "Citation source kind is not an allowed snapshot resource.",
                    target=target,
                    details={"source_kind": source_kind},
                )
            if not _snapshot_contains(snapshot, resource_type, source_id):
                raise AiAssistanceError(
                    "AI_CITATION_SCOPE_MISMATCH",
                    "Citation source is outside the context snapshot.",
                    target=target,
                    details={"source_kind": source_kind, "source_id": source_id},
                )
            try:
                info = self._contexts.resolve_resource(
                    resource_type=resource_type,
                    resource_id=source_id,
                )
            except ApexError as exc:
                raise AiAssistanceError(
                    "AI_CITATION_NOT_FOUND",
                    "Citation source could not be resolved.",
                    target=target,
                    details={"source_kind": source_kind, "source_id": source_id},
                ) from exc
            if info["case_id"] != case_id:
                raise AiAssistanceError(
                    "AI_CITATION_CASE_MISMATCH",
                    "Citation source belongs to another case.",
                    target=target,
                )
            if (
                evidence_id is not None
                and info.get("evidence_id") is not None
                and str(info["evidence_id"]) != str(evidence_id)
            ):
                raise AiAssistanceError(
                    "AI_CITATION_SCOPE_MISMATCH",
                    "Citation evidence_id does not match the cited resource.",
                    target=target,
                    details={
                        "citation_evidence_id": str(evidence_id),
                        "resource_evidence_id": str(info["evidence_id"]),
                    },
                )
            if citation.get("source_revision") is not None:
                expected = _snapshot_revision(snapshot, resource_type, source_id)
                if expected is not None and str(citation["source_revision"]) != str(expected):
                    raise AiAssistanceError(
                        "AI_CITATION_REVISION_MISMATCH",
                        "Citation source revision does not match the snapshot revision.",
                        target=target,
                    )
            normalized.append(citation)
        return _stable_citations(normalized)

    def _validate_evidence_ids(self, case_id: str, evidence_ids: list[str]) -> None:
        for evidence_id in evidence_ids:
            evidence = self._repository.get_evidence(evidence_id)
            if evidence is None:
                raise AiAssistanceError(
                    "AI_CITATION_NOT_FOUND",
                    "Referenced evidence does not exist.",
                    target="evidence_ids",
                )
            if evidence.case_id != case_id:
                raise AiAssistanceError(
                    "AI_CITATION_CASE_MISMATCH",
                    "Referenced evidence belongs to another case.",
                    target="evidence_ids",
                )

    def _validate_resource_ids_in_snapshot(
        self, snapshot: AnalysisContextSnapshot, resource_ids: list[str]
    ) -> None:
        allowed = {
            resource_id
            for values in snapshot.included_resource_ids.values()
            for resource_id in values
        }
        for resource_id in resource_ids:
            if resource_id not in allowed:
                raise AiAssistanceError(
                    "AI_CITATION_SCOPE_MISMATCH",
                    "Referenced resource is outside the context snapshot.",
                    target="source_resource_ids",
                )

    def _validate_resource_ids_in_scope(
        self, scope_context: AnalysisScopeContext, resource_ids: list[str]
    ) -> None:
        allowed = set(scope_context.resource_ids)
        for resource_id in resource_ids:
            if resource_id not in allowed:
                raise AiAssistanceError(
                    "AI_CITATION_SCOPE_MISMATCH",
                    "Referenced resource is outside the scope context.",
                    target="referenced_resource_ids",
                )

    def _append_noop_stale_marker(self, target_type: str, target_id: str, reason: str) -> None:
        del target_type, target_id, reason

    def _require_case(self, case_id: str) -> Any:
        case = self._repository.get_case(case_id)
        if case is None:
            raise NotFoundError("CASE_NOT_FOUND", "Case not found.", target="case_id")
        return case

    def _require_snapshot(self, context_snapshot_id: str) -> AnalysisContextSnapshot:
        snapshot = self._repository.get_analysis_context_snapshot(context_snapshot_id)
        if snapshot is None:
            raise AiAssistanceError(
                "AI_REQUEST_NOT_FOUND",
                "Context snapshot for AI assistance was not found.",
                target="context_snapshot_id",
            )
        return cast(AnalysisContextSnapshot, snapshot)

    def _require_review_target(self, target_type: str, target_id: str) -> Any:
        if target_type == AiVerificationTargetType.KEYWORD_RECOMMENDATION.value:
            target = self._repository.get_ai_keyword_recommendation(target_id)
        elif target_type == AiVerificationTargetType.SCOPE_SUMMARY.value:
            target = self._repository.get_ai_scope_summary(target_id)
        else:
            target = None
        if target is None:
            raise AiAssistanceError(
                "AI_REVIEW_TARGET_NOT_FOUND",
                "AI review target was not found.",
                target="target_id",
            )
        return target

    @staticmethod
    def _require_target_case(actual_case_id: str, expected_case_id: str | None) -> None:
        if expected_case_id is not None and expected_case_id != actual_case_id:
            raise AiAssistanceError(
                "AI_TARGET_CASE_MISMATCH",
                "AI review or promotion target belongs to another case.",
                target="case_id",
            )

    def _require_promotable_recommendation(
        self, recommendation: AiKeywordRecommendation
    ) -> None:
        if recommendation.review_status not in {
            AiReviewStatus.ACCEPTED.value,
            AiReviewStatus.CORRECTED.value,
        }:
            raise AiAssistanceError(
                "AI_REVIEW_TRANSITION_INVALID",
                "Only accepted or corrected keyword recommendations can be promoted.",
                target="recommendation_id",
            )

    @staticmethod
    def _validate_keyword_set_case(
        recommendation: AiKeywordRecommendation, keyword_set: KeywordSet
    ) -> None:
        if keyword_set.case_id != recommendation.case_id:
            raise AiAssistanceError(
                "AI_REVIEW_CASE_MISMATCH",
                "Keyword set belongs to another case.",
                target="keyword_set_id",
            )

    @staticmethod
    def _limit(
        value: int,
        *,
        minimum: int,
        maximum: int,
        code: str = "VALIDATION_ERROR",
        target: str = "limit",
    ) -> int:
        if isinstance(value, bool) or value < minimum or value > maximum:
            if code == "VALIDATION_ERROR":
                raise ValidationError("Integer option is outside the allowed range.", target=target)
            raise AiAssistanceError(
                code,
                "Integer option is outside the allowed range.",
                target=target,
                details={"minimum": minimum, "maximum": maximum, "value": value},
            )
        return value


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


def _scope_value(value: Any, target: str) -> str:
    return _enum_value(AnalysisScopeType, value, target)


def _required_string(payload: Mapping[str, Any], field: str) -> str:
    value = payload.get(field)
    if value is None and field == "value":
        value = payload.get("keyword")
    if not isinstance(value, str) or value == "":
        raise ValidationError("Field must be a non-empty string.", target=field)
    return value


def _required_non_empty(value: Any, target: str) -> str:
    if value is None or not str(value).strip():
        raise ValidationError("Field must be a non-empty string.", target=target)
    return str(value).strip()


def _bounded_non_empty(value: Any, target: str, maximum: int) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValidationError("Field must be a non-empty string.", target=target)
    if len(value) > maximum:
        raise ValidationError("Field exceeds the maximum length.", target=target)
    return value.strip()


def _optional_non_empty(value: Any, target: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        raise ValidationError("Field must be a non-empty string.", target=target)
    return value.strip()


def _bounded_optional_text(value: Any, target: str, maximum: int) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValidationError("Field must be a string.", target=target)
    if len(value) > maximum:
        raise ValidationError("Field exceeds the maximum length.", target=target)
    return value


def _required_reason(value: Any, target: str = "reason") -> str:
    reason = _required_non_empty(value, target)
    if len(reason) > MAX_REASON_LENGTH:
        raise ValidationError("Reason exceeds the maximum length.", target=target)
    return reason


def _required_list(payload: Mapping[str, Any], field: str) -> list[Any]:
    value = payload.get(field)
    if not isinstance(value, list):
        raise ValidationError("Field must be a list.", target=field)
    return value


def _required_optional_list(value: Any, target: str) -> list[Any]:
    if not isinstance(value, list):
        raise ValidationError("Field must be a list.", target=target)
    return value


def _string_list(value: Any, target: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or any(not isinstance(item, str) or not item for item in value):
        raise ValidationError("Field must be a list of non-empty strings.", target=target)
    return _dedupe(value)


def _metadata_string(value: Any, target: str) -> str:
    if value is None:
        return "UNKNOWN"
    if not isinstance(value, str) or value == "":
        raise ValidationError("Provider metadata must be a non-empty string.", target=target)
    if len(value) > MAX_PROVIDER_METADATA_LENGTH:
        raise ValidationError("Provider metadata is too long.", target=target)
    normalized = target.casefold()
    if any(part in normalized for part in _FORBIDDEN_KEY_PARTS):
        raise ValidationError("Provider metadata target is forbidden.", target=target)
    return value


def _optional_timestamp(value: Any, *, default: datetime, target: str) -> datetime:
    if value in (None, ""):
        return default
    if isinstance(value, datetime):
        return value
    if not isinstance(value, str):
        raise ValidationError("Timestamp field must be a string.", target=target)
    try:
        return parse_timestamp(value)
    except ValueError as error:
        raise ValidationError("Timestamp field is invalid.", target=target) from error


def _validate_keyword_value(value: str, keyword_type: KeywordType, target: str) -> str:
    if not value.strip():
        raise ValidationError("Keyword value cannot be empty.", target=target)
    if "\x00" in value:
        raise ValidationError("Keyword value cannot contain a null byte.", target=target)
    max_length = {
        KeywordType.URL: 2048,
        KeywordType.DOMAIN: 253,
        KeywordType.IP_ADDRESS: 128,
        KeywordType.HASH: 128,
        KeywordType.REGEX: 512,
        KeywordType.PATH: 4096,
        KeywordType.REGISTRY_PATH: 4096,
        KeywordType.COMMAND: 4096,
    }.get(keyword_type, 1024)
    if len(value) > max_length:
        raise ValidationError("Keyword value exceeds its type limit.", target=target)
    if keyword_type is KeywordType.IP_ADDRESS:
        try:
            ipaddress.ip_address(value)
        except ValueError as error:
            raise ValidationError("Invalid IP address keyword.", target=target) from error
    elif keyword_type is KeywordType.URL:
        parsed = urlparse(value)
        if parsed.scheme not in {"http", "https", "ftp", "file"} or not parsed.netloc:
            raise ValidationError("Invalid URL keyword.", target=target)
    elif keyword_type is KeywordType.DOMAIN and _DOMAIN_RE.match(value) is None:
        raise ValidationError("Invalid domain keyword.", target=target)
    elif keyword_type is KeywordType.HASH and _HASH_RE.match(value) is None:
        raise ValidationError("Invalid hash keyword.", target=target)
    return value


def _normalize_keyword(value: str, keyword_type: KeywordType) -> str:
    if keyword_type is KeywordType.HASH:
        return value.lower().split(":", 1)[-1]
    if keyword_type in {
        KeywordType.DOMAIN,
        KeywordType.URL,
        KeywordType.EMAIL,
        KeywordType.IP_ADDRESS,
    }:
        return value.casefold()
    return value.casefold()


def _validate_safe_text(value: str, target: str) -> None:
    if "\x00" in value:
        raise ValidationError("Text cannot contain a null byte.", target=target)
    if _DANGEROUS_TEXT.search(value) is not None or _BASE64_DATA.search(value) is not None:
        raise ValidationError(
            "Text cannot contain executable HTML or embedded base64 data.",
            target=target,
        )


def _validate_contract_payload(value: Any, *, target: str) -> None:
    _reject_forbidden_json(value, target=target)
    if _depth(value) > MAX_JSON_DEPTH:
        raise AiAssistanceError(
            "AI_REQUEST_LIMIT_EXCEEDED",
            "AI payload exceeds the maximum JSON depth.",
            target=target,
        )
    if len(canonical_json_bytes(value)) > MAX_JSON_BYTES:
        raise AiAssistanceError(
            "AI_REQUEST_LIMIT_EXCEEDED",
            "AI payload exceeds the maximum serialized size.",
            target=target,
        )


def _reject_forbidden_json(value: Any, *, target: str) -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            normalized = str(key).casefold().replace("-", "_")
            if any(part in normalized for part in _FORBIDDEN_KEY_PARTS):
                raise ValidationError(
                    "AI assistance contracts cannot store prompts, secrets, "
                    "or raw provider bodies.",
                    target=target,
                )
            if any(part == normalized for part in _RAW_BLOB_KEYS):
                raise ValidationError(
                    "AI assistance contracts cannot store raw blobs.",
                    target=target,
                )
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


def _has_warning(warnings: list[Any], code: str) -> bool:
    return any(isinstance(item, Mapping) and item.get("code") == code for item in warnings)


def _stable_warnings(warnings: list[Any]) -> list[dict[str, Any]]:
    normalized: dict[str, dict[str, Any]] = {}
    for item in warnings:
        if not isinstance(item, Mapping):
            continue
        code = str(item.get("code", "WARNING"))
        normalized[canonical_sha256(dict(item))] = {"code": code, **dict(item)}
    return [normalized[key] for key in sorted(normalized)]


def _bounded_warnings(value: Any, target: str) -> list[dict[str, Any]]:
    warnings = _required_optional_list(value, target)
    if len(warnings) > MAX_WARNING_COUNT:
        raise AiAssistanceError(
            "AI_REQUEST_LIMIT_EXCEEDED",
            "AI result exceeds the maximum warning count.",
            target=target,
        )
    for warning in warnings:
        if not isinstance(warning, Mapping):
            raise ValidationError("Warning must be a JSON object.", target=target)
        code = warning.get("code")
        if not isinstance(code, str) or re.fullmatch(r"[A-Z][A-Z0-9_]*", code) is None:
            raise ValidationError("Warning code is invalid.", target=target)
    return _stable_warnings(warnings)


def _stable_citations(citations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_hash = {canonical_sha256(item): item for item in citations}
    return [by_hash[key] for key in sorted(by_hash)]


def _state_warnings(snapshot: AnalysisContextSnapshot) -> list[dict[str, Any]]:
    warnings: list[dict[str, Any]] = []
    if snapshot.partial_state.get("is_partial"):
        warnings.append({"code": PARTIAL_WARNING, "developer_message": "Snapshot is partial."})
    if snapshot.stale_state.get("is_stale"):
        warnings.append({"code": STALE_WARNING, "developer_message": "Snapshot is stale."})
    return warnings


def _state_warnings_for_request(request: AiAssistanceRequest) -> list[dict[str, Any]]:
    warnings: list[dict[str, Any]] = []
    if request.is_partial:
        warnings.append(
            {
                "code": PARTIAL_WARNING,
                "developer_message": "AI result was generated from a partial snapshot.",
            }
        )
    if request.is_stale:
        warnings.append(
            {
                "code": STALE_WARNING,
                "developer_message": "AI result was generated from a stale snapshot.",
            }
        )
    return warnings


def _partial_state(
    request: AiAssistanceRequest, scope: AnalysisScopeContext | None = None
) -> dict[str, Any]:
    return {
        "is_partial": request.is_partial or (scope.is_partial if scope is not None else False),
        "partial_reasons": [
            warning["code"]
            for warning in _state_warnings_for_request(request)
            if warning["code"] == PARTIAL_WARNING
        ],
        "generated_from_snapshot_at": to_json_timestamp(request.requested_at),
    }


def _stale_state(
    request: AiAssistanceRequest, scope: AnalysisScopeContext | None = None
) -> dict[str, Any]:
    stale_reasons: list[str] = []
    for item in request.coverage_summary.values():
        if isinstance(item, Mapping):
            stale_reasons.extend(str(reason) for reason in item.get("stale_reasons", []))
    if scope is not None:
        stale_reasons.extend(scope.stale_reasons)
    return {
        "is_stale": request.is_stale or bool(stale_reasons),
        "stale_reasons": _dedupe(stale_reasons),
        "context_fingerprint": request.context_fingerprint,
        "source_revision_fingerprint": request.source_revision_fingerprint,
    }


def _dedupe(values: Iterable[str]) -> list[str]:
    return sorted({str(item) for item in values if str(item)})


def _resource_type_for_citation(source_kind: str) -> str | None:
    return {
        "EVIDENCE": "EVIDENCE",
        "FILE": "FILE_SYSTEM_NODE",
        "ARTIFACT": "ARTIFACT",
        "TIMELINE_EVENT": "TIMELINE_EVENT",
        "SEARCH_RESULT": "SEARCH_RESULT",
        "MACHINE_EXTRACTION": "MACHINE_CANDIDATE",
        "CUSTODY_EVENT": "CUSTODY_EVENT",
    }.get(source_kind)


def _snapshot_contains(
    snapshot: AnalysisContextSnapshot, resource_type: str, resource_id: str
) -> bool:
    if resource_id in snapshot.included_resource_ids.get(resource_type, []):
        return True
    if resource_type == "ARTIFACT":
        for alias in ("REGISTRY", "EVENT_LOG", "PREFETCH", "BROWSER", "MEDIA"):
            if resource_id in snapshot.included_resource_ids.get(alias, []):
                return True
    if resource_type in {"REGISTRY", "EVENT_LOG", "PREFETCH", "BROWSER", "MEDIA"}:
        return resource_id in snapshot.included_resource_ids.get("ARTIFACT", [])
    return False


def _snapshot_revision(
    snapshot: AnalysisContextSnapshot, resource_type: str, resource_id: str
) -> str | int | None:
    for state in snapshot.source_revisions:
        state_type = (
            state.resource_type.value
            if hasattr(state.resource_type, "value")
            else str(state.resource_type)
        )
        if state_type == resource_type and state.resource_id == resource_id:
            return state.expected_revision
    return None


def _review_status_for_action(action: str, previous_status: str) -> str:
    if action == AiVerificationAction.ACCEPT.value:
        return AiReviewStatus.ACCEPTED.value
    if action == AiVerificationAction.REJECT.value:
        return AiReviewStatus.REJECTED.value
    if action == AiVerificationAction.CORRECT.value:
        return AiReviewStatus.CORRECTED.value
    if action == AiVerificationAction.COMMENT.value:
        return previous_status
    raise ValidationError("Unsupported review action.", target="action")


def _promotion_match_mode(keyword_type: str) -> str:
    return (
        KeywordMatchMode.REGEX_METADATA.value
        if keyword_type == KeywordType.REGEX.value
        else KeywordMatchMode.TERM.value
    )


def _keyword_set_duplicate(
    keyword_set: KeywordSet,
    *,
    term: str,
    match_mode: str,
    case_sensitive: bool,
) -> Any | None:
    normalized = term if case_sensitive else term.casefold()
    for keyword in keyword_set.keywords:
        keyword_normalized = keyword.term if keyword.case_sensitive else keyword.term.casefold()
        if (
            keyword_normalized == normalized
            and keyword.match_mode.value == match_mode
            and keyword.case_sensitive == case_sensitive
        ):
            return keyword
    return None


def _without_generated_fields(value: dict[str, Any]) -> dict[str, Any]:
    excluded = {
        "recommendation_id",
        "recommendation_batch_id",
        "created_at",
        "review_status",
        "current_review_revision",
        "effective_value",
        "effective_reason",
        "corrected_reason",
    }
    return {key: item for key, item in value.items() if key not in excluded}


def _encode_cursor(field: str, value: str) -> str:
    payload = json.dumps({field: value}, sort_keys=True, separators=(",", ":"))
    return base64.urlsafe_b64encode(payload.encode("utf-8")).decode("ascii")


def _decode_cursor(value: str | None, *, field: str) -> str | None:
    if value is None:
        return None
    try:
        data = json.loads(base64.urlsafe_b64decode(value.encode("ascii")).decode("utf-8"))
        parsed = data[field]
        if not isinstance(parsed, str) or not parsed:
            raise ValueError("cursor field missing")
        return parsed
    except Exception as error:
        raise ValidationError("Invalid cursor.", target="cursor") from error
