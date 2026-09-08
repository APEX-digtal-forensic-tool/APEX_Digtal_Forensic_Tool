"""Minimal structural projection over existing artifact, context and AI request DTOs."""

from __future__ import annotations

from apex_forensic.domain.enums import AiDataSourceType, ArtifactType, DataClassification
from apex_forensic.domain.errors import ValidationError
from apex_forensic.domain.models.ai import AiAssistanceRequest
from apex_forensic.domain.models.ai_governance import (
    PROJECTION_FIELDS,
    AiDataReference,
    SafeAiProjection,
)
from apex_forensic.domain.models.artifact import ArtifactRecord
from apex_forensic.domain.models.context import AnalysisContextSnapshot
from apex_forensic.domain.models.secret import redact_secret_fields
from apex_forensic.domain.services.canonical import canonical_sha256

AiProjectionSource = ArtifactRecord | AnalysisContextSnapshot | AiAssistanceRequest


def ai_data_reference(source: AiProjectionSource) -> AiDataReference:
    """Bind a reference to the exact source DTO without changing the source."""

    if isinstance(source, ArtifactRecord):
        kind, identifier = AiDataSourceType.ARTIFACT, source.artifact_id
    elif isinstance(source, AnalysisContextSnapshot):
        kind, identifier = AiDataSourceType.CONTEXT_SNAPSHOT, source.context_snapshot_id
    elif isinstance(source, AiAssistanceRequest):
        kind, identifier = AiDataSourceType.AI_ASSISTANCE_REQUEST, source.assistance_request_id
    else:
        raise ValidationError("Unsupported AI projection source.")
    return AiDataReference(
        source.case_id,
        identifier,
        kind,
        canonical_sha256(source.to_schema_dict()),
    )


def build_safe_ai_projection(
    source: AiProjectionSource,
    *,
    classification: DataClassification = DataClassification.SENSITIVE,
    contains_secrets: bool = True,
    selected_fields: tuple[str, ...] | None = None,
) -> SafeAiProjection:
    """Drop free text, payloads, locators, citations and arbitrary metadata.

    Field-name redaction alone cannot sanitize arbitrary forensic text. This version selects
    only validated structural enums, booleans and numbers. Classification never decreases.
    """

    if not isinstance(classification, DataClassification) or type(contains_secrets) is not bool:
        raise ValidationError("Expected classification and secret-presence metadata.")
    reference = ai_data_reference(source)
    data = source.to_schema_dict()
    redacted = redact_secret_fields(data)
    if contains_secrets or source_has_secret_fields(source):
        classification = DataClassification.SECRET
    if isinstance(source, AnalysisContextSnapshot):
        redacted["is_partial"] = source.partial_state.get("is_partial", True)
        redacted["is_stale"] = source.stale_state.get("is_stale", True)
        redacted["resource_count"] = sum(len(ids) for ids in source.included_resource_ids.values())
    allowed = PROJECTION_FIELDS[reference.source_type]
    names = tuple(sorted(allowed)) if selected_fields is None else selected_fields
    if (
        not isinstance(names, tuple)
        or any(not isinstance(name, str) for name in names)
        or len(set(names)) != len(names)
        or not set(names) <= allowed
    ):
        raise ValidationError("Unsupported or duplicate projection field selection.")
    return SafeAiProjection(
        source=reference,
        classification=classification,
        selected_fields=tuple((name, redacted[name]) for name in names),
    )


def source_has_secret_fields(source: AiProjectionSource) -> bool:
    """Recognize existing secret-field markers and credential/cookie artifact categories.

    This reuses the redactor's rules, and makes no claim to detect secrets in free text.
    """

    if isinstance(source, ArtifactRecord) and source.artifact_type in {
        ArtifactType.BROWSER_COOKIE,
        ArtifactType.BROWSER_CREDENTIAL,
    }:
        return True
    data = source.to_schema_dict()
    return canonical_sha256(data) != canonical_sha256(redact_secret_fields(data))
