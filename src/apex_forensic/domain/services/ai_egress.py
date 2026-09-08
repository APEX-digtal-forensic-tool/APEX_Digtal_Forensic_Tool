"""Pure, deterministic AI egress policy evaluation; never sends data."""

from apex_forensic.domain.enums import (
    AiDataForm,
    AiDestinationCategory,
    AiEgressDecision,
    AiEgressReason,
    AiSecretHandling,
)
from apex_forensic.domain.errors import ValidationError
from apex_forensic.domain.models.ai_governance import AiEgressData, AiEgressResult, CaseAiPolicy


def evaluate_ai_egress(
    policy: CaseAiPolicy | None,
    data: AiEgressData,
    destination: AiDestinationCategory,
) -> AiEgressResult:
    """Assess trusted metadata; transformation requirements are not transmission grants.

    A transformed representation must be evaluated again with the original classification.
    Destination category is supplied by the trusted integration, never inferred from a URL.
    """

    if not isinstance(data, AiEgressData) or not isinstance(destination, AiDestinationCategory):
        raise ValidationError("Expected typed egress metadata and destination category.")
    if policy is not None and not isinstance(policy, CaseAiPolicy):
        raise ValidationError("Expected a case AI policy.")
    denied: list[AiEgressReason] = []
    required: list[AiEgressReason] = []
    transformations: tuple[AiDataForm, ...] = ()
    if policy is None:
        denied.append(AiEgressReason.POLICY_MISSING)
    else:
        if policy.case_id != data.source.case_id:
            denied.append(AiEgressReason.CASE_MISMATCH)
        if not policy.ai_enabled:
            denied.append(AiEgressReason.AI_DISABLED)
        if destination == AiDestinationCategory.EXTERNAL:
            if policy.local_only:
                denied.append(AiEgressReason.LOCAL_ONLY)
            if not policy.external_allowed:
                denied.append(AiEgressReason.EXTERNAL_DENIED)
        if data.classification not in policy.allowed_classifications:
            denied.append(AiEgressReason.CLASSIFICATION_DENIED)
        if data.contains_secrets:
            if policy.secret_handling == AiSecretHandling.DENY:
                denied.append(AiEgressReason.SECRET_DENIED)
            if data.redaction_applied:
                denied.append(AiEgressReason.REDACTION_INCOMPLETE)
        if policy.projection_required and not data.projection_applied:
            required.append(AiEgressReason.PROJECTION_REQUIRED)
            transformations = (AiDataForm.SAFE_PROJECTION,)
        if data.data_form == AiDataForm.RAW and not policy.raw_allowed:
            if transformations:
                required.append(AiEgressReason.RAW_DENIED)
            else:
                denied.append(AiEgressReason.RAW_DENIED)
        if not data.redaction_applied and (
            policy.redaction_required
            or (data.contains_secrets and policy.secret_handling == AiSecretHandling.REDACT)
        ):
            required.append(AiEgressReason.REDACTION_REQUIRED)
            if not transformations:
                transformations = (AiDataForm.REDACTED,)
    if denied:
        decision = AiEgressDecision.DENY
        reasons = tuple(denied)
        transformations = ()
    elif AiDataForm.SAFE_PROJECTION in transformations:
        decision = AiEgressDecision.ALLOW_PROJECTION_ONLY
        reasons = tuple(required)
    elif transformations:
        decision = AiEgressDecision.ALLOW_WITH_REDACTION
        reasons = tuple(required)
    else:
        decision = AiEgressDecision.ALLOW
        reasons = (AiEgressReason.POLICY_SATISFIED,)
    return AiEgressResult(
        data=data,
        destination=destination,
        decision=decision,
        reason_codes=reasons,
        required_transformations=transformations,
        policy_id=None if policy is None else policy.policy_id,
        policy_revision=None if policy is None else policy.revision,
        policy_fingerprint=None if policy is None else policy.content_fingerprint,
    )
