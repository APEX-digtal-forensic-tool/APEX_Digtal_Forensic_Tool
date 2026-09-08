"""Case policy lifecycle and audited egress assessment, with no runtime execution."""

from __future__ import annotations

from dataclasses import replace

from apex_forensic.domain.enums import (
    AiDataSourceType,
    AiDestinationCategory,
    AiSecretHandling,
    DataClassification,
)
from apex_forensic.domain.errors import NotFoundError, StateConflictError, ValidationError
from apex_forensic.domain.models.ai_governance import (
    AiEgressAuditRecord,
    AiEgressData,
    CaseAiPolicy,
    SafeAiProjection,
)
from apex_forensic.domain.services.ai_egress import evaluate_ai_egress
from apex_forensic.domain.services.ai_projection import (
    AiProjectionSource,
    ai_data_reference,
    build_safe_ai_projection,
    source_has_secret_fields,
)
from apex_forensic.ports.ai_governance import AiGovernanceRepository, AiProjectionSourceRepository
from apex_forensic.ports.case_repository import CaseRepository
from apex_forensic.ports.clock import Clock
from apex_forensic.ports.id_generator import IdGenerator


class CaseAiPolicyService:
    """Create immutable revisions with explicit optimistic concurrency."""

    def __init__(
        self,
        *,
        repository: AiGovernanceRepository,
        cases: CaseRepository,
        clock: Clock,
        id_generator: IdGenerator,
    ) -> None:
        self._repository = repository
        self._cases = cases
        self._clock = clock
        self._ids = id_generator

    def get(self, case_id: str) -> CaseAiPolicy | None:
        _require_case(self._cases, case_id)
        return self._repository.get_case_ai_policy(case_id)

    def configure(
        self,
        *,
        case_id: str,
        expected_revision: int,
        ai_enabled: bool = False,
        external_allowed: bool = False,
        local_only: bool = True,
        allowed_classifications: tuple[DataClassification, ...] = (
            DataClassification.PUBLIC,
            DataClassification.INTERNAL,
        ),
        secret_handling: AiSecretHandling = AiSecretHandling.DENY,
        raw_allowed: bool = False,
        redaction_required: bool = True,
        projection_required: bool = True,
    ) -> CaseAiPolicy:
        _require_case(self._cases, case_id)
        if type(expected_revision) is not int or expected_revision < 0:
            raise ValidationError("Expected a nonnegative policy revision.")
        policy = CaseAiPolicy(
            policy_id=self._ids.new_id(),
            case_id=case_id,
            revision=expected_revision + 1,
            created_at=self._clock.now(),
            ai_enabled=ai_enabled,
            external_allowed=external_allowed,
            local_only=local_only,
            allowed_classifications=allowed_classifications,
            secret_handling=secret_handling,
            raw_allowed=raw_allowed,
            redaction_required=redaction_required,
            projection_required=projection_required,
        )
        self._repository.save_case_ai_policy(policy, expected_revision=expected_revision)
        return policy


class AiProjectionService:
    """Resolve existing source records, then create detached structural projections."""

    def __init__(
        self,
        *,
        sources: AiProjectionSourceRepository,
        cases: CaseRepository,
    ) -> None:
        self._sources = sources
        self._cases = cases

    def get_source(
        self,
        *,
        case_id: str,
        source_id: str,
        source_type: AiDataSourceType,
    ) -> AiProjectionSource:
        _require_case(self._cases, case_id)
        if not isinstance(source_type, AiDataSourceType):
            raise ValidationError("Expected an AI data source type.")
        source: AiProjectionSource | None
        if source_type == AiDataSourceType.ARTIFACT:
            source = self._sources.get_artifact(source_id)
        elif source_type == AiDataSourceType.CONTEXT_SNAPSHOT:
            source = self._sources.get_analysis_context_snapshot(source_id)
        else:
            source = self._sources.get_ai_assistance_request(source_id)
        if source is None:
            raise NotFoundError("AI_SOURCE_NOT_FOUND", "AI data source does not exist.")
        if source.case_id != case_id:
            raise ValidationError("AI source belongs to another case.", target="source_id")
        return source

    def create(
        self,
        *,
        case_id: str,
        source_id: str,
        source_type: AiDataSourceType,
        classification: DataClassification = DataClassification.SENSITIVE,
        contains_secrets: bool = True,
        selected_fields: tuple[str, ...] | None = None,
    ) -> SafeAiProjection:
        source = self.get_source(case_id=case_id, source_id=source_id, source_type=source_type)
        return build_safe_ai_projection(
            source,
            classification=classification,
            contains_secrets=contains_secrets,
            selected_fields=selected_fields,
        )


class AiEgressService:
    """Evaluate current policy and persist the assessment before returning it.

    Generic metadata evaluation trusts caller classification, destination and redaction
    attestations. evaluate_projection additionally reconstructs the projection from its
    stored source. Neither operation transmits data or invokes an AI provider.
    """

    def __init__(
        self,
        *,
        repository: AiGovernanceRepository,
        projections: AiProjectionService,
        clock: Clock,
        id_generator: IdGenerator,
    ) -> None:
        self._repository = repository
        self._projections = projections
        self._clock = clock
        self._ids = id_generator

    def evaluate(
        self,
        data: AiEgressData,
        *,
        destination: AiDestinationCategory,
    ) -> AiEgressAuditRecord:
        if not isinstance(data, AiEgressData):
            raise ValidationError("Expected typed egress metadata.")
        if data.projection_applied:
            raise ValidationError("Use evaluate_projection to verify a safe projection.")
        return self._evaluate(data, destination=destination)

    def _evaluate(
        self,
        data: AiEgressData,
        *,
        destination: AiDestinationCategory,
    ) -> AiEgressAuditRecord:
        reference = data.source
        source = self._projections.get_source(
            case_id=reference.case_id,
            source_id=reference.source_id,
            source_type=reference.source_type,
        )
        if ai_data_reference(source) != reference:
            raise StateConflictError("AI data source changed; rebuild the assessment.")
        if source_has_secret_fields(source):
            data = replace(
                data,
                classification=DataClassification.SECRET,
                contains_secrets=data.contains_secrets or not data.redaction_applied,
            )
        result = evaluate_ai_egress(
            self._repository.get_case_ai_policy(reference.case_id),
            data,
            destination,
        )
        record = AiEgressAuditRecord(self._ids.new_id(), result, self._clock.now())
        self._repository.append_ai_egress_audit(record)
        return record

    def evaluate_projection(
        self,
        projection: SafeAiProjection,
        *,
        destination: AiDestinationCategory,
    ) -> AiEgressAuditRecord:
        if not isinstance(projection, SafeAiProjection):
            raise ValidationError("Expected a safe AI projection.")
        reference = projection.source
        rebuilt = self._projections.create(
            case_id=reference.case_id,
            source_id=reference.source_id,
            source_type=reference.source_type,
            classification=projection.classification,
            contains_secrets=False,
            selected_fields=tuple(name for name, _ in projection.selected_fields),
        )
        if rebuilt != projection:
            raise StateConflictError("Projection no longer matches its source; rebuild it.")
        return self._evaluate(projection.egress_data(), destination=destination)


def _require_case(repository: CaseRepository, case_id: str) -> None:
    if repository.get_case(case_id) is None:
        raise NotFoundError("CASE_NOT_FOUND", "Case does not exist.", target="case_id")
