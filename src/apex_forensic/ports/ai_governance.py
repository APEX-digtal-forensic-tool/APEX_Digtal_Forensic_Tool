"""Persistence boundaries for case AI policy and egress assessments."""

from typing import Protocol

from apex_forensic.domain.models.ai import AiAssistanceRequest
from apex_forensic.domain.models.ai_governance import AiEgressAuditRecord, CaseAiPolicy
from apex_forensic.domain.models.artifact import ArtifactRecord
from apex_forensic.domain.models.context import AnalysisContextSnapshot


class AiGovernanceRepository(Protocol):
    def save_case_ai_policy(self, policy: CaseAiPolicy, *, expected_revision: int) -> None: ...

    def get_case_ai_policy(self, case_id: str) -> CaseAiPolicy | None: ...

    def append_ai_egress_audit(self, record: AiEgressAuditRecord) -> None: ...

    def list_ai_egress_audits(
        self,
        *,
        case_id: str,
        source_id: str | None = None,
    ) -> list[AiEgressAuditRecord]: ...


class AiProjectionSourceRepository(Protocol):
    """Read-only subset of existing source repository operations."""

    def get_artifact(self, artifact_id: str) -> ArtifactRecord | None: ...

    def get_analysis_context_snapshot(
        self,
        context_snapshot_id: str,
    ) -> AnalysisContextSnapshot | None: ...

    def get_ai_assistance_request(
        self,
        assistance_request_id: str,
    ) -> AiAssistanceRequest | None: ...
