"""Machine-extracted candidate persistence port for Phase 5."""

from __future__ import annotations

from typing import Protocol

from apex_forensic.domain.models import (
    CandidateReviewEvent,
    MachineExtractedCandidate,
    ProviderCapability,
)


class MachineExtractionRepository(Protocol):
    """Persistence operations for OCR/STT candidate contracts and review history."""

    def save_provider_capability(self, capability: ProviderCapability) -> None: ...

    def list_provider_capabilities(
        self,
        *,
        capability_type: str | None = None,
    ) -> list[ProviderCapability]: ...

    def save_machine_candidate(self, candidate: MachineExtractedCandidate) -> None: ...

    def get_machine_candidate(self, candidate_id: str) -> MachineExtractedCandidate | None: ...

    def list_machine_candidates(
        self,
        *,
        case_id: str,
        evidence_id: str | None = None,
        review_status: str | None = None,
        after_candidate_id: str | None = None,
        limit: int = 100,
    ) -> list[MachineExtractedCandidate]: ...

    def append_candidate_review(
        self,
        event: CandidateReviewEvent,
        *,
        correction_text: str | None,
    ) -> MachineExtractedCandidate: ...

    def list_candidate_reviews(self, candidate_id: str) -> list[CandidateReviewEvent]: ...
