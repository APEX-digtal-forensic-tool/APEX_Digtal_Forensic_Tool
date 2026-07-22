"""Case repository port."""

from __future__ import annotations

from typing import Protocol

from apex_forensic.domain.models import Case, Evidence


class CaseRepository(Protocol):
    """Persistence operations required by the case manager."""

    def save_case(self, case: Case) -> None:
        """Persist a new case."""
        ...

    def update_case(self, case: Case) -> None:
        """Persist changes to an existing case."""
        ...

    def get_case(self, case_id: str) -> Case | None:
        """Return a case by ID."""
        ...

    def list_cases(self) -> list[Case]:
        """Return all cases."""
        ...

    def list_evidence_for_case(self, case_id: str) -> list[Evidence]:
        """Return evidence registered to a case."""
        ...
