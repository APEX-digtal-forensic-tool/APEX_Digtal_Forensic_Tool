"""Case management application service."""

from __future__ import annotations

from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from apex_forensic.constants import DEFAULT_LOCALE, DEFAULT_TIMEZONE, SCHEMA_VERSION
from apex_forensic.domain.enums import CaseStatus
from apex_forensic.domain.errors import NotFoundError, ValidationError
from apex_forensic.domain.models import Case, Evidence
from apex_forensic.ports.case_repository import CaseRepository
from apex_forensic.ports.clock import Clock
from apex_forensic.ports.id_generator import IdGenerator


class CaseManager:
    """Coordinates Phase 1 case use cases."""

    def __init__(
        self,
        repository: CaseRepository,
        clock: Clock,
        id_generator: IdGenerator,
    ) -> None:
        self._repository = repository
        self._clock = clock
        self._id_generator = id_generator

    def create_case(
        self,
        *,
        name: str,
        investigator: str | None = None,
        description: str | None = None,
        locale: str = DEFAULT_LOCALE,
        timezone: str = DEFAULT_TIMEZONE,
    ) -> Case:
        """Create and persist a new case."""

        if not name.strip():
            raise ValidationError("Case name is required.", target="name")
        self._validate_timezone(timezone)
        now = self._clock.now()
        case = Case(
            case_id=self._id_generator.new_id(),
            name=name,
            description=description,
            investigator=investigator,
            locale=locale,
            timezone=timezone,
            status=CaseStatus.OPEN,
            created_at=now,
            updated_at=now,
            schema_version=SCHEMA_VERSION,
            metadata={},
        )
        self._repository.save_case(case)
        return case

    def get_case(self, case_id: str) -> Case:
        """Return one case or raise a structured not-found error."""

        case = self._repository.get_case(case_id)
        if case is None:
            raise NotFoundError("CASE_NOT_FOUND", f"Case not found: {case_id}", target="case_id")
        return case

    def list_cases(self) -> list[Case]:
        """Return all cases."""

        return self._repository.list_cases()

    def update_metadata(
        self,
        case_id: str,
        *,
        name: str | None = None,
        description: str | None = None,
        investigator: str | None = None,
    ) -> Case:
        """Update editable case metadata."""

        case = self.get_case(case_id)
        if name is not None:
            if not name.strip():
                raise ValidationError("Case name cannot be blank.", target="name")
            case.name = name
        if description is not None:
            case.description = description
        if investigator is not None:
            case.investigator = investigator
        case.updated_at = self._clock.now()
        self._repository.update_case(case)
        return case

    def change_status(self, case_id: str, status: CaseStatus) -> Case:
        """Change case state without physically deleting rows."""

        case = self.get_case(case_id)
        case.status = status
        case.updated_at = self._clock.now()
        self._repository.update_case(case)
        return case

    def delete_case(self, case_id: str) -> Case:
        """Soft-delete a case by archiving it instead of removing rows."""

        return self.change_status(case_id, CaseStatus.ARCHIVED)

    def change_locale(self, case_id: str, locale: str) -> Case:
        """Change the case locale."""

        if not locale:
            raise ValidationError("Locale is required.", target="locale")
        case = self.get_case(case_id)
        case.locale = locale
        case.updated_at = self._clock.now()
        self._repository.update_case(case)
        return case

    def change_timezone(self, case_id: str, timezone: str) -> Case:
        """Change the case display timezone after validating it with tzdb."""

        self._validate_timezone(timezone)
        case = self.get_case(case_id)
        case.timezone = timezone
        case.updated_at = self._clock.now()
        self._repository.update_case(case)
        return case

    def list_evidence(self, case_id: str) -> list[Evidence]:
        """Return evidence registered to a case."""

        self.get_case(case_id)
        return self._repository.list_evidence_for_case(case_id)

    @staticmethod
    def _validate_timezone(timezone: str) -> None:
        try:
            ZoneInfo(timezone)
        except ZoneInfoNotFoundError as error:
            raise ValidationError(
                "Invalid IANA timezone identifier.",
                target="timezone",
                details={"timezone": timezone},
            ) from error
