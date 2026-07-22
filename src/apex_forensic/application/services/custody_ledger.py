"""Append-only chain of custody service."""

from __future__ import annotations

from datetime import datetime
from zoneinfo import ZoneInfo

from apex_forensic._time import to_json_timestamp
from apex_forensic.constants import CUSTODY_LEDGER_VERSION, ENGINE_VERSION, SCHEMA_VERSION
from apex_forensic.domain.enums import CustodyEventType
from apex_forensic.domain.errors import NotFoundError, StateConflictError, ValidationError
from apex_forensic.domain.models import CustodyEvent
from apex_forensic.domain.services.canonical import canonical_sha256
from apex_forensic.ports.case_repository import CaseRepository
from apex_forensic.ports.clock import Clock
from apex_forensic.ports.custody_repository import CustodyRepository
from apex_forensic.ports.evidence_repository import EvidenceRepository
from apex_forensic.ports.id_generator import IdGenerator


class CustodyLedger:
    """Creates and verifies hash-linked, append-only custody events."""

    def __init__(
        self,
        case_repository: CaseRepository,
        evidence_repository: EvidenceRepository,
        custody_repository: CustodyRepository,
        clock: Clock,
        id_generator: IdGenerator,
    ) -> None:
        self._case_repository = case_repository
        self._evidence_repository = evidence_repository
        self._custody_repository = custody_repository
        self._clock = clock
        self._id_generator = id_generator

    def add_event(
        self,
        *,
        evidence_id: str,
        event_type: CustodyEventType,
        actor_name: str,
        action: str,
        actor_id: str | None = None,
        actor_role: str | None = None,
        organization: str | None = None,
        source_location: str | None = None,
        destination_location: str | None = None,
        reason: str | None = None,
        occurred_at_utc: datetime | None = None,
        tool_name: str | None = "APEX Forensic Core",
        tool_version: str | None = ENGINE_VERSION,
        previous_hash: dict[str, str] | None = None,
        current_hash: dict[str, str] | None = None,
        notes: str | None = None,
        correction_of_event_id: str | None = None,
    ) -> CustodyEvent:
        """Append a new custody event."""

        evidence = self._evidence_repository.get_evidence(evidence_id)
        if evidence is None:
            raise NotFoundError(
                "EVIDENCE_NOT_FOUND",
                f"Evidence not found: {evidence_id}",
                target="evidence_id",
            )
        case = self._case_repository.get_case(evidence.case_id)
        if case is None:
            raise NotFoundError("CASE_NOT_FOUND", f"Case not found: {evidence.case_id}")
        if event_type is CustodyEventType.CORRECTION:
            if correction_of_event_id is None:
                raise ValidationError(
                    "CORRECTION events require correction_of_event_id.",
                    target="correction_of_event_id",
                )
            if self._custody_repository.get_custody_event(correction_of_event_id) is None:
                raise NotFoundError(
                    "OBJECT_NOT_FOUND",
                    f"Correction target not found: {correction_of_event_id}",
                    target="correction_of_event_id",
                )
        elif correction_of_event_id is not None:
            raise ValidationError(
                "Only CORRECTION events may reference correction_of_event_id.",
                target="correction_of_event_id",
            )

        existing = self._custody_repository.list_custody_events(evidence_id)
        previous_event_hash = existing[-1].event_hash if existing else None
        revision = (existing[-1].immutable_revision + 1) if existing else 1
        occurred = occurred_at_utc or self._clock.now()
        created_at = self._clock.now()
        displayed = occurred.astimezone(ZoneInfo(case.timezone))
        event_data = {
            "schema_version": SCHEMA_VERSION,
            "event_id": self._id_generator.new_id(),
            "case_id": evidence.case_id,
            "evidence_id": evidence_id,
            "event_type": event_type.value,
            "actor_id": actor_id,
            "actor_name": actor_name,
            "actor_role": actor_role,
            "organization": organization,
            "source_location": source_location,
            "destination_location": destination_location,
            "action": action,
            "reason": reason,
            "occurred_at_utc": to_json_timestamp(occurred),
            "displayed_at": displayed.isoformat(timespec="microseconds"),
            "timezone": case.timezone,
            "tool_name": tool_name,
            "tool_version": tool_version,
            "previous_hash": previous_hash,
            "current_hash": current_hash,
            "notes": notes,
            "created_at": to_json_timestamp(created_at),
            "immutable_revision": revision,
            "previous_event_hash": previous_event_hash,
            "event_hash": "",
            "ledger_algorithm": "SHA256",
            "ledger_version": CUSTODY_LEDGER_VERSION,
            "approval": None,
            "correction_of_event_id": correction_of_event_id,
        }
        event_data["event_hash"] = canonical_sha256(event_data, exclude_keys={"event_hash"})
        event = CustodyEvent(event_data)
        self._custody_repository.save_custody_event(event)
        return event

    def list_events(self, evidence_id: str) -> list[CustodyEvent]:
        """Return custody events for evidence."""

        return self._custody_repository.list_custody_events(evidence_id)

    def verify_chain(self, evidence_id: str) -> bool:
        """Verify previous-hash links and canonical event hashes."""

        previous_hash: str | None = None
        expected_revision = 1
        for event in self._custody_repository.list_custody_events(evidence_id):
            data = event.to_schema_dict()
            if data["immutable_revision"] != expected_revision:
                return False
            if data["previous_event_hash"] != previous_hash:
                return False
            if canonical_sha256(data, exclude_keys={"event_hash"}) != data["event_hash"]:
                return False
            previous_hash = data["event_hash"]
            expected_revision += 1
        return True

    def add_correction(
        self,
        *,
        evidence_id: str,
        correction_of_event_id: str,
        actor_name: str,
        reason: str,
        notes: str | None = None,
    ) -> CustodyEvent:
        """Append a correction event rather than mutating prior ledger rows."""

        if not reason:
            raise StateConflictError("Correction events require a reason.", target="reason")
        return self.add_event(
            evidence_id=evidence_id,
            event_type=CustodyEventType.CORRECTION,
            actor_name=actor_name,
            action="Correction event appended",
            reason=reason,
            notes=notes,
            correction_of_event_id=correction_of_event_id,
        )
