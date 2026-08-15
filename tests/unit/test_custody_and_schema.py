from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from apex_forensic.domain.enums import CustodyEventType, HashAlgorithm
from apex_forensic.domain.errors import ValidationError


def test_custody_event_append_correction_and_hash_chain(
    services,
    sample_file: Path,
    schema_validator,
) -> None:
    case = services.cases.create_case(name="Case", investigator="analyst")
    evidence = services.evidence.register_evidence(case_id=case.case_id, source_path=sample_file)
    opened = services.custody.add_event(
        evidence_id=evidence.evidence_id,
        event_type=CustodyEventType.OPENED,
        actor_name="analyst",
        action="Opened read-only evidence stream",
    )
    correction = services.custody.add_correction(
        evidence_id=evidence.evidence_id,
        correction_of_event_id=opened.event_id,
        actor_name="analyst",
        reason="Clarified access note",
    )

    events = services.custody.list_events(evidence.evidence_id)
    assert [event.immutable_revision for event in events] == [1, 2, 3]
    assert correction.to_schema_dict()["correction_of_event_id"] == opened.event_id
    assert services.custody.verify_chain(evidence.evidence_id) is True
    for event in events:
        schema_validator.validate_custody_event(event.to_schema_dict())


def test_custody_events_are_append_only(services, sample_file: Path) -> None:
    case = services.cases.create_case(name="Case")
    evidence = services.evidence.register_evidence(case_id=case.case_id, source_path=sample_file)
    event = services.custody.list_events(evidence.evidence_id)[0]

    with pytest.raises(sqlite3.IntegrityError):
        services.repository.connection.execute(
            "UPDATE custody_events SET event_type = ? WHERE event_id = ?",
            ("ANALYZED", event.event_id),
        )
    with pytest.raises(sqlite3.IntegrityError):
        services.repository.connection.execute(
            "DELETE FROM custody_events WHERE event_id = ?",
            (event.event_id,),
        )


def test_hash_verification_records_match_and_mismatch(services, sample_file: Path) -> None:
    case = services.cases.create_case(name="Case")
    evidence = services.evidence.register_evidence(case_id=case.case_id, source_path=sample_file)
    services.evidence.calculate_hash(
        evidence_id=evidence.evidence_id,
        algorithm=HashAlgorithm.SHA256,
        chunk_size=64,
    )
    verification, _ = services.evidence.verify_evidence(
        evidence_id=evidence.evidence_id,
        algorithm=HashAlgorithm.SHA256,
        chunk_size=64,
    )
    assert verification.to_schema_dict()["status"] == "MATCH"
    assert verification.to_schema_dict()["case_id"] == case.case_id
    stored_row = services.repository.connection.execute(
        "SELECT case_id FROM hash_verifications WHERE verification_id = ?",
        (verification.to_schema_dict()["id"],),
    ).fetchone()
    assert stored_row["case_id"] == case.case_id

    sample_file.write_bytes(b"modified")
    mismatch, job = services.evidence.verify_evidence(
        evidence_id=evidence.evidence_id,
        algorithm=HashAlgorithm.SHA256,
        chunk_size=64,
    )
    assert mismatch.to_schema_dict()["status"] == "MISMATCH"
    assert job.warnings[0]["code"] == "HASH_MISMATCH"
    history = services.repository.list_hash_verifications(evidence.evidence_id)
    assert len(history) == 2
    assert {item.to_schema_dict()["case_id"] for item in history} == {case.case_id}


def test_hash_verification_error_history_is_preserved(services, sample_file: Path) -> None:
    case = services.cases.create_case(name="Case")
    evidence = services.evidence.register_evidence(case_id=case.case_id, source_path=sample_file)
    services.evidence.calculate_hash(
        evidence_id=evidence.evidence_id,
        algorithm=HashAlgorithm.SHA256,
        chunk_size=64,
    )
    sample_file.unlink()

    with pytest.raises(ValidationError):
        services.evidence.verify_evidence(
            evidence_id=evidence.evidence_id,
            algorithm=HashAlgorithm.SHA256,
            chunk_size=64,
        )
    history = services.repository.list_hash_verifications(evidence.evidence_id)
    assert history[0].to_schema_dict()["status"] == "ERROR"
    assert history[0].to_schema_dict()["error"]["code"] == "VALIDATION_ERROR"
