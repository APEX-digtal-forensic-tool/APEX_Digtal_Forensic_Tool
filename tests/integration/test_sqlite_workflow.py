from __future__ import annotations

from pathlib import Path

from apex_forensic.config import build_services
from apex_forensic.domain.enums import HashAlgorithm


def test_sqlite_reopen_and_schema_validated_workflow(
    tmp_path: Path,
    schema_validator,
) -> None:
    db_path = tmp_path / "case.db"
    sample = tmp_path / "증거 자료.bin"
    sample.write_bytes(b"phase1 integration data" * 16)

    services = build_services(db_path)
    case = services.cases.create_case(name="한글 사건", investigator="권태욱")
    evidence = services.evidence.register_evidence(case_id=case.case_id, source_path=sample)
    record, job = services.evidence.calculate_hash(
        evidence_id=evidence.evidence_id,
        algorithm=HashAlgorithm.SHA1,
        chunk_size=32,
    )
    verification, verify_job = services.evidence.verify_evidence(
        evidence_id=evidence.evidence_id,
        algorithm=HashAlgorithm.SHA1,
        chunk_size=32,
    )
    services.close()

    reopened = build_services(db_path)
    try:
        loaded_case = reopened.cases.get_case(case.case_id)
        loaded_evidence = reopened.evidence.get_evidence(evidence.evidence_id)
        events = reopened.custody.list_events(evidence.evidence_id)
        verifications = reopened.repository.list_hash_verifications(evidence.evidence_id)

        assert loaded_case.name == "한글 사건"
        assert loaded_case.locale == "ko-KR"
        assert loaded_case.timezone == "Asia/Seoul"
        assert loaded_evidence.source_path.name == "증거 자료.bin"
        assert loaded_evidence.hashes[0].digest == record.digest
        assert verification.to_schema_dict()["status"] == "MATCH"
        assert verifications[0].to_schema_dict()["status"] == "MATCH"
        assert reopened.repository.get_job(job.job_id) is not None
        assert reopened.repository.get_job(verify_job.job_id) is not None
        assert reopened.custody.verify_chain(evidence.evidence_id) is True

        schema_validator.validate_case(loaded_case.to_schema_dict())
        schema_validator.validate_evidence(loaded_evidence.to_schema_dict())
        schema_validator.validate_job(reopened.repository.get_job(job.job_id).to_schema_dict())
        for event in events:
            schema_validator.validate_custody_event(event.to_schema_dict())
    finally:
        reopened.close()


def test_utc_storage_and_asia_seoul_custody_display(tmp_path: Path) -> None:
    db_path = tmp_path / "time.db"
    sample = tmp_path / "evidence.bin"
    sample.write_bytes(b"time")
    services = build_services(db_path)
    try:
        case = services.cases.create_case(name="Time Case")
        evidence = services.evidence.register_evidence(case_id=case.case_id, source_path=sample)
        event = services.custody.list_events(evidence.evidence_id)[0].to_schema_dict()

        assert event["occurred_at_utc"].endswith("Z")
        assert event["timezone"] == "Asia/Seoul"
        assert "+09:00" in event["displayed_at"]
    finally:
        services.close()
