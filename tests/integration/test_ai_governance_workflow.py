from __future__ import annotations

import copy
import json
import sqlite3
from dataclasses import replace
from uuid import uuid4

import pytest

from apex_forensic.adapters.persistence.sqlite import SQLiteRepository
from apex_forensic.config import ServiceBundle, build_services
from apex_forensic.domain.enums import (
    AiDataForm,
    AiDataSourceType,
    AiDestinationCategory,
    AiEgressDecision,
    AiEgressReason,
    AiSecretHandling,
    AnalysisContextPurpose,
    AnalysisProfileType,
    DataClassification,
)
from apex_forensic.domain.errors import NotFoundError, StateConflictError, ValidationError
from apex_forensic.domain.models import AiEgressAuditRecord, AiEgressData, ArtifactQuery
from apex_forensic.domain.services.ai_egress import evaluate_ai_egress
from apex_forensic.domain.services.ai_projection import ai_data_reference


@pytest.fixture
def governed_sources(services, tmp_path):
    root = tmp_path / "증거"
    root.mkdir()
    path = root / "event.xml"
    path.write_text(
        """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
<System><Provider Name="Synthetic"/><EventID>1</EventID><EventRecordID>1</EventRecordID>
<TimeCreated SystemTime="2026-09-08T00:00:00Z"/></System>
<EventData><Data Name="password">opaque-secret</Data></EventData></Event>""",
        encoding="utf-8",
    )
    case = services.cases.create_case(name="AI 거버넌스")
    evidence = services.evidence.register_evidence(case_id=case.case_id, source_path=root)
    services.fs.index_evidence(
        case_id=case.case_id,
        evidence_id=evidence.evidence_id,
        profile_type=AnalysisProfileType.FULL_ANALYSIS,
    )
    services.artifacts.analyze_evidence(case_id=case.case_id, evidence_id=evidence.evidence_id)
    artifact = services.artifacts.list_artifacts(ArtifactQuery(case_id=case.case_id)).items[0]
    context = services.contexts.create(
        session_id="governance-test",
        case_id=case.case_id,
        selected_artifact_ids=[artifact.artifact_id],
    )
    snapshot = services.contexts.build_from_session(
        context.session_context_id,
        purpose=AnalysisContextPurpose.AI_REQUEST,
        scopes=["eventlog"],
    )
    request = services.ai.create_request_from_context_snapshot(
        case_id=case.case_id,
        context_snapshot_id=snapshot.context_snapshot_id,
    )
    return case, artifact, snapshot, request, path


def _permit(services, case_id, **options):
    return services.ai_policies.configure(
        **(
            {
                "case_id": case_id,
                "expected_revision": 0,
                "ai_enabled": True,
                "external_allowed": True,
                "local_only": False,
                "allowed_classifications": tuple(DataClassification),
                "secret_handling": AiSecretHandling.REDACT,
            }
            | options
        )
    )


@pytest.mark.parametrize("index", [1, 2, 3])
def test_existing_artifact_context_request_projection_flow(
    services,
    governed_sources,
    schema_validator,
    index,
):
    case, artifact, snapshot, request, path = governed_sources
    source = governed_sources[index]
    before = copy.deepcopy(source.to_schema_dict())
    evidence_before = path.read_bytes()
    reference = ai_data_reference(source)
    policy = _permit(services, case.case_id)
    raw = AiEgressData(reference, DataClassification.SENSITIVE, True)
    preliminary = services.ai_egress.evaluate(raw, destination=AiDestinationCategory.EXTERNAL)
    assert preliminary.result.decision == AiEgressDecision.ALLOW_PROJECTION_ONLY
    assert not preliminary.to_schema_dict()["projection_applied"]
    projection = services.ai_projections.create(
        case_id=case.case_id,
        source_id=reference.source_id,
        source_type=reference.source_type,
        classification=raw.classification,
    )
    final = services.ai_egress.evaluate_projection(
        projection,
        destination=AiDestinationCategory.EXTERNAL,
    )
    assert final.result.decision == AiEgressDecision.ALLOW
    assert final.result.policy_id == policy.policy_id
    assert final.result.data.classification == DataClassification.SECRET
    assert final.result.data.source == reference
    assert final.result.data.content_fingerprint == projection.content_fingerprint
    assert final.to_schema_dict()["redaction_applied"] is True
    assert final.to_schema_dict()["projection_applied"] is True
    for name, record in [
        ("safe-ai-projection", projection),
        ("ai-egress-audit", preliminary),
        ("ai-egress-audit", final),
    ]:
        schema_validator.validate(f"{name}.schema.json", record.to_schema_dict())
        assert "opaque-secret" not in json.dumps(record.to_schema_dict())
    assert source.to_schema_dict() == before
    assert path.read_bytes() == evidence_before
    assert services.repository.get_artifact(artifact.artifact_id).to_schema_dict() == (
        artifact.to_schema_dict()
    )
    assert services.contexts.get_snapshot(snapshot.context_snapshot_id).to_schema_dict() == (
        snapshot.to_schema_dict()
    )
    assert services.ai.get_request(request.assistance_request_id).to_schema_dict() == (
        request.to_schema_dict()
    )
    reopened = build_services(services.repository.db_path)
    try:
        assert reopened.ai_policies.get(case.case_id) == policy
        records = reopened.repository.list_ai_egress_audits(
            case_id=case.case_id,
            source_id=reference.source_id,
        )
        assert records == [preliminary, final]
        assert records[-1].result.reason == final.result.reason
        assert records[-1].result.reason_codes == final.result.reason_codes
    finally:
        reopened.close()


def test_missing_policy_disabled_policy_and_revisions_are_audited(services, governed_sources):
    case, artifact, _, _, _ = governed_sources
    raw = AiEgressData(ai_data_reference(artifact))
    missing = services.ai_egress.evaluate(raw, destination=AiDestinationCategory.LOCAL)
    assert missing.result.reason_codes == (AiEgressReason.POLICY_MISSING,)
    disabled = services.ai_policies.configure(case_id=case.case_id, expected_revision=0)
    denied = services.ai_egress.evaluate(raw, destination=AiDestinationCategory.LOCAL)
    assert AiEgressReason.AI_DISABLED in denied.result.reason_codes
    assert denied.result.policy_id == disabled.policy_id
    enabled = _permit(services, case.case_id, expected_revision=1)
    assert enabled.revision == 2
    assert enabled.policy_id != disabled.policy_id
    assert services.repository.list_ai_egress_audits(case_id=case.case_id) == [missing, denied]
    assert (
        services.repository.connection.execute(
            "SELECT COUNT(*) FROM case_ai_policies WHERE case_id = ?",
            (case.case_id,),
        ).fetchone()[0]
        == 2
    )
    with pytest.raises(StateConflictError):
        _permit(services, case.case_id, expected_revision=1)


def test_policy_change_between_evaluation_and_audit_is_rejected(services, governed_sources):
    case, artifact, _, _, _ = governed_sources
    policy = _permit(services, case.case_id)
    old_result = evaluate_ai_egress(
        policy, AiEgressData(ai_data_reference(artifact)), AiDestinationCategory.LOCAL
    )
    services.ai_policies.configure(case_id=case.case_id, expected_revision=1)
    with pytest.raises(StateConflictError):
        services.repository.append_ai_egress_audit(
            AiEgressAuditRecord(str(uuid4()), old_result, policy.created_at),
        )
    assert services.repository.list_ai_egress_audits(case_id=case.case_id) == []


def test_missing_policy_race_is_rejected(services, governed_sources):
    case, artifact, _, _, _ = governed_sources
    old_result = evaluate_ai_egress(
        None, AiEgressData(ai_data_reference(artifact)), AiDestinationCategory.LOCAL
    )
    policy = _permit(services, case.case_id)
    with pytest.raises(StateConflictError):
        services.repository.append_ai_egress_audit(
            AiEgressAuditRecord(str(uuid4()), old_result, policy.created_at),
        )


@pytest.mark.parametrize("table", ["case_ai_policies", "ai_egress_audit_records"])
def test_governance_persistence_is_append_only(services, governed_sources, table):
    case, artifact, _, _, _ = governed_sources
    _permit(services, case.case_id)
    services.ai_egress.evaluate(
        AiEgressData(ai_data_reference(artifact)), destination=AiDestinationCategory.LOCAL
    )
    for sql in (f"UPDATE {table} SET case_id = case_id", f"DELETE FROM {table}"):
        with pytest.raises(sqlite3.IntegrityError), services.repository.connection:
            services.repository.connection.execute(sql)


def test_governance_cannot_cross_case_or_use_missing_sources(services, governed_sources):
    case, artifact, _, _, _ = governed_sources
    other = services.cases.create_case(name="Other")
    reference = ai_data_reference(artifact)
    with pytest.raises(ValidationError):
        services.ai_projections.create(
            case_id=other.case_id,
            source_id=artifact.artifact_id,
            source_type=AiDataSourceType.ARTIFACT,
        )
    with pytest.raises(NotFoundError):
        services.ai_projections.create(
            case_id=case.case_id, source_id=str(uuid4()), source_type=AiDataSourceType.ARTIFACT
        )
    with pytest.raises(NotFoundError):
        services.ai_policies.configure(case_id=str(uuid4()), expected_revision=0)
    policy = _permit(services, other.case_id)
    result = evaluate_ai_egress(
        policy, AiEgressData(replace(reference, case_id=other.case_id)), AiDestinationCategory.LOCAL
    )
    with pytest.raises(sqlite3.IntegrityError):
        services.repository.append_ai_egress_audit(
            AiEgressAuditRecord(str(uuid4()), result, policy.created_at),
        )
    assert services.repository.list_ai_egress_audits(case_id=other.case_id) == []


def test_stale_tampered_projection_and_flag_only_claim_are_rejected(services, governed_sources):
    case, artifact, _, _, _ = governed_sources
    _permit(services, case.case_id)
    projection = services.ai_projections.create(
        case_id=case.case_id,
        source_id=artifact.artifact_id,
        source_type=AiDataSourceType.ARTIFACT,
    )
    with pytest.raises(ValidationError):
        services.ai_egress.evaluate(
            projection.egress_data(), destination=AiDestinationCategory.LOCAL
        )
    tampered = replace(projection, selected_fields=(("confidence", 0.125),))
    with pytest.raises(StateConflictError):
        services.ai_egress.evaluate_projection(tampered, destination=AiDestinationCategory.LOCAL)
    stale = replace(projection, source=replace(projection.source, source_fingerprint="a" * 64))
    with pytest.raises(StateConflictError):
        services.ai_egress.evaluate_projection(stale, destination=AiDestinationCategory.LOCAL)
    with pytest.raises(StateConflictError):
        services.ai_egress.evaluate(
            AiEgressData(stale.source), destination=AiDestinationCategory.LOCAL
        )
    assert services.repository.list_ai_egress_audits(case_id=case.case_id) == []


def test_known_secret_metadata_cannot_be_lowered_by_caller(services, governed_sources):
    case, artifact, _, _, _ = governed_sources
    _permit(
        services,
        case.case_id,
        raw_allowed=True,
        projection_required=False,
        redaction_required=False,
        allowed_classifications=(DataClassification.PUBLIC,),
    )
    raw = AiEgressData(ai_data_reference(artifact), DataClassification.PUBLIC, False)
    record = services.ai_egress.evaluate(raw, destination=AiDestinationCategory.EXTERNAL)
    assert record.result.data.classification == DataClassification.SECRET
    assert record.result.decision == AiEgressDecision.DENY
    assert AiEgressReason.CLASSIFICATION_DENIED in record.result.reason_codes


def test_redaction_required_and_final_flags_survive_round_trip(services, governed_sources):
    case, artifact, _, _, _ = governed_sources
    _permit(services, case.case_id, raw_allowed=True, projection_required=False)
    raw = AiEgressData(ai_data_reference(artifact))
    required = services.ai_egress.evaluate(raw, destination=AiDestinationCategory.LOCAL)
    assert required.result.decision == AiEgressDecision.ALLOW_WITH_REDACTION
    # Generic REDACTED metadata is explicitly a trusted integration attestation, bound to a digest.
    redacted = replace(
        raw, contains_secrets=False, data_form=AiDataForm.REDACTED, content_fingerprint="b" * 64
    )
    final = services.ai_egress.evaluate(redacted, destination=AiDestinationCategory.LOCAL)
    assert final.result.decision == AiEgressDecision.ALLOW
    saved = services.repository.list_ai_egress_audits(case_id=case.case_id)[-1]
    assert saved == final
    assert saved.to_schema_dict()["redaction_applied"] is True
    assert saved.to_schema_dict()["projection_applied"] is False


def test_upgrade_existing_database_is_idempotent_and_keeps_case_data(services, governed_sources):
    case, artifact, snapshot, request, _ = governed_sources
    db_path = services.repository.db_path
    # Remove only the newly introduced empty tables to model the previous engine schema.
    with services.repository.connection:
        services.repository.connection.execute("DROP TABLE ai_egress_audit_records")
        services.repository.connection.execute("DROP TABLE case_ai_policies")
        services.repository.connection.execute(
            "DELETE FROM schema_migrations WHERE version = 'apex-engine-ai-data-governance'",
        )
    reopened = build_services(db_path)
    try:
        reopened.repository.initialize()
        assert reopened.cases.get_case(case.case_id) == case
        assert reopened.repository.get_artifact(artifact.artifact_id) == artifact
        assert reopened.repository.get_analysis_context_snapshot(snapshot.context_snapshot_id) == (
            snapshot
        )
        assert reopened.ai.get_request(request.assistance_request_id) == request
        assert reopened.ai_policies.get(case.case_id) is None
        assert reopened.repository.connection.execute("PRAGMA foreign_key_check").fetchall() == []
        markers = reopened.repository.connection.execute(
            "SELECT version FROM schema_migrations "
            "WHERE version = 'apex-engine-ai-data-governance'",
        ).fetchall()
        assert len(markers) == 1
    finally:
        reopened.close()


def test_audit_storage_failure_does_not_return_permission(services, governed_sources, monkeypatch):
    case, artifact, _, _, _ = governed_sources
    _permit(services, case.case_id)
    projection = services.ai_projections.create(
        case_id=case.case_id,
        source_id=artifact.artifact_id,
        source_type=AiDataSourceType.ARTIFACT,
    )

    def unavailable(_record):
        raise OSError("Synthetic audit storage unavailable")

    monkeypatch.setattr(services.repository, "append_ai_egress_audit", unavailable)
    with pytest.raises(OSError, match="audit storage unavailable"):
        services.ai_egress.evaluate_projection(projection, destination=AiDestinationCategory.LOCAL)
    assert services.repository.list_ai_egress_audits(case_id=case.case_id) == []


def test_audit_foreign_key_binds_exact_policy_fingerprint(services, governed_sources):
    case, artifact, _, _, _ = governed_sources
    policy = _permit(services, case.case_id)
    result = evaluate_ai_egress(
        policy,
        AiEgressData(ai_data_reference(artifact)),
        AiDestinationCategory.LOCAL,
    )
    forged = replace(result, policy_fingerprint="f" * 64)
    with pytest.raises(sqlite3.IntegrityError):
        services.repository.append_ai_egress_audit(
            AiEgressAuditRecord(str(uuid4()), forged, policy.created_at),
        )
    assert services.repository.list_ai_egress_audits(case_id=case.case_id) == []


def test_policy_expected_revision_across_connections(services, governed_sources):
    case, _, _, _, _ = governed_sources
    # Open the existing repository without re-running unrelated service bootstrap writes.
    second = SQLiteRepository(services.repository.db_path)
    try:
        assert second.get_case_ai_policy(case.case_id) is None
        policy = _permit(services, case.case_id)
        stale = replace(policy, policy_id=str(uuid4()))
        with pytest.raises(StateConflictError):
            second.save_case_ai_policy(stale, expected_revision=0)
        assert second.get_case_ai_policy(case.case_id) == policy
    finally:
        second.close()


def test_service_bundle_original_constructor_remains_compatible(services):
    original = {
        name: getattr(services, name)
        for name in (
            "repository",
            "cases",
            "evidence",
            "images",
            "custody",
            "fs",
            "artifacts",
            "search",
            "timeline",
            "candidates",
            "ai",
            "reports",
            "contexts",
            "context",
            "views",
            "interface",
        )
    }
    compatible = ServiceBundle(**original)
    case = services.cases.create_case(name="Compatible constructor")
    assert compatible.ai_policies.get(case.case_id) is None
    assert compatible.ai is services.ai
    assert compatible.contexts is services.contexts
