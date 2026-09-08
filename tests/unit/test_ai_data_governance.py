from __future__ import annotations

import copy
import json
from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime
from itertools import product
from uuid import uuid4

import pytest
from jsonschema import Draft202012Validator

from apex_forensic.domain.enums import (
    AiDataForm,
    AiDataSourceType,
    AiDestinationCategory,
    AiEgressDecision,
    AiEgressReason,
    AiSecretHandling,
    ArtifactParseStatus,
    ArtifactSourceKind,
    ArtifactType,
    DataClassification,
)
from apex_forensic.domain.errors import ValidationError
from apex_forensic.domain.models import (
    AiDataReference,
    AiEgressAuditRecord,
    AiEgressData,
    AiEgressResult,
    ArtifactRecord,
    CaseAiPolicy,
    SafeAiProjection,
)
from apex_forensic.domain.models.secret import redact_secret_fields
from apex_forensic.domain.services.ai_egress import evaluate_ai_egress
from apex_forensic.domain.services.ai_projection import ai_data_reference, build_safe_ai_projection

NOW = datetime(2026, 9, 8, tzinfo=UTC)
CASE_ID = "ca5e0000-0000-4000-8000-000000000001"
SOURCE_ID = "aabb0000-0000-4000-8000-000000000001"


def _policy(**options):
    defaults = {
        "policy_id": str(uuid4()),
        "case_id": CASE_ID,
        "revision": 1,
        "created_at": NOW,
        "ai_enabled": True,
        "external_allowed": True,
        "local_only": False,
        "raw_allowed": True,
        "redaction_required": False,
        "projection_required": False,
    }
    return CaseAiPolicy(**(defaults | options))


def _data(**options):
    defaults = {
        "source": AiDataReference(CASE_ID, SOURCE_ID, AiDataSourceType.ARTIFACT, "a" * 64),
        "classification": DataClassification.PUBLIC,
        "contains_secrets": False,
        "data_form": AiDataForm.RAW,
        "content_fingerprint": "b" * 64,
    }
    return AiEgressData(**(defaults | options))


def _artifact(**options):
    defaults = {
        "artifact_id": SOURCE_ID,
        "case_id": CASE_ID,
        "evidence_id": str(uuid4()),
        "source_file_node_id": str(uuid4()),
        "artifact_type": ArtifactType.EVENT_LOG_RECORD,
        "artifact_subtype": "event",
        "analyzer_id": "synthetic",
        "analyzer_version": "1",
        "parser_backend": "synthetic",
        "parser_backend_version": "1",
        "source_path": "/opaque-secret/path",
        "source_kind": ArtifactSourceKind.EVENT_LOG_XML,
        "observed_at_raw": "opaque-secret",
        "observed_at_utc": NOW,
        "timezone_source": "UTC",
        "timezone_confidence": "HIGH",
        "title": "opaque-secret",
        "summary": "opaque-secret",
        "fields": {"password": "opaque-secret", "notes": "opaque-secret"},
        "raw_locator": {"path": "opaque-secret"},
        "citations": [{"excerpt": "opaque-secret"}],
        "warnings": [{"developer_message": "opaque-secret"}],
        "parse_status": ArtifactParseStatus.SUCCESS,
        "confidence": 1.0,
        "is_partial": False,
        "index_revision": 1,
        "created_at": NOW,
        "updated_at": NOW,
        "dedup_key": "a" * 64,
    }
    return ArtifactRecord(**(defaults | options))


@pytest.mark.parametrize("classification", list(DataClassification))
def test_classification_enum_serialization_and_schema(classification, schema_validator):
    assert DataClassification(json.loads(json.dumps(classification))) is classification
    schema_validator.validate("data-classification.schema.json", classification.value)
    data = _data(classification=classification)
    assert AiEgressData.from_schema_dict(data.to_schema_dict()) == data
    schema_validator.validate("ai-egress-data.schema.json", data.to_schema_dict())


@pytest.mark.parametrize("invalid", ["private", "public", "", None, 7, True, [], {}])
def test_invalid_classification_is_rejected(invalid, schema_validator):
    with pytest.raises((ValueError, TypeError)):
        DataClassification(invalid)
    with pytest.raises(ValidationError):
        _data(classification=invalid)
    with pytest.raises(ValidationError):
        schema_validator.validate("data-classification.schema.json", invalid)


@pytest.mark.parametrize(
    ("options", "data_options", "destination", "expected", "reason"),
    [
        ({}, {}, "EXTERNAL", "ALLOW", "POLICY_SATISFIED"),
        ({"ai_enabled": False}, {}, "LOCAL", "DENY", "AI_DISABLED"),
        ({"local_only": True}, {}, "EXTERNAL", "DENY", "LOCAL_ONLY"),
        ({"local_only": True}, {}, "LOCAL", "ALLOW", "POLICY_SATISFIED"),
        ({"external_allowed": False}, {}, "EXTERNAL", "DENY", "EXTERNAL_DENIED"),
        ({"external_allowed": False}, {}, "LOCAL", "ALLOW", "POLICY_SATISFIED"),
        (
            {},
            {"classification": DataClassification.SENSITIVE},
            "EXTERNAL",
            "DENY",
            "CLASSIFICATION_DENIED",
        ),
        (
            {},
            {"classification": DataClassification.SECRET},
            "EXTERNAL",
            "DENY",
            "CLASSIFICATION_DENIED",
        ),
        ({"raw_allowed": False}, {}, "LOCAL", "DENY", "RAW_DENIED"),
        (
            {"raw_allowed": False},
            {"data_form": AiDataForm.STRUCTURED},
            "LOCAL",
            "ALLOW",
            "POLICY_SATISFIED",
        ),
        (
            {"redaction_required": True},
            {},
            "EXTERNAL",
            "ALLOW_WITH_REDACTION",
            "REDACTION_REQUIRED",
        ),
        (
            {"redaction_required": True},
            {"data_form": AiDataForm.REDACTED},
            "LOCAL",
            "ALLOW",
            "POLICY_SATISFIED",
        ),
        (
            {"projection_required": True, "raw_allowed": False},
            {},
            "LOCAL",
            "ALLOW_PROJECTION_ONLY",
            "PROJECTION_REQUIRED",
        ),
        (
            {"projection_required": True},
            {"data_form": AiDataForm.REDACTED},
            "EXTERNAL",
            "ALLOW_PROJECTION_ONLY",
            "PROJECTION_REQUIRED",
        ),
        (
            {"projection_required": True, "redaction_required": True},
            {"data_form": AiDataForm.SAFE_PROJECTION},
            "EXTERNAL",
            "ALLOW",
            "POLICY_SATISFIED",
        ),
        ({"allowed_classifications": ()}, {}, "LOCAL", "DENY", "CLASSIFICATION_DENIED"),
        ({"case_id": str(uuid4())}, {}, "LOCAL", "DENY", "CASE_MISMATCH"),
    ],
)
def test_policy_decision_scenarios(
    options, data_options, destination, expected, reason, schema_validator
):
    policy, data = _policy(**options), _data(**data_options)
    result = evaluate_ai_egress(policy, data, AiDestinationCategory(destination))
    assert result.decision == expected
    assert AiEgressReason(reason) in result.reason_codes
    assert evaluate_ai_egress(policy, data, AiDestinationCategory(destination)) == result
    schema_validator.validate("case-ai-policy.schema.json", policy.to_schema_dict())
    schema_validator.validate("ai-egress-decision.schema.json", result.to_schema_dict())
    assert AiEgressResult.from_schema_dict(result.to_schema_dict()) == result


@pytest.mark.parametrize("destination", list(AiDestinationCategory))
@pytest.mark.parametrize(
    ("handling", "expected"),
    [
        (AiSecretHandling.DENY, AiEgressDecision.DENY),
        (AiSecretHandling.REDACT, AiEgressDecision.ALLOW_WITH_REDACTION),
        (AiSecretHandling.ALLOW, AiEgressDecision.ALLOW),
    ],
)
def test_explicit_secret_policy_and_reassessment(handling, expected, destination):
    policy = _policy(allowed_classifications=tuple(DataClassification), secret_handling=handling)
    raw = _data(contains_secrets=True)
    assert raw.classification == DataClassification.SECRET
    assert evaluate_ai_egress(policy, raw, destination).decision == expected
    incomplete = replace(raw, data_form=AiDataForm.REDACTED)
    assert evaluate_ai_egress(policy, incomplete, destination).decision == AiEgressDecision.DENY
    redacted = replace(incomplete, contains_secrets=False)
    assert redacted.classification == DataClassification.SECRET
    assert evaluate_ai_egress(policy, redacted, destination).decision == AiEgressDecision.ALLOW
    limited = replace(policy, allowed_classifications=(DataClassification.PUBLIC,))
    assert evaluate_ai_egress(limited, redacted, destination).decision == AiEgressDecision.DENY


def test_default_and_missing_policy_fail_closed(schema_validator):
    data = _data()
    default = CaseAiPolicy(str(uuid4()), CASE_ID, 1, NOW)
    for policy in (None, default):
        for destination in AiDestinationCategory:
            result = evaluate_ai_egress(policy, data, destination)
            assert result.decision == AiEgressDecision.DENY
            schema_validator.validate("ai-egress-decision.schema.json", result.to_schema_dict())
    assert _data(contains_secrets=True).classification == DataClassification.SECRET
    assert AiEgressData(data.source).contains_secrets is True


def test_policy_combination_safety_invariants():
    # Explore interactions, including contradictory flags, not just isolated happy paths.
    for enabled, external, local_only, raw, redaction, projection in product(
        (False, True), repeat=6
    ):
        policy = _policy(
            ai_enabled=enabled,
            external_allowed=external,
            local_only=local_only,
            raw_allowed=raw,
            redaction_required=redaction,
            projection_required=projection,
        )
        for destination, form in product(AiDestinationCategory, AiDataForm):
            data = _data(data_form=form)
            result = evaluate_ai_egress(policy, data, destination)
            if not enabled or (
                destination == AiDestinationCategory.EXTERNAL and (not external or local_only)
            ):
                assert result.decision == AiEgressDecision.DENY
            if result.decision == AiEgressDecision.ALLOW:
                assert raw or form != AiDataForm.RAW
                assert not redaction or data.redaction_applied
                assert not projection or data.projection_applied
                assert not result.required_transformations


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("ai_enabled", "false"),
        ("external_allowed", 1),
        ("local_only", None),
        ("raw_allowed", "yes"),
        ("redaction_required", 0),
        ("projection_required", []),
        ("revision", True),
        ("revision", 0),
        ("secret_handling", "ALLOW"),
        ("allowed_classifications", [DataClassification.PUBLIC]),
        ("allowed_classifications", ("PUBLIC",)),
        ("allowed_classifications", (DataClassification.PUBLIC, DataClassification.PUBLIC)),
        ("created_at", datetime(2026, 1, 1)),
        ("case_id", "password=opaque-secret"),
    ],
)
def test_policy_rejects_ambiguous_values(field, value):
    with pytest.raises(ValidationError) as error:
        _policy(**{field: value})
    assert "opaque-secret" not in str(error.value)


def test_policy_contract_round_trip_and_canonical_classification_order(schema_validator):
    policy = _policy(allowed_classifications=(DataClassification.SECRET, DataClassification.PUBLIC))
    assert policy.allowed_classifications == (DataClassification.PUBLIC, DataClassification.SECRET)
    data = json.loads(json.dumps(policy.to_schema_dict()))
    assert CaseAiPolicy.from_schema_dict(data) == policy
    assert CaseAiPolicy.from_schema_dict(data).content_fingerprint == policy.content_fingerprint
    for update in (
        {"extra": 1},
        {"schema_version": "2.0.0"},
        {"ai_enabled": "true"},
        {"created_at": "2026-09-08T00:00:00"},
        {"allowed_classifications": ["UNCLASSIFIED"]},
    ):
        invalid = data | update
        with pytest.raises(ValidationError):
            CaseAiPolicy.from_schema_dict(invalid)
        with pytest.raises(ValidationError):
            schema_validator.validate("case-ai-policy.schema.json", invalid)


def test_projection_detaches_evidence_and_excludes_all_free_text(schema_validator):
    artifact = _artifact()
    before = copy.deepcopy(artifact.to_schema_dict())
    selected = ("is_partial", "artifact_type")
    projection = build_safe_ai_projection(
        artifact,
        classification=DataClassification.SENSITIVE,
        contains_secrets=False,
        selected_fields=selected,
    )
    assert projection.classification == DataClassification.SECRET
    assert projection.source == ai_data_reference(artifact)
    assert set(dict(projection.selected_fields)) == set(selected)
    assert artifact.to_schema_dict() == before
    serialized = projection.to_schema_dict()
    assert "opaque-secret" not in json.dumps(serialized)
    schema_validator.validate("safe-ai-projection.schema.json", serialized)
    assert SafeAiProjection.from_schema_dict(serialized) == projection
    serialized["fields"]["artifact_type"] = "changed"
    assert artifact.to_schema_dict() == before
    assert dict(projection.selected_fields)["artifact_type"] == "EVENT_LOG_RECORD"
    assert (
        build_safe_ai_projection(
            artifact,
            classification=DataClassification.SENSITIVE,
            contains_secrets=False,
            selected_fields=tuple(reversed(selected)),
        )
        == projection
    )
    with pytest.raises(FrozenInstanceError):
        projection.classification = DataClassification.PUBLIC


@pytest.mark.parametrize("kind", [ArtifactType.BROWSER_COOKIE, ArtifactType.BROWSER_CREDENTIAL])
def test_credential_category_stays_secret_without_plaintext_fields(kind):
    projection = build_safe_ai_projection(
        _artifact(artifact_type=kind, fields={}),
        classification=DataClassification.PUBLIC,
        contains_secrets=False,
    )
    assert projection.classification == DataClassification.SECRET


@pytest.mark.parametrize(
    "selection",
    [
        ("title",),
        ("fields",),
        ("raw_locator",),
        ("citations",),
        ("confidence", "confidence"),
        (),
        ("fields.password",),
        ("unknown",),
        ["is_partial"],
    ],
)
def test_projection_rejects_unapproved_fields(selection):
    with pytest.raises(ValidationError):
        build_safe_ai_projection(_artifact(), selected_fields=selection)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("artifact_type", "opaque-secret"),
        ("parse_status", "opaque-secret"),
        ("confidence", float("nan")),
        ("confidence", float("inf")),
        ("confidence", True),
        ("confidence", "opaque-secret"),
        ("confidence", 1.1),
        ("is_partial", "opaque-secret"),
    ],
)
def test_projection_rejects_secret_injection_into_structural_fields(field, value):
    artifact = _artifact()
    # Dataclasses are mutable upstream; the projection still validates every selected value.
    if field in {"artifact_type", "parse_status"}:
        projection = build_safe_ai_projection(artifact)
        with pytest.raises(ValidationError):
            replace(projection, selected_fields=((field, value),))
    else:
        setattr(artifact, field, value)
        with pytest.raises(ValidationError):
            build_safe_ai_projection(artifact, selected_fields=(field,))


def test_redaction_reuses_existing_rules_without_claiming_text_detection():
    raw = {"nested": [{"access_token": "opaque-secret"}], "notes": "unlabeled-secret"}
    before = copy.deepcopy(raw)
    clean = redact_secret_fields(raw)
    assert raw == before
    assert clean["nested"][0]["access_token"] == "<redacted>"
    assert clean["notes"] == "unlabeled-secret"
    clean["nested"].append("new")
    assert raw == before
    projection = build_safe_ai_projection(_artifact(fields={"notes": "unlabeled-secret"}))
    assert "unlabeled-secret" not in json.dumps(projection.to_schema_dict())


def test_projection_fingerprint_tampering_and_schema_mismatch_rejected(schema_validator):
    projection = build_safe_ai_projection(_artifact())
    for update in (
        {"content_fingerprint": "b" * 64},
        {"projection_applied": False},
        {"fields": {"title": "opaque-secret"}},
        {"schema_version": "2.0.0"},
    ):
        with pytest.raises(ValidationError):
            SafeAiProjection.from_schema_dict(projection.to_schema_dict() | update)
    with pytest.raises(ValidationError):
        schema_validator.validate(
            "safe-ai-projection.schema.json",
            projection.to_schema_dict() | {"fields": {"token": "bad"}},
        )


@pytest.mark.parametrize("form", list(AiDataForm))
def test_audit_serialization_flags_and_reason_contract(form, schema_validator):
    result = evaluate_ai_egress(_policy(), _data(data_form=form), AiDestinationCategory.LOCAL)
    record = AiEgressAuditRecord(str(uuid4()), result, NOW)
    serialized = record.to_schema_dict()
    schema_validator.validate("ai-egress-audit.schema.json", serialized)
    assert AiEgressAuditRecord.from_schema_dict(serialized) == record
    assert record.result.reason == "Policy satisfied"
    assert serialized["redaction_applied"] == (
        form in {AiDataForm.REDACTED, AiDataForm.SAFE_PROJECTION}
    )
    assert serialized["projection_applied"] == (form == AiDataForm.SAFE_PROJECTION)
    with pytest.raises(ValidationError):
        AiEgressAuditRecord.from_schema_dict(
            serialized
            | {
                "redaction_applied": not serialized["redaction_applied"],
            }
        )


def test_all_governance_schemas_are_valid_draft_2020_12(project_root):
    for name in (
        "case-ai-policy",
        "data-classification",
        "ai-egress-data",
        "ai-egress-decision",
        "safe-ai-projection",
        "ai-egress-audit",
    ):
        Draft202012Validator.check_schema(
            json.loads(
                (project_root / "schemas" / "v1" / f"{name}.schema.json").read_text(),
            )
        )


@pytest.mark.parametrize("timestamp", ["2026-09-08T09:00:00+09:00", "2026-09-08t00:00:00z"])
def test_contract_timestamps_normalize_valid_offsets(timestamp, schema_validator):
    policy = _policy()
    data = policy.to_schema_dict() | {"created_at": timestamp}
    schema_validator.validate("case-ai-policy.schema.json", data)
    assert CaseAiPolicy.from_schema_dict(data).created_at == NOW
    result = evaluate_ai_egress(policy, _data(), AiDestinationCategory.LOCAL)
    record = AiEgressAuditRecord(str(uuid4()), result, NOW)
    data = record.to_schema_dict() | {"created_at": timestamp}
    schema_validator.validate("ai-egress-audit.schema.json", data)
    assert AiEgressAuditRecord.from_schema_dict(data) == record
