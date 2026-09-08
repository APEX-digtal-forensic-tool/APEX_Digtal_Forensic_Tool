"""Immutable AI data governance contracts, independent of provider execution."""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, fields
from datetime import datetime
from typing import Any
from uuid import UUID

from apex_forensic._time import parse_timestamp, to_json_timestamp
from apex_forensic.constants import SCHEMA_VERSION
from apex_forensic.domain.enums import (
    AiAssistancePurpose,
    AiDataForm,
    AiDataSourceType,
    AiDestinationCategory,
    AiEgressDecision,
    AiEgressReason,
    AiSecretHandling,
    ArtifactParseStatus,
    ArtifactType,
    DataClassification,
)
from apex_forensic.domain.errors import ValidationError
from apex_forensic.domain.services.canonical import canonical_sha256


def _uuid(value: str, target: str) -> None:
    try:
        if not isinstance(value, str) or str(UUID(value)) != value.lower():
            raise ValueError
    except (ValueError, AttributeError):
        raise ValidationError("Expected a UUID identifier.", target=target) from None


def _digest(value: Any, target: str) -> None:
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise ValidationError("Expected a SHA-256 fingerprint.", target=target)


def _boolean(value: Any, target: str) -> None:
    if type(value) is not bool:
        raise ValidationError("Expected a boolean.", target=target)


def _enum(value: Any, enum_type: type[Any], target: str) -> None:
    if not isinstance(value, enum_type):
        raise ValidationError("Expected a supported enum value.", target=target)


def _positive(value: Any, target: str) -> None:
    if type(value) is not int or value < 1:
        raise ValidationError("Expected a positive integer.", target=target)


def _parse_contract_timestamp(value: Any) -> datetime:
    if (
        not isinstance(value, str)
        or re.fullmatch(
            r"[0-9]{4}-[0-9]{2}-[0-9]{2}[Tt][0-9]{2}:[0-9]{2}:[0-9]{2}"
            r"(?:\.[0-9]+)?(?:[Zz]|[+-][0-9]{2}:[0-9]{2})",
            value,
        )
        is None
    ):
        raise ValidationError("Expected a timestamp with an explicit timezone.")
    try:
        return parse_timestamp(value.upper())
    except ValueError:
        raise ValidationError("Expected a valid timestamp.") from None


def _keys(data: dict[str, Any], expected: set[str]) -> None:
    if set(data) != expected:
        raise ValidationError("Contract fields are missing or unsupported.")


@dataclass(frozen=True, slots=True)
class CaseAiPolicy:
    """Append-only case policy revision. Missing policy never grants permission."""

    policy_id: str
    case_id: str
    revision: int
    created_at: datetime
    ai_enabled: bool = False
    external_allowed: bool = False
    local_only: bool = True
    allowed_classifications: tuple[DataClassification, ...] = (
        DataClassification.PUBLIC,
        DataClassification.INTERNAL,
    )
    secret_handling: AiSecretHandling = AiSecretHandling.DENY
    raw_allowed: bool = False
    redaction_required: bool = True
    projection_required: bool = True

    def __post_init__(self) -> None:
        _uuid(self.policy_id, "policy_id")
        _uuid(self.case_id, "case_id")
        _positive(self.revision, "revision")
        if not isinstance(self.created_at, datetime) or self.created_at.utcoffset() is None:
            raise ValidationError("Policy time must have a timezone.", target="created_at")
        for name in (
            "ai_enabled",
            "external_allowed",
            "local_only",
            "raw_allowed",
            "redaction_required",
            "projection_required",
        ):
            _boolean(getattr(self, name), name)
        _enum(self.secret_handling, AiSecretHandling, "secret_handling")
        if not isinstance(self.allowed_classifications, tuple):
            raise ValidationError("Classifications must be an immutable tuple.")
        for item in self.allowed_classifications:
            _enum(item, DataClassification, "allowed_classifications")
        if len(set(self.allowed_classifications)) != len(self.allowed_classifications):
            raise ValidationError("Duplicate classification.", target="allowed_classifications")
        object.__setattr__(
            self,
            "allowed_classifications",
            tuple(item for item in DataClassification if item in self.allowed_classifications),
        )

    @property
    def content_fingerprint(self) -> str:
        return canonical_sha256(self.to_schema_dict())

    def to_schema_dict(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "policy_id": self.policy_id,
            "case_id": self.case_id,
            "revision": self.revision,
            "created_at": to_json_timestamp(self.created_at),
            "ai_enabled": self.ai_enabled,
            "external_allowed": self.external_allowed,
            "local_only": self.local_only,
            "allowed_classifications": [item.value for item in self.allowed_classifications],
            "secret_handling": self.secret_handling.value,
            "raw_allowed": self.raw_allowed,
            "redaction_required": self.redaction_required,
            "projection_required": self.projection_required,
        }

    @classmethod
    def from_schema_dict(cls, data: dict[str, Any]) -> CaseAiPolicy:
        _keys(data, {item.name for item in fields(cls)} | {"schema_version"})
        if data["schema_version"] != SCHEMA_VERSION:
            raise ValidationError("Unsupported governance schema version.")
        values = {key: value for key, value in data.items() if key != "schema_version"}
        try:
            values["created_at"] = _parse_contract_timestamp(values["created_at"])
            values["allowed_classifications"] = tuple(
                DataClassification(item) for item in values["allowed_classifications"]
            )
            values["secret_handling"] = AiSecretHandling(values["secret_handling"])
        except (ValueError, TypeError):
            raise ValidationError("Invalid policy contract.") from None
        return cls(**values)


@dataclass(frozen=True, slots=True)
class AiDataReference:
    """Reference to an existing forensic record, never the raw evidence itself."""

    case_id: str
    source_id: str
    source_type: AiDataSourceType
    source_fingerprint: str

    def __post_init__(self) -> None:
        _uuid(self.case_id, "case_id")
        _uuid(self.source_id, "source_id")
        _enum(self.source_type, AiDataSourceType, "source_type")
        _digest(self.source_fingerprint, "source_fingerprint")

    def to_schema_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "source_id": self.source_id,
            "source_type": self.source_type.value,
            "source_fingerprint": self.source_fingerprint,
        }

    @classmethod
    def from_schema_dict(cls, data: dict[str, Any]) -> AiDataReference:
        _keys(data, {item.name for item in fields(cls)})
        try:
            return cls(**{**data, "source_type": AiDataSourceType(data["source_type"])})
        except (TypeError, ValueError):
            raise ValidationError("Invalid AI data reference.") from None


@dataclass(frozen=True, slots=True)
class AiEgressData:
    """Trusted metadata for an exact representation being evaluated.

    Classification is supplied by the forensic caller, not inferred by a language model.
    Unknown secret presence is conservatively treated as secret-bearing. Transform labels
    are attestations, not proof that an arbitrary payload is safe.
    """

    source: AiDataReference
    classification: DataClassification = DataClassification.SENSITIVE
    contains_secrets: bool = True
    data_form: AiDataForm = AiDataForm.RAW
    content_fingerprint: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.source, AiDataReference):
            raise ValidationError("Expected an AI data reference.")
        _enum(self.classification, DataClassification, "classification")
        _enum(self.data_form, AiDataForm, "data_form")
        _boolean(self.contains_secrets, "contains_secrets")
        if self.contains_secrets:
            object.__setattr__(self, "classification", DataClassification.SECRET)
        if self.content_fingerprint is not None:
            _digest(self.content_fingerprint, "content_fingerprint")
        if self.data_form != AiDataForm.RAW and self.content_fingerprint is None:
            raise ValidationError("Derived representations require a content fingerprint.")

    @property
    def redaction_applied(self) -> bool:
        return self.data_form in {AiDataForm.REDACTED, AiDataForm.SAFE_PROJECTION}

    @property
    def projection_applied(self) -> bool:
        return self.data_form == AiDataForm.SAFE_PROJECTION

    def to_schema_dict(self) -> dict[str, Any]:
        return {
            "source": self.source.to_schema_dict(),
            "classification": self.classification.value,
            "contains_secrets": self.contains_secrets,
            "data_form": self.data_form.value,
            "content_fingerprint": self.content_fingerprint,
        }

    @classmethod
    def from_schema_dict(cls, data: dict[str, Any]) -> AiEgressData:
        _keys(data, {item.name for item in fields(cls)})
        try:
            return cls(
                source=AiDataReference.from_schema_dict(data["source"]),
                classification=DataClassification(data["classification"]),
                contains_secrets=data["contains_secrets"],
                data_form=AiDataForm(data["data_form"]),
                content_fingerprint=data["content_fingerprint"],
            )
        except (ValueError, TypeError):
            raise ValidationError("Invalid egress data contract.") from None


@dataclass(frozen=True, slots=True)
class AiEgressResult:
    """A deterministic assessment. Only ALLOW authorizes this exact representation."""

    data: AiEgressData
    destination: AiDestinationCategory
    decision: AiEgressDecision
    reason_codes: tuple[AiEgressReason, ...]
    required_transformations: tuple[AiDataForm, ...]
    policy_id: str | None
    policy_revision: int | None
    policy_fingerprint: str | None

    def __post_init__(self) -> None:
        if not isinstance(self.data, AiEgressData):
            raise ValidationError("Expected egress metadata.")
        _enum(self.destination, AiDestinationCategory, "destination")
        _enum(self.decision, AiEgressDecision, "decision")
        if not isinstance(self.reason_codes, tuple) or not self.reason_codes:
            raise ValidationError("Decision requires immutable reason codes.")
        for reason in self.reason_codes:
            _enum(reason, AiEgressReason, "reason_codes")
        if not isinstance(self.required_transformations, tuple):
            raise ValidationError("Transformations must be an immutable tuple.")
        for form in self.required_transformations:
            if form not in (AiDataForm.REDACTED, AiDataForm.SAFE_PROJECTION):
                raise ValidationError("Unsupported required transformation.")
            _enum(form, AiDataForm, "required_transformations")
        expected_transformations = {
            AiEgressDecision.ALLOW: (),
            AiEgressDecision.DENY: (),
            AiEgressDecision.ALLOW_WITH_REDACTION: (AiDataForm.REDACTED,),
            AiEgressDecision.ALLOW_PROJECTION_ONLY: (AiDataForm.SAFE_PROJECTION,),
        }
        if self.required_transformations != expected_transformations[self.decision]:
            raise ValidationError("Decision and required transformations disagree.")
        if len(set(self.reason_codes)) != len(self.reason_codes):
            raise ValidationError("Duplicate egress reason codes.")
        if self.decision == AiEgressDecision.ALLOW and self.reason_codes != (
            AiEgressReason.POLICY_SATISFIED,
        ):
            raise ValidationError("An allow decision must satisfy the policy.")
        if self.policy_id is None:
            if self.decision != AiEgressDecision.DENY:
                raise ValidationError("A missing policy must deny egress.")
            if self.policy_revision is not None or self.policy_fingerprint is not None:
                raise ValidationError("Incomplete policy reference.")
        else:
            _uuid(self.policy_id, "policy_id")
            _positive(self.policy_revision, "policy_revision")
            _digest(self.policy_fingerprint, "policy_fingerprint")

    @property
    def reason(self) -> str:
        return "; ".join(
            reason.value.replace("_", " ").capitalize() for reason in self.reason_codes
        )

    def to_schema_dict(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "data": self.data.to_schema_dict(),
            "destination": self.destination.value,
            "decision": self.decision.value,
            "reason": self.reason,
            "reason_codes": [item.value for item in self.reason_codes],
            "required_transformations": [item.value for item in self.required_transformations],
            "policy_id": self.policy_id,
            "policy_revision": self.policy_revision,
            "policy_fingerprint": self.policy_fingerprint,
        }

    @classmethod
    def from_schema_dict(cls, data: dict[str, Any]) -> AiEgressResult:
        _keys(data, {item.name for item in fields(cls)} | {"schema_version", "reason"})
        if data["schema_version"] != SCHEMA_VERSION:
            raise ValidationError("Unsupported governance schema version.")
        try:
            result = cls(
                data=AiEgressData.from_schema_dict(data["data"]),
                destination=AiDestinationCategory(data["destination"]),
                decision=AiEgressDecision(data["decision"]),
                reason_codes=tuple(AiEgressReason(item) for item in data["reason_codes"]),
                required_transformations=tuple(
                    AiDataForm(item) for item in data["required_transformations"]
                ),
                policy_id=data["policy_id"],
                policy_revision=data["policy_revision"],
                policy_fingerprint=data["policy_fingerprint"],
            )
        except (TypeError, ValueError):
            raise ValidationError("Invalid egress decision contract.") from None
        if result.reason != data["reason"]:
            raise ValidationError("Decision reason does not match its codes.")
        return result


@dataclass(frozen=True, slots=True)
class SafeAiProjection:
    """Detached, scalar-only field selection. No source text or raw locator is exported."""

    source: AiDataReference
    classification: DataClassification
    selected_fields: tuple[tuple[str, str | int | float | bool | None], ...]
    projection_version: str = "safe-ai-projection-v1"

    def __post_init__(self) -> None:
        if not isinstance(self.source, AiDataReference):
            raise ValidationError("Expected an AI data reference.")
        _enum(self.classification, DataClassification, "classification")
        if self.projection_version != "safe-ai-projection-v1":
            raise ValidationError("Unsupported projection version.")
        # Validate the allowlist on every construction, including deserialization.
        validate_projection_fields(self.source.source_type, self.selected_fields)
        object.__setattr__(self, "selected_fields", tuple(sorted(self.selected_fields)))

    @property
    def content_fingerprint(self) -> str:
        return canonical_sha256(
            {
                "source": self.source.to_schema_dict(),
                "classification": self.classification.value,
                "fields": dict(self.selected_fields),
                "projection_version": self.projection_version,
            }
        )

    def egress_data(self) -> AiEgressData:
        return AiEgressData(
            self.source,
            self.classification,
            False,
            AiDataForm.SAFE_PROJECTION,
            self.content_fingerprint,
        )

    def to_schema_dict(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "source": self.source.to_schema_dict(),
            "classification": self.classification.value,
            "fields": dict(self.selected_fields),
            "redaction_applied": True,
            "projection_applied": True,
            "content_fingerprint": self.content_fingerprint,
            "projection_version": self.projection_version,
        }

    @classmethod
    def from_schema_dict(cls, data: dict[str, Any]) -> SafeAiProjection:
        _keys(
            data,
            {
                "schema_version",
                "source",
                "classification",
                "fields",
                "redaction_applied",
                "projection_applied",
                "content_fingerprint",
                "projection_version",
            },
        )
        if (
            data["schema_version"] != SCHEMA_VERSION
            or data["redaction_applied"] is not True
            or data["projection_applied"] is not True
        ):
            raise ValidationError("Invalid safe projection contract.")
        try:
            result = cls(
                source=AiDataReference.from_schema_dict(data["source"]),
                classification=DataClassification(data["classification"]),
                selected_fields=tuple(data["fields"].items()),
                projection_version=data["projection_version"],
            )
        except (TypeError, ValueError, AttributeError):
            raise ValidationError("Invalid safe projection contract.") from None
        if data["content_fingerprint"] != result.content_fingerprint:
            raise ValidationError("Projection fingerprint mismatch.")
        return result


@dataclass(frozen=True, slots=True)
class AiEgressAuditRecord:
    """An assessment record, not proof of transmission or a provider request log."""

    audit_id: str
    result: AiEgressResult
    created_at: datetime

    def __post_init__(self) -> None:
        _uuid(self.audit_id, "audit_id")
        if not isinstance(self.result, AiEgressResult):
            raise ValidationError("Expected an egress result.")
        if not isinstance(self.created_at, datetime) or self.created_at.utcoffset() is None:
            raise ValidationError("Audit time must have a timezone.")

    def to_schema_dict(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "audit_id": self.audit_id,
            "result": self.result.to_schema_dict(),
            "redaction_applied": self.result.data.redaction_applied,
            "projection_applied": self.result.data.projection_applied,
            "created_at": to_json_timestamp(self.created_at),
        }

    @classmethod
    def from_schema_dict(cls, data: dict[str, Any]) -> AiEgressAuditRecord:
        _keys(
            data,
            {
                "schema_version",
                "audit_id",
                "result",
                "redaction_applied",
                "projection_applied",
                "created_at",
            },
        )
        result = cls(
            audit_id=data["audit_id"],
            result=AiEgressResult.from_schema_dict(data["result"]),
            created_at=_parse_contract_timestamp(data["created_at"]),
        )
        if (
            data["schema_version"] != SCHEMA_VERSION
            or data["redaction_applied"] is not result.result.data.redaction_applied
            or data["projection_applied"] is not result.result.data.projection_applied
        ):
            raise ValidationError("Audit metadata is inconsistent with its decision.")
        return result


PROJECTION_FIELDS: dict[AiDataSourceType, frozenset[str]] = {
    AiDataSourceType.ARTIFACT: frozenset(
        {
            "artifact_type",
            "parse_status",
            "confidence",
            "is_partial",
        }
    ),
    AiDataSourceType.CONTEXT_SNAPSHOT: frozenset(
        {
            "search_index_revision",
            "timeline_revision",
            "is_partial",
            "is_stale",
            "resource_count",
        }
    ),
    AiDataSourceType.AI_ASSISTANCE_REQUEST: frozenset(
        {
            "purpose",
            "is_partial",
            "is_stale",
            "resource_count",
            "max_keyword_candidates",
            "max_summary_length",
        }
    ),
}


def validate_projection_fields(
    source_type: AiDataSourceType,
    values: tuple[tuple[str, str | int | float | bool | None], ...],
) -> None:
    """Validate fixed structural fields; free text is deliberately outside this contract."""

    if (
        not isinstance(values, tuple)
        or not values
        or any(not isinstance(pair, tuple) or len(pair) != 2 for pair in values)
    ):
        raise ValidationError("Projection requires immutable field pairs.")
    names = [name for name, _ in values]
    if any(not isinstance(name, str) for name in names):
        raise ValidationError("Invalid projection field name.")
    if len(set(names)) != len(names) or not set(names) <= PROJECTION_FIELDS[source_type]:
        raise ValidationError("Projection contains duplicate or unsupported fields.")
    enum_fields = {
        "artifact_type": ArtifactType,
        "parse_status": ArtifactParseStatus,
        "purpose": AiAssistancePurpose,
    }
    for name, value in values:
        if name in enum_fields:
            try:
                if not isinstance(value, str):
                    raise ValueError
                enum_fields[name](value)
            except (ValueError, TypeError):
                raise ValidationError("Invalid structural enum field.", target=name) from None
        elif name in {"is_partial", "is_stale"}:
            _boolean(value, name)
        elif name == "confidence":
            if (
                not isinstance(value, (int, float))
                or isinstance(value, bool)
                or not math.isfinite(value)
                or not 0 <= value <= 1
            ):
                raise ValidationError("Invalid confidence field.", target=name)
        elif name in {"timeline_revision", "search_index_revision"} and value is None:
            continue
        elif type(value) is not int or not 0 <= value <= 2**63 - 1:
            raise ValidationError("Invalid numeric projection field.", target=name)
