"""Advanced runtime secret and decryption DTOs.

These models keep plaintext secret material out of schema output by default. Runtime adapters can
hold ephemeral bytes while API, CLI, repository, and audit paths receive redacted summaries.
"""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from apex_forensic._time import to_json_timestamp
from apex_forensic.constants import SCHEMA_VERSION
from apex_forensic.domain.errors import DecryptionError

_SENSITIVE_FIELD_NAMES = {
    "api_key",
    "apikey",
    "authorization",
    "cookie",
    "key",
    "password",
    "plaintext",
    "plaintext_b64",
    "secret",
    "token",
}
_SENSITIVE_KEY_MARKERS = (
    "api_key",
    "apikey",
    "authorization",
    "cookie_value",
    "key_material",
    "key_value",
    "password",
    "private_key",
    "raw_key",
    "secret_material",
    "secret_value",
    "token",
)
_SENSITIVE_MESSAGE_MARKERS = ("password", "secret", "token", "cookie", "key=")


def _ts(value: datetime | None) -> str | None:
    return None if value is None else to_json_timestamp(value)


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


@dataclass(frozen=True, slots=True)
class RedactedSecret:
    """Safe summary of secret bytes for API, log, and repository surfaces."""

    secret_id: str
    case_id: str
    key_source_kind: str
    length: int
    sha256: str
    redacted_preview: str = "<redacted>"

    def to_schema_dict(self) -> dict[str, Any]:
        return {
            "secret_id": self.secret_id,
            "case_id": self.case_id,
            "key_source_kind": self.key_source_kind,
            "length": self.length,
            "sha256": self.sha256,
            "redacted_preview": self.redacted_preview,
        }


@dataclass(frozen=True, slots=True)
class SecretReference:
    """Stable reference to secret material without embedding the secret bytes."""

    secret_id: str
    case_id: str
    evidence_id: str | None
    key_source_kind: str
    provider_id: str
    source_kind: str
    source_path: str | None = None
    source_revision: int | None = None
    fingerprint: str | None = None
    raw_locator: dict[str, Any] = field(default_factory=dict)
    created_at: datetime | None = None
    reference_version: str = SCHEMA_VERSION

    def assert_case(self, case_id: str) -> None:
        if self.case_id != case_id:
            raise DecryptionError(
                "SOURCE_MISMATCH",
                "Secret reference belongs to another case.",
                target="case_id",
                details={"secret_id": self.secret_id},
            )

    def to_schema_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.reference_version,
            "secret_id": self.secret_id,
            "case_id": self.case_id,
            "evidence_id": self.evidence_id,
            "key_source_kind": self.key_source_kind,
            "provider_id": self.provider_id,
            "source_kind": self.source_kind,
            "source_path": self.source_path,
            "source_revision": self.source_revision,
            "fingerprint": self.fingerprint,
            "raw_locator": self.raw_locator,
            "created_at": _ts(self.created_at),
        }


@dataclass(frozen=True, slots=True)
class SecretMaterial:
    """Ephemeral plaintext secret bytes with explicit redacted serialization."""

    reference: SecretReference
    value: bytes = field(repr=False)
    algorithm: str | None = None
    created_at: datetime | None = None

    def __post_init__(self) -> None:
        if not self.value:
            raise DecryptionError(
                "KEY_UNAVAILABLE",
                "Secret material is empty.",
                target="value",
                details={"secret_id": self.reference.secret_id},
            )

    @property
    def redacted(self) -> RedactedSecret:
        return RedactedSecret(
            secret_id=self.reference.secret_id,
            case_id=self.reference.case_id,
            key_source_kind=self.reference.key_source_kind,
            length=len(self.value),
            sha256=_sha256(self.value),
        )

    def to_schema_dict(self, *, include_secret: bool = False) -> dict[str, Any]:
        data = {
            "reference": self.reference.to_schema_dict(),
            "redacted": self.redacted.to_schema_dict(),
            "algorithm": self.algorithm,
            "created_at": _ts(self.created_at),
        }
        if include_secret:
            data["secret_b64"] = base64.b64encode(self.value).decode("ascii")
        return data


@dataclass(frozen=True, slots=True)
class SecretDerivationInput:
    """Bounded key-derivation inputs for an offline evidence source."""

    case_id: str
    evidence_id: str | None
    key_source_kind: str
    references: list[SecretReference] = field(default_factory=list)
    parameters: dict[str, Any] = field(default_factory=dict)
    input_version: str = SCHEMA_VERSION

    def assert_references_same_case(self) -> None:
        for reference in self.references:
            reference.assert_case(self.case_id)

    def to_schema_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.input_version,
            "case_id": self.case_id,
            "evidence_id": self.evidence_id,
            "key_source_kind": self.key_source_kind,
            "references": [item.to_schema_dict() for item in self.references],
            "parameters": _redact_mapping(self.parameters),
        }


@dataclass(frozen=True, slots=True)
class DecryptionAttempt:
    """One bounded provider attempt with sanitized error metadata."""

    attempt_id: str
    case_id: str
    evidence_id: str | None
    provider_id: str
    provider_version: str
    algorithm: str
    key_source_kind: str
    status: str
    started_at: datetime
    completed_at: datetime | None = None
    warnings: list[dict[str, Any]] = field(default_factory=list)
    error_code: str | None = None
    error_message: str | None = None
    attempt_version: str = SCHEMA_VERSION

    def to_schema_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.attempt_version,
            "attempt_id": self.attempt_id,
            "case_id": self.case_id,
            "evidence_id": self.evidence_id,
            "provider_id": self.provider_id,
            "provider_version": self.provider_version,
            "algorithm": self.algorithm,
            "key_source_kind": self.key_source_kind,
            "status": self.status,
            "started_at": _ts(self.started_at),
            "completed_at": _ts(self.completed_at),
            "warnings": _redact_list(self.warnings),
            "error_code": self.error_code,
            "error_message": sanitize_error_message(self.error_message),
        }


@dataclass(frozen=True, slots=True)
class DecryptionResult:
    """Provider result that redacts plaintext unless an explicit caller opts in."""

    attempt: DecryptionAttempt
    status: str
    plaintext: bytes | None = field(default=None, repr=False)
    output_kind: str | None = None
    content_sha256: str | None = None
    content_length: int | None = None
    citations: list[dict[str, Any]] = field(default_factory=list)
    partial: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)
    result_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.plaintext is not None:
            object.__setattr__(
                self,
                "content_sha256",
                self.content_sha256 or _sha256(self.plaintext),
            )
            object.__setattr__(self, "content_length", self.content_length or len(self.plaintext))

    def to_schema_dict(self, *, include_plaintext: bool = False) -> dict[str, Any]:
        data = {
            "schema_version": self.result_version,
            "attempt": self.attempt.to_schema_dict(),
            "status": self.status,
            "output_kind": self.output_kind,
            "content_sha256": self.content_sha256,
            "content_length": self.content_length,
            "citations": self.citations,
            "partial": self.partial,
            "metadata": _redact_mapping(self.metadata),
        }
        if include_plaintext and self.plaintext is not None:
            data["plaintext_b64"] = base64.b64encode(self.plaintext).decode("ascii")
        return data


@dataclass(frozen=True, slots=True)
class SecretProviderCapability:
    """Capability descriptor for secret/decryption providers."""

    provider_id: str
    provider_version: str
    capability_type: str
    runtime_status: str
    supported_key_sources: list[str]
    supported_algorithms: list[str]
    requires_host: bool = False
    requires_network: bool = False
    warnings: list[dict[str, Any]] = field(default_factory=list)
    generated_at: datetime | None = None
    capability_version: str = SCHEMA_VERSION

    def to_schema_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.capability_version,
            "provider_id": self.provider_id,
            "provider_version": self.provider_version,
            "capability_type": self.capability_type,
            "runtime_status": self.runtime_status,
            "supported_key_sources": self.supported_key_sources,
            "supported_algorithms": self.supported_algorithms,
            "requires_host": self.requires_host,
            "requires_network": self.requires_network,
            "warnings": _redact_list(self.warnings),
            "generated_at": _ts(self.generated_at),
        }


def sanitize_error_message(message: str | None) -> str | None:
    if message is None:
        return None
    lowered = message.casefold()
    if any(marker in lowered for marker in _SENSITIVE_MESSAGE_MARKERS):
        return "Sensitive provider error redacted."
    return message[:500]


def _redact_mapping(value: dict[str, Any]) -> dict[str, Any]:
    redacted: dict[str, Any] = {}
    for key, item in value.items():
        lowered = key.casefold()
        if _is_sensitive_field_name(lowered):
            redacted[key] = "<redacted>"
        else:
            redacted[key] = _redact_value(item)
    return redacted


def _redact_list(value: list[Any]) -> list[Any]:
    return [_redact_value(item) for item in value]


def _redact_value(value: Any) -> Any:
    if isinstance(value, dict):
        return _redact_mapping(value)
    if isinstance(value, list):
        return _redact_list(value)
    return value


def _is_sensitive_field_name(lowered: str) -> bool:
    return lowered in _SENSITIVE_FIELD_NAMES or any(
        marker in lowered for marker in _SENSITIVE_KEY_MARKERS
    )
