"""Offline DPAPI provider boundary.

The current runtime does not ship an offline DPAPI implementation. This adapter keeps the
boundary explicit so callers get a structured capability result instead of a fake empty decrypt.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import importlib.util
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from apex_forensic.adapters.artifacts.browser import decrypt_chromium_aes_gcm_secret
from apex_forensic.constants import ENGINE_VERSION
from apex_forensic.domain.errors import DecryptionError
from apex_forensic.domain.models import (
    DecryptionAttempt,
    DecryptionResult,
    SecretDerivationInput,
    SecretMaterial,
    SecretProviderCapability,
)

CHROMIUM_AES_GCM_SECRET_ALGORITHM = "CHROMIUM_AES_GCM_SECRET"
MAX_LOCAL_STATE_BYTES = 4 * 1024 * 1024


class DpapiUnavailableProvider:
    """Structured unavailable boundary for offline DPAPI operations."""

    provider_id = "apex.dpapi.offline"
    provider_version = ENGINE_VERSION

    def __init__(
        self,
        *,
        dependency_candidates: tuple[str, ...] = (
            "dpapick",
            "impacket.dpapi",
            "pypykatz.dpapi",
        ),
    ) -> None:
        self._dependency_candidates = dependency_candidates

    def capabilities(self) -> SecretProviderCapability:
        missing = [
            name for name in self._dependency_candidates if not _dependency_available(name)
        ]
        return SecretProviderCapability(
            provider_id=self.provider_id,
            provider_version=self.provider_version,
            capability_type="DPAPI_PROVIDER",
            runtime_status="CAPABILITY_UNAVAILABLE",
            supported_key_sources=[
                "WINDOWS_USER_PASSWORD",
                "WINDOWS_DOMAIN_BACKUP_KEY",
                "WINDOWS_SYSTEM_LSA_SECRETS",
            ],
            supported_algorithms=["DPAPI_BLOB", "CHROMIUM_LOCAL_STATE_DPAPI_KEY"],
            requires_host=False,
            requires_network=False,
            generated_at=datetime.now(UTC),
            warnings=[
                {
                    "code": "CAPABILITY_UNAVAILABLE",
                    "developer_message": (
                        "Offline DPAPI backend dependencies are not installed or configured."
                    ),
                    "details": {
                        "missing_dependency_candidates": missing,
                        "live_user_context_used": False,
                    },
                }
            ],
        )

    def discover_profiles(
        self,
        *,
        case_id: str,
        evidence_id: str,
        root_path: str,
    ) -> list[dict[str, Any]]:
        return [
            {
                "case_id": case_id,
                "evidence_id": evidence_id,
                "root_path": root_path,
                "status": "CAPABILITY_UNAVAILABLE",
                "reason": "OFFLINE_DPAPI_BACKEND_UNAVAILABLE",
                "profiles": [],
            }
        ]

    def resolve_master_key(
        self,
        derivation_input: SecretDerivationInput,
        *,
        sid: str,
        masterkey_guid: str,
        cancellation_requested: bool = False,
    ) -> SecretMaterial:
        del cancellation_requested
        derivation_input.assert_references_same_case()
        raise DecryptionError(
            "CAPABILITY_UNAVAILABLE",
            "Offline DPAPI master key resolution is not available in this runtime.",
            target="dpapi",
            details={
                "provider_id": self.provider_id,
                "sid_present": bool(sid),
                "masterkey_guid_present": bool(masterkey_guid),
            },
        )

    def inspect_chromium_local_state(
        self,
        *,
        case_id: str,
        evidence_id: str | None,
        local_state_path: str,
        source_revision: int | None = None,
    ) -> dict[str, Any]:
        return inspect_chromium_local_state_file(
            case_id=case_id,
            evidence_id=evidence_id,
            local_state_path=local_state_path,
            provider_id=self.provider_id,
            source_revision=source_revision,
        )

    def decrypt_blob(
        self,
        derivation_input: SecretDerivationInput,
        blob: bytes,
        *,
        cancellation_requested: bool = False,
    ) -> DecryptionResult:
        del cancellation_requested
        derivation_input.assert_references_same_case()
        now = datetime.now(UTC)
        return DecryptionResult(
            attempt=DecryptionAttempt(
                attempt_id=f"dpapi-{uuid4()}",
                case_id=derivation_input.case_id,
                evidence_id=derivation_input.evidence_id,
                provider_id=self.provider_id,
                provider_version=self.provider_version,
                algorithm="DPAPI_BLOB",
                key_source_kind=derivation_input.key_source_kind,
                status="CAPABILITY_UNAVAILABLE",
                started_at=now,
                completed_at=now,
                warnings=[
                    {
                        "code": "CAPABILITY_UNAVAILABLE",
                        "developer_message": (
                            "Offline DPAPI blob decryption requires an installed backend and "
                            "explicit offline key material."
                        ),
                    }
                ],
                error_code="OFFLINE_DPAPI_BACKEND_UNAVAILABLE",
                error_message="Offline DPAPI backend unavailable.",
            ),
            status="CAPABILITY_UNAVAILABLE",
            output_kind="DPAPI_PLAINTEXT",
            content_length=None,
            metadata={
                "ciphertext_length": len(blob),
                "ciphertext_emitted": False,
                "live_user_context_used": False,
                "success_without_key": False,
            },
            partial=False,
        )

    def decrypt_chromium_secret(
        self,
        derivation_input: SecretDerivationInput,
        encrypted_value: bytes,
        key_material: SecretMaterial,
        *,
        include_plaintext: bool = False,
        cancellation_requested: bool = False,
    ) -> DecryptionResult:
        del key_material, include_plaintext, cancellation_requested
        derivation_input.assert_references_same_case()
        now = datetime.now(UTC)
        return DecryptionResult(
            attempt=DecryptionAttempt(
                attempt_id=f"dpapi-chromium-{uuid4()}",
                case_id=derivation_input.case_id,
                evidence_id=derivation_input.evidence_id,
                provider_id=self.provider_id,
                provider_version=self.provider_version,
                algorithm=CHROMIUM_AES_GCM_SECRET_ALGORITHM,
                key_source_kind=derivation_input.key_source_kind,
                status="CAPABILITY_UNAVAILABLE",
                started_at=now,
                completed_at=now,
                warnings=[
                    {
                        "code": "CAPABILITY_UNAVAILABLE",
                        "developer_message": (
                            "Chromium secret decryption requires the external-key DPAPI "
                            "adapter and explicit offline key material."
                        ),
                    }
                ],
                error_code="OFFLINE_DPAPI_BACKEND_UNAVAILABLE",
                error_message="Offline DPAPI backend unavailable.",
            ),
            status="CAPABILITY_UNAVAILABLE",
            output_kind="CHROMIUM_SECRET",
            content_length=None,
            metadata={
                "ciphertext_length": len(encrypted_value),
                "ciphertext_emitted": False,
                "plaintext_emitted": False,
                "live_user_context_used": False,
                "success_without_key": False,
            },
            partial=False,
        )


class DpapiExternalKeyProvider:
    """DPAPI-adjacent runtime for Chromium secrets when a key is explicitly supplied."""

    provider_id = "apex.dpapi.external-key"
    provider_version = ENGINE_VERSION

    def capabilities(self) -> SecretProviderCapability:
        available = _dependency_available("cryptography.hazmat.primitives.ciphers.aead")
        return SecretProviderCapability(
            provider_id=self.provider_id,
            provider_version=self.provider_version,
            capability_type="DPAPI_PROVIDER",
            runtime_status="AVAILABLE_WITH_EXTERNAL_KEY"
            if available
            else "CAPABILITY_UNAVAILABLE",
            supported_key_sources=[
                "EXTERNAL_KEY",
                "EXTERNAL_OFFLINE_KEY_MATERIAL",
                "CHROMIUM_LOCAL_STATE_UNPROTECTED_KEY",
            ],
            supported_algorithms=[CHROMIUM_AES_GCM_SECRET_ALGORITHM],
            requires_host=False,
            requires_network=False,
            generated_at=datetime.now(UTC),
            warnings=[]
            if available
            else [
                {
                    "code": "CAPABILITY_UNAVAILABLE",
                    "developer_message": (
                        "Chromium AES-GCM secret decryption requires the cryptography package."
                    ),
                    "details": {"missing_dependency_candidates": ["cryptography"]},
                }
            ],
        )

    def inspect_chromium_local_state(
        self,
        *,
        case_id: str,
        evidence_id: str | None,
        local_state_path: str,
        source_revision: int | None = None,
    ) -> dict[str, Any]:
        return inspect_chromium_local_state_file(
            case_id=case_id,
            evidence_id=evidence_id,
            local_state_path=local_state_path,
            provider_id=self.provider_id,
            source_revision=source_revision,
        )

    def decrypt_chromium_secret(
        self,
        derivation_input: SecretDerivationInput,
        encrypted_value: bytes,
        key_material: SecretMaterial,
        *,
        include_plaintext: bool = False,
        cancellation_requested: bool = False,
    ) -> DecryptionResult:
        del cancellation_requested
        derivation_input.assert_references_same_case()
        key_material.reference.assert_case(derivation_input.case_id)
        now = datetime.now(UTC)
        if len(key_material.value) not in {16, 24, 32}:
            return self._result(
                derivation_input,
                now=now,
                status="INVALID_KEY",
                error_code="INVALID_KEY",
                error_message="Invalid Chromium AES-GCM key length.",
                output_kind="CHROMIUM_SECRET",
                metadata={
                    "ciphertext_length": len(encrypted_value),
                    "key_length": len(key_material.value),
                    "key_source": key_material.redacted.to_schema_dict(),
                    "plaintext_emitted": False,
                },
                warnings=[
                    {
                        "code": "INVALID_KEY",
                        "developer_message": "Chromium AES-GCM key length must be 16, 24, or 32.",
                    }
                ],
            )
        decrypted = decrypt_chromium_aes_gcm_secret(
            encrypted_value,
            key=key_material.value,
            key_provider_id=key_material.reference.provider_id,
            key_provider_version=self.provider_version,
            include_plaintext=include_plaintext,
        )
        status = _dpapi_chromium_status(str(decrypted["status"]))
        plaintext = decrypted.get("plaintext")
        plaintext_bytes = plaintext if isinstance(plaintext, bytes) else None
        content_sha256 = decrypted.get("plaintext_sha256")
        content_length = decrypted.get("plaintext_length")
        warnings = []
        if status == "DECRYPTED" and not include_plaintext:
            warnings.append(
                {
                    "code": "PLAINTEXT_REDACTED",
                    "developer_message": "Chromium secret plaintext was decrypted and redacted.",
                }
            )
        elif status != "DECRYPTED":
            warnings.append(
                {
                    "code": status,
                    "developer_message": "Chromium secret decryption did not complete.",
                    "failure_reason": str(decrypted.get("failure_reason") or "UNKNOWN"),
                }
            )
        return self._result(
            derivation_input,
            now=now,
            status=status,
            error_code=None if status == "DECRYPTED" else str(decrypted.get("failure_reason")),
            error_message=None if status == "DECRYPTED" else "Chromium secret decryption failed.",
            output_kind="CHROMIUM_SECRET",
            plaintext=plaintext_bytes,
            content_sha256=str(content_sha256) if content_sha256 is not None else None,
            content_length=int(content_length) if content_length is not None else None,
            citations=_chromium_secret_citations(derivation_input),
            metadata={
                "ciphertext_length": len(encrypted_value),
                "secret_format": _chromium_secret_format(encrypted_value),
                "key_source": key_material.redacted.to_schema_dict(),
                "key_reference": key_material.reference.to_schema_dict(),
                "plaintext_emitted": bool(decrypted.get("plaintext_emitted")),
                "failure_reason": decrypted.get("failure_reason"),
                "live_user_context_used": False,
                "success_without_key": False,
            },
            warnings=warnings,
        )

    def _result(
        self,
        derivation_input: SecretDerivationInput,
        *,
        now: datetime,
        status: str,
        output_kind: str,
        error_code: str | None,
        error_message: str | None,
        plaintext: bytes | None = None,
        content_sha256: str | None = None,
        content_length: int | None = None,
        citations: list[dict[str, Any]] | None = None,
        metadata: dict[str, Any] | None = None,
        warnings: list[dict[str, Any]] | None = None,
    ) -> DecryptionResult:
        return DecryptionResult(
            attempt=DecryptionAttempt(
                attempt_id=f"dpapi-chromium-{uuid4()}",
                case_id=derivation_input.case_id,
                evidence_id=derivation_input.evidence_id,
                provider_id=self.provider_id,
                provider_version=self.provider_version,
                algorithm=CHROMIUM_AES_GCM_SECRET_ALGORITHM,
                key_source_kind=derivation_input.key_source_kind,
                status=status,
                started_at=now,
                completed_at=now,
                warnings=warnings or [],
                error_code=error_code,
                error_message=error_message,
            ),
            status=status,
            plaintext=plaintext,
            output_kind=output_kind,
            content_sha256=content_sha256,
            content_length=content_length,
            citations=citations or [],
            partial=False,
            metadata=metadata or {},
        )


def inspect_chromium_local_state_file(
    *,
    case_id: str,
    evidence_id: str | None,
    local_state_path: str,
    provider_id: str,
    source_revision: int | None = None,
) -> dict[str, Any]:
    created_at = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    path = Path(local_state_path)
    raw_locator: dict[str, Any] = {
        "source_path": str(path),
        "secret_value_emitted": False,
    }
    base: dict[str, Any] = {
        "schema_version": "1.0.0",
        "case_id": case_id,
        "evidence_id": evidence_id,
        "provider_id": provider_id,
        "source_kind": "BROWSER_LOCAL_STATE",
        "scope": "UNKNOWN",
        "sid": None,
        "masterkey_guid": None,
        "source_path": str(path),
        "source_revision": source_revision,
        "fingerprint": None,
        "raw_locator": raw_locator,
        "status": "KEY_UNAVAILABLE",
        "warnings": [],
        "created_at": created_at,
    }
    if not path.is_file():
        return base | {
            "status": "KEY_UNAVAILABLE",
            "warnings": [
                {
                    "code": "KEY_UNAVAILABLE",
                    "developer_message": "Chromium Local State file is unavailable.",
                }
            ],
        }
    size = path.stat().st_size
    if size > MAX_LOCAL_STATE_BYTES:
        return base | {
            "status": "CORRUPT_KEY_MATERIAL",
            "raw_locator": raw_locator | {"size_bytes": size},
            "warnings": [
                {
                    "code": "INPUT_TOO_LARGE",
                    "developer_message": "Chromium Local State file exceeds the size limit.",
                    "max_bytes": MAX_LOCAL_STATE_BYTES,
                }
            ],
        }
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return base | {
            "status": "CORRUPT_KEY_MATERIAL",
            "raw_locator": raw_locator | {"size_bytes": size},
            "warnings": [
                {
                    "code": "CORRUPT_KEY_MATERIAL",
                    "developer_message": "Chromium Local State JSON could not be parsed.",
                }
            ],
        }
    os_crypt = payload.get("os_crypt") if isinstance(payload, dict) else None
    if not isinstance(os_crypt, dict):
        return base | {
            "status": "KEY_UNAVAILABLE",
            "raw_locator": raw_locator | {"json_pointer": "/os_crypt"},
            "warnings": [
                {
                    "code": "KEY_UNAVAILABLE",
                    "developer_message": "Chromium Local State does not contain os_crypt data.",
                }
            ],
        }
    app_bound = os_crypt.get("app_bound_encrypted_key")
    if isinstance(app_bound, str) and app_bound:
        return base | {
            "status": "UNSUPPORTED_VERSION",
            "raw_locator": raw_locator
            | {
                "json_pointer": "/os_crypt/app_bound_encrypted_key",
                "app_bound_key_present": True,
                "encrypted_key_emitted": False,
            },
            "warnings": [
                {
                    "code": "UNSUPPORTED_VERSION",
                    "developer_message": (
                        "Chromium app-bound encrypted key is not supported by this runtime."
                    ),
                }
            ],
        }
    encrypted_key = os_crypt.get("encrypted_key")
    if not isinstance(encrypted_key, str) or not encrypted_key:
        return base | {
            "status": "KEY_UNAVAILABLE",
            "raw_locator": raw_locator | {"json_pointer": "/os_crypt/encrypted_key"},
            "warnings": [
                {
                    "code": "KEY_UNAVAILABLE",
                    "developer_message": "Chromium Local State encrypted_key is missing.",
                }
            ],
        }
    try:
        decoded = base64.b64decode(encrypted_key.encode("ascii"), validate=True)
    except (UnicodeEncodeError, binascii.Error):
        return base | {
            "status": "CORRUPT_KEY_MATERIAL",
            "raw_locator": raw_locator | {"json_pointer": "/os_crypt/encrypted_key"},
            "warnings": [
                {
                    "code": "CORRUPT_KEY_MATERIAL",
                    "developer_message": "Chromium Local State encrypted_key is not valid base64.",
                }
            ],
        }
    dpapi_prefix_present = decoded.startswith(b"DPAPI")
    protected = decoded[5:] if dpapi_prefix_present else decoded
    digest = hashlib.sha256(protected).hexdigest() if protected else None
    status = "KEY_UNAVAILABLE" if dpapi_prefix_present else "UNSUPPORTED_VERSION"
    warning_code = status
    warning_message = (
        "Chromium Local State DPAPI key was found; offline unwrap requires DPAPI key material."
        if dpapi_prefix_present
        else "Chromium Local State key format is not a Windows DPAPI encrypted key."
    )
    return base | {
        "source_kind": "CHROMIUM_LOCAL_STATE_DPAPI_KEY",
        "fingerprint": digest,
        "status": status,
        "raw_locator": raw_locator
        | {
            "json_pointer": "/os_crypt/encrypted_key",
            "encrypted_key_length": len(decoded),
            "protected_key_length": len(protected),
            "dpapi_prefix_present": dpapi_prefix_present,
            "encrypted_key_emitted": False,
        },
        "warnings": [
            {
                "code": warning_code,
                "developer_message": warning_message,
            }
        ],
    }


def _dpapi_chromium_status(status: str) -> str:
    if status == "DECRYPTED":
        return "DECRYPTED"
    if status == "KEY_UNAVAILABLE":
        return "KEY_UNAVAILABLE"
    if status == "CAPABILITY_UNAVAILABLE":
        return "CAPABILITY_UNAVAILABLE"
    if status == "UNSUPPORTED_SECRET_FORMAT":
        return "UNSUPPORTED_ALGORITHM"
    if status == "DECRYPTION_FAILED":
        return "AUTHENTICATION_FAILED"
    return "FAILED"


def _chromium_secret_format(value: bytes) -> str:
    if value.startswith((b"v10", b"v11", b"v20")):
        return value[:3].decode("ascii", errors="replace").upper()
    return "UNKNOWN_OR_LEGACY"


def _chromium_secret_citations(
    derivation_input: SecretDerivationInput,
) -> list[dict[str, Any]]:
    citation = derivation_input.parameters.get("citation")
    if isinstance(citation, dict):
        return [citation]
    return [
        {
            "case_id": derivation_input.case_id,
            "evidence_id": derivation_input.evidence_id,
            "source_kind": "CHROMIUM_SECRET",
            "source_id": derivation_input.parameters.get("source_id", "external-key-runtime"),
        }
    ]


def _dependency_available(module_name: str) -> bool:
    try:
        return importlib.util.find_spec(module_name) is not None
    except (ImportError, ModuleNotFoundError, ValueError):
        return False
