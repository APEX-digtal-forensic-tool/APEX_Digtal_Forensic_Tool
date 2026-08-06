"""Offline DPAPI provider boundary.

The current runtime does not ship an offline DPAPI implementation. This adapter keeps the
boundary explicit so callers get a structured capability result instead of a fake empty decrypt.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import importlib
import importlib.util
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

from apex_forensic.adapters.artifacts.browser import decrypt_chromium_aes_gcm_secret
from apex_forensic.constants import ENGINE_VERSION
from apex_forensic.domain.errors import DecryptionError
from apex_forensic.domain.models import (
    DecryptionAttempt,
    DecryptionResult,
    SecretDerivationInput,
    SecretMaterial,
    SecretProviderCapability,
    SecretReference,
)

CHROMIUM_AES_GCM_SECRET_ALGORITHM = "CHROMIUM_AES_GCM_SECRET"
DPAPI_BLOB_ALGORITHM = "DPAPI_BLOB"
CHROMIUM_LOCAL_STATE_DPAPI_KEY_ALGORITHM = "CHROMIUM_LOCAL_STATE_DPAPI_KEY"
MAX_LOCAL_STATE_BYTES = 4 * 1024 * 1024
MAX_DPAPI_BLOB_BYTES = 64 * 1024 * 1024
MAX_DPAPI_MASTERKEY_BYTES = 2 * 1024 * 1024


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


class DpapiOfflineProvider:
    """Offline DPAPI runtime backed by impacket when the optional dependency is installed."""

    provider_id = "apex.dpapi.offline"
    provider_version = ENGINE_VERSION

    def __init__(
        self,
        *,
        dependency_candidates: tuple[str, ...] = ("impacket.dpapi",),
    ) -> None:
        self._dependency_candidates = dependency_candidates

    def capabilities(self) -> SecretProviderCapability:
        missing = [
            name for name in self._dependency_candidates if not _dependency_available(name)
        ]
        available = not missing
        return SecretProviderCapability(
            provider_id=self.provider_id,
            provider_version=self.provider_version,
            capability_type="DPAPI_PROVIDER",
            runtime_status="IMPLEMENTED_RUNTIME" if available else "CAPABILITY_UNAVAILABLE",
            supported_key_sources=[
                "WINDOWS_USER_PASSWORD",
                "WINDOWS_NT_HASH",
                "EXTERNAL_MASTERKEY",
                "BROWSER_LOCAL_STATE",
            ],
            supported_algorithms=[
                "DPAPI_MASTERKEY",
                DPAPI_BLOB_ALGORITHM,
                CHROMIUM_LOCAL_STATE_DPAPI_KEY_ALGORITHM,
                CHROMIUM_AES_GCM_SECRET_ALGORITHM,
            ],
            requires_host=False,
            requires_network=False,
            generated_at=datetime.now(UTC),
            warnings=[]
            if available
            else [
                {
                    "code": "CAPABILITY_UNAVAILABLE",
                    "developer_message": (
                        "Offline DPAPI runtime requires the impacket optional dependency."
                    ),
                    "details": {"missing_dependency_candidates": missing},
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
        if _load_impacket_dpapi() is None:
            return DpapiUnavailableProvider(
                dependency_candidates=self._dependency_candidates
            ).discover_profiles(
                case_id=case_id,
                evidence_id=evidence_id,
                root_path=root_path,
            )
        root = Path(root_path)
        if not root.exists():
            return [
                {
                    "case_id": case_id,
                    "evidence_id": evidence_id,
                    "root_path": str(root),
                    "status": "KEY_UNAVAILABLE",
                    "reason": "DPAPI_PROFILE_ROOT_MISSING",
                    "profiles": [],
                }
            ]
        profiles: list[dict[str, Any]] = []
        for path in sorted(root.rglob("*")):
            if len(profiles) >= 10_000:
                profiles.append(
                    {
                        "case_id": case_id,
                        "evidence_id": evidence_id,
                        "root_path": str(root),
                        "status": "PARTIAL",
                        "reason": "DPAPI_PROFILE_DISCOVERY_LIMIT_REACHED",
                        "profiles_scanned": len(profiles),
                    }
                )
                break
            if not _looks_like_masterkey_file(path):
                continue
            profiles.append(
                self._inspect_masterkey_file(
                    case_id=case_id,
                    evidence_id=evidence_id,
                    masterkey_path=path,
                )
            )
        return profiles

    def resolve_master_key(
        self,
        derivation_input: SecretDerivationInput,
        *,
        sid: str,
        masterkey_guid: str,
        cancellation_requested: bool = False,
    ) -> SecretMaterial:
        if cancellation_requested:
            raise DecryptionError(
                "OPERATION_CANCELLED",
                "Offline DPAPI master key resolution was cancelled.",
                target="dpapi",
            )
        derivation_input.assert_references_same_case()
        dpapi = _require_impacket_dpapi()
        external_masterkey = _secret_parameter_bytes(
            derivation_input.parameters,
            b64_name="masterkey_b64",
            hex_name="masterkey_hex",
            bytes_name="masterkey",
        )
        if external_masterkey is not None:
            if len(external_masterkey) != 64:
                raise DecryptionError(
                    "INVALID_KEY",
                    "External DPAPI master key must be 64 bytes.",
                    target="masterkey",
                    details={"key_length": len(external_masterkey), "secret_value_emitted": False},
                )
            return self._secret_material(
                derivation_input,
                value=external_masterkey,
                secret_id=f"dpapi-masterkey-{_normalize_guid(masterkey_guid) or 'external'}",
                source_kind="EXTERNAL_MASTERKEY",
                sid=sid or None,
                masterkey_guid=masterkey_guid or None,
                source_path=None,
                algorithm="DPAPI_MASTERKEY",
            )

        masterkey_path = _string_parameter(derivation_input.parameters, "masterkey_path")
        if masterkey_path is None:
            raise DecryptionError(
                "KEY_UNAVAILABLE",
                "Offline DPAPI master key file path was not supplied.",
                target="masterkey_path",
                details={"sid_present": bool(sid), "masterkey_guid_present": bool(masterkey_guid)},
            )
        parsed = _parse_masterkey_file(Path(masterkey_path), dpapi=dpapi)
        parsed_guid = parsed["masterkey_guid"]
        expected_guid = _normalize_guid(masterkey_guid)
        if expected_guid and parsed_guid and expected_guid != parsed_guid:
            raise DecryptionError(
                "SOURCE_MISMATCH",
                "DPAPI master key GUID does not match the protected blob.",
                target="masterkey_guid",
                details={
                    "expected_masterkey_guid": expected_guid,
                    "actual_masterkey_guid": parsed_guid,
                },
            )
        if not sid:
            raise DecryptionError(
                "KEY_UNAVAILABLE",
                "Offline DPAPI user SID is required for password or NT hash derivation.",
                target="sid",
            )
        candidates = _dpapi_user_key_candidates(
            dpapi,
            sid=sid,
            parameters=derivation_input.parameters,
        )
        if not candidates:
            raise DecryptionError(
                "KEY_UNAVAILABLE",
                "Password, NT hash, or external master key material was not supplied.",
                target="key_source",
                details={"secret_value_emitted": False},
            )

        masterkey = parsed["masterkey"]
        for candidate in candidates:
            decrypted = masterkey.decrypt(candidate["key"])
            if decrypted:
                return self._secret_material(
                    derivation_input,
                    value=decrypted,
                    secret_id=f"dpapi-masterkey-{parsed_guid or uuid4()}",
                    source_kind=candidate["source_kind"],
                    sid=sid,
                    masterkey_guid=parsed_guid,
                    source_path=str(masterkey_path),
                    algorithm="DPAPI_MASTERKEY",
                    raw_locator={
                        "masterkey_path": str(masterkey_path),
                        "candidate_kind": candidate["source_kind"],
                        "candidate_index": candidate["index"],
                        "secret_value_emitted": False,
                    },
                )
        raise DecryptionError(
            "AUTHENTICATION_FAILED",
            "DPAPI master key could not be decrypted with the supplied offline credential.",
            target="key_source",
            details={
                "candidate_count": len(candidates),
                "masterkey_guid": parsed_guid,
                "secret_value_emitted": False,
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
        derivation_input.assert_references_same_case()
        now = datetime.now(UTC)
        if cancellation_requested:
            return self._result(
                derivation_input,
                now=now,
                algorithm=DPAPI_BLOB_ALGORITHM,
                status="OPERATION_CANCELLED",
                output_kind="DPAPI_PLAINTEXT",
                error_code="OPERATION_CANCELLED",
                error_message="Offline DPAPI blob decryption was cancelled.",
                metadata={"plaintext_emitted": False},
            )
        dpapi = _load_impacket_dpapi()
        if dpapi is None:
            return DpapiUnavailableProvider(
                dependency_candidates=self._dependency_candidates
            ).decrypt_blob(derivation_input, blob)
        if len(blob) > MAX_DPAPI_BLOB_BYTES:
            return self._result(
                derivation_input,
                now=now,
                algorithm=DPAPI_BLOB_ALGORITHM,
                status="FAILED",
                output_kind="DPAPI_PLAINTEXT",
                error_code="INPUT_TOO_LARGE",
                error_message="DPAPI blob exceeds the size limit.",
                metadata={
                    "ciphertext_length": len(blob),
                    "max_bytes": MAX_DPAPI_BLOB_BYTES,
                    "ciphertext_emitted": False,
                    "plaintext_emitted": False,
                },
                warnings=[
                    {
                        "code": "INPUT_TOO_LARGE",
                        "developer_message": "DPAPI blob exceeds the configured size limit.",
                    }
                ],
            )
        try:
            dpapi_blob = dpapi.DPAPI_BLOB(blob)
            masterkey_guid = str(UUID(bytes_le=dpapi_blob["GuidMasterKey"]))
            flags = int(dpapi_blob["Flags"])
        except Exception:
            return self._result(
                derivation_input,
                now=now,
                algorithm=DPAPI_BLOB_ALGORITHM,
                status="CORRUPT_KEY_MATERIAL",
                output_kind="DPAPI_PLAINTEXT",
                error_code="CORRUPT_DPAPI_BLOB",
                error_message="DPAPI blob could not be parsed.",
                metadata={
                    "ciphertext_length": len(blob),
                    "ciphertext_sha256": _sha256(blob),
                    "ciphertext_emitted": False,
                    "plaintext_emitted": False,
                },
            )
        sid = _string_parameter(derivation_input.parameters, "sid") or ""
        try:
            key_material = self.resolve_master_key(
                derivation_input,
                sid=sid,
                masterkey_guid=masterkey_guid,
            )
        except DecryptionError as error:
            return self._result_from_error(
                derivation_input,
                now=now,
                algorithm=DPAPI_BLOB_ALGORITHM,
                output_kind="DPAPI_PLAINTEXT",
                error=error,
                metadata={
                    "ciphertext_length": len(blob),
                    "ciphertext_sha256": _sha256(blob),
                    "ciphertext_emitted": False,
                    "plaintext_emitted": False,
                    "masterkey_guid": masterkey_guid,
                    "scope": _dpapi_blob_scope(flags),
                    "live_user_context_used": False,
                },
            )

        entropy = _secret_parameter_bytes(
            derivation_input.parameters,
            b64_name="entropy_b64",
            hex_name="entropy_hex",
            bytes_name="entropy",
        )
        try:
            plaintext = dpapi_blob.decrypt(key_material.value, entropy=entropy)
        except Exception:
            plaintext = None
        if plaintext is None:
            return self._result(
                derivation_input,
                now=now,
                algorithm=DPAPI_BLOB_ALGORITHM,
                status="AUTHENTICATION_FAILED",
                output_kind="DPAPI_PLAINTEXT",
                error_code="DPAPI_BLOB_AUTHENTICATION_FAILED",
                error_message="DPAPI blob authentication failed.",
                metadata={
                    "ciphertext_length": len(blob),
                    "ciphertext_sha256": _sha256(blob),
                    "ciphertext_emitted": False,
                    "plaintext_emitted": False,
                    "masterkey_guid": masterkey_guid,
                    "scope": _dpapi_blob_scope(flags),
                    "key_source": key_material.redacted.to_schema_dict(),
                    "live_user_context_used": False,
                },
            )
        return self._result(
            derivation_input,
            now=now,
            algorithm=DPAPI_BLOB_ALGORITHM,
            status="DECRYPTED",
            output_kind="DPAPI_PLAINTEXT",
            error_code=None,
            error_message=None,
            plaintext=plaintext,
            citations=_dpapi_citations(derivation_input, source_kind="DPAPI_BLOB"),
            metadata={
                "ciphertext_length": len(blob),
                "ciphertext_sha256": _sha256(blob),
                "ciphertext_emitted": False,
                "plaintext_emitted": False,
                "masterkey_guid": masterkey_guid,
                "scope": _dpapi_blob_scope(flags),
                "key_source": key_material.redacted.to_schema_dict(),
                "key_reference": key_material.reference.to_schema_dict(),
                "live_user_context_used": False,
            },
            warnings=[
                {
                    "code": "PLAINTEXT_REDACTED",
                    "developer_message": "DPAPI plaintext was decrypted and redacted.",
                }
            ],
        )

    def decrypt_chromium_local_state_key(
        self,
        derivation_input: SecretDerivationInput,
        *,
        local_state_path: str,
        source_revision: int | None = None,
        cancellation_requested: bool = False,
    ) -> DecryptionResult:
        inspection = self.inspect_chromium_local_state(
            case_id=derivation_input.case_id,
            evidence_id=derivation_input.evidence_id,
            local_state_path=local_state_path,
            source_revision=source_revision,
        )
        now = datetime.now(UTC)
        protected_key = _read_chromium_local_state_protected_key(local_state_path)
        if not isinstance(protected_key, bytes):
            status = str(protected_key["status"])
            return self._result(
                derivation_input,
                now=now,
                algorithm=CHROMIUM_LOCAL_STATE_DPAPI_KEY_ALGORITHM,
                status=status,
                output_kind="CHROMIUM_LOCAL_STATE_KEY",
                error_code=status,
                error_message="Chromium Local State DPAPI key could not be read.",
                metadata={
                    "local_state": inspection,
                    "plaintext_emitted": False,
                    "live_user_context_used": False,
                },
                warnings=protected_key.get("warnings", []),
            )
        decrypt_result = self.decrypt_blob(
            derivation_input,
            protected_key,
            cancellation_requested=cancellation_requested,
        )
        return DecryptionResult(
            attempt=DecryptionAttempt(
                attempt_id=f"dpapi-local-state-{uuid4()}",
                case_id=derivation_input.case_id,
                evidence_id=derivation_input.evidence_id,
                provider_id=self.provider_id,
                provider_version=self.provider_version,
                algorithm=CHROMIUM_LOCAL_STATE_DPAPI_KEY_ALGORITHM,
                key_source_kind=derivation_input.key_source_kind,
                status=decrypt_result.status,
                started_at=decrypt_result.attempt.started_at,
                completed_at=datetime.now(UTC),
                warnings=decrypt_result.attempt.warnings,
                error_code=decrypt_result.attempt.error_code,
                error_message=decrypt_result.attempt.error_message,
            ),
            status=decrypt_result.status,
            plaintext=decrypt_result.plaintext,
            output_kind="CHROMIUM_LOCAL_STATE_KEY",
            content_sha256=decrypt_result.content_sha256,
            content_length=decrypt_result.content_length,
            citations=[
                {
                    "case_id": derivation_input.case_id,
                    "evidence_id": derivation_input.evidence_id,
                    "source_kind": "BROWSER_LOCAL_STATE",
                    "source_path": local_state_path,
                    "source_revision": source_revision,
                    "raw_locator": {"json_pointer": "/os_crypt/encrypted_key"},
                }
            ],
            partial=False,
            metadata={
                "local_state": inspection,
                "dpapi_blob": decrypt_result.metadata,
                "plaintext_emitted": False,
                "live_user_context_used": False,
            },
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
        return DpapiExternalKeyProvider().decrypt_chromium_secret(
            derivation_input,
            encrypted_value,
            key_material,
            include_plaintext=include_plaintext,
            cancellation_requested=cancellation_requested,
        )

    def _inspect_masterkey_file(
        self,
        *,
        case_id: str,
        evidence_id: str,
        masterkey_path: Path,
    ) -> dict[str, Any]:
        created_at = datetime.now(UTC).isoformat().replace("+00:00", "Z")
        sid = _sid_from_masterkey_path(masterkey_path)
        raw_locator: dict[str, Any] = {
            "source_path": str(masterkey_path),
            "secret_value_emitted": False,
        }
        base: dict[str, Any] = {
            "schema_version": "1.0.0",
            "case_id": case_id,
            "evidence_id": evidence_id,
            "provider_id": self.provider_id,
            "source_kind": "EXTERNAL_MASTERKEY",
            "scope": "USER" if sid else "UNKNOWN",
            "sid": sid,
            "masterkey_guid": _normalize_guid(masterkey_path.name),
            "source_path": str(masterkey_path),
            "source_revision": None,
            "fingerprint": None,
            "raw_locator": raw_locator,
            "status": "KEY_UNAVAILABLE",
            "warnings": [],
            "created_at": created_at,
        }
        try:
            parsed = _parse_masterkey_file(masterkey_path, dpapi=_require_impacket_dpapi())
        except DecryptionError as error:
            return base | {
                "status": error.code,
                "warnings": [
                    {
                        "code": error.code,
                        "developer_message": error.developer_message,
                    }
                ],
            }
        return base | {
            "masterkey_guid": parsed["masterkey_guid"],
            "fingerprint": parsed["fingerprint"],
            "raw_locator": raw_locator
            | {
                "masterkey_length": parsed["masterkey_length"],
                "version": parsed["version"],
            },
        }

    def _secret_material(
        self,
        derivation_input: SecretDerivationInput,
        *,
        value: bytes,
        secret_id: str,
        source_kind: str,
        sid: str | None,
        masterkey_guid: str | None,
        source_path: str | None,
        algorithm: str,
        raw_locator: dict[str, Any] | None = None,
    ) -> SecretMaterial:
        return SecretMaterial(
            reference=SecretReference(
                secret_id=secret_id,
                case_id=derivation_input.case_id,
                evidence_id=derivation_input.evidence_id,
                key_source_kind=derivation_input.key_source_kind,
                provider_id=self.provider_id,
                source_kind=source_kind,
                source_path=source_path,
                fingerprint=_sha256(value),
                raw_locator={
                    "sid": sid,
                    "masterkey_guid": masterkey_guid,
                    "secret_value_emitted": False,
                }
                | (raw_locator or {}),
                created_at=datetime.now(UTC),
            ),
            value=value,
            algorithm=algorithm,
            created_at=datetime.now(UTC),
        )

    def _result_from_error(
        self,
        derivation_input: SecretDerivationInput,
        *,
        now: datetime,
        algorithm: str,
        output_kind: str,
        error: DecryptionError,
        metadata: dict[str, Any],
    ) -> DecryptionResult:
        return self._result(
            derivation_input,
            now=now,
            algorithm=algorithm,
            status=error.code,
            output_kind=output_kind,
            error_code=error.code,
            error_message=error.developer_message,
            metadata=metadata,
            warnings=[
                {
                    "code": error.code,
                    "developer_message": error.developer_message,
                }
            ],
        )

    def _result(
        self,
        derivation_input: SecretDerivationInput,
        *,
        now: datetime,
        algorithm: str,
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
                attempt_id=f"dpapi-{uuid4()}",
                case_id=derivation_input.case_id,
                evidence_id=derivation_input.evidence_id,
                provider_id=self.provider_id,
                provider_version=self.provider_version,
                algorithm=algorithm,
                key_source_kind=derivation_input.key_source_kind,
                status=status,
                started_at=now,
                completed_at=datetime.now(UTC),
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


def _load_impacket_dpapi() -> Any | None:
    try:
        return importlib.import_module("impacket.dpapi")
    except (ImportError, ModuleNotFoundError, ValueError):
        return None


def _require_impacket_dpapi() -> Any:
    dpapi = _load_impacket_dpapi()
    if dpapi is None:
        raise DecryptionError(
            "CAPABILITY_UNAVAILABLE",
            "Offline DPAPI runtime requires the impacket optional dependency.",
            target="dependency",
            details={"missing_dependency_candidates": ["impacket.dpapi"]},
        )
    return dpapi


def _parse_masterkey_file(path: Path, *, dpapi: Any) -> dict[str, Any]:
    try:
        size = path.stat().st_size
    except OSError as error:
        raise DecryptionError(
            "KEY_UNAVAILABLE",
            "DPAPI master key file is unavailable.",
            target="masterkey_path",
        ) from error
    if size > MAX_DPAPI_MASTERKEY_BYTES:
        raise DecryptionError(
            "CORRUPT_KEY_MATERIAL",
            "DPAPI master key file exceeds the size limit.",
            target="masterkey_path",
            details={"max_bytes": MAX_DPAPI_MASTERKEY_BYTES},
        )
    try:
        data = path.read_bytes()
        masterkey_file = dpapi.MasterKeyFile(data)
        masterkey_length = int(masterkey_file["MasterKeyLen"])
        header_length = len(masterkey_file)
        masterkey_data = data[header_length : header_length + masterkey_length]
        if len(masterkey_data) != masterkey_length or masterkey_length <= 0:
            raise ValueError("invalid master key length")
        masterkey = dpapi.MasterKey(masterkey_data)
    except Exception as error:
        raise DecryptionError(
            "CORRUPT_KEY_MATERIAL",
            "DPAPI master key file could not be parsed.",
            target="masterkey_path",
        ) from error
    return {
        "version": int(masterkey_file["Version"]),
        "masterkey_guid": _normalize_guid(
            masterkey_file["Guid"].decode("utf-16le", errors="ignore")
        ),
        "masterkey_length": masterkey_length,
        "fingerprint": _sha256(masterkey_data),
        "masterkey": masterkey,
    }


def _dpapi_user_key_candidates(
    dpapi: Any,
    *,
    sid: str,
    parameters: dict[str, Any],
) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    password = _string_parameter(parameters, "password")
    if password is not None:
        for index, key in enumerate(dpapi.deriveKeysFromUser(sid, password)):
            candidates.append(
                {
                    "source_kind": "WINDOWS_USER_PASSWORD",
                    "index": index,
                    "key": key,
                }
            )
    nt_hash = _secret_parameter_bytes(
        parameters,
        b64_name="nt_hash_b64",
        hex_name="nt_hash_hex",
        bytes_name="nt_hash",
    )
    if nt_hash is not None:
        if len(nt_hash) not in {16, 20}:
            raise DecryptionError(
                "INVALID_KEY",
                "DPAPI NT hash input must be 16 bytes, or 20 bytes for SHA1 user keys.",
                target="nt_hash",
                details={"hash_length": len(nt_hash), "secret_value_emitted": False},
            )
        for index, key in enumerate(dpapi.deriveKeysFromUserkey(sid, nt_hash)):
            candidates.append(
                {
                    "source_kind": "WINDOWS_NT_HASH",
                    "index": index,
                    "key": key,
                }
            )
    return candidates


def _read_chromium_local_state_protected_key(local_state_path: str) -> bytes | dict[str, Any]:
    path = Path(local_state_path)
    try:
        if path.stat().st_size > MAX_LOCAL_STATE_BYTES:
            return {
                "status": "CORRUPT_KEY_MATERIAL",
                "warnings": [
                    {
                        "code": "INPUT_TOO_LARGE",
                        "developer_message": "Chromium Local State file exceeds the size limit.",
                    }
                ],
            }
        payload = json.loads(path.read_text(encoding="utf-8"))
        os_crypt = payload.get("os_crypt") if isinstance(payload, dict) else None
        encrypted_key = os_crypt.get("encrypted_key") if isinstance(os_crypt, dict) else None
        if not isinstance(encrypted_key, str) or not encrypted_key:
            return {
                "status": "KEY_UNAVAILABLE",
                "warnings": [
                    {
                        "code": "KEY_UNAVAILABLE",
                        "developer_message": "Chromium Local State encrypted_key is missing.",
                    }
                ],
            }
        decoded = base64.b64decode(encrypted_key.encode("ascii"), validate=True)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, UnicodeEncodeError, binascii.Error):
        return {
            "status": "CORRUPT_KEY_MATERIAL",
            "warnings": [
                {
                    "code": "CORRUPT_KEY_MATERIAL",
                    "developer_message": "Chromium Local State encrypted_key could not be parsed.",
                }
            ],
        }
    if not decoded.startswith(b"DPAPI"):
        return {
            "status": "UNSUPPORTED_VERSION",
            "warnings": [
                {
                    "code": "UNSUPPORTED_VERSION",
                    "developer_message": (
                        "Chromium Local State key format is not a Windows DPAPI encrypted key."
                    ),
                }
            ],
        }
    protected = decoded[5:]
    if not protected:
        return {
            "status": "CORRUPT_KEY_MATERIAL",
            "warnings": [
                {
                    "code": "CORRUPT_KEY_MATERIAL",
                    "developer_message": "Chromium Local State DPAPI payload is empty.",
                }
            ],
        }
    return protected


def _secret_parameter_bytes(
    parameters: dict[str, Any],
    *,
    b64_name: str,
    hex_name: str,
    bytes_name: str,
) -> bytes | None:
    raw_bytes = parameters.get(bytes_name)
    if isinstance(raw_bytes, bytes):
        return raw_bytes
    hex_value = _string_parameter(parameters, hex_name)
    if hex_value:
        try:
            return bytes.fromhex(hex_value.strip())
        except ValueError as error:
            raise DecryptionError(
                "INVALID_KEY",
                "Secret input is not valid hex.",
                target=hex_name,
                details={"secret_value_emitted": False},
            ) from error
    b64_value = _string_parameter(parameters, b64_name)
    if b64_value:
        try:
            return base64.b64decode(b64_value.encode("ascii"), validate=True)
        except (UnicodeEncodeError, binascii.Error) as error:
            raise DecryptionError(
                "INVALID_KEY",
                "Secret input is not valid base64.",
                target=b64_name,
                details={"secret_value_emitted": False},
            ) from error
    return None


def _string_parameter(parameters: dict[str, Any], name: str) -> str | None:
    value = parameters.get(name)
    if isinstance(value, str) and value:
        return value
    return None


def _looks_like_masterkey_file(path: Path) -> bool:
    if path.is_symlink() or not path.is_file():
        return False
    if path.name.casefold() in {"preferred", "credhist"}:
        return False
    return _normalize_guid(path.name) is not None


def _sid_from_masterkey_path(path: Path) -> str | None:
    parent = path.parent.name
    if parent.startswith("S-1-"):
        return parent
    return None


def _normalize_guid(value: str | None) -> str | None:
    if value is None:
        return None
    cleaned = value.strip().strip("\x00").strip("{}")
    if not cleaned:
        return None
    try:
        return str(UUID(cleaned))
    except ValueError:
        return None


def _dpapi_blob_scope(flags: int) -> str:
    if flags & 0x4:
        return "MACHINE"
    return "USER"


def _dpapi_citations(
    derivation_input: SecretDerivationInput,
    *,
    source_kind: str,
) -> list[dict[str, Any]]:
    citation = derivation_input.parameters.get("citation")
    if isinstance(citation, dict):
        return [citation]
    return [
        {
            "case_id": derivation_input.case_id,
            "evidence_id": derivation_input.evidence_id,
            "source_kind": source_kind,
            "source_id": derivation_input.parameters.get("source_id", "dpapi-runtime"),
        }
    ]


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


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
