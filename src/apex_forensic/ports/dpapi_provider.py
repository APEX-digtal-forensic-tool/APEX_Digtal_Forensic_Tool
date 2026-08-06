"""Offline DPAPI runtime port."""

from __future__ import annotations

from typing import Any, Protocol

from apex_forensic.domain.models import (
    DecryptionResult,
    SecretDerivationInput,
    SecretMaterial,
    SecretProviderCapability,
)


class DpapiProviderPort(Protocol):
    """Boundary for offline DPAPI profile, master key, and blob operations."""

    @property
    def provider_id(self) -> str: ...

    @property
    def provider_version(self) -> str: ...

    def capabilities(self) -> SecretProviderCapability: ...

    def discover_profiles(
        self,
        *,
        case_id: str,
        evidence_id: str,
        root_path: str,
    ) -> list[dict[str, Any]]: ...

    def resolve_master_key(
        self,
        derivation_input: SecretDerivationInput,
        *,
        sid: str,
        masterkey_guid: str,
        cancellation_requested: bool = False,
    ) -> SecretMaterial: ...

    def inspect_chromium_local_state(
        self,
        *,
        case_id: str,
        evidence_id: str | None,
        local_state_path: str,
        source_revision: int | None = None,
    ) -> dict[str, Any]: ...

    def decrypt_blob(
        self,
        derivation_input: SecretDerivationInput,
        blob: bytes,
        *,
        cancellation_requested: bool = False,
    ) -> DecryptionResult: ...

    def decrypt_chromium_secret(
        self,
        derivation_input: SecretDerivationInput,
        encrypted_value: bytes,
        key_material: SecretMaterial,
        *,
        include_plaintext: bool = False,
        cancellation_requested: bool = False,
    ) -> DecryptionResult: ...
