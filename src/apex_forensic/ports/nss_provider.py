"""Firefox NSS runtime port."""

from __future__ import annotations

from typing import Any, Protocol

from apex_forensic.domain.models import (
    DecryptionResult,
    SecretDerivationInput,
    SecretProviderCapability,
)


class NssProviderPort(Protocol):
    """Boundary for offline Firefox key4.db/logins.json decryption."""

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

    def decrypt_logins(
        self,
        derivation_input: SecretDerivationInput,
        *,
        profile_path: str,
        primary_password: str | None = None,
        cancellation_requested: bool = False,
    ) -> list[DecryptionResult]: ...
