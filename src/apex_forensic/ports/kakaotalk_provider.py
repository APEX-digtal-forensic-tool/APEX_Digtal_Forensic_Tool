"""KakaoTalk encrypted store runtime port."""

from __future__ import annotations

from typing import Protocol

from apex_forensic.domain.models import (
    DecryptionResult,
    SecretDerivationInput,
    SecretProviderCapability,
)


class KakaoTalkProviderPort(Protocol):
    """Boundary for offline KakaoTalk encrypted store inspection and decryption."""

    @property
    def provider_id(self) -> str: ...

    @property
    def provider_version(self) -> str: ...

    def capabilities(self) -> SecretProviderCapability: ...

    def inspect_store(
        self,
        *,
        case_id: str,
        evidence_id: str | None,
        store_path: str,
        profile_root: str | None = None,
    ) -> dict[str, object]: ...

    def acquire_key_material(
        self,
        *,
        case_id: str,
        evidence_id: str | None,
        profile_root: str | None = None,
        platform: str = "WINDOWS_DESKTOP",
    ) -> dict[str, object]: ...

    def decrypt_store(
        self,
        derivation_input: SecretDerivationInput,
        *,
        store_path: str,
        profile_root: str | None = None,
        cancellation_requested: bool = False,
    ) -> DecryptionResult: ...
