"""Provider-neutral secret and decryption runtime ports."""

from __future__ import annotations

from typing import Protocol

from apex_forensic.domain.errors import DecryptionError
from apex_forensic.domain.models import (
    DecryptionResult,
    SecretDerivationInput,
    SecretMaterial,
    SecretProviderCapability,
    SecretReference,
)


class SecretProviderPort(Protocol):
    """Boundary for resolving secret references into ephemeral material."""

    @property
    def provider_id(self) -> str: ...

    @property
    def provider_version(self) -> str: ...

    def capabilities(self) -> SecretProviderCapability: ...

    def resolve(
        self,
        reference: SecretReference,
        derivation_input: SecretDerivationInput,
        *,
        cancellation_requested: bool = False,
    ) -> SecretMaterial: ...


class DecryptionProviderPort(Protocol):
    """Boundary for decrypting bounded offline evidence blobs."""

    @property
    def provider_id(self) -> str: ...

    @property
    def provider_version(self) -> str: ...

    def capabilities(self) -> SecretProviderCapability: ...

    def decrypt(
        self,
        derivation_input: SecretDerivationInput,
        ciphertext: bytes,
        *,
        algorithm: str,
        cancellation_requested: bool = False,
    ) -> DecryptionResult: ...


class UnavailableSecretProvider:
    """Default secret provider that returns an explicit unavailable boundary."""

    provider_id = "apex.secret.unavailable"
    provider_version = "1.0.0"

    def capabilities(self) -> SecretProviderCapability:
        return SecretProviderCapability(
            provider_id=self.provider_id,
            provider_version=self.provider_version,
            capability_type="SECRET_PROVIDER",
            runtime_status="CAPABILITY_UNAVAILABLE",
            supported_key_sources=[],
            supported_algorithms=[],
            warnings=[
                {
                    "code": "CAPABILITY_UNAVAILABLE",
                    "developer_message": "No advanced secret provider is configured.",
                }
            ],
        )

    def resolve(
        self,
        reference: SecretReference,
        derivation_input: SecretDerivationInput,
        *,
        cancellation_requested: bool = False,
    ) -> SecretMaterial:
        del reference, derivation_input, cancellation_requested
        raise DecryptionError(
            "CAPABILITY_UNAVAILABLE",
            "No advanced secret provider is configured.",
            target="secret_provider",
            details={"provider_id": self.provider_id},
        )
