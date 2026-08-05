"""KakaoTalk encrypted store provider boundary."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from apex_forensic.constants import ENGINE_VERSION
from apex_forensic.domain.models import (
    DecryptionAttempt,
    DecryptionResult,
    SecretDerivationInput,
    SecretProviderCapability,
)


class KakaoTalkEncryptedStoreProvider:
    """Structured key-unavailable boundary for KakaoTalk encrypted SQLite stores."""

    provider_id = "apex.communication.kakaotalk"
    provider_version = ENGINE_VERSION

    def capabilities(self) -> SecretProviderCapability:
        return SecretProviderCapability(
            provider_id=self.provider_id,
            provider_version=self.provider_version,
            capability_type="KAKAOTALK_PROVIDER",
            runtime_status="KEY_UNAVAILABLE",
            supported_key_sources=["KAKAOTALK_USER_KEY_MATERIAL"],
            supported_algorithms=["KAKAOTALK_ENCRYPTED_SQLITE"],
            requires_host=False,
            requires_network=False,
            generated_at=datetime.now(UTC),
            warnings=[
                {
                    "code": "KEY_UNAVAILABLE",
                    "developer_message": (
                        "No validated offline KakaoTalk key provider is configured."
                    ),
                    "details": {"success_without_key": False},
                }
            ],
        )

    def inspect_store(
        self,
        *,
        case_id: str,
        evidence_id: str | None,
        store_path: str,
    ) -> dict[str, object]:
        path = Path(store_path)
        if not path.is_file():
            return {
                "case_id": case_id,
                "evidence_id": evidence_id,
                "store_path": store_path,
                "status": "SOURCE_UNAVAILABLE",
                "reason": "KAKAOTALK_STORE_NOT_FOUND",
                "success_without_key": False,
            }
        data = path.read_bytes()
        return {
            "case_id": case_id,
            "evidence_id": evidence_id,
            "store_path": store_path,
            "status": "KEY_UNAVAILABLE",
            "reason": "KAKAOTALK_KEY_PROVIDER_UNAVAILABLE",
            "encrypted_store_detected": True,
            "store_length": len(data),
            "store_sha256": hashlib.sha256(data).hexdigest(),
            "raw_store_emitted": False,
            "success_without_key": False,
        }

    def decrypt_store(
        self,
        derivation_input: SecretDerivationInput,
        *,
        store_path: str,
        cancellation_requested: bool = False,
    ) -> DecryptionResult:
        del cancellation_requested
        derivation_input.assert_references_same_case()
        inspected = self.inspect_store(
            case_id=derivation_input.case_id,
            evidence_id=derivation_input.evidence_id,
            store_path=store_path,
        )
        status = str(inspected["status"])
        now = datetime.now(UTC)
        return DecryptionResult(
            attempt=DecryptionAttempt(
                attempt_id=f"kakaotalk-{uuid4()}",
                case_id=derivation_input.case_id,
                evidence_id=derivation_input.evidence_id,
                provider_id=self.provider_id,
                provider_version=self.provider_version,
                algorithm="KAKAOTALK_ENCRYPTED_SQLITE",
                key_source_kind=derivation_input.key_source_kind,
                status=status,
                started_at=now,
                completed_at=now,
                warnings=[
                    {
                        "code": status,
                        "developer_message": (
                            "KakaoTalk store decryption did not run because required offline "
                            "key material is unavailable."
                        ),
                    }
                ],
                error_code=str(inspected["reason"]),
                error_message="KakaoTalk offline key provider unavailable.",
            ),
            status=status,
            output_kind="KAKAOTALK_SQLITE_PLAINTEXT",
            metadata={
                **inspected,
                "plaintext_emitted": False,
                "success_without_key": False,
            },
        )
