"""Semantically verify the offline KakaoTalk encrypted-store boundary."""

from __future__ import annotations

# ruff: noqa: E402, I001

import argparse
import hashlib
import json
import os
from typing import Any

from verification_common import ensure_source_tree_importable

ensure_source_tree_importable(__file__)

from apex_forensic.adapters.decryption import KakaoTalkEncryptedStoreProvider
from apex_forensic.domain.models import SecretDerivationInput


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify APEX KakaoTalk provider boundary.")
    parser.add_argument("--case-id", default="verification-case")
    parser.add_argument("--evidence-id", default="verification-evidence")
    parser.add_argument("--store-path")
    parser.add_argument("--profile-root")
    parser.add_argument("--platform", default="WINDOWS_DESKTOP")
    parser.add_argument("--application-version")
    parser.add_argument("--database-schema-version")
    parser.add_argument("--pragma-key-env")
    parser.add_argument("--user-nonce-env")
    parser.add_argument("--db-key-hex-env")
    parser.add_argument("--db-iv-hex-env")
    parser.add_argument("--expect-message")
    parser.add_argument("--require-decrypted", action="store_true")
    parser.add_argument("--require-available", action="store_true")
    parser.add_argument("--require-real-fixture", action="store_true")
    args = parser.parse_args()

    provider = KakaoTalkEncryptedStoreProvider()
    capability = provider.capabilities().to_schema_dict()
    acquisition = provider.acquire_key_material(
        case_id=args.case_id,
        evidence_id=args.evidence_id,
        profile_root=args.profile_root,
        platform=args.platform,
    )
    output: dict[str, Any] = {
        "capability": capability,
        "key_acquisition": acquisition,
    }
    secret_values: list[str] = []
    decrypt_schema: dict[str, Any] | None = None
    if args.store_path:
        output["inspect"] = provider.inspect_store(
            case_id=args.case_id,
            evidence_id=args.evidence_id,
            store_path=args.store_path,
            profile_root=args.profile_root,
        )
        parameters: dict[str, Any] = {"platform": args.platform}
        if args.application_version:
            parameters["application_version"] = args.application_version
        if args.database_schema_version:
            parameters["database_schema_version"] = args.database_schema_version
        for env_attr, parameter_name in (
            ("pragma_key_env", "pragma_key"),
            ("user_nonce_env", "user_nonce"),
            ("db_key_hex_env", "db_key_hex"),
            ("db_iv_hex_env", "db_iv_hex"),
        ):
            env_name = getattr(args, env_attr)
            value = os.environ.get(env_name) if env_name else None
            if value:
                parameters[parameter_name] = value
                secret_values.append(value)
        decrypt_result = provider.decrypt_store(
            SecretDerivationInput(
                case_id=args.case_id,
                evidence_id=args.evidence_id,
                key_source_kind="EXTERNAL_OFFLINE_KEY_MATERIAL",
                parameters=parameters,
            ),
            store_path=args.store_path,
            profile_root=args.profile_root,
        )
        decrypt_schema = _remove_diagnostic_plaintext(decrypt_result.to_schema_dict())
        output["decrypt"] = decrypt_schema

    messages = _messages_from_result(decrypt_schema)
    expected_hash = (
        hashlib.sha256(args.expect_message.encode("utf-8")).hexdigest()
        if args.expect_message is not None
        else None
    )
    expected_message_present = expected_hash is None or any(
        item.get("message_text_sha256") == expected_hash for item in messages
    )
    serialized_for_leak_check = json.dumps(output, ensure_ascii=False, sort_keys=True)
    leak_markers = [value for value in secret_values if len(value) >= 4]
    if args.expect_message and len(args.expect_message) >= 4:
        leak_markers.append(args.expect_message)
    leakage_violations = [
        f"raw_value_{index}"
        for index, value in enumerate(leak_markers, start=1)
        if value in serialized_for_leak_check
    ]
    if "plaintext_b64" in serialized_for_leak_check:
        leakage_violations.append("plaintext_b64")

    decrypt_status = _nested_value(decrypt_schema, "status")
    metadata = decrypt_schema.get("metadata", {}) if decrypt_schema else {}
    real_fixture_verified = metadata.get("real_kakaotalk_fixture_verified") is True
    external_key_contract_decrypted = decrypt_status == "KAKAOTALK_DECRYPTED"
    schema_status = (
        "SCHEMA_VERIFIED"
        if external_key_contract_decrypted
        else decrypt_status
        if decrypt_status in {"UNSUPPORTED_SCHEMA", "CORRUPT_DB"}
        else "NOT_ATTEMPTED"
    )
    output["phases"] = {
        "provider_capability": capability.get("runtime_status"),
        "profile_evidence_discovery": acquisition.get("discovery_status"),
        "version_verification": acquisition.get("version_status"),
        "key_material_discovery": acquisition.get("key_material_status"),
        "key_derivation": (
            "KEY_DERIVED"
            if isinstance(metadata, dict) and metadata.get("key_source")
            else "NOT_ATTEMPTED"
        ),
        "database_decryption": decrypt_status or "NOT_ATTEMPTED",
        "schema_verification": schema_status,
        "chatlogs_extraction": (
            "EXTRACTED" if external_key_contract_decrypted else "NOT_ATTEMPTED"
        ),
        "secret_leakage_check": "PASSED" if not leakage_violations else "FAILED",
        "real_fixture_verification": (
            "VERIFIED" if real_fixture_verified else "BLOCKED_EXTERNAL_FIXTURE"
        ),
    }
    output["verification"] = {
        "external_key_contract_decrypted": external_key_contract_decrypted,
        "message_count": len(messages),
        "expected_message_present": expected_message_present,
        "message_contents_emitted": False,
        "secret_leakage_check_passed": not leakage_violations,
        "secret_leakage_violations": leakage_violations,
        "real_kakaotalk_fixture_verified": real_fixture_verified,
    }
    print(json.dumps(output, ensure_ascii=False, indent=2))
    if args.require_available and capability["runtime_status"] not in {
        "AVAILABLE",
        "AVAILABLE_WITH_EXTERNAL_KEY",
    }:
        return 1
    if args.require_decrypted and (
        not external_key_contract_decrypted
        or not expected_message_present
        or leakage_violations
    ):
        return 1
    if args.require_real_fixture and not real_fixture_verified:
        return 1
    return 0


def _remove_diagnostic_plaintext(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: _remove_diagnostic_plaintext(item)
            for key, item in value.items()
            if key not in {"message_preview", "plaintext_b64"}
        }
    if isinstance(value, list):
        return [_remove_diagnostic_plaintext(item) for item in value]
    return value


def _messages_from_result(result: dict[str, Any] | None) -> list[dict[str, Any]]:
    if not result:
        return []
    metadata = result.get("metadata")
    if not isinstance(metadata, dict):
        return []
    messages = metadata.get("messages")
    if not isinstance(messages, list):
        return []
    return [item for item in messages if isinstance(item, dict)]


def _nested_value(value: dict[str, Any] | None, key: str) -> Any:
    return value.get(key) if value is not None else None


if __name__ == "__main__":
    raise SystemExit(main())
