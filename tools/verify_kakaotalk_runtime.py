"""Verify KakaoTalk encrypted-store boundary without decrypting private content."""

from __future__ import annotations

import argparse
import json
import os

from apex_forensic.adapters.decryption import KakaoTalkEncryptedStoreProvider
from apex_forensic.domain.models import SecretDerivationInput


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify APEX KakaoTalk provider boundary.")
    parser.add_argument("--case-id", default="verification-case")
    parser.add_argument("--evidence-id", default="verification-evidence")
    parser.add_argument("--store-path")
    parser.add_argument("--platform", default="WINDOWS_DESKTOP")
    parser.add_argument("--application-version", default="2.0.8.990")
    parser.add_argument("--database-schema-version", default="chatLogs")
    parser.add_argument("--pragma-key-env")
    parser.add_argument("--user-nonce-env")
    parser.add_argument("--db-key-hex-env")
    parser.add_argument("--db-iv-hex-env")
    parser.add_argument("--expect-message")
    parser.add_argument("--require-decrypted", action="store_true")
    parser.add_argument("--require-available", action="store_true")
    args = parser.parse_args()

    provider = KakaoTalkEncryptedStoreProvider()
    capability = provider.capabilities().to_schema_dict()
    output: dict[str, object] = {"capability": capability}
    if args.store_path:
        output["inspect"] = provider.inspect_store(
            case_id=args.case_id,
            evidence_id=args.evidence_id,
            store_path=args.store_path,
        )
        parameters = {
            "platform": args.platform,
            "application_version": args.application_version,
            "database_schema_version": args.database_schema_version,
        }
        for env_attr, parameter_name in (
            ("pragma_key_env", "pragma_key"),
            ("user_nonce_env", "user_nonce"),
            ("db_key_hex_env", "db_key_hex"),
            ("db_iv_hex_env", "db_iv_hex"),
        ):
            env_name = getattr(args, env_attr)
            if env_name and os.environ.get(env_name):
                parameters[parameter_name] = os.environ[env_name]
        output["decrypt"] = provider.decrypt_store(
            SecretDerivationInput(
                case_id=args.case_id,
                evidence_id=args.evidence_id,
                key_source_kind="EXTERNAL_OFFLINE_KEY_MATERIAL",
                parameters=parameters,
            ),
            store_path=args.store_path,
        ).to_schema_dict()
        messages = output["decrypt"]["metadata"].get("messages", [])  # type: ignore[index]
        flattened = " ".join(str(item.get("message_preview", "")) for item in messages)
        output["verification"] = {
            "decrypted": output["decrypt"]["status"] == "KAKAOTALK_DECRYPTED",  # type: ignore[index]
            "message_count": len(messages),
            "expected_message_present": (
                args.expect_message is None or args.expect_message in flattened
            ),
        }
    print(json.dumps(output, ensure_ascii=False, indent=2))
    if args.require_available and capability["runtime_status"] not in {
        "AVAILABLE",
        "AVAILABLE_WITH_EXTERNAL_KEY",
    }:
        return 1
    if args.require_decrypted:
        verification = output.get("verification", {})
        if not verification.get("decrypted") or not verification.get("expected_message_present"):
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
