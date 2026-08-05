"""Verify KakaoTalk encrypted-store boundary without decrypting private content."""

from __future__ import annotations

import argparse
import json

from apex_forensic.adapters.decryption import KakaoTalkEncryptedStoreProvider
from apex_forensic.domain.models import SecretDerivationInput


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify APEX KakaoTalk provider boundary.")
    parser.add_argument("--case-id", default="verification-case")
    parser.add_argument("--evidence-id", default="verification-evidence")
    parser.add_argument("--store-path")
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
        output["decrypt"] = provider.decrypt_store(
            SecretDerivationInput(
                case_id=args.case_id,
                evidence_id=args.evidence_id,
                key_source_kind="EXTERNAL_OFFLINE_KEY_MATERIAL",
            ),
            store_path=args.store_path,
        ).to_schema_dict()
    print(json.dumps(output, ensure_ascii=False, indent=2))
    if args.require_available and capability["runtime_status"] != "AVAILABLE":
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
