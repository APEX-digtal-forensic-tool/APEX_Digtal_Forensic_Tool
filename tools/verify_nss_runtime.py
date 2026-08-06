"""Verify Firefox NSS runtime without emitting passwords."""

from __future__ import annotations

import argparse
import json
import os

from apex_forensic.adapters.decryption import NssLibProvider
from apex_forensic.domain.models import SecretDerivationInput


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify APEX Firefox NSS runtime.")
    parser.add_argument("--case-id", default="verification-case")
    parser.add_argument("--evidence-id", default="verification-evidence")
    parser.add_argument("--root-path")
    parser.add_argument("--profile-path")
    parser.add_argument("--primary-password-env")
    parser.add_argument("--require-available", action="store_true")
    args = parser.parse_args()

    provider = NssLibProvider()
    capability = provider.capabilities().to_schema_dict()
    output: dict[str, object] = {"capability": capability}
    if args.root_path:
        output["profiles"] = provider.discover_profiles(
            case_id=args.case_id,
            evidence_id=args.evidence_id,
            root_path=args.root_path,
        )
    if args.profile_path:
        primary_password = (
            os.environ.get(args.primary_password_env)
            if args.primary_password_env is not None
            else None
        )
        output["decrypt"] = [
            item.to_schema_dict()
            for item in provider.decrypt_logins(
                SecretDerivationInput(
                    case_id=args.case_id,
                    evidence_id=args.evidence_id,
                    key_source_kind="EXTERNAL_OFFLINE_KEY_MATERIAL",
                ),
                profile_path=args.profile_path,
                primary_password=primary_password,
            )
        ]
    print(json.dumps(output, ensure_ascii=False, indent=2))
    if args.require_available and capability["runtime_status"] not in {
        "AVAILABLE",
        "AVAILABLE_WITH_EXTERNAL_KEY",
        "IMPLEMENTED_RUNTIME",
    }:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
