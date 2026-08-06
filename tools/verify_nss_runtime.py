"""Verify Firefox NSS runtime without emitting passwords."""

from __future__ import annotations

# ruff: noqa: E402, I001

import argparse
import json
import os

from verification_common import (
    ensure_source_tree_importable,
    fixture_path_policy,
    nss_live_profile_roots,
)

ensure_source_tree_importable(__file__)

from apex_forensic.adapters.decryption import NssLibProvider
from apex_forensic.domain.models import SecretDerivationInput


_EPILOG = """
Fixture input contract:
  Use a synthetic or legally redistributable Firefox profile fixture only. Do not point
  --root-path or --profile-path at the current user's live Firefox profile.

Required profile fixture fields:
  --profile-path must contain key4.db and logins.json. Use --primary-password-env only
  for fixture primary passwords. --root-path may point at a fixture directory containing
  one or more Firefox Profiles/* directories.

Windows PowerShell example:
  $env:APEX_NSS_PRIMARY_PASSWORD = "<synthetic-fixture-primary-password>"
  py -3.11 tools\\verify_nss_runtime.py `
    --root-path C:\\apex-fixtures\\firefox `
    --profile-path C:\\apex-fixtures\\firefox\\Profiles\\verify.default `
    --primary-password-env APEX_NSS_PRIMARY_PASSWORD `
    --require-available
"""


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify APEX Firefox NSS runtime.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=_EPILOG,
    )
    parser.add_argument("--case-id", default="verification-case")
    parser.add_argument("--evidence-id", default="verification-evidence")
    parser.add_argument("--root-path")
    parser.add_argument("--profile-path")
    parser.add_argument("--primary-password-env")
    parser.add_argument("--require-available", action="store_true")
    args = parser.parse_args()

    provider = NssLibProvider()
    capability = provider.capabilities().to_schema_dict()
    policy = fixture_path_policy(
        {
            "root_path": args.root_path,
            "profile_path": args.profile_path,
        },
        forbidden_roots=nss_live_profile_roots(),
    )
    output: dict[str, object] = {
        "capability": capability,
        "verification": {
            "status": (
                policy["status"]
                if policy["status"] != "ACCEPTED"
                else "CONFIGURED"
                if args.root_path or args.profile_path
                else "EXTERNAL_FIXTURE_NOT_CONFIGURED"
            ),
            "uses_live_user_profile": False,
            "fixture_policy": policy,
            "fixture_inputs": {
                "root_path": bool(args.root_path),
                "profile_path": bool(args.profile_path),
                "primary_password_env": bool(args.primary_password_env),
            },
            "secret_values_emitted": False,
        },
    }
    if policy["status"] != "ACCEPTED":
        print(json.dumps(output, ensure_ascii=False, indent=2))
        return 1
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
