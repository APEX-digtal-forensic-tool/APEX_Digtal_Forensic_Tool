"""Verify DPAPI provider boundary without live user-context access."""

from __future__ import annotations

import argparse
import base64
import binascii
import json
import os

from apex_forensic.adapters.decryption import DpapiExternalKeyProvider, DpapiUnavailableProvider
from apex_forensic.domain.models import SecretDerivationInput, SecretMaterial, SecretReference


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify APEX offline DPAPI provider boundary.")
    parser.add_argument("--case-id", default="verification-case")
    parser.add_argument("--evidence-id", default="verification-evidence")
    parser.add_argument("--input-file")
    parser.add_argument("--local-state-path")
    parser.add_argument("--chromium-input-file")
    key_group = parser.add_mutually_exclusive_group()
    key_group.add_argument("--key-hex-env")
    key_group.add_argument("--key-b64-env")
    parser.add_argument("--require-available", action="store_true")
    args = parser.parse_args()

    provider = DpapiUnavailableProvider()
    external_provider = DpapiExternalKeyProvider()
    capability = provider.capabilities().to_schema_dict()
    external_capability = external_provider.capabilities().to_schema_dict()
    output: dict[str, object] = {
        "capability": capability,
        "external_key_capability": external_capability,
    }
    if args.input_file:
        with open(args.input_file, "rb") as handle:
            blob = handle.read(64 * 1024 * 1024 + 1)
        if len(blob) > 64 * 1024 * 1024:
            output["decrypt"] = {"status": "INPUT_TOO_LARGE", "max_bytes": 64 * 1024 * 1024}
        else:
            result = provider.decrypt_blob(
                SecretDerivationInput(
                    case_id=args.case_id,
                    evidence_id=args.evidence_id,
                    key_source_kind="EXTERNAL_OFFLINE_KEY_MATERIAL",
                ),
                blob,
            )
            output["decrypt"] = result.to_schema_dict()
    if args.local_state_path:
        output["local_state"] = provider.inspect_chromium_local_state(
            case_id=args.case_id,
            evidence_id=args.evidence_id,
            local_state_path=args.local_state_path,
        )
    if args.chromium_input_file:
        key = _key_from_env(args.key_hex_env, args.key_b64_env)
        with open(args.chromium_input_file, "rb") as handle:
            blob = handle.read(64 * 1024 * 1024 + 1)
        if len(blob) > 64 * 1024 * 1024:
            output["chromium_decrypt"] = {
                "status": "INPUT_TOO_LARGE",
                "max_bytes": 64 * 1024 * 1024,
            }
        elif key is None:
            output["chromium_decrypt"] = {
                "status": "KEY_UNAVAILABLE",
                "key_value_emitted": False,
            }
        else:
            derivation = SecretDerivationInput(
                case_id=args.case_id,
                evidence_id=args.evidence_id,
                key_source_kind="EXTERNAL_OFFLINE_KEY_MATERIAL",
            )
            key_material = SecretMaterial(
                reference=SecretReference(
                    secret_id="verification-chromium-key",
                    case_id=args.case_id,
                    evidence_id=args.evidence_id,
                    key_source_kind="EXTERNAL_OFFLINE_KEY_MATERIAL",
                    provider_id="verifier-env",
                    source_kind="ENVIRONMENT_VARIABLE",
                    raw_locator={
                        "env_name": args.key_hex_env or args.key_b64_env,
                        "value_emitted": False,
                    },
                ),
                value=key,
                algorithm="AES-GCM",
            )
            output["chromium_decrypt"] = external_provider.decrypt_chromium_secret(
                derivation,
                blob,
                key_material,
            ).to_schema_dict()
    print(json.dumps(output, ensure_ascii=False, indent=2))
    if args.require_available and external_capability["runtime_status"] not in {
        "AVAILABLE",
        "AVAILABLE_WITH_EXTERNAL_KEY",
    }:
        return 1
    return 0


def _key_from_env(hex_env: str | None, b64_env: str | None) -> bytes | None:
    env_name = hex_env or b64_env
    if env_name is None:
        return None
    value = os.environ.get(env_name)
    if value is None:
        return None
    try:
        if hex_env is not None:
            return bytes.fromhex(value.strip())
        return base64.b64decode(value.encode("ascii"), validate=True)
    except (ValueError, binascii.Error):
        return None


if __name__ == "__main__":
    raise SystemExit(main())
