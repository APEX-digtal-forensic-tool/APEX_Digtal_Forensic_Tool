"""Verify offline DPAPI runtime without live user-context access."""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os

from apex_forensic.adapters.decryption import DpapiExternalKeyProvider, DpapiOfflineProvider
from apex_forensic.domain.models import SecretDerivationInput, SecretMaterial, SecretReference


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify APEX offline DPAPI provider boundary.")
    parser.add_argument("--case-id", default="verification-case")
    parser.add_argument("--evidence-id", default="verification-evidence")
    parser.add_argument("--input-file")
    parser.add_argument("--local-state-path")
    parser.add_argument("--decrypt-local-state-key", action="store_true")
    parser.add_argument("--chromium-input-file")
    parser.add_argument("--sid")
    parser.add_argument("--masterkey-path")
    parser.add_argument("--password-env")
    parser.add_argument("--nt-hash-hex-env")
    parser.add_argument("--nt-hash-b64-env")
    parser.add_argument("--masterkey-hex-env")
    parser.add_argument("--masterkey-b64-env")
    parser.add_argument("--entropy-hex-env")
    parser.add_argument("--entropy-b64-env")
    key_group = parser.add_mutually_exclusive_group()
    key_group.add_argument("--key-hex-env")
    key_group.add_argument("--key-b64-env")
    parser.add_argument("--require-available", action="store_true")
    args = parser.parse_args()

    provider = DpapiOfflineProvider()
    external_provider = DpapiExternalKeyProvider()
    capability = provider.capabilities().to_schema_dict()
    external_capability = external_provider.capabilities().to_schema_dict()
    output: dict[str, object] = {
        "capability": capability,
        "external_key_capability": external_capability,
        "verification": {
            "status": (
                "CONFIGURED"
                if _dpapi_fixture_configured(args)
                else "EXTERNAL_FIXTURE_NOT_CONFIGURED"
            ),
            "uses_live_user_context": False,
            "requires_windows_host": False,
            "fixture_inputs": {
                "input_file": bool(args.input_file),
                "local_state_path": bool(args.local_state_path),
                "chromium_input_file": bool(args.chromium_input_file),
                "masterkey_path": bool(args.masterkey_path),
                "sid": bool(args.sid),
            },
            "secret_values_emitted": False,
        },
    }
    derivation = _dpapi_derivation(args)
    if args.input_file:
        with open(args.input_file, "rb") as handle:
            blob = handle.read(64 * 1024 * 1024 + 1)
        if len(blob) > 64 * 1024 * 1024:
            output["decrypt"] = {"status": "INPUT_TOO_LARGE", "max_bytes": 64 * 1024 * 1024}
        else:
            result = provider.decrypt_blob(
                derivation,
                blob,
            )
            output["decrypt"] = result.to_schema_dict()
    if args.local_state_path:
        output["local_state"] = provider.inspect_chromium_local_state(
            case_id=args.case_id,
            evidence_id=args.evidence_id,
            local_state_path=args.local_state_path,
        )
        if args.decrypt_local_state_key:
            local_state_result = provider.decrypt_chromium_local_state_key(
                derivation,
                local_state_path=args.local_state_path,
            )
            output["local_state_decrypt"] = local_state_result.to_schema_dict()
    if args.chromium_input_file:
        key = _key_from_env(args.key_hex_env, args.key_b64_env)
        local_state_key: bytes | None = None
        if key is None and args.local_state_path and args.decrypt_local_state_key:
            result = provider.decrypt_chromium_local_state_key(
                derivation,
                local_state_path=args.local_state_path,
            )
            if result.status == "DECRYPTED":
                local_state_key = result.plaintext
        with open(args.chromium_input_file, "rb") as handle:
            blob = handle.read(64 * 1024 * 1024 + 1)
        if len(blob) > 64 * 1024 * 1024:
            output["chromium_decrypt"] = {
                "status": "INPUT_TOO_LARGE",
                "max_bytes": 64 * 1024 * 1024,
            }
        elif key is None and local_state_key is None:
            output["chromium_decrypt"] = {
                "status": "KEY_UNAVAILABLE",
                "key_value_emitted": False,
            }
        else:
            effective_key = key if key is not None else local_state_key
            if effective_key is None:
                output["chromium_decrypt"] = {
                    "status": "KEY_UNAVAILABLE",
                    "key_value_emitted": False,
                }
                print(json.dumps(output, ensure_ascii=False, indent=2))
                return 0
            key_material = SecretMaterial(
                reference=SecretReference(
                    secret_id=f"verification-chromium-{hashlib.sha256(effective_key).hexdigest()[:16]}",
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
                value=effective_key,
                algorithm="AES-GCM",
            )
            output["chromium_decrypt"] = external_provider.decrypt_chromium_secret(
                derivation,
                blob,
                key_material,
            ).to_schema_dict()
    print(json.dumps(output, ensure_ascii=False, indent=2))
    if args.require_available and capability["runtime_status"] not in {
        "AVAILABLE",
        "AVAILABLE_WITH_EXTERNAL_KEY",
        "IMPLEMENTED_RUNTIME",
    }:
        return 1
    if args.chromium_input_file and external_capability["runtime_status"] not in {
        "AVAILABLE",
        "AVAILABLE_WITH_EXTERNAL_KEY",
        "IMPLEMENTED_RUNTIME",
    }:
        return 1
    return 0


def _dpapi_fixture_configured(args: argparse.Namespace) -> bool:
    return bool(
        args.input_file
        or args.local_state_path
        or args.chromium_input_file
        or args.masterkey_path
    )


def _dpapi_derivation(args: argparse.Namespace) -> SecretDerivationInput:
    parameters: dict[str, object] = {}
    if args.sid:
        parameters["sid"] = args.sid
    if args.masterkey_path:
        parameters["masterkey_path"] = args.masterkey_path
    for attr, parameter_name in (
        ("password_env", "password"),
        ("nt_hash_hex_env", "nt_hash_hex"),
        ("nt_hash_b64_env", "nt_hash_b64"),
        ("masterkey_hex_env", "masterkey_hex"),
        ("masterkey_b64_env", "masterkey_b64"),
        ("entropy_hex_env", "entropy_hex"),
        ("entropy_b64_env", "entropy_b64"),
    ):
        env_name = getattr(args, attr)
        if env_name:
            value = os.environ.get(env_name)
            if value is not None:
                parameters[parameter_name] = value
    key_source_kind = "EXTERNAL_OFFLINE_KEY_MATERIAL"
    if args.password_env:
        key_source_kind = "WINDOWS_USER_PASSWORD"
    elif args.nt_hash_hex_env or args.nt_hash_b64_env:
        key_source_kind = "WINDOWS_NT_HASH"
    elif args.masterkey_hex_env or args.masterkey_b64_env:
        key_source_kind = "EXTERNAL_MASTERKEY"
    return SecretDerivationInput(
        case_id=args.case_id,
        evidence_id=args.evidence_id,
        key_source_kind=key_source_kind,
        parameters=parameters,
    )


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
