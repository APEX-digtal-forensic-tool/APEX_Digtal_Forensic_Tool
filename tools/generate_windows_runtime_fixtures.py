#!/usr/bin/env python3
"""Generate redistributable synthetic Windows runtime fixtures.

The generated files contain only fixed synthetic secrets. The manifest records
expected hashes and redacted result shapes, never the fixture credential values.
"""

from __future__ import annotations

import argparse
import base64
import ctypes
import ctypes.util
import hashlib
import json
import struct
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID

DPAPI_FIXTURE_ID = "apex-dpapi-synthetic-runtime-v1"
NSS_FIXTURE_ID = "apex-nss-synthetic-runtime-v1"
MANIFEST_SCHEMA_VERSION = "apex.windows-runtime-fixtures.v1"

DPAPI_PASSWORD_ENV = "APEX_DPAPI_FIXTURE_PASSWORD"
DPAPI_PASSWORD_VALUE = "apex synthetic dpapi fixture password v1"
DPAPI_SID = "S-1-5-21-1111111111-2222222222-3333333333-1001"
DPAPI_MASTERKEY_GUID = UUID("11111111-2222-3333-8444-555555555555")
DPAPI_MASTERKEY_BYTES = hashlib.sha512(b"apex synthetic offline dpapi masterkey").digest()
DPAPI_PLAINTEXT = "APEX synthetic DPAPI runtime secret 한글".encode()
CHROMIUM_KEY_BYTES = hashlib.sha256(b"apex synthetic chromium local state key").digest()
CHROMIUM_PLAINTEXT = "APEX synthetic Chromium AES-GCM secret 한글".encode()

NSS_PRIMARY_PASSWORD_ENV = "APEX_NSS_PRIMARY_PASSWORD"
NSS_PRIMARY_PASSWORD_VALUE = "apex synthetic nss primary password v1"
NSS_USERNAME = b"apex.synthetic@example.invalid"
NSS_PASSWORD = "APEX synthetic Firefox NSS login secret 한글".encode()
NSS_ENCRYPT_SYMBOL = "PK11SDR_Encrypt"
_NSS_REQUIRED_SYMBOLS = (
    "NSS_InitReadWrite",
    "NSS_Shutdown",
    "PK11_GetInternalKeySlot",
    "PK11_FreeSlot",
    "PK11_InitPin",
    "PK11_CheckUserPassword",
    "PK11_Authenticate",
    NSS_ENCRYPT_SYMBOL,
    "SECITEM_ZfreeItem",
)


class FixtureGenerationError(RuntimeError):
    """Raised when a required fixture cannot be generated."""


class SECItem(ctypes.Structure):
    _fields_ = [
        ("type", ctypes.c_uint),
        ("data", ctypes.POINTER(ctypes.c_ubyte)),
        ("len", ctypes.c_uint),
    ]


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate synthetic DPAPI, Chromium, and Firefox NSS runtime fixtures."
    )
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--manifest-path")
    parser.add_argument("--nss-library-path")
    parser.add_argument("--overwrite", action="store_true")
    parser.add_argument("--require-dpapi", action="store_true")
    parser.add_argument("--require-nss", action="store_true")
    parser.add_argument("--require-all", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    output_dir = Path(args.output_dir).expanduser().resolve(strict=False)
    manifest_path = (
        Path(args.manifest_path).expanduser().resolve(strict=False)
        if args.manifest_path
        else output_dir / "windows-runtime-fixtures.manifest.json"
    )
    _prepare_output_dir(output_dir, overwrite=args.overwrite)

    generated_at = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    dpapi = _generate_dpapi_fixture(output_dir)
    nss = _generate_nss_fixture(output_dir, library_path=args.nss_library_path)
    manifest = {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "fixture_suite_id": "apex-windows-runtime-synthetic-fixtures-v1",
        "source": "APEX generated synthetic fixture set",
        "license": "CC0-1.0",
        "generated_at": generated_at,
        "synthetic_only": True,
        "secret_values_emitted": False,
        "live_user_profile_used": False,
        "verification_flows": {
            "linux_generated_nss_windows_decrypt_supported": True,
            "manifest_relative_paths_supported": True,
        },
        "dpapi": dpapi,
        "nss": nss,
        "ai_provider": {
            "live_smoke_status": "EXTERNAL_PROVIDER_NOT_CONFIGURED",
            "required_env": [
                "APEX_AI_VERIFY_BASE_URL",
                "APEX_AI_VERIFY_MODEL",
                "APEX_AI_VERIFY_API_KEY_ENV",
                "<value of APEX_AI_VERIFY_API_KEY_ENV>",
            ],
            "secret_values_emitted": False,
        },
        "kakaotalk": {
            "status": "BLOCKED_EXTERNAL_FIXTURE",
            "automatic_key_acquisition_status": "BLOCKED_EXTERNAL_FIXTURE",
            "redistributable_fixture_status": "BLOCKED_EXTERNAL_FIXTURE",
            "synthetic_aes_contract_promoted_to_real_fixture": False,
        },
    }
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    summary = {
        "status": _suite_status(dpapi, nss),
        "manifest_path": str(manifest_path),
        "output_dir": str(output_dir),
        "dpapi_status": dpapi["status"],
        "nss_status": nss["status"],
        "secret_values_emitted": False,
    }
    if args.json:
        print(json.dumps(summary, ensure_ascii=False, indent=2))
    else:
        print(f"manifest_path={manifest_path}")
        print(f"dpapi_status={dpapi['status']}")
        print(f"nss_status={nss['status']}")
        print("secret_values_emitted=false")

    require_dpapi = args.require_dpapi or args.require_all
    require_nss = args.require_nss or args.require_all
    if require_dpapi and dpapi["status"] != "GENERATED":
        return 1
    if require_nss and nss["status"] != "GENERATED":
        return 1
    return 0


def _prepare_output_dir(output_dir: Path, *, overwrite: bool) -> None:
    if output_dir.exists() and any(output_dir.iterdir()) and not overwrite:
        raise FixtureGenerationError(
            f"output directory is not empty; pass --overwrite or choose a new path: {output_dir}"
        )
    output_dir.mkdir(parents=True, exist_ok=True)


def _generate_dpapi_fixture(output_dir: Path) -> dict[str, Any]:
    try:
        dpapi, aes, hmac, md4, sha1, sha512, pad, aes_gcm = _load_dpapi_dependencies()
    except FixtureGenerationError as error:
        return _unavailable_fixture(
            fixture_id=DPAPI_FIXTURE_ID,
            status="CAPABILITY_UNAVAILABLE",
            warning_code="DPAPI_FIXTURE_DEPENDENCY_UNAVAILABLE",
            message=str(error),
        )

    nt_hash = md4.new(DPAPI_PASSWORD_VALUE.encode("utf-16le")).digest()
    wrapping_key = dpapi.deriveKeysFromUser(DPAPI_SID, DPAPI_PASSWORD_VALUE)[1]
    masterkey_bytes = _synthetic_dpapi_masterkey(
        dpapi,
        aes=aes,
        hmac=hmac,
        sha512=sha512,
        wrapping_key=wrapping_key,
        masterkey=DPAPI_MASTERKEY_BYTES,
    )
    masterkey_file = dpapi.MasterKeyFile()
    masterkey_file["Version"] = 2
    masterkey_file["unk1"] = 0
    masterkey_file["unk2"] = 0
    masterkey_file["Guid"] = str(DPAPI_MASTERKEY_GUID).encode("utf-16le")
    masterkey_file["Unkown"] = 0
    masterkey_file["Policy"] = 0
    masterkey_file["Flags"] = 0
    masterkey_file["MasterKeyLen"] = len(masterkey_bytes)
    masterkey_file["BackupKeyLen"] = 0
    masterkey_file["CredHistLen"] = 0
    masterkey_file["DomainKeyLen"] = 0

    protect_dir = output_dir / "dpapi" / "Protect" / DPAPI_SID
    protect_dir.mkdir(parents=True, exist_ok=True)
    masterkey_path = protect_dir / str(DPAPI_MASTERKEY_GUID)
    masterkey_path.write_bytes(masterkey_file.getData() + masterkey_bytes)

    blob = _synthetic_dpapi_blob(
        dpapi,
        aes=aes,
        hmac=hmac,
        sha1=sha1,
        sha512=sha512,
        pad=pad,
        masterkey_guid=DPAPI_MASTERKEY_GUID,
        masterkey=DPAPI_MASTERKEY_BYTES,
        plaintext=DPAPI_PLAINTEXT,
        salt=bytes.fromhex("202122232425262728292a2b2c2d2e2f"),
        hmac_value=bytes.fromhex(
            "303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f"
        ),
    )
    blob_path = output_dir / "dpapi" / "blob.bin"
    blob_path.write_bytes(blob)

    local_state_blob = _synthetic_dpapi_blob(
        dpapi,
        aes=aes,
        hmac=hmac,
        sha1=sha1,
        sha512=sha512,
        pad=pad,
        masterkey_guid=DPAPI_MASTERKEY_GUID,
        masterkey=DPAPI_MASTERKEY_BYTES,
        plaintext=CHROMIUM_KEY_BYTES,
        salt=bytes.fromhex("404142434445464748494a4b4c4d4e4f"),
        hmac_value=bytes.fromhex(
            "505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f"
        ),
    )
    chromium_dir = output_dir / "chromium"
    chromium_dir.mkdir(parents=True, exist_ok=True)
    local_state_path = chromium_dir / "Local State"
    local_state_path.write_text(
        json.dumps(
            {
                "os_crypt": {
                    "encrypted_key": base64.b64encode(b"DPAPI" + local_state_blob).decode(
                        "ascii"
                    )
                }
            }
        ),
        encoding="utf-8",
    )

    nonce = b"\x05" * 12
    chromium_secret = (
        b"v10" + nonce + aes_gcm(CHROMIUM_KEY_BYTES).encrypt(nonce, CHROMIUM_PLAINTEXT, None)
    )
    chromium_secret_path = chromium_dir / "aes-gcm-secret.bin"
    chromium_secret_path.write_bytes(chromium_secret)

    return {
        "fixture_id": DPAPI_FIXTURE_ID,
        "status": "GENERATED",
        "source": "APEX generated synthetic DPAPI fixture",
        "license": "CC0-1.0",
        "version": "1",
        "sid": DPAPI_SID,
        "masterkey_guid": str(DPAPI_MASTERKEY_GUID),
        "masterkey_path": str(masterkey_path),
        "masterkey_path_relative": _fixture_relative_path(masterkey_path, output_dir),
        "input_file": str(blob_path),
        "input_file_relative": _fixture_relative_path(blob_path, output_dir),
        "local_state_path": str(local_state_path),
        "local_state_path_relative": _fixture_relative_path(local_state_path, output_dir),
        "chromium_input_file": str(chromium_secret_path),
        "chromium_input_file_relative": _fixture_relative_path(chromium_secret_path, output_dir),
        "credential_env": DPAPI_PASSWORD_ENV,
        "credential_value_emitted": False,
        "expected_key_source": "WINDOWS_USER_PASSWORD",
        "algorithm": {
            "masterkey": "DPAPI_MASTERKEY AES-256/SHA-512",
            "blob": "DPAPI_BLOB AES-256/SHA-512",
            "chromium_local_state": "CHROMIUM_LOCAL_STATE_DPAPI_KEY",
            "chromium_secret": "CHROMIUM_AES_GCM_SECRET v10",
        },
        "file_hashes": {
            "masterkey_sha256": _file_sha256(masterkey_path),
            "blob_sha256": _file_sha256(blob_path),
            "local_state_sha256": _file_sha256(local_state_path),
            "chromium_secret_sha256": _file_sha256(chromium_secret_path),
        },
        "expected_plaintext_sha256": _sha256(DPAPI_PLAINTEXT),
        "expected_nt_hash_sha256": _sha256(nt_hash),
        "expected_redacted_result": {
            "dpapi_blob": {
                "status": "DECRYPTED",
                "output_kind": "DPAPI_PLAINTEXT",
                "content_sha256": _sha256(DPAPI_PLAINTEXT),
                "content_length": len(DPAPI_PLAINTEXT),
                "plaintext_emitted": False,
            },
            "chromium_local_state_key": {
                "status": "DECRYPTED",
                "output_kind": "CHROMIUM_LOCAL_STATE_KEY",
                "content_sha256": _sha256(CHROMIUM_KEY_BYTES),
                "content_length": len(CHROMIUM_KEY_BYTES),
                "plaintext_emitted": False,
            },
            "chromium_secret": {
                "status": "DECRYPTED",
                "output_kind": "CHROMIUM_SECRET",
                "content_sha256": _sha256(CHROMIUM_PLAINTEXT),
                "content_length": len(CHROMIUM_PLAINTEXT),
                "plaintext_emitted": False,
            },
        },
    }


def _load_dpapi_dependencies() -> tuple[Any, Any, Any, Any, Any, Any, Any, Any]:
    try:
        from Cryptodome.Cipher import AES
        from Cryptodome.Hash import HMAC, MD4, SHA1, SHA512
        from Cryptodome.Util.Padding import pad
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from impacket import dpapi
    except ImportError as error:
        raise FixtureGenerationError(
            "DPAPI fixture generation requires impacket, pycryptodomex, and cryptography."
        ) from error
    return dpapi, AES, HMAC, MD4, SHA1, SHA512, pad, AESGCM


def _synthetic_dpapi_masterkey(
    dpapi: Any,
    *,
    aes: Any,
    hmac: Any,
    sha512: Any,
    wrapping_key: bytes,
    masterkey: bytes,
) -> bytes:
    salt = bytes.fromhex("00112233445566778899aabbccddeeff")
    hmac_salt = bytes.fromhex("102132435465768798a9babbdcedfe0f")
    rounds = 8000
    hmac_value = hmac.new(hmac.new(wrapping_key, hmac_salt, sha512).digest(), masterkey, sha512)
    cleartext = hmac_salt + hmac_value.digest() + masterkey
    masterkey_record = dpapi.MasterKey()
    derived = masterkey_record.deriveKey(
        wrapping_key,
        salt,
        48,
        rounds,
        lambda passphrase, value: hmac.new(passphrase, value, sha512).digest(),
    )
    masterkey_record["Version"] = 2
    masterkey_record["Salt"] = salt
    masterkey_record["MasterKeyIterationCount"] = rounds
    masterkey_record["HashAlgo"] = dpapi.ALGORITHMS.CALG_SHA_512.value
    masterkey_record["CryptAlgo"] = dpapi.ALGORITHMS.CALG_AES_256.value
    masterkey_record["data"] = aes.new(
        derived[:32],
        aes.MODE_CBC,
        iv=derived[32:48],
    ).encrypt(cleartext)
    return masterkey_record.getData()


def _synthetic_dpapi_blob(
    dpapi: Any,
    *,
    aes: Any,
    hmac: Any,
    sha1: Any,
    sha512: Any,
    pad: Any,
    masterkey_guid: UUID,
    masterkey: bytes,
    plaintext: bytes,
    salt: bytes,
    hmac_value: bytes,
) -> bytes:
    key_hash = sha1.new(masterkey).digest()
    session = hmac.new(key_hash, salt, sha512).digest()
    blob_record = dpapi.DPAPI_BLOB()
    blob_record["HashAlgo"] = dpapi.ALGORITHMS.CALG_SHA_512.value
    blob_record["CryptAlgo"] = dpapi.ALGORITHMS.CALG_AES_256.value
    derived = blob_record.deriveKey(session)
    encrypted = aes.new(derived[:32], aes.MODE_CBC, iv=b"\x00" * 16).encrypt(
        pad(plaintext, 16)
    )
    description = "APEX synthetic DPAPI fixture\x00".encode("utf-16le")
    raw_without_signature = b"".join(
        [
            struct.pack("<L", 1),
            b"\x00" * 16,
            struct.pack("<L", 1),
            masterkey_guid.bytes_le,
            struct.pack("<L", 0),
            struct.pack("<L", len(description)),
            description,
            struct.pack("<L", dpapi.ALGORITHMS.CALG_AES_256.value),
            struct.pack("<L", 256),
            struct.pack("<L", len(salt)),
            salt,
            struct.pack("<L", 0),
            b"",
            struct.pack("<L", dpapi.ALGORITHMS.CALG_SHA_512.value),
            struct.pack("<L", 512),
            struct.pack("<L", len(hmac_value)),
            hmac_value,
            struct.pack("<L", len(encrypted)),
            encrypted,
            struct.pack("<L", 64),
        ]
    )
    signer = hmac.new(key_hash, hmac_value, sha512)
    signer.update(raw_without_signature[20:-4])
    return raw_without_signature + signer.digest()


def _generate_nss_fixture(output_dir: Path, *, library_path: str | None) -> dict[str, Any]:
    resolved_library = library_path or ctypes.util.find_library("nss3")
    if resolved_library is None:
        return _unavailable_fixture(
            fixture_id=NSS_FIXTURE_ID,
            status="NSS_CAPABILITY_UNAVAILABLE",
            warning_code="NSS_FIXTURE_DEPENDENCY_UNAVAILABLE",
            message="Firefox NSS fixture generation requires libnss3.",
        )
    try:
        lib = ctypes.CDLL(resolved_library)
    except OSError as error:
        return _unavailable_fixture(
            fixture_id=NSS_FIXTURE_ID,
            status="NSS_CAPABILITY_UNAVAILABLE",
            warning_code="NSS_FIXTURE_DEPENDENCY_UNAVAILABLE",
            message=str(error),
            details={"nss_library_path": str(resolved_library)},
        )

    missing_symbols = _missing_nss_symbols(lib)
    if missing_symbols:
        encrypt_missing = NSS_ENCRYPT_SYMBOL in missing_symbols
        return _unavailable_fixture(
            fixture_id=NSS_FIXTURE_ID,
            status=(
                "NSS_ENCRYPT_SYMBOL_UNAVAILABLE"
                if encrypt_missing
                else "NSS_CAPABILITY_UNAVAILABLE"
            ),
            warning_code=(
                "NSS_ENCRYPT_SYMBOL_UNAVAILABLE"
                if encrypt_missing
                else "NSS_SYMBOL_UNAVAILABLE"
            ),
            message=(
                "Firefox NSS library cannot generate a synthetic fixture because "
                f"{NSS_ENCRYPT_SYMBOL} is unavailable. Generate the NSS fixture on a "
                "host whose NSS exports that symbol, then pass the generated manifest "
                "to the Windows verifier."
                if encrypt_missing
                else "Firefox NSS fixture generation requires NSS symbols that are unavailable."
            ),
            details={
                "nss_library_path": str(resolved_library),
                "missing_symbols": missing_symbols,
                "linux_generated_nss_windows_decrypt_supported": True,
            },
        )

    profile = output_dir / "firefox" / "Profiles" / "verify.default"
    profile.mkdir(parents=True, exist_ok=True)
    try:
        _configure_nss_library(lib)
        config = f"sql:{profile}".encode()
        if lib.NSS_InitReadWrite(config) != 0:
            raise FixtureGenerationError("NSS_InitReadWrite failed for the synthetic profile.")
        slot = lib.PK11_GetInternalKeySlot()
        if not slot:
            raise FixtureGenerationError(
                "PK11_GetInternalKeySlot failed for the synthetic profile."
            )
        password_bytes = NSS_PRIMARY_PASSWORD_VALUE.encode("utf-8")
        try:
            if lib.PK11_InitPin(slot, None, password_bytes) != 0:
                raise FixtureGenerationError("PK11_InitPin failed for the synthetic profile.")
            if lib.PK11_CheckUserPassword(slot, password_bytes) != 0:
                raise FixtureGenerationError("PK11_CheckUserPassword failed for the fixture PIN.")
            if lib.PK11_Authenticate(slot, 1, None) != 0:
                raise FixtureGenerationError("PK11_Authenticate failed for the synthetic profile.")
            encrypted_username = _nss_encrypt(lib, NSS_USERNAME)
            encrypted_password = _nss_encrypt(lib, NSS_PASSWORD)
        finally:
            lib.PK11_FreeSlot(slot)
            lib.NSS_Shutdown()
    except (FixtureGenerationError, OSError) as error:
        return _unavailable_fixture(
            fixture_id=NSS_FIXTURE_ID,
            status="NSS_CAPABILITY_UNAVAILABLE",
            warning_code="NSS_FIXTURE_GENERATION_FAILED",
            message=str(error),
        )

    logins_path = profile / "logins.json"
    logins_path.write_text(
        json.dumps(
            {
                "nextId": 2,
                "version": 3,
                "logins": [
                    {
                        "id": 1,
                        "hostname": "https://example.invalid",
                        "httpRealm": None,
                        "formSubmitURL": "https://example.invalid/login",
                        "usernameField": "user",
                        "passwordField": "pass",
                        "encryptedUsername": base64.b64encode(encrypted_username).decode(
                            "ascii"
                        ),
                        "encryptedPassword": base64.b64encode(encrypted_password).decode(
                            "ascii"
                        ),
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    key4_path = profile / "key4.db"
    return {
        "fixture_id": NSS_FIXTURE_ID,
        "status": "GENERATED",
        "source": "APEX generated synthetic Firefox NSS fixture",
        "license": "CC0-1.0",
        "version": "1",
        "root_path": str(output_dir / "firefox"),
        "root_path_relative": _fixture_relative_path(output_dir / "firefox", output_dir),
        "profile_path": str(profile),
        "profile_path_relative": _fixture_relative_path(profile, output_dir),
        "key4_db_path": str(key4_path),
        "key4_db_path_relative": _fixture_relative_path(key4_path, output_dir),
        "logins_json_path": str(logins_path),
        "logins_json_path_relative": _fixture_relative_path(logins_path, output_dir),
        "primary_password_required": True,
        "primary_password_env": NSS_PRIMARY_PASSWORD_ENV,
        "credential_value_emitted": False,
        "algorithm": "FIREFOX_NSS_LOGINS_JSON/PK11SDR",
        "generation_method": "NSS_PK11SDR_ENCRYPT_SYMBOL",
        "linux_generated_windows_decrypt_supported": True,
        "expected_login_count": 1,
        "file_hashes": {
            "key4_db_sha256": _file_sha256(key4_path) if key4_path.exists() else None,
            "logins_json_sha256": _file_sha256(logins_path),
        },
        "expected_plaintext_sha256": _sha256(NSS_USERNAME + b"\x00" + NSS_PASSWORD),
        "expected_redacted_result": {
            "status": "NSS_DECRYPTED",
            "output_kind": "FIREFOX_LOGIN",
            "login_count": 1,
            "username": {
                "sha256": _sha256(NSS_USERNAME),
                "length": len(NSS_USERNAME),
                "redacted_preview": "<redacted>",
            },
            "password": {
                "sha256": _sha256(NSS_PASSWORD),
                "length": len(NSS_PASSWORD),
                "redacted_preview": "<redacted>",
            },
            "plaintext_emitted": False,
        },
    }


def _missing_nss_symbols(lib: Any) -> list[str]:
    return [name for name in _NSS_REQUIRED_SYMBOLS if not hasattr(lib, name)]


def _configure_nss_library(lib: Any) -> None:
    lib.NSS_InitReadWrite.argtypes = [ctypes.c_char_p]
    lib.NSS_InitReadWrite.restype = ctypes.c_int
    lib.NSS_Shutdown.argtypes = []
    lib.NSS_Shutdown.restype = ctypes.c_int
    lib.PK11_GetInternalKeySlot.argtypes = []
    lib.PK11_GetInternalKeySlot.restype = ctypes.c_void_p
    lib.PK11_FreeSlot.argtypes = [ctypes.c_void_p]
    lib.PK11_FreeSlot.restype = None
    lib.PK11_InitPin.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]
    lib.PK11_InitPin.restype = ctypes.c_int
    lib.PK11_CheckUserPassword.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
    lib.PK11_CheckUserPassword.restype = ctypes.c_int
    lib.PK11_Authenticate.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p]
    lib.PK11_Authenticate.restype = ctypes.c_int
    lib.PK11SDR_Encrypt.argtypes = [
        ctypes.POINTER(SECItem),
        ctypes.POINTER(SECItem),
        ctypes.POINTER(SECItem),
        ctypes.c_void_p,
    ]
    lib.PK11SDR_Encrypt.restype = ctypes.c_int
    lib.SECITEM_ZfreeItem.argtypes = [ctypes.POINTER(SECItem), ctypes.c_int]
    lib.SECITEM_ZfreeItem.restype = None


def _nss_encrypt(lib: Any, plaintext: bytes) -> bytes:
    key_id = SECItem(0, None, 0)
    input_buffer = (ctypes.c_ubyte * len(plaintext)).from_buffer_copy(plaintext)
    input_item = SECItem(0, input_buffer, len(plaintext))
    output_item = SECItem()
    if (
        lib.PK11SDR_Encrypt(
            ctypes.byref(key_id),
            ctypes.byref(input_item),
            ctypes.byref(output_item),
            None,
        )
        != 0
    ):
        raise FixtureGenerationError("PK11SDR_Encrypt failed for a synthetic login field.")
    try:
        return ctypes.string_at(output_item.data, output_item.len)
    finally:
        if output_item.data:
            lib.SECITEM_ZfreeItem(ctypes.byref(output_item), 0)


def _unavailable_fixture(
    *,
    fixture_id: str,
    status: str,
    warning_code: str,
    message: str,
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    warning: dict[str, Any] = {
        "code": warning_code,
        "developer_message": message,
        "secret_values_emitted": False,
    }
    if details:
        warning["details"] = details
    return {
        "fixture_id": fixture_id,
        "status": status,
        "source": "APEX generated synthetic fixture set",
        "license": "CC0-1.0",
        "secret_values_emitted": False,
        "warnings": [warning],
    }


def _fixture_relative_path(path: Path, fixture_root: Path) -> str:
    return path.resolve(strict=False).relative_to(
        fixture_root.resolve(strict=False)
    ).as_posix()


def _suite_status(dpapi: dict[str, Any], nss: dict[str, Any]) -> str:
    if dpapi["status"] == "GENERATED" and nss["status"] == "GENERATED":
        return "GENERATED"
    if dpapi["status"] == "GENERATED" or nss["status"] == "GENERATED":
        return "PARTIAL"
    return "CAPABILITY_UNAVAILABLE"


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _file_sha256(path: Path) -> str:
    return _sha256(path.read_bytes())


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except FixtureGenerationError as error:
        print(
            json.dumps(
                {
                    "status": "FAILED",
                    "error_code": "FIXTURE_GENERATION_FAILED",
                    "error_message": str(error),
                    "secret_values_emitted": False,
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        raise SystemExit(1) from error
