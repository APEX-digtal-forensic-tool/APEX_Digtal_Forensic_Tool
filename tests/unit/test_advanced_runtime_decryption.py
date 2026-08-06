from __future__ import annotations

import base64
import ctypes
import ctypes.util
import hashlib
import json
import sqlite3
import struct
import subprocess
import sys
from pathlib import Path
from uuid import UUID

import pytest
from cryptography.hazmat.primitives import padding as crypto_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from apex_forensic.adapters.decryption import (
    DpapiExternalKeyProvider,
    DpapiOfflineProvider,
    DpapiUnavailableProvider,
    KakaoTalkEncryptedStoreProvider,
    NssLibProvider,
    NssUnavailableProvider,
)
from apex_forensic.cli.commands import main
from apex_forensic.config import build_services
from apex_forensic.domain.models import SecretDerivationInput, SecretMaterial, SecretReference


def _derivation() -> SecretDerivationInput:
    return SecretDerivationInput(
        case_id="case-1",
        evidence_id="ev-1",
        key_source_kind="EXTERNAL_OFFLINE_KEY_MATERIAL",
    )


def _write_synthetic_nss_profile(profile: Path, *, logins_version: int = 3) -> None:
    profile.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(profile / "key4.db") as connection:
        connection.execute("CREATE TABLE nssPrivate (id PRIMARY KEY, a0 BLOB)")
        connection.execute("INSERT INTO nssPrivate (id, a0) VALUES (?, ?)", (1, b"fixture"))
    (profile / "logins.json").write_text(
        json.dumps(
            {
                "nextId": 2,
                "version": logins_version,
                "logins": [
                    {
                        "id": 1,
                        "hostname": "https://example.invalid",
                        "encryptedUsername": "MDo=",
                        "encryptedPassword": "MDo=",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )


def _write_kakaotalk_external_key_contract_fixture(tmp_path: Path) -> dict[str, object]:
    plaintext_db = tmp_path / "chatLogs_plain.sqlite"
    with sqlite3.connect(plaintext_db) as connection:
        connection.execute(
            """
            CREATE TABLE chatLogs (
                logId INTEGER PRIMARY KEY,
                authorId TEXT,
                type INTEGER,
                sentAt INTEGER,
                message TEXT,
                attachment TEXT,
                deleted INTEGER
            )
            """
        )
        connection.executemany(
            """
            INSERT INTO chatLogs (
                logId, authorId, type, sentAt, message, attachment, deleted
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    1001,
                    "alice",
                    1,
                    1_700_000_001,
                    "안녕하세요 hello forensic",
                    None,
                    0,
                ),
                (
                    1002,
                    "bob",
                    18,
                    1_700_000_002,
                    "첨부 파일",
                    "https://example.invalid/download?token=secret",
                    1,
                ),
            ],
        )
    pragma_key = base64.b64encode(hashlib.sha512(b"apex-kakao-pragma").digest()).decode(
        "ascii"
    )
    user_nonce = "1234567890"
    key, iv = _kakao_key_iv(pragma_key, user_nonce)
    plaintext = plaintext_db.read_bytes()
    encrypted = _encrypt_kakaotalk_contract_bytes(plaintext, key, iv)
    encrypted_db = tmp_path / "chatLogs_42.edb"
    encrypted_db.write_bytes(encrypted)
    return {
        "store": encrypted_db,
        "pragma_key": pragma_key,
        "user_nonce": user_nonce,
        "plaintext": plaintext,
        "message": "안녕하세요 hello forensic",
    }


def _encrypt_kakaotalk_contract_bytes(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    padder = crypto_padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return encryptor.update(padded) + encryptor.finalize()


def _kakao_key_iv(pragma_key: str, user_nonce: str) -> tuple[bytes, bytes]:
    seed = (pragma_key + user_nonce).encode("utf-8")
    material = (seed * ((512 // len(seed)) + 1))[:512]
    key = hashlib.md5(material, usedforsecurity=False).digest()
    iv = hashlib.md5(base64.b64encode(key), usedforsecurity=False).digest()
    return key, iv


class _TestSECItem(ctypes.Structure):
    _fields_ = [
        ("type", ctypes.c_uint),
        ("data", ctypes.POINTER(ctypes.c_ubyte)),
        ("len", ctypes.c_uint),
    ]


def _write_real_nss_profile(
    profile: Path,
    *,
    primary_password: str | None = None,
) -> dict[str, object]:
    library_path = ctypes.util.find_library("nss3")
    if library_path is None:
        pytest.skip("libnss3 is required for NSS runtime fixture generation")
    lib = ctypes.CDLL(library_path)
    if not hasattr(lib, "PK11SDR_Encrypt"):
        pytest.skip(
            "installed NSS runtime does not export PK11SDR_Encrypt; "
            "use a pre-generated NSS profile for decryption verification"
        )
    profile.mkdir(parents=True, exist_ok=True)
    _configure_test_nss_library(lib)
    config = f"sql:{profile}".encode()
    assert lib.NSS_InitReadWrite(config) == 0
    slot = lib.PK11_GetInternalKeySlot()
    assert slot
    password_bytes = (primary_password or "").encode("utf-8")
    try:
        assert lib.PK11_InitPin(slot, None, password_bytes) == 0
        assert lib.PK11_CheckUserPassword(slot, password_bytes) == 0
        assert lib.PK11_Authenticate(slot, 1, None) == 0
        username = b"alice@example.invalid"
        password = "correct horse nss 한글".encode()
        encrypted_username = _test_nss_encrypt(lib, username)
        encrypted_password = _test_nss_encrypt(lib, password)
    finally:
        lib.PK11_FreeSlot(slot)
        assert lib.NSS_Shutdown() == 0
    (profile / "logins.json").write_text(
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
    return {
        "profile": profile,
        "primary_password": primary_password,
        "username": username,
        "password": password,
    }


def _configure_test_nss_library(lib: object) -> None:
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
        ctypes.POINTER(_TestSECItem),
        ctypes.POINTER(_TestSECItem),
        ctypes.POINTER(_TestSECItem),
        ctypes.c_void_p,
    ]
    lib.PK11SDR_Encrypt.restype = ctypes.c_int
    lib.SECITEM_ZfreeItem.argtypes = [ctypes.POINTER(_TestSECItem), ctypes.c_int]
    lib.SECITEM_ZfreeItem.restype = None


def _test_nss_encrypt(lib: object, plaintext: bytes) -> bytes:
    key_id = _TestSECItem(0, None, 0)
    input_buffer = (ctypes.c_ubyte * len(plaintext)).from_buffer_copy(plaintext)
    input_item = _TestSECItem(0, input_buffer, len(plaintext))
    output_item = _TestSECItem()
    assert lib.PK11SDR_Encrypt(
        ctypes.byref(key_id),
        ctypes.byref(input_item),
        ctypes.byref(output_item),
        None,
    ) == 0
    try:
        return ctypes.string_at(output_item.data, output_item.len)
    finally:
        if output_item.data:
            lib.SECITEM_ZfreeItem(ctypes.byref(output_item), 0)


def _write_synthetic_dpapi_fixture(tmp_path: Path) -> dict[str, object]:
    dpapi = pytest.importorskip("impacket.dpapi")
    pytest.importorskip("Cryptodome")
    crypto = pytest.importorskip("cryptography.hazmat.primitives.ciphers.aead")
    from Cryptodome.Cipher import AES
    from Cryptodome.Hash import HMAC, MD4, SHA1, SHA512

    sid = "S-1-5-21-111-222-333-1001"
    password = "CorrectHorseBatteryStaple!"
    nt_hash = MD4.new(password.encode("utf-16le")).digest()
    masterkey_guid = UUID("11111111-2222-3333-8444-555555555555")
    masterkey = hashlib.sha512(b"apex synthetic offline dpapi masterkey").digest()
    wrapping_key = dpapi.deriveKeysFromUser(sid, password)[1]
    masterkey_bytes = _synthetic_dpapi_masterkey(dpapi, wrapping_key, masterkey)
    masterkey_file = dpapi.MasterKeyFile()
    masterkey_file["Version"] = 2
    masterkey_file["unk1"] = 0
    masterkey_file["unk2"] = 0
    masterkey_file["Guid"] = str(masterkey_guid).encode("utf-16le")
    masterkey_file["Unkown"] = 0
    masterkey_file["Policy"] = 0
    masterkey_file["Flags"] = 0
    masterkey_file["MasterKeyLen"] = len(masterkey_bytes)
    masterkey_file["BackupKeyLen"] = 0
    masterkey_file["CredHistLen"] = 0
    masterkey_file["DomainKeyLen"] = 0
    profile = (
        tmp_path
        / "Users"
        / "Alice"
        / "AppData"
        / "Roaming"
        / "Microsoft"
        / "Protect"
        / sid
    )
    profile.mkdir(parents=True)
    masterkey_path = profile / str(masterkey_guid)
    masterkey_path.write_bytes(masterkey_file.getData() + masterkey_bytes)

    plaintext = "offline dpapi plaintext 한글".encode()
    blob = _synthetic_dpapi_blob(
        dpapi,
        aes=AES,
        hmac=HMAC,
        sha1=SHA1,
        sha512=SHA512,
        masterkey_guid=masterkey_guid,
        masterkey=masterkey,
        plaintext=plaintext,
        salt=bytes.fromhex("202122232425262728292a2b2c2d2e2f"),
        hmac_value=bytes.fromhex(
            "303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f"
        ),
    )
    blob_path = tmp_path / "fixture.dpapi"
    blob_path.write_bytes(blob)

    chromium_key = hashlib.sha256(b"apex synthetic chromium local state key").digest()
    local_state_blob = _synthetic_dpapi_blob(
        dpapi,
        aes=AES,
        hmac=HMAC,
        sha1=SHA1,
        sha512=SHA512,
        masterkey_guid=masterkey_guid,
        masterkey=masterkey,
        plaintext=chromium_key,
        salt=bytes.fromhex("404142434445464748494a4b4c4d4e4f"),
        hmac_value=bytes.fromhex(
            "505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f"
        ),
    )
    local_state = tmp_path / "Local State"
    local_state.write_text(
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
    chromium_plaintext = "local state chromium secret 한글".encode()
    chromium_secret = (
        b"v10"
        + nonce
        + crypto.AESGCM(chromium_key).encrypt(nonce, chromium_plaintext, None)
    )
    chromium_secret_path = tmp_path / "chromium-secret.bin"
    chromium_secret_path.write_bytes(chromium_secret)
    return {
        "sid": sid,
        "password": password,
        "nt_hash": nt_hash,
        "masterkey_guid": str(masterkey_guid),
        "masterkey": masterkey,
        "masterkey_path": masterkey_path,
        "plaintext": plaintext,
        "blob": blob,
        "blob_path": blob_path,
        "local_state": local_state,
        "chromium_key": chromium_key,
        "chromium_secret": chromium_secret,
        "chromium_secret_path": chromium_secret_path,
        "chromium_plaintext": chromium_plaintext,
    }


def _synthetic_dpapi_masterkey(dpapi: object, wrapping_key: bytes, masterkey: bytes) -> bytes:
    from Cryptodome.Cipher import AES
    from Cryptodome.Hash import HMAC, SHA512

    salt = bytes.fromhex("00112233445566778899aabbccddeeff")
    hmac_salt = bytes.fromhex("102132435465768798a9babbdcedfe0f")
    rounds = 8000
    hmac_value = HMAC.new(HMAC.new(wrapping_key, hmac_salt, SHA512).digest(), masterkey, SHA512)
    cleartext = hmac_salt + hmac_value.digest() + masterkey
    masterkey_record = dpapi.MasterKey()
    derived = masterkey_record.deriveKey(
        wrapping_key,
        salt,
        48,
        rounds,
        lambda passphrase, value: HMAC.new(passphrase, value, SHA512).digest(),
    )
    masterkey_record["Version"] = 2
    masterkey_record["Salt"] = salt
    masterkey_record["MasterKeyIterationCount"] = rounds
    masterkey_record["HashAlgo"] = dpapi.ALGORITHMS.CALG_SHA_512.value
    masterkey_record["CryptAlgo"] = dpapi.ALGORITHMS.CALG_AES_256.value
    masterkey_record["data"] = AES.new(
        derived[:32],
        AES.MODE_CBC,
        iv=derived[32:48],
    ).encrypt(cleartext)
    return masterkey_record.getData()


def _synthetic_dpapi_blob(
    dpapi: object,
    *,
    aes: object,
    hmac: object,
    sha1: object,
    sha512: object,
    masterkey_guid: UUID,
    masterkey: bytes,
    plaintext: bytes,
    salt: bytes,
    hmac_value: bytes,
) -> bytes:
    from Cryptodome.Util.Padding import pad

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


def test_dpapi_provider_reports_unavailable_without_plaintext() -> None:
    provider = DpapiUnavailableProvider(dependency_candidates=("definitely_missing_dpapi",))

    capability = provider.capabilities().to_schema_dict()
    result = provider.decrypt_blob(_derivation(), b"DPAPI\x00ciphertext").to_schema_dict()

    assert capability["runtime_status"] == "CAPABILITY_UNAVAILABLE"
    assert capability["warnings"][0]["code"] == "CAPABILITY_UNAVAILABLE"
    assert result["status"] == "CAPABILITY_UNAVAILABLE"
    assert result["metadata"]["ciphertext_length"] == len(b"DPAPI\x00ciphertext")
    assert result["metadata"]["ciphertext_emitted"] is False
    assert "plaintext_b64" not in result
    assert "DPAPI\x00ciphertext" not in str(result)


def test_dpapi_external_key_provider_decrypts_chromium_aes_gcm_secret(
    schema_validator,
) -> None:
    crypto = pytest.importorskip("cryptography.hazmat.primitives.ciphers.aead")
    key = b"\x01" * 32
    nonce = b"\x02" * 12
    plaintext = "한글 chromium secret".encode()
    encrypted = b"v10" + nonce + crypto.AESGCM(key).encrypt(nonce, plaintext, None)
    reference = SecretReference(
        secret_id="chromium-key",
        case_id="case-1",
        evidence_id="ev-1",
        key_source_kind="EXTERNAL_OFFLINE_KEY_MATERIAL",
        provider_id="fixture",
        source_kind="SYNTHETIC_FIXTURE",
    )
    material = SecretMaterial(reference=reference, value=key, algorithm="AES-GCM")
    provider = DpapiExternalKeyProvider()

    capability = provider.capabilities().to_schema_dict()
    redacted = provider.decrypt_chromium_secret(_derivation(), encrypted, material).to_schema_dict()
    emitted = provider.decrypt_chromium_secret(
        _derivation(),
        encrypted,
        material,
        include_plaintext=True,
    ).to_schema_dict(include_plaintext=True)
    failed = provider.decrypt_chromium_secret(
        _derivation(),
        encrypted[:-1] + bytes([encrypted[-1] ^ 0xFF]),
        material,
    ).to_schema_dict()
    invalid_key = provider.decrypt_chromium_secret(
        _derivation(),
        encrypted,
        SecretMaterial(reference=reference, value=b"short", algorithm="AES-GCM"),
    ).to_schema_dict()

    assert capability["runtime_status"] == "AVAILABLE_WITH_EXTERNAL_KEY"
    schema_validator.validate("secret-provider-capability.schema.json", capability)
    schema_validator.validate("decryption-result.schema.json", redacted)
    schema_validator.validate("decryption-result.schema.json", failed)
    assert redacted["status"] == "DECRYPTED"
    assert redacted["content_length"] == len(plaintext)
    assert redacted["metadata"]["plaintext_emitted"] is False
    assert redacted["metadata"]["key_source"]["length"] == 32
    assert "plaintext_b64" not in redacted
    assert "chromium secret" not in str(redacted)
    assert emitted["plaintext_b64"]
    assert failed["status"] == "AUTHENTICATION_FAILED"
    assert failed["metadata"]["failure_reason"] == "AES_GCM_AUTHENTICATION_FAILED"
    assert invalid_key["status"] == "INVALID_KEY"
    assert invalid_key["metadata"]["key_source"]["sha256"]


def test_dpapi_provider_inspects_chromium_local_state_key_source(
    tmp_path: Path,
    schema_validator,
) -> None:
    protected_key = b"synthetic-dpapi-protected-key"
    local_state = tmp_path / "Local State"
    local_state.write_text(
        json.dumps(
            {
                "os_crypt": {
                    "encrypted_key": base64.b64encode(b"DPAPI" + protected_key).decode("ascii")
                }
            }
        ),
        encoding="utf-8",
    )
    provider = DpapiUnavailableProvider()

    inspected = provider.inspect_chromium_local_state(
        case_id="case-1",
        evidence_id="ev-1",
        local_state_path=str(local_state),
        source_revision=7,
    )

    assert inspected["status"] == "KEY_UNAVAILABLE"
    assert inspected["source_kind"] == "CHROMIUM_LOCAL_STATE_DPAPI_KEY"
    assert inspected["fingerprint"]
    assert inspected["raw_locator"]["dpapi_prefix_present"] is True
    assert inspected["raw_locator"]["encrypted_key_emitted"] is False
    assert protected_key.decode("ascii") not in json.dumps(inspected)
    schema_validator.validate("dpapi-key-source.schema.json", inspected)


def test_dpapi_provider_reports_app_bound_local_state_as_unsupported(
    tmp_path: Path,
    schema_validator,
) -> None:
    local_state = tmp_path / "Local State"
    local_state.write_text(
        json.dumps({"os_crypt": {"app_bound_encrypted_key": "v20synthetic"}}),
        encoding="utf-8",
    )

    inspected = DpapiUnavailableProvider().inspect_chromium_local_state(
        case_id="case-1",
        evidence_id="ev-1",
        local_state_path=str(local_state),
    )

    assert inspected["status"] == "UNSUPPORTED_VERSION"
    assert inspected["warnings"][0]["code"] == "UNSUPPORTED_VERSION"
    schema_validator.validate("dpapi-key-source.schema.json", inspected)


def test_dpapi_offline_provider_decrypts_blob_with_password_nt_hash_and_masterkey(
    tmp_path: Path,
    schema_validator,
) -> None:
    fixture = _write_synthetic_dpapi_fixture(tmp_path)
    provider = DpapiOfflineProvider()

    capability = provider.capabilities().to_schema_dict()
    discovered = provider.discover_profiles(
        case_id="case-1",
        evidence_id="ev-1",
        root_path=str(tmp_path),
    )
    password_derivation = SecretDerivationInput(
        case_id="case-1",
        evidence_id="ev-1",
        key_source_kind="WINDOWS_USER_PASSWORD",
        parameters={
            "sid": fixture["sid"],
            "masterkey_path": str(fixture["masterkey_path"]),
            "password": fixture["password"],
        },
    )
    password_result = provider.decrypt_blob(
        password_derivation,
        fixture["blob"],  # type: ignore[arg-type]
    )
    nt_hash_result = provider.decrypt_blob(
        SecretDerivationInput(
            case_id="case-1",
            evidence_id="ev-1",
            key_source_kind="WINDOWS_NT_HASH",
            parameters={
                "sid": fixture["sid"],
                "masterkey_path": str(fixture["masterkey_path"]),
                "nt_hash_hex": fixture["nt_hash"].hex(),  # type: ignore[union-attr]
            },
        ),
        fixture["blob"],  # type: ignore[arg-type]
    )
    external_result = provider.decrypt_blob(
        SecretDerivationInput(
            case_id="case-1",
            evidence_id="ev-1",
            key_source_kind="EXTERNAL_MASTERKEY",
            parameters={"masterkey_hex": fixture["masterkey"].hex()},  # type: ignore[union-attr]
        ),
        fixture["blob"],  # type: ignore[arg-type]
    )
    wrong_password = provider.decrypt_blob(
        SecretDerivationInput(
            case_id="case-1",
            evidence_id="ev-1",
            key_source_kind="WINDOWS_USER_PASSWORD",
            parameters={
                "sid": fixture["sid"],
                "masterkey_path": str(fixture["masterkey_path"]),
                "password": "wrong-password",
            },
        ),
        fixture["blob"],  # type: ignore[arg-type]
    ).to_schema_dict()
    wrong_nt_hash = provider.decrypt_blob(
        SecretDerivationInput(
            case_id="case-1",
            evidence_id="ev-1",
            key_source_kind="WINDOWS_NT_HASH",
            parameters={
                "sid": fixture["sid"],
                "masterkey_path": str(fixture["masterkey_path"]),
                "nt_hash_hex": "00" * 16,
            },
        ),
        fixture["blob"],  # type: ignore[arg-type]
    ).to_schema_dict()

    assert capability["runtime_status"] == "IMPLEMENTED_RUNTIME"
    schema_validator.validate("secret-provider-capability.schema.json", capability)
    assert len(discovered) == 1
    assert discovered[0]["status"] == "KEY_UNAVAILABLE"
    assert discovered[0]["sid"] == fixture["sid"]
    schema_validator.validate("dpapi-key-source.schema.json", discovered[0])
    assert password_result.status == "DECRYPTED"
    assert password_result.plaintext == fixture["plaintext"]
    assert nt_hash_result.status == "DECRYPTED"
    assert nt_hash_result.plaintext == fixture["plaintext"]
    assert external_result.status == "DECRYPTED"
    assert external_result.plaintext == fixture["plaintext"]
    redacted = password_result.to_schema_dict()
    schema_validator.validate("decryption-result.schema.json", redacted)
    assert "plaintext_b64" not in redacted
    assert fixture["password"] not in json.dumps(redacted, ensure_ascii=False)
    assert fixture["plaintext"].decode() not in json.dumps(redacted, ensure_ascii=False)  # type: ignore[union-attr]
    assert wrong_password["status"] == "AUTHENTICATION_FAILED"
    assert wrong_nt_hash["status"] == "AUTHENTICATION_FAILED"


def test_dpapi_offline_provider_unwraps_chromium_local_state_and_secret(
    tmp_path: Path,
    schema_validator,
) -> None:
    fixture = _write_synthetic_dpapi_fixture(tmp_path)
    provider = DpapiOfflineProvider()
    derivation = SecretDerivationInput(
        case_id="case-1",
        evidence_id="ev-1",
        key_source_kind="WINDOWS_USER_PASSWORD",
        parameters={
            "sid": fixture["sid"],
            "masterkey_path": str(fixture["masterkey_path"]),
            "password": fixture["password"],
        },
    )

    local_state_key = provider.decrypt_chromium_local_state_key(
        derivation,
        local_state_path=str(fixture["local_state"]),
        source_revision=3,
    )
    key_material = SecretMaterial(
        reference=SecretReference(
            secret_id="fixture-local-state-key",
            case_id="case-1",
            evidence_id="ev-1",
            key_source_kind="BROWSER_LOCAL_STATE",
            provider_id=provider.provider_id,
            source_kind="CHROMIUM_LOCAL_STATE_DPAPI_KEY",
            source_path=str(fixture["local_state"]),
        ),
        value=local_state_key.plaintext or b"",
        algorithm="AES-GCM",
    )
    chromium_result = provider.decrypt_chromium_secret(
        SecretDerivationInput(
            case_id="case-1",
            evidence_id="ev-1",
            key_source_kind="BROWSER_LOCAL_STATE",
        ),
        fixture["chromium_secret"],  # type: ignore[arg-type]
        key_material,
    )

    assert local_state_key.status == "DECRYPTED"
    assert local_state_key.plaintext == fixture["chromium_key"]
    local_state_schema = local_state_key.to_schema_dict()
    schema_validator.validate("decryption-result.schema.json", local_state_schema)
    assert "plaintext_b64" not in local_state_schema
    assert fixture["chromium_key"].hex() not in json.dumps(local_state_schema)  # type: ignore[union-attr]
    assert chromium_result.status == "DECRYPTED"
    assert chromium_result.content_length == len(fixture["chromium_plaintext"])  # type: ignore[arg-type]
    assert "chromium secret" not in json.dumps(chromium_result.to_schema_dict())


def test_dpapi_offline_provider_reports_corrupt_masterkey_and_blob(tmp_path: Path) -> None:
    fixture = _write_synthetic_dpapi_fixture(tmp_path)
    provider = DpapiOfflineProvider()
    corrupt_masterkey = tmp_path / "corrupt-masterkey"
    corrupt_masterkey.write_bytes(b"not-a-masterkey")

    corrupt_masterkey_result = provider.decrypt_blob(
        SecretDerivationInput(
            case_id="case-1",
            evidence_id="ev-1",
            key_source_kind="WINDOWS_USER_PASSWORD",
            parameters={
                "sid": fixture["sid"],
                "masterkey_path": str(corrupt_masterkey),
                "password": fixture["password"],
            },
        ),
        fixture["blob"],  # type: ignore[arg-type]
    ).to_schema_dict()
    corrupt_blob_result = provider.decrypt_blob(
        SecretDerivationInput(
            case_id="case-1",
            evidence_id="ev-1",
            key_source_kind="WINDOWS_USER_PASSWORD",
            parameters={
                "sid": fixture["sid"],
                "masterkey_path": str(fixture["masterkey_path"]),
                "password": fixture["password"],
            },
        ),
        b"not-a-dpapi-blob",
    ).to_schema_dict()

    assert corrupt_masterkey_result["status"] == "CORRUPT_KEY_MATERIAL"
    assert corrupt_blob_result["status"] == "CORRUPT_KEY_MATERIAL"
    assert "not-a-masterkey" not in json.dumps(corrupt_masterkey_result)
    assert "not-a-dpapi-blob" not in json.dumps(corrupt_blob_result)


def test_dpapi_offline_cli_records_real_decryption_and_reopens(
    tmp_path: Path,
    capsys: object,
    monkeypatch,
) -> None:
    fixture = _write_synthetic_dpapi_fixture(tmp_path)
    db_path = tmp_path / "dpapi-runtime.db"
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    (evidence_root / "note.txt").write_text("synthetic evidence", encoding="utf-8")
    monkeypatch.setenv("APEX_TEST_DPAPI_PASSWORD", fixture["password"])

    assert (
        main(
            [
                "--db",
                str(db_path),
                "case",
                "create",
                "--name",
                "DPAPI Runtime",
                "--json",
            ]
        )
        == 0
    )
    case_id = json.loads(capsys.readouterr().out)["id"]
    assert (
        main(
            [
                "--db",
                str(db_path),
                "evidence",
                "add",
                "--case-id",
                case_id,
                "--path",
                str(evidence_root),
                "--json",
            ]
        )
        == 0
    )
    evidence_id = json.loads(capsys.readouterr().out)["id"]

    assert (
        main(
            [
                "--db",
                str(db_path),
                "secret",
                "dpapi",
                "decrypt-blob",
                "--case-id",
                case_id,
                "--evidence-id",
                evidence_id,
                "--key-source-kind",
                "WINDOWS_USER_PASSWORD",
                "--sid",
                fixture["sid"],  # type: ignore[list-item]
                "--masterkey-path",
                str(fixture["masterkey_path"]),
                "--password-env",
                "APEX_TEST_DPAPI_PASSWORD",
                "--input-file",
                str(fixture["blob_path"]),
                "--json",
            ]
        )
        == 0
    )
    output = json.loads(capsys.readouterr().out)
    assert output["status"] == "DECRYPTED"
    assert output["content_length"] == len(fixture["plaintext"])  # type: ignore[arg-type]
    assert "plaintext_b64" not in output
    assert fixture["password"] not in json.dumps(output)

    services = build_services(db_path)
    try:
        results = services.repository.list_decryption_results(case_id=case_id)
        assert [item["status"] for item in results] == ["DECRYPTED"]
        assert "plaintext_b64" not in results[0]
        assert fixture["plaintext"].decode() not in json.dumps(results[0], ensure_ascii=False)  # type: ignore[union-attr]
    finally:
        services.close()


def test_dpapi_runtime_verifier_decrypts_synthetic_fixture(
    tmp_path: Path,
    project_root: Path,
    cli_env: dict[str, str],
) -> None:
    fixture = _write_synthetic_dpapi_fixture(tmp_path)
    env = cli_env | {"APEX_TEST_DPAPI_PASSWORD": str(fixture["password"])}

    completed = subprocess.run(
        [
            sys.executable,
            str(project_root / "tools" / "verify_dpapi_runtime.py"),
            "--case-id",
            "case-1",
            "--evidence-id",
            "ev-1",
            "--input-file",
            str(fixture["blob_path"]),
            "--local-state-path",
            str(fixture["local_state"]),
            "--decrypt-local-state-key",
            "--sid",
            str(fixture["sid"]),
            "--masterkey-path",
            str(fixture["masterkey_path"]),
            "--password-env",
            "APEX_TEST_DPAPI_PASSWORD",
            "--require-available",
        ],
        check=False,
        capture_output=True,
        env=env,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
    payload = json.loads(completed.stdout)
    assert payload["capability"]["runtime_status"] == "IMPLEMENTED_RUNTIME"
    assert payload["decrypt"]["status"] == "DECRYPTED"
    assert payload["local_state_decrypt"]["status"] == "DECRYPTED"
    serialized = json.dumps(payload, ensure_ascii=False)
    assert "plaintext_b64" not in serialized
    assert fixture["password"] not in serialized
    assert fixture["plaintext"].decode() not in serialized  # type: ignore[union-attr]


def test_nss_provider_discovers_profile_candidates_but_decryption_is_unavailable(
    tmp_path: Path,
    schema_validator,
) -> None:
    profile = tmp_path / "Firefox" / "Profiles" / "abc.default-release"
    _write_synthetic_nss_profile(profile)
    provider = NssUnavailableProvider(dependency_candidates=("definitely_missing_nss",))

    discovered_profiles = provider.discover_profiles(
        case_id="case-1",
        evidence_id="ev-1",
        root_path=str(tmp_path),
    )
    discovered = discovered_profiles[0]
    result = provider.decrypt_logins(
        _derivation(),
        profile_path=str(profile),
        primary_password="do-not-emit",
    )[0].to_schema_dict()

    assert discovered["status"] == "NSS_CAPABILITY_UNAVAILABLE"
    assert discovered["schema_status"] == "SUPPORTED"
    assert discovered["key4_db_present"] is True
    assert discovered["logins_json_present"] is True
    assert discovered["fingerprint"]
    schema_validator.validate("nss-profile.schema.json", discovered)
    assert result["status"] == "CAPABILITY_UNAVAILABLE"
    assert result["metadata"]["profile"]["schema_status"] == "SUPPORTED"
    assert "plaintext_b64" not in result
    assert "do-not-emit" not in str(result)
    assert result["metadata"]["primary_password_supplied"] == "<redacted>"


def test_nss_lib_provider_decrypts_logins_without_primary_password(
    tmp_path: Path,
    schema_validator,
) -> None:
    fixture = _write_real_nss_profile(tmp_path / "Firefox" / "Profiles" / "real.default")
    provider = NssLibProvider()

    capability = provider.capabilities().to_schema_dict()
    discovered = provider.discover_profiles(
        case_id="case-1",
        evidence_id="ev-1",
        root_path=str(tmp_path),
    )
    results = provider.decrypt_logins(
        SecretDerivationInput(
            case_id="case-1",
            evidence_id="ev-1",
            key_source_kind="FIREFOX_KEY4_DB",
        ),
        profile_path=str(fixture["profile"]),
    )

    assert capability["runtime_status"] == "IMPLEMENTED_RUNTIME"
    schema_validator.validate("secret-provider-capability.schema.json", capability)
    assert len(discovered) == 1
    assert discovered[0]["status"] == "NSS_DECRYPTED"
    assert discovered[0]["primary_password_required"] is False
    schema_validator.validate("nss-profile.schema.json", discovered[0])
    assert len(results) == 1
    result = results[0]
    assert result.status == "NSS_DECRYPTED"
    assert fixture["username"] in result.plaintext  # type: ignore[operator]
    assert fixture["password"] in result.plaintext  # type: ignore[operator]
    redacted = result.to_schema_dict()
    schema_validator.validate("decryption-result.schema.json", redacted)
    serialized = json.dumps(redacted, ensure_ascii=False)
    assert "plaintext_b64" not in redacted
    assert fixture["username"].decode() not in serialized  # type: ignore[union-attr]
    assert fixture["password"].decode() not in serialized  # type: ignore[union-attr]
    assert redacted["metadata"]["username"]["length"] == len(fixture["username"])  # type: ignore[arg-type]
    assert redacted["metadata"]["username"]["redacted_preview"] == "<redacted>"
    assert redacted["metadata"]["password"] == "<redacted>"


def test_nss_lib_provider_primary_password_success_and_failures(tmp_path: Path) -> None:
    fixture = _write_real_nss_profile(
        tmp_path / "Firefox" / "Profiles" / "locked.default",
        primary_password="nss-primary-pass",
    )
    provider = NssLibProvider()
    derivation = SecretDerivationInput(
        case_id="case-1",
        evidence_id="ev-1",
        key_source_kind="FIREFOX_PRIMARY_PASSWORD",
    )

    discovered = provider.discover_profiles(
        case_id="case-1",
        evidence_id="ev-1",
        root_path=str(tmp_path),
    )
    missing_password = provider.decrypt_logins(
        derivation,
        profile_path=str(fixture["profile"]),
    )[0].to_schema_dict()
    wrong_password = provider.decrypt_logins(
        derivation,
        profile_path=str(fixture["profile"]),
        primary_password="wrong",
    )[0].to_schema_dict()
    correct_password = provider.decrypt_logins(
        derivation,
        profile_path=str(fixture["profile"]),
        primary_password="nss-primary-pass",
    )[0]

    assert discovered[0]["status"] == "PRIMARY_PASSWORD_REQUIRED"
    assert discovered[0]["primary_password_required"] is True
    assert missing_password["status"] == "PRIMARY_PASSWORD_REQUIRED"
    assert wrong_password["status"] == "INVALID_PRIMARY_PASSWORD"
    assert correct_password.status == "NSS_DECRYPTED"
    assert fixture["password"] in correct_password.plaintext  # type: ignore[operator]
    assert "nss-primary-pass" not in json.dumps(correct_password.to_schema_dict())


def test_nss_lib_provider_reports_corrupt_encrypted_login(tmp_path: Path) -> None:
    fixture = _write_real_nss_profile(tmp_path / "Firefox" / "Profiles" / "corrupt-login.default")
    logins_path = Path(fixture["profile"]) / "logins.json"
    payload = json.loads(logins_path.read_text(encoding="utf-8"))
    payload["logins"][0]["encryptedPassword"] = "not-valid-base64"
    logins_path.write_text(json.dumps(payload), encoding="utf-8")

    result = NssLibProvider().decrypt_logins(
        SecretDerivationInput(
            case_id="case-1",
            evidence_id="ev-1",
            key_source_kind="FIREFOX_KEY4_DB",
        ),
        profile_path=str(fixture["profile"]),
    )[0].to_schema_dict()

    assert result["status"] == "CORRUPT_KEY_MATERIAL"
    assert "not-valid-base64" not in json.dumps(result)


def test_nss_runtime_verifier_decrypts_synthetic_profile(
    tmp_path: Path,
    project_root: Path,
    cli_env: dict[str, str],
) -> None:
    fixture = _write_real_nss_profile(tmp_path / "Firefox" / "Profiles" / "verify.default")

    completed = subprocess.run(
        [
            sys.executable,
            str(project_root / "tools" / "verify_nss_runtime.py"),
            "--case-id",
            "case-1",
            "--evidence-id",
            "ev-1",
            "--root-path",
            str(tmp_path),
            "--profile-path",
            str(fixture["profile"]),
            "--require-available",
        ],
        check=False,
        capture_output=True,
        env=cli_env,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
    payload = json.loads(completed.stdout)
    assert payload["capability"]["runtime_status"] == "IMPLEMENTED_RUNTIME"
    assert payload["profiles"][0]["status"] == "NSS_DECRYPTED"
    assert payload["decrypt"][0]["status"] == "NSS_DECRYPTED"
    serialized = json.dumps(payload, ensure_ascii=False)
    assert "plaintext_b64" not in serialized
    assert fixture["username"].decode() not in serialized  # type: ignore[union-attr]
    assert fixture["password"].decode() not in serialized  # type: ignore[union-attr]


def test_nss_provider_reports_corrupt_components_and_missing_profiles(
    tmp_path: Path,
    schema_validator,
) -> None:
    corrupt = tmp_path / "Firefox" / "Profiles" / "corrupt.default"
    corrupt.mkdir(parents=True)
    (corrupt / "key4.db").write_bytes(b"not sqlite")
    (corrupt / "logins.json").write_text("{", encoding="utf-8")
    key_only = tmp_path / "Firefox" / "Profiles" / "key-only.default"
    key_only.mkdir(parents=True)
    with sqlite3.connect(key_only / "key4.db") as connection:
        connection.execute("CREATE TABLE nssPrivate (id PRIMARY KEY, a0 BLOB)")
    provider = NssUnavailableProvider(dependency_candidates=("definitely_missing_nss",))

    profiles = provider.discover_profiles(
        case_id="case-1",
        evidence_id="ev-1",
        root_path=str(tmp_path),
    )

    assert {item["profile_path"] for item in profiles} == {str(corrupt), str(key_only)}
    by_status = {item["profile_path"]: item for item in profiles}
    assert by_status[str(corrupt)]["schema_status"] == "NSS_SCHEMA_UNSUPPORTED"
    assert by_status[str(key_only)]["status"] == "NSS_PROFILE_INCOMPLETE"
    assert {warning["code"] for warning in by_status[str(corrupt)]["warnings"]} == {
        "NSS_KEY4_DB_CORRUPT",
        "NSS_LOGINS_JSON_CORRUPT",
    }
    for profile in profiles:
        schema_validator.validate("nss-profile.schema.json", profile)


def test_nss_provider_discovers_multiple_profiles(tmp_path: Path) -> None:
    first = tmp_path / "Profiles" / "first.default"
    second = tmp_path / "Profiles" / "second.default-release"
    _write_synthetic_nss_profile(first)
    _write_synthetic_nss_profile(second)

    profiles = NssUnavailableProvider(
        dependency_candidates=("definitely_missing_nss",)
    ).discover_profiles(
        case_id="case-1",
        evidence_id="ev-1",
        root_path=str(tmp_path),
    )

    assert [Path(item["profile_path"]).name for item in profiles] == [
        "first.default",
        "second.default-release",
    ]


def test_kakaotalk_provider_hashes_store_and_requires_key(tmp_path: Path) -> None:
    store = tmp_path / "KakaoTalk" / "kakaotalk.db"
    store.parent.mkdir()
    store.write_bytes(b"encrypted-kakao-fixture-with-token=secret")
    provider = KakaoTalkEncryptedStoreProvider()

    capability = provider.capabilities().to_schema_dict()
    inspected = provider.inspect_store(
        case_id="case-1",
        evidence_id="ev-1",
        store_path=str(store),
    )
    result = provider.decrypt_store(_derivation(), store_path=str(store)).to_schema_dict()

    assert capability["runtime_status"] == "AVAILABLE_WITH_EXTERNAL_KEY"
    assert any(item["code"] == "BLOCKED_EXTERNAL_FIXTURE" for item in capability["warnings"])
    assert inspected["status"] == "KEY_UNAVAILABLE"
    assert inspected["automatic_key_acquisition_status"] == "BLOCKED_EXTERNAL_FIXTURE"
    assert inspected["redistributable_fixture_status"] == "BLOCKED_EXTERNAL_FIXTURE"
    assert inspected["real_kakaotalk_fixture_verified"] is False
    assert inspected["raw_store_emitted"] is False
    assert result["status"] == "KEY_UNAVAILABLE"
    assert result["metadata"]["store_length"] == len(b"encrypted-kakao-fixture-with-token=secret")
    assert "plaintext_b64" not in result
    assert "token=secret" not in str(result)


def test_kakaotalk_provider_decrypts_external_key_contract_fixture(
    tmp_path: Path,
    schema_validator,
) -> None:
    fixture = _write_kakaotalk_external_key_contract_fixture(tmp_path)
    provider = KakaoTalkEncryptedStoreProvider()
    derivation = SecretDerivationInput(
        case_id="case-1",
        evidence_id="ev-1",
        key_source_kind="KAKAOTALK_KPRAGMA_AND_SERVER_NONCE",
        parameters={
            "platform": "WINDOWS_DESKTOP",
            "application_version": "2.0.8.990",
            "database_schema_version": "chatLogs",
            "pragma_key": fixture["pragma_key"],
            "user_nonce": fixture["user_nonce"],
        },
    )

    result = provider.decrypt_store(derivation, store_path=str(fixture["store"]))
    schema = result.to_schema_dict()

    assert result.status == "KAKAOTALK_DECRYPTED"
    assert result.plaintext == fixture["plaintext"]
    assert schema["status"] == "KAKAOTALK_DECRYPTED"
    assert schema["content_sha256"] == hashlib.sha256(fixture["plaintext"]).hexdigest()
    assert schema["metadata"]["message_count"] == 2
    assert schema["metadata"]["algorithm_contract_fixture_status"] == "CONTRACT_ONLY"
    assert schema["metadata"]["real_kakaotalk_fixture_verified"] is False
    assert schema["metadata"]["sqlite_integrity_check"] == "ok"
    assert schema["metadata"]["messages"][0]["message_preview"] == fixture["message"]
    assert schema["metadata"]["messages"][1]["attachment_present"] is True
    assert schema["metadata"]["messages"][1]["deleted_candidate"] is True
    assert schema["metadata"]["search_projection_ready"] is True
    assert schema["metadata"]["timeline_projection_ready"] is True
    assert schema["citations"]
    assert "plaintext_b64" not in schema
    assert "token=secret" not in str(schema)
    schema_validator.validate("decryption-result.schema.json", schema)


def test_kakaotalk_provider_rejects_wrong_key_and_unsupported_version(
    tmp_path: Path,
) -> None:
    fixture = _write_kakaotalk_external_key_contract_fixture(tmp_path)
    provider = KakaoTalkEncryptedStoreProvider()
    wrong_key = SecretDerivationInput(
        case_id="case-1",
        evidence_id="ev-1",
        key_source_kind="KAKAOTALK_KPRAGMA_AND_SERVER_NONCE",
        parameters={
            "platform": "WINDOWS_DESKTOP",
            "application_version": "2.0.8.990",
            "database_schema_version": "chatLogs",
            "pragma_key": fixture["pragma_key"],
            "user_nonce": "wrong",
        },
    )
    unsupported = SecretDerivationInput(
        case_id="case-1",
        evidence_id="ev-1",
        key_source_kind="KAKAOTALK_KPRAGMA_AND_SERVER_NONCE",
        parameters={
            "platform": "WINDOWS_DESKTOP",
            "application_version": "3.0.0.0",
            "database_schema_version": "chatLogs",
            "pragma_key": fixture["pragma_key"],
            "user_nonce": fixture["user_nonce"],
        },
    )

    wrong_result = provider.decrypt_store(wrong_key, store_path=str(fixture["store"]))
    unsupported_result = provider.decrypt_store(unsupported, store_path=str(fixture["store"]))

    assert wrong_result.status == "AUTHENTICATION_FAILED"
    assert wrong_result.plaintext is None
    assert unsupported_result.status == "UNSUPPORTED_VERSION"
    assert unsupported_result.plaintext is None


def test_kakaotalk_provider_reports_corrupt_db_with_correct_external_key(
    tmp_path: Path,
) -> None:
    pragma_key = base64.b64encode(hashlib.sha512(b"apex-kakao-pragma").digest()).decode(
        "ascii"
    )
    user_nonce = "1234567890"
    key, iv = _kakao_key_iv(pragma_key, user_nonce)
    corrupt_store = tmp_path / "chatLogs_corrupt.edb"
    corrupt_store.write_bytes(
        _encrypt_kakaotalk_contract_bytes(b"SQLite format 3\x00" + (b"\x00" * 256), key, iv)
    )
    provider = KakaoTalkEncryptedStoreProvider()
    derivation = SecretDerivationInput(
        case_id="case-1",
        evidence_id="ev-1",
        key_source_kind="KAKAOTALK_KPRAGMA_AND_SERVER_NONCE",
        parameters={
            "platform": "WINDOWS_DESKTOP",
            "application_version": "2.0.8.990",
            "database_schema_version": "chatLogs",
            "pragma_key": pragma_key,
            "user_nonce": user_nonce,
        },
    )

    result = provider.decrypt_store(derivation, store_path=str(corrupt_store)).to_schema_dict()

    assert result["status"] == "FAILED"
    assert result["attempt"]["error_code"] == "KAKAOTALK_CORRUPT_DB"
    assert result["metadata"]["raw_store_emitted"] is False
    assert result["metadata"]["plaintext_emitted"] is False


def test_kakaotalk_verifier_decrypts_external_key_contract_without_real_fixture_claim(
    tmp_path: Path,
    project_root: Path,
    cli_env: dict[str, str],
) -> None:
    fixture = _write_kakaotalk_external_key_contract_fixture(tmp_path)
    cli_env = {
        **cli_env,
        "APEX_KAKAO_PRAGMA_KEY": str(fixture["pragma_key"]),
        "APEX_KAKAO_USER_NONCE": str(fixture["user_nonce"]),
    }

    completed = subprocess.run(
        [
            sys.executable,
            str(project_root / "tools" / "verify_kakaotalk_runtime.py"),
            "--store-path",
            str(fixture["store"]),
            "--pragma-key-env",
            "APEX_KAKAO_PRAGMA_KEY",
            "--user-nonce-env",
            "APEX_KAKAO_USER_NONCE",
            "--expect-message",
            str(fixture["message"]),
            "--require-decrypted",
            "--require-available",
        ],
        check=False,
        capture_output=True,
        env=cli_env,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
    payload = json.loads(completed.stdout)
    assert payload["key_acquisition"]["status"] == "BLOCKED_EXTERNAL_FIXTURE"
    assert payload["decrypt"]["status"] == "KAKAOTALK_DECRYPTED"
    assert payload["verification"]["message_count"] == 2
    assert payload["verification"]["expected_message_present"] is True
    assert payload["verification"]["real_kakaotalk_fixture_verified"] is False


def test_secret_provider_and_decryption_schemas_validate_runtime_boundaries(
    schema_validator,
) -> None:
    provider = DpapiUnavailableProvider(dependency_candidates=("definitely_missing_dpapi",))
    request = _derivation().to_schema_dict()
    result = provider.decrypt_blob(_derivation(), b"DPAPI\x00ciphertext").to_schema_dict()

    schema_validator.validate(
        "secret-provider-capability.schema.json",
        provider.capabilities().to_schema_dict(),
    )
    schema_validator.validate("decryption-request.schema.json", request)
    schema_validator.validate("decryption-result.schema.json", result)


def test_secret_cli_capability_and_kakaotalk_inspect_are_structured(
    tmp_path: Path,
    capsys: object,
) -> None:
    db_path = tmp_path / "cli.db"
    store = tmp_path / "KakaoTalk" / "kakaotalk.db"
    store.parent.mkdir()
    store.write_bytes(b"encrypted-kakao-cli-fixture")

    capability_exit = main(
        [
            "--db",
            str(db_path),
            "secret",
            "capability",
            "--provider",
            "all",
            "--json",
        ]
    )
    capability_output = capsys.readouterr().out
    blob = tmp_path / "dpapi.blob"
    blob.write_bytes(b"DPAPI-alias-fixture")
    dpapi_exit = main(
        [
            "--db",
            str(db_path),
            "secret",
            "decrypt-dpapi",
            "--case-id",
            "case-1",
            "--evidence-id",
            "ev-1",
            "--input-file",
            str(blob),
            "--json",
        ]
    )
    dpapi_output = capsys.readouterr().out
    inspect_exit = main(
        [
            "--db",
            str(db_path),
            "secret",
            "kakaotalk",
            "inspect",
            "--case-id",
            "case-1",
            "--evidence-id",
            "ev-1",
            "--path",
            str(store),
            "--json",
        ]
    )
    inspect_output = capsys.readouterr().out
    local_state = tmp_path / "Local State"
    local_state.write_text(
        json.dumps(
            {
                "os_crypt": {
                    "encrypted_key": base64.b64encode(b"DPAPIsynthetic-cli-key").decode("ascii")
                }
            }
        ),
        encoding="utf-8",
    )
    local_state_exit = main(
        [
            "--db",
            str(db_path),
            "secret",
            "dpapi",
            "inspect-local-state",
            "--case-id",
            "case-1",
            "--evidence-id",
            "ev-1",
            "--local-state-path",
            str(local_state),
            "--json",
        ]
    )
    local_state_output = capsys.readouterr().out

    capabilities = json.loads(capability_output)
    dpapi_result = json.loads(dpapi_output)
    inspected = json.loads(inspect_output)
    local_state_result = json.loads(local_state_output)
    assert capability_exit == 0
    assert dpapi_exit == 0
    assert inspect_exit == 0
    assert local_state_exit == 0
    assert {item["capability_type"] for item in capabilities} == {
        "DPAPI_PROVIDER",
        "NSS_PROVIDER",
        "KAKAOTALK_PROVIDER",
    }
    assert dpapi_result["status"] in {"CAPABILITY_UNAVAILABLE", "CORRUPT_KEY_MATERIAL"}
    assert dpapi_result["metadata"]["ciphertext_emitted"] is False
    assert inspected["status"] == "KEY_UNAVAILABLE"
    assert inspected["raw_store_emitted"] is False
    assert local_state_result["status"] == "KEY_UNAVAILABLE"
    assert local_state_result["raw_locator"]["encrypted_key_emitted"] is False
