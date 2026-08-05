from __future__ import annotations

import base64
import json
import sqlite3
from pathlib import Path

import pytest

from apex_forensic.adapters.decryption import (
    DpapiExternalKeyProvider,
    DpapiUnavailableProvider,
    KakaoTalkEncryptedStoreProvider,
    NssUnavailableProvider,
)
from apex_forensic.cli.commands import main
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

    assert capability["runtime_status"] == "KEY_UNAVAILABLE"
    assert inspected["status"] == "KEY_UNAVAILABLE"
    assert inspected["raw_store_emitted"] is False
    assert result["status"] == "KEY_UNAVAILABLE"
    assert result["metadata"]["store_length"] == len(b"encrypted-kakao-fixture-with-token=secret")
    assert "plaintext_b64" not in result
    assert "token=secret" not in str(result)


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
    assert dpapi_result["status"] == "CAPABILITY_UNAVAILABLE"
    assert dpapi_result["metadata"]["ciphertext_emitted"] is False
    assert inspected["status"] == "KEY_UNAVAILABLE"
    assert inspected["raw_store_emitted"] is False
    assert local_state_result["status"] == "KEY_UNAVAILABLE"
    assert local_state_result["raw_locator"]["encrypted_key_emitted"] is False
