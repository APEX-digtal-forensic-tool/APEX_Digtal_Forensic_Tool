"""Firefox NSS provider boundary."""

import base64
import binascii
import ctypes
import ctypes.util
import hashlib
import importlib.util
import json
import sqlite3
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from apex_forensic.constants import ENGINE_VERSION
from apex_forensic.domain.errors import DecryptionError
from apex_forensic.domain.models import (
    DecryptionAttempt,
    DecryptionResult,
    SecretDerivationInput,
    SecretProviderCapability,
)

MAX_KEY4_DB_BYTES = 64 * 1024 * 1024
MAX_LOGINS_JSON_BYTES = 16 * 1024 * 1024
SUPPORTED_LOGINS_JSON_VERSIONS = {3}
_NSS_LOCK = threading.Lock()


class _SECItem(ctypes.Structure):
    _fields_ = [
        ("type", ctypes.c_uint),
        ("data", ctypes.POINTER(ctypes.c_ubyte)),
        ("len", ctypes.c_uint),
    ]


class NssUnavailableProvider:
    """Structured unavailable boundary for offline Firefox NSS decryption."""

    provider_id = "apex.firefox.nss"
    provider_version = ENGINE_VERSION

    def __init__(self, *, dependency_candidates: tuple[str, ...] = ("nss", "firefox_decrypt")):
        self._dependency_candidates = dependency_candidates

    def capabilities(self) -> SecretProviderCapability:
        missing = [
            name for name in self._dependency_candidates if not _dependency_available(name)
        ]
        return SecretProviderCapability(
            provider_id=self.provider_id,
            provider_version=self.provider_version,
            capability_type="NSS_PROVIDER",
            runtime_status="CAPABILITY_UNAVAILABLE",
            supported_key_sources=["FIREFOX_KEY4_DB", "FIREFOX_PRIMARY_PASSWORD"],
            supported_algorithms=["FIREFOX_NSS_LOGINS_JSON"],
            requires_host=False,
            requires_network=False,
            generated_at=datetime.now(UTC),
            warnings=[
                {
                    "code": "CAPABILITY_UNAVAILABLE",
                    "developer_message": (
                        "Firefox NSS key database decryption backend is not installed or "
                        "configured."
                    ),
                    "details": {"missing_dependency_candidates": missing},
                }
            ],
        )

    def discover_profiles(
        self,
        *,
        case_id: str,
        evidence_id: str,
        root_path: str,
    ) -> list[dict[str, object]]:
        root = Path(root_path)
        if not root.exists():
            return []
        profile_dirs = {
            candidate.parent
            for component in ("key4.db", "logins.json")
            for candidate in root.rglob(component)
        }
        return [
            _inspect_profile(
                case_id=case_id,
                evidence_id=evidence_id,
                profile_path=profile_path,
                root_path=root,
            )
            for profile_path in sorted(profile_dirs)
        ]

    def decrypt_logins(
        self,
        derivation_input: SecretDerivationInput,
        *,
        profile_path: str,
        primary_password: str | None = None,
        cancellation_requested: bool = False,
    ) -> list[DecryptionResult]:
        del cancellation_requested
        derivation_input.assert_references_same_case()
        now = datetime.now(UTC)
        profile = _inspect_profile(
            case_id=derivation_input.case_id,
            evidence_id=derivation_input.evidence_id,
            profile_path=Path(profile_path),
            root_path=None,
        )
        if profile["status"] == "NSS_PROFILE_INCOMPLETE":
            error_code = "FIREFOX_NSS_PROFILE_INCOMPLETE"
            error_message = "Firefox NSS profile is missing key4.db or logins.json."
        elif profile["schema_status"] == "NSS_SCHEMA_UNSUPPORTED":
            error_code = "FIREFOX_NSS_SCHEMA_UNSUPPORTED"
            error_message = "Firefox NSS profile components are corrupt or unsupported."
        else:
            error_code = "FIREFOX_NSS_BACKEND_UNAVAILABLE"
            error_message = "Firefox NSS backend unavailable."
        return [
            DecryptionResult(
                attempt=DecryptionAttempt(
                    attempt_id=f"nss-{uuid4()}",
                    case_id=derivation_input.case_id,
                    evidence_id=derivation_input.evidence_id,
                    provider_id=self.provider_id,
                    provider_version=self.provider_version,
                    algorithm="FIREFOX_NSS_LOGINS_JSON",
                    key_source_kind=derivation_input.key_source_kind,
                    status="CAPABILITY_UNAVAILABLE",
                    started_at=now,
                    completed_at=now,
                    warnings=[
                        {
                            "code": "CAPABILITY_UNAVAILABLE",
                            "developer_message": (
                                "Firefox login decryption requires an installed NSS backend and "
                                "validated key database handling."
                            ),
                        }
                    ],
                    error_code=error_code,
                    error_message=error_message,
                ),
                status="CAPABILITY_UNAVAILABLE",
                output_kind="FIREFOX_LOGIN_RECORDS",
                metadata={
                    "profile": profile,
                    "primary_password_supplied": primary_password is not None,
                    "primary_password_emitted": False,
                    "success_without_key": False,
                    "secret_fields_emitted": False,
                },
            )
        ]


class NssLibProvider:
    """Offline Firefox NSS runtime using libnss3 PK11SDR decryption."""

    provider_id = "apex.firefox.nss"
    provider_version = ENGINE_VERSION

    def capabilities(self) -> SecretProviderCapability:
        library_path = _find_nss_library()
        available = library_path is not None
        return SecretProviderCapability(
            provider_id=self.provider_id,
            provider_version=self.provider_version,
            capability_type="NSS_PROVIDER",
            runtime_status="IMPLEMENTED_RUNTIME" if available else "CAPABILITY_UNAVAILABLE",
            supported_key_sources=["FIREFOX_KEY4_DB", "FIREFOX_PRIMARY_PASSWORD"],
            supported_algorithms=["FIREFOX_NSS_LOGINS_JSON", "PK11SDR"],
            requires_host=False,
            requires_network=False,
            generated_at=datetime.now(UTC),
            warnings=[]
            if available
            else [
                {
                    "code": "CAPABILITY_UNAVAILABLE",
                    "developer_message": "Firefox NSS runtime requires libnss3.",
                    "details": {"missing_dependency_candidates": ["libnss3"]},
                }
            ],
        )

    def discover_profiles(
        self,
        *,
        case_id: str,
        evidence_id: str,
        root_path: str,
    ) -> list[dict[str, object]]:
        profiles = NssUnavailableProvider().discover_profiles(
            case_id=case_id,
            evidence_id=evidence_id,
            root_path=root_path,
        )
        if _find_nss_library() is None:
            return profiles
        return [self._with_runtime_status(profile) for profile in profiles]

    def decrypt_logins(
        self,
        derivation_input: SecretDerivationInput,
        *,
        profile_path: str,
        primary_password: str | None = None,
        cancellation_requested: bool = False,
    ) -> list[DecryptionResult]:
        del cancellation_requested
        derivation_input.assert_references_same_case()
        profile = _inspect_profile(
            case_id=derivation_input.case_id,
            evidence_id=derivation_input.evidence_id,
            profile_path=Path(profile_path),
            root_path=None,
        )
        if _find_nss_library() is None:
            return NssUnavailableProvider().decrypt_logins(
                derivation_input,
                profile_path=profile_path,
                primary_password=primary_password,
            )
        if profile["status"] == "NSS_PROFILE_INCOMPLETE":
            return [
                self._result(
                    derivation_input,
                    status="NSS_PROFILE_INCOMPLETE",
                    error_code="FIREFOX_NSS_PROFILE_INCOMPLETE",
                    error_message="Firefox NSS profile is missing key4.db or logins.json.",
                    metadata={
                        "profile": profile,
                        "primary_password_supplied": primary_password is not None,
                    },
                )
            ]
        if profile["schema_status"] == "NSS_SCHEMA_UNSUPPORTED":
            return [
                self._result(
                    derivation_input,
                    status="NSS_SCHEMA_UNSUPPORTED",
                    error_code="FIREFOX_NSS_SCHEMA_UNSUPPORTED",
                    error_message="Firefox NSS profile components are corrupt or unsupported.",
                    metadata={
                        "profile": profile,
                        "primary_password_supplied": primary_password is not None,
                    },
                )
            ]
        try:
            logins = _read_logins_json(Path(profile_path) / "logins.json")
        except DecryptionError as error:
            return [
                self._result(
                    derivation_input,
                    status=error.code,
                    error_code=error.code,
                    error_message=error.developer_message,
                    metadata={
                        "profile": profile,
                        "primary_password_supplied": primary_password is not None,
                    },
                )
            ]
        with _NSS_LOCK:
            runtime = _NssRuntime(Path(profile_path))
            try:
                runtime.open()
                password_status = runtime.authenticate(primary_password)
                if password_status != "NSS_DECRYPTED":
                    return [
                        self._result(
                            derivation_input,
                            status=password_status,
                            error_code=password_status,
                            error_message=_nss_password_error_message(password_status),
                            metadata={
                                "profile": profile | {"status": password_status},
                                "primary_password_supplied": primary_password is not None,
                                "secret_fields_emitted": False,
                            },
                        )
                    ]
                results: list[DecryptionResult] = []
                for index, row in enumerate(logins):
                    results.append(
                        self._decrypt_login_row(
                            runtime,
                            derivation_input,
                            profile=profile | {"status": "NSS_DECRYPTED"},
                            profile_path=Path(profile_path),
                            row=row,
                            index=index,
                            primary_password_supplied=primary_password is not None,
                        )
                    )
                return results
            except DecryptionError as error:
                return [
                    self._result(
                        derivation_input,
                        status=error.code,
                        error_code=error.code,
                        error_message=error.developer_message,
                        metadata={
                            "profile": profile,
                            "primary_password_supplied": primary_password is not None,
                            "secret_fields_emitted": False,
                        },
                    )
                ]
            finally:
                runtime.close()

    def _with_runtime_status(self, profile: dict[str, object]) -> dict[str, object]:
        if profile.get("schema_status") != "SUPPORTED":
            return profile
        with _NSS_LOCK:
            runtime = _NssRuntime(Path(str(profile["profile_path"])))
            try:
                runtime.open()
                status = runtime.authenticate(None)
                return profile | {
                    "status": status,
                    "primary_password_required": status == "PRIMARY_PASSWORD_REQUIRED",
                }
            except DecryptionError:
                return profile | {
                    "status": "NSS_CAPABILITY_UNAVAILABLE",
                    "primary_password_required": None,
                }
            finally:
                runtime.close()

    def _decrypt_login_row(
        self,
        runtime: "_NssRuntime",
        derivation_input: SecretDerivationInput,
        *,
        profile: dict[str, object],
        profile_path: Path,
        row: dict[str, Any],
        index: int,
        primary_password_supplied: bool,
    ) -> DecryptionResult:
        login_id = row.get("id", index)
        hostname = row.get("hostname")
        try:
            username = runtime.decrypt_base64(str(row.get("encryptedUsername", "")))
            password = runtime.decrypt_base64(str(row.get("encryptedPassword", "")))
        except (DecryptionError, UnicodeDecodeError) as error:
            code = error.code if isinstance(error, DecryptionError) else "AUTHENTICATION_FAILED"
            message = (
                error.developer_message
                if isinstance(error, DecryptionError)
                else "Firefox login row could not be decoded as UTF-8."
            )
            return self._result(
                derivation_input,
                status=code,
                error_code=code,
                error_message=message,
                metadata={
                    "profile": profile,
                    "login_id": login_id,
                    "hostname": hostname,
                    "row_index": index,
                    "primary_password_supplied": primary_password_supplied,
                    "secret_fields_emitted": False,
                },
            )
        plaintext = json.dumps(
            {
                "hostname": hostname,
                "username": username.decode("utf-8"),
                "password": password.decode("utf-8"),
            },
            ensure_ascii=False,
            sort_keys=True,
        ).encode("utf-8")
        return self._result(
            derivation_input,
            status="NSS_DECRYPTED",
            error_code=None,
            error_message=None,
            plaintext=plaintext,
            citations=[
                {
                    "case_id": derivation_input.case_id,
                    "evidence_id": derivation_input.evidence_id,
                    "source_kind": "FIREFOX_LOGINS_JSON",
                    "source_path": str(profile_path / "logins.json"),
                    "raw_locator": {
                        "json_pointer": f"/logins/{index}",
                        "login_id": login_id,
                    },
                }
            ],
            metadata={
                "profile": profile,
                "login_id": login_id,
                "hostname": hostname,
                "row_index": index,
                "username": _secret_summary(
                    f"firefox-login-{login_id}-username",
                    derivation_input.case_id,
                    username,
                    key_source_kind=derivation_input.key_source_kind,
                ),
                "password": _secret_summary(
                    f"firefox-login-{login_id}-password",
                    derivation_input.case_id,
                    password,
                    key_source_kind=derivation_input.key_source_kind,
                ),
                "primary_password_supplied": primary_password_supplied,
                "secret_fields_emitted": False,
                "provider_library": _find_nss_library(),
            },
            warnings=[
                {
                    "code": "PLAINTEXT_REDACTED",
                    "developer_message": (
                        "Firefox login username/password were decrypted and redacted."
                    ),
                }
            ],
        )

    def _result(
        self,
        derivation_input: SecretDerivationInput,
        *,
        status: str,
        error_code: str | None,
        error_message: str | None,
        metadata: dict[str, Any],
        plaintext: bytes | None = None,
        citations: list[dict[str, Any]] | None = None,
        warnings: list[dict[str, Any]] | None = None,
    ) -> DecryptionResult:
        now = datetime.now(UTC)
        return DecryptionResult(
            attempt=DecryptionAttempt(
                attempt_id=f"nss-{uuid4()}",
                case_id=derivation_input.case_id,
                evidence_id=derivation_input.evidence_id,
                provider_id=self.provider_id,
                provider_version=self.provider_version,
                algorithm="FIREFOX_NSS_LOGINS_JSON",
                key_source_kind=derivation_input.key_source_kind,
                status=status,
                started_at=now,
                completed_at=now,
                warnings=warnings or [],
                error_code=error_code,
                error_message=error_message,
            ),
            status=status,
            plaintext=plaintext,
            output_kind="FIREFOX_LOGIN_RECORDS",
            citations=citations or [],
            metadata=metadata,
        )


class _NssRuntime:
    def __init__(self, profile_path: Path) -> None:
        self._profile_path = profile_path
        self._lib = _load_nss_library()
        self._slot: int | None = None
        self._opened = False

    def open(self) -> None:
        config = f"sql:{self._profile_path}".encode()
        if self._lib.NSS_Init(config) != 0:
            raise DecryptionError(
                "NSS_CAPABILITY_UNAVAILABLE",
                "NSS could not initialize the Firefox profile.",
                target="profile_path",
                details={"profile_path": str(self._profile_path), "nss_error": self.error()},
            )
        self._opened = True
        slot = self._lib.PK11_GetInternalKeySlot()
        if not slot:
            raise DecryptionError(
                "NSS_CAPABILITY_UNAVAILABLE",
                "NSS internal key slot is unavailable.",
                target="key4.db",
                details={"nss_error": self.error()},
            )
        self._slot = int(slot)

    def authenticate(self, primary_password: str | None) -> str:
        if self._slot is None:
            raise DecryptionError(
                "NSS_CAPABILITY_UNAVAILABLE",
                "NSS profile is not initialized.",
                target="profile_path",
            )
        password = primary_password if primary_password is not None else ""
        encoded = password.encode("utf-8")
        if self._lib.PK11_CheckUserPassword(self._slot, encoded) != 0:
            return (
                "INVALID_PRIMARY_PASSWORD"
                if primary_password is not None
                else "PRIMARY_PASSWORD_REQUIRED"
            )
        if self._lib.PK11_Authenticate(self._slot, 1, None) != 0:
            return (
                "INVALID_PRIMARY_PASSWORD"
                if primary_password is not None
                else "PRIMARY_PASSWORD_REQUIRED"
            )
        return "NSS_DECRYPTED"

    def decrypt_base64(self, encrypted_value: str) -> bytes:
        try:
            encrypted = base64.b64decode(encrypted_value.encode("ascii"), validate=True)
        except (UnicodeEncodeError, binascii.Error) as error:
            raise DecryptionError(
                "CORRUPT_KEY_MATERIAL",
                "Firefox login encrypted value is not valid base64.",
                target="logins.json",
            ) from error
        input_buffer = (ctypes.c_ubyte * len(encrypted)).from_buffer_copy(encrypted)
        input_item = _SECItem(0, input_buffer, len(encrypted))
        output_item = _SECItem()
        if (
            self._lib.PK11SDR_Decrypt(
                ctypes.byref(input_item),
                ctypes.byref(output_item),
                None,
            )
            != 0
        ):
            raise DecryptionError(
                "AUTHENTICATION_FAILED",
                "Firefox NSS login secret decryption failed.",
                target="logins.json",
                details={"nss_error": self.error()},
            )
        try:
            return ctypes.string_at(output_item.data, output_item.len)
        finally:
            if output_item.data:
                self._lib.SECITEM_ZfreeItem(ctypes.byref(output_item), 0)

    def close(self) -> None:
        if self._slot is not None:
            self._lib.PK11_FreeSlot(self._slot)
            self._slot = None
        if self._opened:
            self._lib.NSS_Shutdown()
            self._opened = False

    def error(self) -> int:
        return int(self._lib.PORT_GetError())


def _find_nss_library() -> str | None:
    discovered = ctypes.util.find_library("nss3")
    if discovered:
        return discovered
    for candidate in (
        "/usr/lib/x86_64-linux-gnu/libnss3.so",
        "/usr/lib64/libnss3.so",
        "/usr/lib/libnss3.so",
    ):
        if Path(candidate).is_file():
            return candidate
    return None


def _load_nss_library() -> Any:
    library_path = _find_nss_library()
    if library_path is None:
        raise DecryptionError(
            "CAPABILITY_UNAVAILABLE",
            "Firefox NSS runtime requires libnss3.",
            target="dependency",
            details={"missing_dependency_candidates": ["libnss3"]},
        )
    lib = ctypes.CDLL(library_path)
    lib.NSS_Init.argtypes = [ctypes.c_char_p]
    lib.NSS_Init.restype = ctypes.c_int
    lib.NSS_Shutdown.argtypes = []
    lib.NSS_Shutdown.restype = ctypes.c_int
    lib.PK11_GetInternalKeySlot.argtypes = []
    lib.PK11_GetInternalKeySlot.restype = ctypes.c_void_p
    lib.PK11_FreeSlot.argtypes = [ctypes.c_void_p]
    lib.PK11_FreeSlot.restype = None
    lib.PK11_CheckUserPassword.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
    lib.PK11_CheckUserPassword.restype = ctypes.c_int
    lib.PK11_Authenticate.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p]
    lib.PK11_Authenticate.restype = ctypes.c_int
    lib.PK11SDR_Decrypt.argtypes = [
        ctypes.POINTER(_SECItem),
        ctypes.POINTER(_SECItem),
        ctypes.c_void_p,
    ]
    lib.PK11SDR_Decrypt.restype = ctypes.c_int
    lib.SECITEM_ZfreeItem.argtypes = [ctypes.POINTER(_SECItem), ctypes.c_int]
    lib.SECITEM_ZfreeItem.restype = None
    lib.PORT_GetError.argtypes = []
    lib.PORT_GetError.restype = ctypes.c_int
    return lib


def _read_logins_json(path: Path) -> list[dict[str, Any]]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise DecryptionError(
            "NSS_SCHEMA_UNSUPPORTED",
            "Firefox logins.json could not be parsed.",
            target="logins.json",
        ) from error
    logins = payload.get("logins") if isinstance(payload, dict) else None
    if not isinstance(logins, list):
        raise DecryptionError(
            "NSS_SCHEMA_UNSUPPORTED",
            "Firefox logins.json does not contain a login array.",
            target="logins.json",
        )
    rows: list[dict[str, Any]] = []
    for row in logins:
        if not isinstance(row, dict):
            raise DecryptionError(
                "NSS_SCHEMA_UNSUPPORTED",
                "Firefox logins.json contains a non-object login row.",
                target="logins.json",
            )
        rows.append(row)
    return rows


def _secret_summary(
    secret_id: str,
    case_id: str,
    value: bytes,
    *,
    key_source_kind: str,
) -> dict[str, Any]:
    return {
        "secret_id": secret_id,
        "case_id": case_id,
        "key_source_kind": key_source_kind,
        "length": len(value),
        "sha256": hashlib.sha256(value).hexdigest(),
        "redacted_preview": "<redacted>",
    }


def _nss_password_error_message(status: str) -> str:
    if status == "PRIMARY_PASSWORD_REQUIRED":
        return "Firefox NSS profile requires a primary password."
    if status == "INVALID_PRIMARY_PASSWORD":
        return "Firefox NSS primary password was rejected."
    return "Firefox NSS authentication failed."


def _dependency_available(module_name: str) -> bool:
    try:
        return importlib.util.find_spec(module_name) is not None
    except (ImportError, ModuleNotFoundError, ValueError):
        return False


def _inspect_profile(
    *,
    case_id: str,
    evidence_id: str | None,
    profile_path: Path,
    root_path: Path | None,
) -> dict[str, object]:
    key4 = profile_path / "key4.db"
    logins = profile_path / "logins.json"
    warnings: list[dict[str, Any]] = []
    key4_probe = _probe_key4_db(key4, warnings) if key4.is_file() else {}
    logins_probe = _probe_logins_json(logins, warnings) if logins.is_file() else {}
    key4_present = key4.is_file()
    logins_present = logins.is_file()
    if not key4_present or not logins_present:
        schema_status = "NSS_PROFILE_INCOMPLETE"
        status = "NSS_PROFILE_INCOMPLETE"
    elif key4_probe.get("status") != "SUPPORTED" or logins_probe.get("status") != "SUPPORTED":
        schema_status = "NSS_SCHEMA_UNSUPPORTED"
        status = "NSS_SCHEMA_UNSUPPORTED"
    else:
        schema_status = "SUPPORTED"
        status = "NSS_CAPABILITY_UNAVAILABLE"
    fingerprint = _profile_fingerprint([path for path in (key4, logins) if path.is_file()])
    return {
        "schema_version": "1.0.0",
        "profile_id": _profile_id(profile_path),
        "case_id": case_id,
        "evidence_id": evidence_id,
        "profile_path": str(profile_path),
        "key4_db_present": key4_present,
        "logins_json_present": logins_present,
        "primary_password_required": None,
        "schema_status": schema_status,
        "status": status,
        "fingerprint": fingerprint,
        "raw_locator": {
            "root_path": str(root_path) if root_path is not None else None,
            "profile_path": str(profile_path),
            "key4_db": _component_locator(key4, root_path),
            "logins_json": _component_locator(logins, root_path),
            "key4_probe": key4_probe,
            "logins_json_probe": logins_probe,
            "secret_fields_emitted": False,
        },
        "warnings": warnings,
        "discovered_at": _iso_timestamp(),
    }


def _probe_key4_db(path: Path, warnings: list[dict[str, Any]]) -> dict[str, Any]:
    if path.stat().st_size > MAX_KEY4_DB_BYTES:
        _append_warning(warnings, "NSS_KEY4_DB_TOO_LARGE", path)
        return {"status": "UNSUPPORTED", "reason": "NSS_KEY4_DB_TOO_LARGE"}
    try:
        with sqlite3.connect(f"file:{path}?mode=ro", uri=True) as connection:
            rows = connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
            ).fetchall()
            tables = [str(row[0]) for row in rows]
            metadata_table = "metadata" if "metadata" in tables else "metaData"
            metadata_rows = 0
            if metadata_table in tables:
                metadata_rows = int(
                    connection.execute(f"SELECT COUNT(*) FROM {metadata_table}").fetchone()[0]
                )
    except sqlite3.Error:
        _append_warning(warnings, "NSS_KEY4_DB_CORRUPT", path)
        return {"status": "CORRUPT", "reason": "SQLITE_READ_FAILED"}
    expected = {"nssPrivate"}
    if not expected.issubset(set(tables)):
        _append_warning(warnings, "NSS_KEY4_DB_SCHEMA_UNSUPPORTED", path)
        return {
            "status": "UNSUPPORTED",
            "reason": "MISSING_NSS_TABLES",
            "tables": tables,
            "required_tables": sorted(expected),
        }
    return {
        "status": "SUPPORTED",
        "tables": tables,
        "metadata_rows": metadata_rows,
        "raw_key_material_emitted": False,
    }


def _probe_logins_json(path: Path, warnings: list[dict[str, Any]]) -> dict[str, Any]:
    if path.stat().st_size > MAX_LOGINS_JSON_BYTES:
        _append_warning(warnings, "NSS_LOGINS_JSON_TOO_LARGE", path)
        return {"status": "UNSUPPORTED", "reason": "NSS_LOGINS_JSON_TOO_LARGE"}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        _append_warning(warnings, "NSS_LOGINS_JSON_CORRUPT", path)
        return {"status": "CORRUPT", "reason": "JSON_READ_FAILED"}
    if not isinstance(payload, dict):
        _append_warning(warnings, "NSS_LOGINS_JSON_SCHEMA_UNSUPPORTED", path)
        return {"status": "UNSUPPORTED", "reason": "ROOT_NOT_OBJECT"}
    version = payload.get("version")
    if not isinstance(version, int) or version not in SUPPORTED_LOGINS_JSON_VERSIONS:
        _append_warning(warnings, "NSS_LOGINS_JSON_SCHEMA_UNSUPPORTED", path)
        return {
            "status": "UNSUPPORTED",
            "reason": "UNSUPPORTED_LOGINS_JSON_VERSION",
            "version": version,
            "supported_versions": sorted(SUPPORTED_LOGINS_JSON_VERSIONS),
        }
    logins = payload.get("logins")
    if not isinstance(logins, list):
        _append_warning(warnings, "NSS_LOGINS_JSON_SCHEMA_UNSUPPORTED", path)
        return {"status": "UNSUPPORTED", "reason": "LOGINS_NOT_ARRAY", "version": version}
    encrypted_rows = 0
    for row in logins:
        if not isinstance(row, dict):
            _append_warning(warnings, "NSS_LOGINS_JSON_SCHEMA_UNSUPPORTED", path)
            return {"status": "UNSUPPORTED", "reason": "LOGIN_ROW_NOT_OBJECT"}
        if isinstance(row.get("encryptedUsername"), str) and isinstance(
            row.get("encryptedPassword"),
            str,
        ):
            encrypted_rows += 1
    return {
        "status": "SUPPORTED",
        "version": version,
        "login_count": len(logins),
        "encrypted_login_rows": encrypted_rows,
        "secret_fields_emitted": False,
    }


def _component_locator(path: Path, root_path: Path | None) -> dict[str, Any]:
    exists = path.is_file()
    relative_path: str | None = None
    if exists and root_path is not None:
        try:
            relative_path = str(path.relative_to(root_path))
        except ValueError:
            relative_path = None
    return {
        "path": str(path),
        "relative_path": relative_path,
        "exists": exists,
        "size": path.stat().st_size if exists else None,
    }


def _profile_fingerprint(paths: list[Path]) -> str | None:
    if not paths:
        return None
    digest = hashlib.sha256()
    for path in sorted(paths):
        digest.update(path.name.encode("utf-8", errors="surrogateescape"))
        with path.open("rb") as handle:
            while chunk := handle.read(1024 * 1024):
                digest.update(chunk)
    return digest.hexdigest()


def _profile_id(profile_path: Path) -> str:
    digest = hashlib.sha256(str(profile_path).encode("utf-8", errors="surrogateescape"))
    return f"firefox-{digest.hexdigest()[:16]}"


def _append_warning(warnings: list[dict[str, Any]], code: str, path: Path) -> None:
    warnings.append(
        {
            "code": code,
            "component": path.name,
            "path": str(path),
            "secret_fields_emitted": False,
        }
    )


def _iso_timestamp() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")
