"""Firefox NSS provider boundary."""

import hashlib
import importlib.util
import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from apex_forensic.constants import ENGINE_VERSION
from apex_forensic.domain.models import (
    DecryptionAttempt,
    DecryptionResult,
    SecretDerivationInput,
    SecretProviderCapability,
)

MAX_KEY4_DB_BYTES = 64 * 1024 * 1024
MAX_LOGINS_JSON_BYTES = 16 * 1024 * 1024
SUPPORTED_LOGINS_JSON_VERSIONS = {3}


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
