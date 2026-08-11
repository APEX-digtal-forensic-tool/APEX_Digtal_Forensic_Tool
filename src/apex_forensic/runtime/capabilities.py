"""Dependency-light runtime capability diagnostics."""

from __future__ import annotations

import argparse
import ctypes
import ctypes.util
import importlib
import importlib.metadata
import importlib.util
import io
import json
import os
import platform
import shutil
import sqlite3
import subprocess
import sys
from collections.abc import Sequence
from typing import Any

from apex_forensic.constants import ENGINE_VERSION

AVAILABLE = "AVAILABLE"
AVAILABLE_WITH_LIMITATIONS = "AVAILABLE_WITH_LIMITATIONS"
CAPABILITY_UNAVAILABLE = "CAPABILITY_UNAVAILABLE"
EXTERNAL_CONFIGURATION_REQUIRED = "EXTERNAL_CONFIGURATION_REQUIRED"
UNSUPPORTED_PLATFORM = "UNSUPPORTED_PLATFORM"
BLOCKED_EXTERNAL_FIXTURE = "BLOCKED_EXTERNAL_FIXTURE"
HOST_VERIFICATION_REQUIRED = "HOST_VERIFICATION_REQUIRED"


def capability_report() -> dict[str, Any]:
    """Return actual host capabilities without emitting environment values or names."""

    capabilities = [
        _python_capability(),
        _sqlite_capability(),
        _sqlite_fts5_capability(),
        _internal_capability("raw-dd-img", "apex_forensic.adapters.evidence.raw"),
        _module_capability("pytsk3", "pytsk3", required_attributes=("Img_Info", "FS_Info")),
        _module_capability("e01-libewf", "pyewf", required_attributes=("handle",)),
        _module_capability("vhd-libvhdi", "pyvhdilib", required_attributes=("file",)),
        _executable_capability("vhdx-qemu-img", "qemu-img", ("--version",)),
        _internal_capability("filesystem-provider", "apex_forensic.adapters.filesystem.pytsk"),
        _internal_capability(
            "registry-parser",
            "apex_forensic.adapters.artifacts.windows.registry",
        ),
        _module_capability(
            "registry-binary-parser",
            "Registry.Registry",
            distribution="python-registry",
            required_attributes=("Registry",),
        ),
        _internal_capability(
            "registry-deleted-cell-carving",
            "apex_forensic.adapters.artifacts.windows.registry_carving",
        ),
        _internal_capability(
            "event-log-parser",
            "apex_forensic.adapters.artifacts.windows.eventlog",
        ),
        _module_capability(
            "event-log-binary-parser",
            "Evtx.Evtx",
            distribution="python-evtx",
            required_attributes=("Evtx",),
        ),
        _internal_capability(
            "prefetch-parser",
            "apex_forensic.adapters.artifacts.windows.prefetch",
        ),
        _module_capability(
            "prefetch-mam",
            "dissect.util.compression.lzxpress_huffman",
            distribution="dissect.util",
        ),
        _windows_event_message_capability(),
        _pillow_capability(),
        _module_capability("browser-cryptography", "cryptography", distribution="cryptography"),
        _executable_capability("ffmpeg", "ffmpeg", ("-version",)),
        _executable_capability("ffprobe", "ffprobe", ("-version",)),
        _rapidocr_capability(),
        _onnxruntime_capability(),
        _faster_whisper_capability(),
        _nss_capability(),
        _module_capability(
            "dpapi-impacket",
            "impacket.dpapi",
            distribution="impacket",
            required_attributes=("DPAPI_BLOB", "MasterKeyFile"),
        ),
        _internal_capability("html-renderer", "apex_forensic.adapters.report.runtime"),
        _module_capability(
            "pdf-renderer",
            "reportlab.platypus",
            distribution="reportlab",
            required_attributes=("SimpleDocTemplate",),
        ),
        _ai_provider_capability(),
        _kakaotalk_existing_capability(),
    ]
    unavailable = sum(
        item["status"] in {CAPABILITY_UNAVAILABLE, EXTERNAL_CONFIGURATION_REQUIRED}
        for item in capabilities
    )
    host_required = sum(item["status"] == HOST_VERIFICATION_REQUIRED for item in capabilities)
    return {
        "schema_version": "1.0.0",
        "engine_version": ENGINE_VERSION,
        "status": (
            AVAILABLE
            if unavailable == 0 and host_required == 0
            else AVAILABLE_WITH_LIMITATIONS
        ),
        "host": {
            "os": platform.system(),
            "platform": platform.platform(),
            "python_version": platform.python_version(),
            "python_implementation": platform.python_implementation(),
            "cpu_count": os.cpu_count(),
        },
        "summary": {
            "capability_count": len(capabilities),
            "unavailable_count": unavailable,
            "host_verification_required_count": host_required,
            "secret_values_emitted": False,
            "environment_values_emitted": False,
            "environment_names_emitted": False,
        },
        "capabilities": capabilities,
    }


def doctor_main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="apex-forensic doctor")
    parser.add_argument("--json", action="store_true", help="Emit structured JSON")
    args = parser.parse_args(argv)
    report = capability_report()
    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    else:
        print(f"APEX {report['engine_version']} runtime: {report['status']}")
        for item in report["capabilities"]:
            version = f" ({item['version']})" if item.get("version") else ""
            print(f"{item['id']}: {item['status']}{version}")
    return 0


def _capability(
    capability_id: str,
    status: str,
    *,
    version: str | None = None,
    reason: str | None = None,
    probe: str,
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "id": capability_id,
        "status": status,
        "version": version,
        "reason": reason,
        "probe": probe,
        "details": details or {},
    }


def _python_capability() -> dict[str, Any]:
    return _capability(
        "python",
        AVAILABLE,
        version=platform.python_version(),
        probe="ACTIVE_INTERPRETER",
        details={"executable_basename": os.path.basename(sys.executable)},
    )


def _sqlite_capability() -> dict[str, Any]:
    try:
        with sqlite3.connect(":memory:") as connection:
            observed = connection.execute("SELECT sqlite_version()").fetchone()
    except sqlite3.Error as error:
        return _capability(
            "sqlite",
            CAPABILITY_UNAVAILABLE,
            reason="SQLITE_RUNTIME_PROBE_FAILED",
            probe="IN_MEMORY_QUERY",
            details={"error_type": type(error).__name__},
        )
    version = str(observed[0]) if observed else sqlite3.sqlite_version
    return _capability("sqlite", AVAILABLE, version=version, probe="IN_MEMORY_QUERY")


def _sqlite_fts5_capability() -> dict[str, Any]:
    try:
        with sqlite3.connect(":memory:") as connection:
            connection.execute("CREATE VIRTUAL TABLE apex_probe USING fts5(value)")
            connection.execute("INSERT INTO apex_probe(value) VALUES ('apex')")
            matched = connection.execute(
                "SELECT count(*) FROM apex_probe WHERE apex_probe MATCH 'apex'"
            ).fetchone()
    except sqlite3.Error as error:
        return _capability(
            "sqlite-fts5",
            CAPABILITY_UNAVAILABLE,
            reason="FTS5_RUNTIME_PROBE_FAILED",
            probe="IN_MEMORY_FTS5_QUERY",
            details={"error_type": type(error).__name__},
        )
    return _capability(
        "sqlite-fts5",
        AVAILABLE if matched and matched[0] == 1 else CAPABILITY_UNAVAILABLE,
        version=sqlite3.sqlite_version,
        reason=None if matched and matched[0] == 1 else "FTS5_QUERY_DID_NOT_MATCH",
        probe="IN_MEMORY_FTS5_QUERY",
    )


def _internal_capability(capability_id: str, module_name: str) -> dict[str, Any]:
    if not _module_spec_available(module_name):
        return _capability(
            capability_id,
            CAPABILITY_UNAVAILABLE,
            reason="ENGINE_MODULE_IMPORT_DEPENDENCY_UNAVAILABLE",
            probe="MODULE_IMPORT",
        )
    try:
        importlib.import_module(module_name)
    except Exception as error:
        details: dict[str, Any] = {"error_type": type(error).__name__}
        if isinstance(error, ModuleNotFoundError) and error.name:
            details["missing_dependency"] = error.name
        return _capability(
            capability_id,
            CAPABILITY_UNAVAILABLE,
            reason="ENGINE_MODULE_IMPORT_FAILED",
            probe="MODULE_IMPORT",
            details=details,
        )
    return _capability(
        capability_id,
        AVAILABLE,
        version=ENGINE_VERSION,
        probe="ENGINE_MODULE_IMPORT",
    )


def _module_capability(
    capability_id: str,
    module_name: str,
    *,
    distribution: str | None = None,
    required_attributes: tuple[str, ...] = (),
) -> dict[str, Any]:
    if not _module_spec_available(module_name):
        return _capability(
            capability_id,
            CAPABILITY_UNAVAILABLE,
            reason="DEPENDENCY_NOT_INSTALLED",
            probe="IMPORT_AND_ATTRIBUTE_CHECK",
            details={"dependency": distribution or module_name.split(".", 1)[0]},
        )
    try:
        module = importlib.import_module(module_name)
        missing = [name for name in required_attributes if not hasattr(module, name)]
    except Exception as error:
        return _capability(
            capability_id,
            CAPABILITY_UNAVAILABLE,
            reason="DEPENDENCY_IMPORT_FAILED",
            probe="IMPORT_AND_ATTRIBUTE_CHECK",
            details={
                "dependency": distribution or module_name.split(".", 1)[0],
                "error_type": type(error).__name__,
            },
        )
    if missing:
        return _capability(
            capability_id,
            CAPABILITY_UNAVAILABLE,
            version=_distribution_version(distribution or module_name.split(".", 1)[0]),
            reason="DEPENDENCY_API_INCOMPATIBLE",
            probe="IMPORT_AND_ATTRIBUTE_CHECK",
            details={"missing_attributes": missing},
        )
    return _capability(
        capability_id,
        AVAILABLE,
        version=_distribution_version(distribution or module_name.split(".", 1)[0]),
        probe="IMPORT_AND_ATTRIBUTE_CHECK",
    )


def _executable_capability(
    capability_id: str,
    executable_name: str,
    version_args: tuple[str, ...],
) -> dict[str, Any]:
    executable = shutil.which(executable_name)
    if executable is None:
        return _capability(
            capability_id,
            CAPABILITY_UNAVAILABLE,
            reason="EXECUTABLE_NOT_FOUND",
            probe="PATH_AND_VERSION_COMMAND",
            details={"executable": executable_name},
        )
    try:
        completed = subprocess.run(  # nosec B603
            [executable, *version_args],
            check=False,
            capture_output=True,
            timeout=5.0,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        return _capability(
            capability_id,
            CAPABILITY_UNAVAILABLE,
            reason="EXECUTABLE_PROBE_FAILED",
            probe="PATH_AND_VERSION_COMMAND",
            details={"executable": executable_name, "error_type": type(error).__name__},
        )
    return _capability(
        capability_id,
        AVAILABLE if completed.returncode == 0 else CAPABILITY_UNAVAILABLE,
        reason=None if completed.returncode == 0 else "VERSION_COMMAND_FAILED",
        probe="PATH_AND_VERSION_COMMAND",
        details={"executable": executable_name, "returncode": completed.returncode},
    )


def _windows_event_message_capability() -> dict[str, Any]:
    if platform.system() != "Windows":
        return _capability(
            "windows-event-message-renderer",
            HOST_VERIFICATION_REQUIRED,
            reason="WINDOWS_HOST_REQUIRED",
            probe="PLATFORM_AND_PYWIN32_API_CHECK",
        )
    return _module_capability(
        "windows-event-message-renderer",
        "win32evtlog",
        distribution="pywin32",
        required_attributes=("EvtOpenPublisherMetadata", "EvtFormatMessage"),
    )


def _pillow_capability() -> dict[str, Any]:
    if not _module_spec_available("PIL.Image"):
        return _capability(
            "pillow",
            CAPABILITY_UNAVAILABLE,
            reason="DEPENDENCY_NOT_INSTALLED",
            probe="IN_MEMORY_IMAGE_ROUND_TRIP",
            details={"dependency": "Pillow"},
        )
    try:
        image_module = importlib.import_module("PIL.Image")
        buffer = io.BytesIO()
        image_module.new("RGB", (1, 1), (0, 0, 0)).save(buffer, format="PNG")
        buffer.seek(0)
        with image_module.open(buffer) as image:
            image.verify()
    except Exception as error:
        return _capability(
            "pillow",
            CAPABILITY_UNAVAILABLE,
            reason="IMAGE_RUNTIME_PROBE_FAILED",
            probe="IN_MEMORY_IMAGE_ROUND_TRIP",
            details={"error_type": type(error).__name__},
        )
    return _capability(
        "pillow",
        AVAILABLE,
        version=_distribution_version("Pillow"),
        probe="IN_MEMORY_IMAGE_ROUND_TRIP",
    )


def _rapidocr_capability() -> dict[str, Any]:
    capability = _module_capability(
        "rapidocr",
        "rapidocr",
        distribution="rapidocr",
        required_attributes=("RapidOCR",),
    )
    if capability["status"] == AVAILABLE:
        capability["status"] = AVAILABLE_WITH_LIMITATIONS
        capability["reason"] = "MODEL_INFERENCE_FIXTURE_NOT_RUN"
        capability["details"] = {"model_inference_verified": False}
    return capability


def _onnxruntime_capability() -> dict[str, Any]:
    capability = _module_capability(
        "onnx-runtime",
        "onnxruntime",
        distribution="onnxruntime",
        required_attributes=("get_available_providers",),
    )
    if capability["status"] == AVAILABLE:
        module = importlib.import_module("onnxruntime")
        capability["details"] = {"providers": list(module.get_available_providers())}
    return capability


def _faster_whisper_capability() -> dict[str, Any]:
    capability = _module_capability(
        "faster-whisper",
        "faster_whisper",
        distribution="faster-whisper",
        required_attributes=("WhisperModel",),
    )
    if capability["status"] == AVAILABLE:
        capability["status"] = AVAILABLE_WITH_LIMITATIONS
        capability["reason"] = "LOCAL_MODEL_CONFIGURATION_REQUIRED"
        capability["details"] = {"model_loaded": False, "model_auto_download": False}
    return capability


def _nss_capability() -> dict[str, Any]:
    library_path = ctypes.util.find_library("nss3")
    if library_path is None:
        return _capability(
            "firefox-nss",
            CAPABILITY_UNAVAILABLE,
            reason="NSS_LIBRARY_NOT_FOUND",
            probe="DYNAMIC_LIBRARY_SYMBOL_CHECK",
        )
    try:
        library = ctypes.CDLL(library_path)
    except OSError as error:
        return _capability(
            "firefox-nss",
            CAPABILITY_UNAVAILABLE,
            reason="NSS_LIBRARY_LOAD_FAILED",
            probe="DYNAMIC_LIBRARY_SYMBOL_CHECK",
            details={"error_type": type(error).__name__},
        )
    required = ("NSS_Init", "NSS_Shutdown", "PK11SDR_Decrypt")
    missing = [name for name in required if not hasattr(library, name)]
    if missing:
        return _capability(
            "firefox-nss",
            CAPABILITY_UNAVAILABLE,
            reason="NSS_DECRYPT_API_INCOMPATIBLE",
            probe="DYNAMIC_LIBRARY_SYMBOL_CHECK",
            details={"missing_symbols": missing},
        )
    return _capability(
        "firefox-nss",
        AVAILABLE_WITH_LIMITATIONS,
        reason="SYNTHETIC_PROFILE_DECRYPT_NOT_RUN",
        probe="DYNAMIC_LIBRARY_SYMBOL_CHECK",
        details={
            "decrypt_symbols_available": True,
            "fixture_generation_symbol_available": hasattr(library, "PK11SDR_Encrypt"),
        },
    )


def _ai_provider_capability() -> dict[str, Any]:
    key_environment_name = os.environ.get("APEX_AI_VERIFY_API_KEY_ENV")
    configured = bool(
        os.environ.get("APEX_AI_VERIFY_BASE_URL")
        and os.environ.get("APEX_AI_VERIFY_MODEL")
        and key_environment_name
        and os.environ.get(key_environment_name)
    )
    return _capability(
        "ai-provider-openai-compatible",
        AVAILABLE_WITH_LIMITATIONS if configured else EXTERNAL_CONFIGURATION_REQUIRED,
        reason="LIVE_PROVIDER_NOT_PROBED" if configured else "PROVIDER_CONFIGURATION_MISSING",
        probe="CONFIGURATION_PRESENCE_ONLY",
        details={"configured": configured, "live_request_performed": False},
    )


def _kakaotalk_existing_capability() -> dict[str, Any]:
    cryptography_available = _module_spec_available("cryptography")
    return _capability(
        "kakaotalk-existing",
        AVAILABLE_WITH_LIMITATIONS if cryptography_available else CAPABILITY_UNAVAILABLE,
        reason=(
            "EXTERNAL_KEY_ONLY_AUTOMATIC_KEY_ACQUISITION_BLOCKED"
            if cryptography_available
            else "CRYPTOGRAPHY_DEPENDENCY_NOT_INSTALLED"
        ),
        probe="EXISTING_DEPENDENCY_STATUS_ONLY",
        details={
            "automatic_key_acquisition_status": BLOCKED_EXTERNAL_FIXTURE,
            "external_key_only": True,
            "android_supported": False,
            "ios_supported": False,
        },
    )


def _module_spec_available(module_name: str) -> bool:
    try:
        return importlib.util.find_spec(module_name) is not None
    except (ImportError, ModuleNotFoundError, ValueError):
        return False


def _distribution_version(distribution: str) -> str | None:
    try:
        return importlib.metadata.version(distribution)
    except importlib.metadata.PackageNotFoundError:
        return None


if __name__ == "__main__":
    raise SystemExit(doctor_main())
