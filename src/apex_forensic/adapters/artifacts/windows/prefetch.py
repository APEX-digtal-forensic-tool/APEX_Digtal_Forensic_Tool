"""Windows Prefetch artifact analyzer."""

from __future__ import annotations

import struct
from pathlib import Path
from typing import Any

from apex_forensic.constants import ENGINE_VERSION
from apex_forensic.domain.enums import (
    ArtifactParseStatus,
    ArtifactSourceKind,
    ArtifactType,
    FileSystemNodeType,
)
from apex_forensic.domain.models import (
    ArtifactAnalysisResult,
    ArtifactCapability,
    ArtifactRecord,
    ArtifactSource,
    Evidence,
    FileSystemNode,
)

from .common import (
    filetime_to_utc,
    issue,
    make_artifact,
    make_raw_locator,
    sha256_hex,
    source_shell,
)

_SUPPORTED_PREFETCH_VERSIONS = {17, 23, 26, 30}
_PREFETCH_RUN_COUNT_OFFSETS = {
    17: 0x90,
    23: 0x98,
    26: 0xD0,
    30: 0xD0,
}
_PREFETCH_LAST_RUN_OFFSETS = {
    17: (0x78,),
    23: (0x80,),
    26: (0x80,),
    30: tuple(0x80 + (index * 8) for index in range(8)),
}


class WindowsPrefetchAnalyzer:
    """Safe minimal metadata parser for Windows Prefetch files."""

    analyzer_id = "windows.prefetch"
    analyzer_version = ENGINE_VERSION

    @property
    def parser_backend(self) -> str:
        return "apex.prefetch_minimal"

    @property
    def parser_backend_version(self) -> str:
        return ENGINE_VERSION

    def capabilities(self) -> ArtifactCapability:
        return ArtifactCapability(
            analyzer_id=self.analyzer_id,
            analyzer_version=self.analyzer_version,
            parser_backend=self.parser_backend,
            parser_backend_version=self.parser_backend_version,
            supported_source_kinds=(ArtifactSourceKind.PREFETCH_FILE,),
            supported_artifact_types=(ArtifactType.PREFETCH_EXECUTION,),
            capabilities=(
                "PREFETCH_MINIMAL_HEADER",
                "PREFETCH_SAFE_BOUNDS_CHECKS",
                "PREFETCH_MAM_COMPRESSION_DETECTION",
            ),
            unavailable_capabilities=("PREFETCH_MAM_DECOMPRESSION",),
            warnings=(
                {
                    "code": "UNSUPPORTED_COMPRESSION",
                    "message_key": "warning.prefetch.mam_decompression_unavailable",
                    "developer_message": (
                        "Windows 10/11 MAM compressed Prefetch files are detected but not "
                        "decompressed."
                    ),
                },
            ),
            metadata={"supported_versions": sorted(_SUPPORTED_PREFETCH_VERSIONS)},
        )

    def detect_source(self, node: FileSystemNode) -> ArtifactSource | None:
        if node.node_type is not FileSystemNodeType.FILE:
            return None
        if (node.extension or "").casefold() != "pf":
            return None
        return source_shell(
            node=node,
            source_kind=ArtifactSourceKind.PREFETCH_FILE,
            analyzer_id=self.analyzer_id,
            analyzer_version=self.analyzer_version,
            parser_backend=self.parser_backend,
            parser_backend_version=self.parser_backend_version,
            priority=50,
        )

    def supports_source(self, source: ArtifactSource) -> bool:
        return source.source_kind is ArtifactSourceKind.PREFETCH_FILE

    def analyze(
        self,
        *,
        evidence: Evidence,
        node: FileSystemNode,
        source: ArtifactSource,
        file_path: Path,
        item_budget: int | None = None,
    ) -> ArtifactAnalysisResult:
        del item_budget
        try:
            data = file_path.read_bytes()
        except OSError as error:
            return ArtifactAnalysisResult(
                errors=(
                    issue(
                        severity="ERROR",
                        code="PREFETCH_READ_FAILED",
                        message_key="error.prefetch.read_failed",
                        developer_message="Prefetch file could not be read.",
                        node=node,
                        details={"error": str(error)},
                    ),
                ),
                parse_status=ArtifactParseStatus.FAILED,
            )
        artifact = _parse_prefetch(evidence=evidence, node=node, source=source, data=data)
        warnings = tuple(
            issue(
                severity="WARNING",
                code=str(warning["code"]),
                message_key=str(warning["message_key"]),
                developer_message=str(warning["developer_message"]),
                node=node,
                details=dict(warning.get("details", {})),
                artifact_id=artifact.artifact_id,
            )
            for warning in artifact.warnings
        )
        return ArtifactAnalysisResult(
            artifacts=(artifact,),
            warnings=warnings,
            parse_status=artifact.parse_status,
            coverage={
                "format_version": artifact.fields.get("format_version"),
                "file_size": artifact.fields.get("file_size"),
            },
        )


def _parse_prefetch(
    *,
    evidence: Evidence,
    node: FileSystemNode,
    source: ArtifactSource,
    data: bytes,
) -> ArtifactRecord:
    content_hash = sha256_hex(data[: min(len(data), 1_048_576)])
    raw_locator = make_raw_locator(
        evidence_id=evidence.evidence_id,
        source_file_node_id=node.node_id,
        source_path=node.display_path,
        source_reference="prefetch:header",
        locator_type="PREFETCH_FIELD",
        offset=0,
        length=min(max(len(data), 1), 1_048_576),
        encoding=None,
        view_types=["HEX"],
        content_sha256=content_hash,
        limitations=["Only safe minimal header fields are parsed in Phase 3."],
        details={"field_offset": 0, "field_length": min(len(data), 1_048_576)},
    )
    if data.startswith(b"MAM"):
        warning = {
            "code": "UNSUPPORTED_COMPRESSION",
            "message_key": "warning.prefetch.unsupported_compression",
            "developer_message": (
                "MAM compressed Prefetch wrapper detected; decompression is not implemented."
            ),
            "details": {"compression": "MAM"},
        }
        return make_artifact(
            evidence=evidence,
            node=node,
            source=source,
            artifact_type=ArtifactType.PREFETCH_EXECUTION,
            artifact_subtype="PREFETCH_MAM_COMPRESSED",
            fields={
                "executable_name": None,
                "prefetch_hash": None,
                "format_version": None,
                "file_size": len(data),
                "run_count": None,
                "last_run_times": [],
                "volume_information": [],
                "referenced_file_path_candidates": [],
                "unsupported_reason": "UNSUPPORTED_COMPRESSION",
                "user_execution_asserted": False,
            },
            raw_locator=raw_locator,
            title=f"Unsupported compressed Prefetch: {node.original_name}",
            summary="MAM compressed Prefetch detected; no decompression was attempted.",
            parse_status=ArtifactParseStatus.UNSUPPORTED,
            confidence=0.4,
            warnings=[warning],
        )
    if len(data) < 84:
        warning = {
            "code": "PREFETCH_HEADER_TOO_SHORT",
            "message_key": "warning.prefetch.header_too_short",
            "developer_message": "Prefetch file is too short for the fixed header.",
            "details": {"file_size": len(data)},
        }
        return _unsupported_prefetch_artifact(
            evidence=evidence,
            node=node,
            source=source,
            raw_locator=raw_locator,
            warning=warning,
            status=ArtifactParseStatus.CORRUPT,
            subtype="PREFETCH_CORRUPT_HEADER",
            unsupported_reason="HEADER_TOO_SHORT",
            format_version=None,
            file_size=len(data),
        )
    version = _read_u32(data, 0)
    signature = data[4:8]
    if signature != b"SCCA":
        warning = {
            "code": "PREFETCH_SIGNATURE_INVALID",
            "message_key": "warning.prefetch.signature_invalid",
            "developer_message": "Prefetch signature is not SCCA.",
            "details": {"signature_hex": signature.hex()},
        }
        return _unsupported_prefetch_artifact(
            evidence=evidence,
            node=node,
            source=source,
            raw_locator=raw_locator,
            warning=warning,
            status=ArtifactParseStatus.CORRUPT,
            subtype="PREFETCH_CORRUPT_SIGNATURE",
            unsupported_reason="INVALID_SIGNATURE",
            format_version=version,
            file_size=len(data),
        )
    if version not in _SUPPORTED_PREFETCH_VERSIONS:
        warning = {
            "code": "PREFETCH_UNSUPPORTED_VERSION",
            "message_key": "warning.prefetch.unsupported_version",
            "developer_message": "Prefetch format version is not supported by the minimal parser.",
            "details": {"format_version": version},
        }
        return _unsupported_prefetch_artifact(
            evidence=evidence,
            node=node,
            source=source,
            raw_locator=raw_locator,
            warning=warning,
            status=ArtifactParseStatus.UNSUPPORTED,
            subtype="PREFETCH_UNSUPPORTED_VERSION",
            unsupported_reason="UNSUPPORTED_VERSION",
            format_version=version,
            file_size=len(data),
        )
    executable_name = _read_utf16_fixed(data, 0x10, 60)
    prefetch_hash = f"{_read_u32(data, 0x4C):08X}"
    header_file_size = _read_u32(data, 0x0C)
    run_count = _read_u32(data, _PREFETCH_RUN_COUNT_OFFSETS[version])
    last_run_times = _last_run_times(data, version)
    warnings: list[dict[str, Any]] = []
    if not last_run_times:
        warnings.append(
            {
                "code": "PREFETCH_LAST_RUN_TIME_UNAVAILABLE",
                "message_key": "warning.prefetch.last_run_time_unavailable",
                "developer_message": (
                    "No safe last run timestamp was present in the supported header range."
                ),
            }
        )
    fields: dict[str, Any] = {
        "executable_name": executable_name,
        "prefetch_hash": prefetch_hash,
        "format_version": version,
        "file_size": len(data),
        "declared_file_size": header_file_size,
        "run_count": run_count,
        "last_run_times": last_run_times,
        "volume_information": [],
        "referenced_file_path_candidates": [],
        "supported_versions": sorted(_SUPPORTED_PREFETCH_VERSIONS),
        "user_execution_asserted": False,
        "field_offsets": {
            "format_version": {"offset": 0, "length": 4},
            "signature": {"offset": 4, "length": 4},
            "file_size": {"offset": 12, "length": 4},
            "executable_name": {"offset": 16, "length": 60},
            "prefetch_hash": {"offset": 76, "length": 4},
            "run_count": {"offset": _PREFETCH_RUN_COUNT_OFFSETS[version], "length": 4},
        },
    }
    observed_raw = last_run_times[0]["raw_filetime"] if last_run_times else None
    observed_utc = None
    if last_run_times:
        parsed = last_run_times[0]["timestamp_utc"]
        if isinstance(parsed, str):
            from apex_forensic._time import parse_timestamp

            observed_utc = parse_timestamp(parsed)
    return make_artifact(
        evidence=evidence,
        node=node,
        source=source,
        artifact_type=ArtifactType.PREFETCH_EXECUTION,
        artifact_subtype=f"PREFETCH_V{version}",
        fields=fields,
        raw_locator=raw_locator,
        title=f"Prefetch execution candidate: {executable_name or node.original_name}",
        summary="Prefetch metadata observed; user execution is not asserted from Prefetch alone.",
        parse_status=ArtifactParseStatus.SUCCESS if not warnings else ArtifactParseStatus.PARTIAL,
        confidence=0.85 if executable_name else 0.65,
        observed_at_raw=observed_raw,
        observed_at_utc=observed_utc,
        timezone_source="WINDOWS_FILETIME_UTC" if observed_utc is not None else None,
        timezone_confidence="HIGH" if observed_utc is not None else "UNKNOWN",
        warnings=warnings,
    )


def _unsupported_prefetch_artifact(
    *,
    evidence: Evidence,
    node: FileSystemNode,
    source: ArtifactSource,
    raw_locator: dict[str, Any],
    warning: dict[str, Any],
    status: ArtifactParseStatus,
    subtype: str,
    unsupported_reason: str,
    format_version: int | None,
    file_size: int,
) -> ArtifactRecord:
    return make_artifact(
        evidence=evidence,
        node=node,
        source=source,
        artifact_type=ArtifactType.PREFETCH_EXECUTION,
        artifact_subtype=subtype,
        fields={
            "executable_name": None,
            "prefetch_hash": None,
            "format_version": format_version,
            "file_size": file_size,
            "run_count": None,
            "last_run_times": [],
            "volume_information": [],
            "referenced_file_path_candidates": [],
            "unsupported_reason": unsupported_reason,
            "user_execution_asserted": False,
        },
        raw_locator=raw_locator,
        title=f"Unsupported Prefetch: {node.original_name}",
        summary="Prefetch file was not parsed as a successful execution artifact.",
        parse_status=status,
        confidence=0.3,
        warnings=[warning],
    )


def _read_u32(data: bytes, offset: int) -> int | None:
    if offset < 0 or offset + 4 > len(data):
        return None
    value: int = struct.unpack_from("<I", data, offset)[0]
    return value


def _read_utf16_fixed(data: bytes, offset: int, char_count: int) -> str | None:
    byte_count = char_count * 2
    if offset < 0 or offset + byte_count > len(data):
        return None
    raw = data[offset : offset + byte_count]
    text = raw.decode("utf-16le", errors="replace").split("\x00", 1)[0]
    return text or None


def _last_run_times(data: bytes, version: int) -> list[dict[str, Any]]:
    values: list[dict[str, Any]] = []
    for offset in _PREFETCH_LAST_RUN_OFFSETS[version]:
        if offset + 8 > len(data):
            continue
        raw_filetime = struct.unpack_from("<Q", data, offset)[0]
        parsed = filetime_to_utc(raw_filetime)
        if parsed is None:
            continue
        values.append(
            {
                "raw_filetime": str(raw_filetime),
                "timestamp_utc": parsed.isoformat(timespec="microseconds").replace("+00:00", "Z"),
                "field_offset": offset,
                "field_length": 8,
            }
        )
    return values
