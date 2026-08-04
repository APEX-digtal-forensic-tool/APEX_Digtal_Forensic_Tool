"""Windows Registry artifact analyzer."""

from __future__ import annotations

import codecs
import hashlib
import importlib
import importlib.metadata
import re
import shlex
import tempfile
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
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
    ArtifactIssue,
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
    source_shell,
)

_REGISTRY_HIVE_NAMES = {"SYSTEM", "SOFTWARE", "NTUSER.DAT", "USRCLASS.DAT"}
_AUTORUN_SUFFIXES = (
    r"software\microsoft\windows\currentversion\run",
    r"software\microsoft\windows\currentversion\runonce",
    r"software\wow6432node\microsoft\windows\currentversion\run",
    r"software\wow6432node\microsoft\windows\currentversion\runonce",
)
_USERASSIST_SEGMENT = r"software\microsoft\windows\currentversion\explorer\userassist"
_TIMEZONE_SUFFIX = r"system\currentcontrolset\control\timezoneinformation"
_USBSTOR_SEGMENT = r"system\currentcontrolset\enum\usbstor"
_WINDOWS_TZ_TO_IANA = {
    "UTC": "Etc/UTC",
    "Korea Standard Time": "Asia/Seoul",
    "Pacific Standard Time": "America/Los_Angeles",
    "Eastern Standard Time": "America/New_York",
}


@dataclass(frozen=True, slots=True)
class _RegValue:
    name: str
    value_type: str
    data: Any
    raw_data: str
    line_no: int
    deleted: bool = False


@dataclass(frozen=True, slots=True)
class _RegSection:
    path: str
    line_no: int
    deleted: bool
    values: tuple[_RegValue, ...]


class WindowsRegistryAnalyzer:
    """Read-only Registry analyzer for export text and optional offline hives."""

    analyzer_id = "windows.registry"
    analyzer_version = ENGINE_VERSION

    @property
    def parser_backend(self) -> str:
        return "apex.registry"

    @property
    def parser_backend_version(self) -> str:
        return ENGINE_VERSION

    def capabilities(self) -> ArtifactCapability:
        unavailable: list[str] = []
        warnings: list[dict[str, Any]] = []
        if self._python_registry_version() is None:
            unavailable.append("REGISTRY_HIVE_BINARY_PARSE")
            warnings.append(
                {
                    "code": "CAPABILITY_UNAVAILABLE",
                    "message_key": "warning.registry.python_registry_unavailable",
                    "developer_message": (
                        "python-registry is not installed; binary hive analysis is unavailable."
                    ),
                }
            )
        regipy_version = self._regipy_version()
        transaction_capabilities: tuple[str, ...]
        if regipy_version is None:
            unavailable.append("REGISTRY_TRANSACTION_LOG_REPLAY")
            transaction_capabilities = ()
            transaction_status = "CAPABILITY_UNAVAILABLE"
            transaction_reason = "regipy is not installed."
        else:
            transaction_capabilities = ("REGISTRY_TRANSACTION_LOG_REPLAY",)
            transaction_status = "OPTIONAL_RUNTIME"
            transaction_reason = None
        return ArtifactCapability(
            analyzer_id=self.analyzer_id,
            analyzer_version=self.analyzer_version,
            parser_backend=self.parser_backend,
            parser_backend_version=self.parser_backend_version,
            supported_source_kinds=(
                ArtifactSourceKind.REGISTRY_EXPORT,
                ArtifactSourceKind.REGISTRY_HIVE,
            ),
            supported_artifact_types=(
                ArtifactType.REGISTRY_KEY,
                ArtifactType.REGISTRY_VALUE,
                ArtifactType.REGISTRY_AUTORUN,
                ArtifactType.REGISTRY_USB_DEVICE,
                ArtifactType.REGISTRY_TIMEZONE,
                ArtifactType.REGISTRY_USERASSIST,
            ),
            capabilities=(
                "REGISTRY_EXPORT_TEXT",
                "REGISTRY_AUTORUN",
                "REGISTRY_USB_HISTORY",
                "REGISTRY_TIMEZONE",
                "REGISTRY_USERASSIST_SAFE",
                "REGISTRY_EXPORT_DELETED_DIRECTIVE_CANDIDATES",
                *transaction_capabilities,
            ),
            unavailable_capabilities=(
                *tuple(unavailable),
                "REGISTRY_BINARY_DELETED_CELL_RECOVERY",
            ),
            warnings=tuple(warnings),
            metadata={
                "binary_hive_dependency": "python-registry",
                "transaction_log_dependency": "regipy",
                "transaction_log_dependency_version": regipy_version,
                "live_registry": False,
                "credential_extraction": False,
                "transaction_log_recovery": {
                    "status": transaction_status,
                    "supported_log_files": [".LOG", ".LOG1", ".LOG2"],
                    "reason": transaction_reason,
                    "base_hive_and_replayed_view_separated": True,
                    "restored_hive_output_policy": "TEMPORARY_DERIVED_VIEW_ONLY",
                    "original_hive_mutated": False,
                },
                "deleted_key_recovery": {
                    "registry_export_delete_directives": "SUPPORTED_CANDIDATE",
                    "binary_deleted_cells": "CAPABILITY_UNAVAILABLE",
                },
            },
        )

    def detect_source(self, node: FileSystemNode) -> ArtifactSource | None:
        if node.node_type is not FileSystemNodeType.FILE:
            return None
        name = node.original_name
        name_upper = name.upper()
        extension = (node.extension or "").casefold()
        if extension == "reg":
            return source_shell(
                node=node,
                source_kind=ArtifactSourceKind.REGISTRY_EXPORT,
                analyzer_id=self.analyzer_id,
                analyzer_version=self.analyzer_version,
                parser_backend="apex.reg_export_text",
                parser_backend_version=ENGINE_VERSION,
                priority=20,
            )
        if name_upper in _REGISTRY_HIVE_NAMES:
            backend_version = self._python_registry_version()
            return source_shell(
                node=node,
                source_kind=ArtifactSourceKind.REGISTRY_HIVE,
                analyzer_id=self.analyzer_id,
                analyzer_version=self.analyzer_version,
                parser_backend="python-registry"
                if backend_version is not None
                else "python-registry-unavailable",
                parser_backend_version=backend_version or "unavailable",
                priority=30,
            )
        return None

    def supports_source(self, source: ArtifactSource) -> bool:
        return source.source_kind in {
            ArtifactSourceKind.REGISTRY_EXPORT,
            ArtifactSourceKind.REGISTRY_HIVE,
        }

    def analyze(
        self,
        *,
        evidence: Evidence,
        node: FileSystemNode,
        source: ArtifactSource,
        file_path: Path,
        item_budget: int | None = None,
    ) -> ArtifactAnalysisResult:
        if source.source_kind is ArtifactSourceKind.REGISTRY_EXPORT:
            return self._analyze_reg_export(
                evidence=evidence,
                node=node,
                source=source,
                file_path=file_path,
                item_budget=item_budget,
            )
        return self._analyze_binary_hive(
            evidence=evidence,
            node=node,
            source=source,
            file_path=file_path,
            item_budget=item_budget,
        )

    def _analyze_reg_export(
        self,
        *,
        evidence: Evidence,
        node: FileSystemNode,
        source: ArtifactSource,
        file_path: Path,
        item_budget: int | None,
    ) -> ArtifactAnalysisResult:
        try:
            raw = file_path.read_bytes()
            text, encoding = _decode_reg_text(raw)
        except OSError as error:
            return ArtifactAnalysisResult(
                errors=(
                    issue(
                        severity="ERROR",
                        code="REGISTRY_EXPORT_READ_FAILED",
                        message_key="error.registry_export.read_failed",
                        developer_message="Registry export could not be read.",
                        node=node,
                        details={"error": str(error)},
                    ),
                ),
                parse_status=ArtifactParseStatus.FAILED,
            )
        if not _has_reg_header(text):
            warning = issue(
                severity="WARNING",
                code="UNSUPPORTED_REGISTRY_EXPORT_HEADER",
                message_key="warning.registry_export.unsupported_header",
                developer_message="Registry export header is missing or unsupported.",
                node=node,
            )
            return ArtifactAnalysisResult(
                warnings=(warning,),
                parse_status=ArtifactParseStatus.UNSUPPORTED,
            )
        try:
            sections, parse_warnings = _parse_reg_sections(text, node=node)
        except ValueError as error:
            return ArtifactAnalysisResult(
                errors=(
                    issue(
                        severity="ERROR",
                        code="CORRUPT_REGISTRY_EXPORT",
                        message_key="error.registry_export.corrupt",
                        developer_message="Registry export text could not be parsed safely.",
                        node=node,
                        details={"error": str(error)},
                    ),
                ),
                parse_status=ArtifactParseStatus.CORRUPT,
            )
        artifacts: list[ArtifactRecord] = []
        for section in sections:
            artifacts.extend(
                self._artifacts_for_section(
                    evidence=evidence,
                    node=node,
                    source=source,
                    section=section,
                    encoding=encoding,
                )
            )
            if item_budget is not None and len(artifacts) >= item_budget:
                return ArtifactAnalysisResult(
                    artifacts=tuple(artifacts[:item_budget]),
                    warnings=(
                        *parse_warnings,
                        issue(
                            severity="WARNING",
                            code="ARTIFACT_ITEM_BUDGET_REACHED",
                            message_key="warning.artifact.item_budget_reached",
                            developer_message=(
                                "Registry export analysis stopped at the configured item budget."
                            ),
                            node=node,
                            details={"item_budget": item_budget},
                        ),
                    ),
                    coverage={"encoding": encoding, "section_count": len(sections)},
                    parse_status=ArtifactParseStatus.PARTIAL,
                )
        return ArtifactAnalysisResult(
            artifacts=tuple(artifacts),
            warnings=tuple(parse_warnings),
            coverage={"encoding": encoding, "section_count": len(sections)},
            parse_status=ArtifactParseStatus.SUCCESS,
        )

    def _artifacts_for_section(
        self,
        *,
        evidence: Evidence,
        node: FileSystemNode,
        source: ArtifactSource,
        section: _RegSection,
        encoding: str,
        view_source: str = "REGISTRY_EXPORT",
        transaction_provenance: dict[str, Any] | None = None,
    ) -> list[ArtifactRecord]:
        artifacts: list[ArtifactRecord] = []
        key_locator = _registry_locator(
            node=node,
            evidence=evidence,
            section=section,
            value=None,
            encoding=encoding,
        )
        key_fields = {
            "registry_path": section.path,
            "root_key": _root_key(section.path),
            "hive_type": _hive_type(section.path, node.original_name),
            "is_deleted_directive": section.deleted,
            "value_count": len(section.values),
            "line_number": section.line_no,
            "last_write_time_raw": None,
            "last_write_time_utc": None,
            "registry_hive_view": view_source,
            "deleted_candidate": section.deleted,
            "recovered_candidate": False,
        }
        if transaction_provenance is not None:
            key_fields["transaction_replay_provenance"] = transaction_provenance
        key_status = ArtifactParseStatus.PARTIAL if section.deleted else ArtifactParseStatus.SUCCESS
        key_subtype = (
            "REGISTRY_EXPORT_DELETED_KEY_CANDIDATE"
            if section.deleted
            else "REGISTRY_EXPORT_KEY"
        )
        key_summary = (
            "Registry export delete directive observed; key is a deleted-key candidate, "
            "not a current observed key."
            if section.deleted
            else "Registry export key observed in offline text."
        )
        if section.deleted:
            key_fields["deleted_candidate_provenance"] = {
                "basis": "REG_EXPORT_DELETE_DIRECTIVE",
                "line_number": section.line_no,
                "confidence": "HIGH_FOR_EXPORT_DIRECTIVE",
                "confirmed_binary_deleted_cell": False,
            }
        artifacts.append(
            make_artifact(
                evidence=evidence,
                node=node,
                source=source,
                artifact_type=ArtifactType.REGISTRY_KEY,
                artifact_subtype=key_subtype,
                fields=key_fields,
                raw_locator=key_locator,
                title=section.path,
                summary=key_summary,
                parse_status=key_status,
                confidence=0.75 if section.deleted else 0.95,
            )
        )
        for value in section.values:
            value_locator = _registry_locator(
                node=node,
                evidence=evidence,
                section=section,
                value=value,
                encoding=encoding,
            )
            value_fields = {
                "registry_path": section.path,
                "value_name": value.name,
                "value_type": value.value_type,
                "raw_data": value.raw_data,
                "normalized_value": _json_value_data(value.data),
                "is_deleted_directive": value.deleted,
                "line_number": value.line_no,
                "hive_type": _hive_type(section.path, node.original_name),
                "registry_hive_view": view_source,
                "deleted_candidate": section.deleted or value.deleted,
                "recovered_candidate": False,
            }
            if transaction_provenance is not None:
                value_fields["transaction_replay_provenance"] = transaction_provenance
            value_subtype = (
                "REGISTRY_EXPORT_DELETED_VALUE_CANDIDATE"
                if value.deleted or section.deleted
                else "REGISTRY_EXPORT_VALUE"
            )
            value_status = (
                ArtifactParseStatus.PARTIAL
                if value.deleted or section.deleted
                else ArtifactParseStatus.SUCCESS
            )
            value_summary = (
                "Registry export delete directive observed for this value; value is a "
                "deleted-value candidate, not a current observed value."
                if value.deleted or section.deleted
                else "Registry export value observed in offline text."
            )
            if value.deleted or section.deleted:
                value_fields["deleted_candidate_provenance"] = {
                    "basis": "REG_EXPORT_DELETE_DIRECTIVE",
                    "section_line_number": section.line_no,
                    "value_line_number": value.line_no,
                    "confidence": "HIGH_FOR_EXPORT_DIRECTIVE",
                    "confirmed_binary_deleted_cell": False,
                }
            artifacts.append(
                make_artifact(
                    evidence=evidence,
                    node=node,
                    source=source,
                    artifact_type=ArtifactType.REGISTRY_VALUE,
                    artifact_subtype=value_subtype,
                    fields=value_fields,
                    raw_locator=value_locator,
                    title=f"{section.path}\\{value.name}",
                    summary=value_summary,
                    parse_status=value_status,
                    confidence=0.7 if value.deleted or section.deleted else 0.95,
                )
            )
            if _is_autorun_path(section.path) and not value.deleted:
                artifacts.append(
                    self._autorun_artifact(
                        evidence=evidence,
                        node=node,
                        source=source,
                        section=section,
                        value=value,
                        raw_locator=value_locator,
                    )
                )
            if _is_userassist_count_path(section.path) and not value.deleted:
                artifacts.append(
                    self._userassist_artifact(
                        evidence=evidence,
                        node=node,
                        source=source,
                        section=section,
                        value=value,
                        raw_locator=value_locator,
                    )
                )
        if _is_timezone_path(section.path):
            artifacts.append(
                self._timezone_artifact(
                    evidence=evidence,
                    node=node,
                    source=source,
                    section=section,
                    raw_locator=key_locator,
                )
            )
        usb = self._usb_artifact(
            evidence=evidence,
            node=node,
            source=source,
            section=section,
            raw_locator=key_locator,
        )
        if usb is not None:
            artifacts.append(usb)
        return artifacts

    def _autorun_artifact(
        self,
        *,
        evidence: Evidence,
        node: FileSystemNode,
        source: ArtifactSource,
        section: _RegSection,
        value: _RegValue,
        raw_locator: dict[str, Any],
    ) -> ArtifactRecord:
        raw_command = "" if value.data is None else str(value.data)
        executable, arguments = _command_candidates(raw_command)
        fields = {
            "value_name": value.name,
            "raw_command": raw_command,
            "executable_candidate": executable,
            "arguments_candidate": arguments,
            "registry_path": section.path,
            "last_write_time_raw": None,
            "last_write_time_utc": None,
            "hive_type": _hive_type(section.path, node.original_name),
            "user_scope": _user_scope(section.path),
            "registry_view": _registry_view(section.path),
            "candidate_confidence_note": (
                "Command parsing is a candidate extraction, not a confirmed executable path."
            ),
        }
        return make_artifact(
            evidence=evidence,
            node=node,
            source=source,
            artifact_type=ArtifactType.REGISTRY_AUTORUN,
            artifact_subtype="RUNONCE" if section.path.casefold().endswith("runonce") else "RUN",
            fields=fields,
            raw_locator=raw_locator,
            title=f"Autorun candidate: {value.name}",
            summary="Registry autorun value observed; executable path is a candidate.",
            parse_status=ArtifactParseStatus.SUCCESS,
            confidence=0.8,
        )

    def _timezone_artifact(
        self,
        *,
        evidence: Evidence,
        node: FileSystemNode,
        source: ArtifactSource,
        section: _RegSection,
        raw_locator: dict[str, Any],
    ) -> ArtifactRecord:
        values = {value.name.casefold(): value.data for value in section.values}
        timezone_key_name = _string_or_none(values.get("timezonekeyname"))
        iana_candidate = _WINDOWS_TZ_TO_IANA.get(timezone_key_name or "")
        bias = _int_or_none(values.get("bias"))
        standard_bias = _int_or_none(values.get("standardbias"))
        daylight_bias = _int_or_none(values.get("daylightbias"))
        dynamic_dst_disabled = _bool_or_none(values.get("dynamicdaylighttimedisabled"))
        fields = {
            "registry_path": section.path,
            "TimeZoneKeyName": timezone_key_name,
            "StandardName": _string_or_none(values.get("standardname")),
            "DaylightName": _string_or_none(values.get("daylightname")),
            "Bias": bias,
            "ActiveTimeBias": _int_or_none(values.get("activetimebias")),
            "StandardBias": standard_bias,
            "DaylightBias": daylight_bias,
            "DynamicDaylightTimeDisabled": dynamic_dst_disabled,
            "registry_last_write_time_raw": None,
            "registry_last_write_time_utc": None,
            "iana_mapping_candidate": iana_candidate,
            "iana_mapping_confidence": "MEDIUM" if iana_candidate else "UNKNOWN",
            "timezone_resolver": {
                "source": "WINDOWS_TIMEZONE_CANDIDATE",
                "confidence": "MEDIUM" if iana_candidate else "LOW",
                "windows_time_zone_key": timezone_key_name,
                "iana_candidate": iana_candidate,
                "bias_minutes": bias,
                "standard_bias_minutes": standard_bias,
                "daylight_bias_minutes": daylight_bias,
                "dynamic_dst": {
                    "dynamic_daylight_time_disabled": dynamic_dst_disabled,
                    "dynamic_dst_rules_parsed": False,
                    "limitation": (
                        "Dynamic DST transition rules require correlated time-zone database "
                        "registry keys and are not inferred from this value alone."
                    ),
                },
                "browser_application_offset_policy": (
                    "Application/browser explicit timestamp offsets are preserved on their "
                    "own artifacts and not overwritten by this Windows timezone candidate."
                ),
                "artifact_offset_policy": "EXPLICIT_OFFSET_WINS_OVER_REGISTRY_CANDIDATE",
                "analyst_override": {
                    "applied": False,
                    "source": "ANALYST_CONFIRMED",
                    "audit_required": True,
                },
            },
        }
        return make_artifact(
            evidence=evidence,
            node=node,
            source=source,
            artifact_type=ArtifactType.REGISTRY_TIMEZONE,
            artifact_subtype="TIMEZONE_INFORMATION",
            fields=fields,
            raw_locator=raw_locator,
            title=f"Windows timezone candidate: {timezone_key_name or 'unknown'}",
            summary="Windows timezone registry values observed; IANA mapping remains a candidate.",
            parse_status=ArtifactParseStatus.SUCCESS,
            confidence=0.85 if timezone_key_name else 0.6,
        )

    def _usb_artifact(
        self,
        *,
        evidence: Evidence,
        node: FileSystemNode,
        source: ArtifactSource,
        section: _RegSection,
        raw_locator: dict[str, Any],
    ) -> ArtifactRecord | None:
        parsed = _parse_usbstor_path(section.path)
        if parsed is None:
            return None
        values = {value.name.casefold(): value.data for value in section.values}
        fields = {
            "registry_path": section.path,
            "vendor_candidate": parsed.get("vendor_candidate"),
            "product_candidate": parsed.get("product_candidate"),
            "serial_candidate": parsed.get("serial_candidate"),
            "device_instance": parsed.get("device_instance"),
            "friendly_name": _string_or_none(values.get("friendlyname")),
            "service": _string_or_none(values.get("service")),
            "first_observed_candidate": None,
            "last_observed_candidate": None,
            "hive_control_set": parsed.get("hive_control_set"),
            "confidence_warning": (
                "USB first/last observation requires additional correlated registry keys."
            ),
        }
        warning = {
            "code": "USB_OBSERVATION_TIME_UNCORRELATED",
            "message_key": "warning.registry.usb_observation_time_uncorrelated",
            "developer_message": (
                "USB device path was observed, but first/last connection time was not derived."
            ),
        }
        return make_artifact(
            evidence=evidence,
            node=node,
            source=source,
            artifact_type=ArtifactType.REGISTRY_USB_DEVICE,
            artifact_subtype="USBSTOR_DEVICE",
            fields=fields,
            raw_locator=raw_locator,
            title=f"USB device candidate: {parsed.get('device_instance')}",
            summary="USBSTOR device instance observed in offline registry source.",
            parse_status=ArtifactParseStatus.PARTIAL,
            confidence=0.65,
            warnings=[warning],
        )

    def _userassist_artifact(
        self,
        *,
        evidence: Evidence,
        node: FileSystemNode,
        source: ArtifactSource,
        section: _RegSection,
        value: _RegValue,
        raw_locator: dict[str, Any],
    ) -> ArtifactRecord:
        decoded_name = codecs.decode(value.name, "rot_13")
        raw_bytes = value.data if isinstance(value.data, bytes) else b""
        parsed, status, warning = _parse_userassist_bytes(raw_bytes)
        fields = {
            "registry_path": section.path,
            "guid_bucket": _userassist_guid(section.path),
            "encoded_value_name": value.name,
            "decoded_value_name": decoded_name,
            "value_type": value.value_type,
            "raw_bytes_hex": raw_bytes.hex(),
        } | parsed
        warnings = [warning] if warning is not None else []
        return make_artifact(
            evidence=evidence,
            node=node,
            source=source,
            artifact_type=ArtifactType.REGISTRY_USERASSIST,
            artifact_subtype="USERASSIST_COUNT",
            fields=fields,
            raw_locator=raw_locator,
            title=f"UserAssist candidate: {decoded_name}",
            summary="UserAssist value observed; only known safe counters were decoded.",
            parse_status=status,
            confidence=0.75 if status is ArtifactParseStatus.SUCCESS else 0.45,
            warnings=warnings,
        )

    def _analyze_binary_hive(
        self,
        *,
        evidence: Evidence,
        node: FileSystemNode,
        source: ArtifactSource,
        file_path: Path,
        item_budget: int | None,
    ) -> ArtifactAnalysisResult:
        backend_version = self._python_registry_version()
        if backend_version is None:
            warning = issue(
                severity="WARNING",
                code="CAPABILITY_UNAVAILABLE",
                message_key="warning.registry.python_registry_unavailable",
                developer_message="python-registry is not installed; binary hive was not parsed.",
                node=node,
                details={"optional_dependency": "python-registry"},
            )
            return ArtifactAnalysisResult(
                warnings=(warning,),
                parse_status=ArtifactParseStatus.UNSUPPORTED,
                coverage={"source_kind": source.source_kind.value},
            )
        try:
            registry_module = importlib.import_module("Registry.Registry")
            registry = registry_module.Registry(str(file_path))
        except Exception as error:
            return ArtifactAnalysisResult(
                errors=(
                    issue(
                        severity="ERROR",
                        code="REGISTRY_HIVE_OPEN_FAILED",
                        message_key="error.registry_hive.open_failed",
                        developer_message="Binary registry hive could not be opened.",
                        node=node,
                        details={"error": str(error)},
                    ),
                ),
                parse_status=ArtifactParseStatus.CORRUPT,
            )
        artifacts, warnings = self._extract_binary_hive_artifacts(
            registry=registry,
            evidence=evidence,
            node=node,
            source=source,
            item_budget=item_budget,
            view_source="ORIGINAL_HIVE",
            transaction_provenance=None,
        )
        replay_warning, replay_artifacts = self._transaction_replay_artifacts(
            file_path=file_path,
            evidence=evidence,
            node=node,
            source=source,
            item_budget=item_budget,
            original_artifacts=artifacts,
        )
        if replay_warning is not None:
            warnings.append(replay_warning)
        artifacts.extend(replay_artifacts)
        status = (
            ArtifactParseStatus.PARTIAL
            if item_budget is not None and len(artifacts) >= item_budget
            else ArtifactParseStatus.SUCCESS
        )
        return ArtifactAnalysisResult(
            artifacts=tuple(artifacts[:item_budget] if item_budget is not None else artifacts),
            warnings=tuple(warnings),
            parse_status=status,
            coverage={
                "binary_backend": "python-registry",
                "backend_version": backend_version,
                "transaction_replay_artifact_count": len(replay_artifacts),
            },
        )

    def _extract_binary_hive_artifacts(
        self,
        *,
        registry: Any,
        evidence: Evidence,
        node: FileSystemNode,
        source: ArtifactSource,
        item_budget: int | None,
        view_source: str,
        transaction_provenance: dict[str, Any] | None,
    ) -> tuple[list[ArtifactRecord], list[ArtifactIssue]]:
        artifacts: list[ArtifactRecord] = []
        warnings: list[ArtifactIssue] = []
        for section in self._binary_sections(registry, node):
            artifacts.extend(
                self._artifacts_for_section(
                    evidence=evidence,
                    node=node,
                    source=source,
                    section=section,
                    encoding="registry-hive",
                    view_source=view_source,
                    transaction_provenance=transaction_provenance,
                )
            )
            if item_budget is not None and len(artifacts) >= item_budget:
                break
        if not artifacts:
            warnings.append(
                issue(
                    severity="WARNING",
                    code="REGISTRY_HIVE_NO_TARGETS",
                    message_key="warning.registry_hive.no_targets",
                    developer_message=(
                        "Binary hive opened, but no Phase 3 target keys were present."
                    ),
                    node=node,
                )
            )
        return artifacts, warnings

    def _transaction_replay_artifacts(
        self,
        *,
        file_path: Path,
        evidence: Evidence,
        node: FileSystemNode,
        source: ArtifactSource,
        item_budget: int | None,
        original_artifacts: list[ArtifactRecord],
    ) -> tuple[ArtifactIssue | None, list[ArtifactRecord]]:
        if self._regipy_version() is None:
            return None, []
        primary, secondary = _transaction_log_paths(file_path)
        if primary is None:
            return None, []
        try:
            recovery_module = importlib.import_module("regipy.recovery")
            registry_module = importlib.import_module("Registry.Registry")
            with tempfile.TemporaryDirectory(prefix="apex-registry-replay-") as temp_dir:
                restored = Path(temp_dir) / f"{file_path.name}.replayed"
                restored_path, dirty_pages = recovery_module.apply_transaction_logs(
                    str(file_path),
                    str(primary),
                    secondary_log_path=None if secondary is None else str(secondary),
                    restored_hive_path=str(restored),
                    verbose=False,
                )
                provenance = {
                    "status": "APPLIED",
                    "adapter": "regipy.recovery.apply_transaction_logs",
                    "adapter_version": self._regipy_version(),
                    "base_hive_sha256": _file_sha256(file_path),
                    "primary_log": _log_provenance(primary),
                    "secondary_log": None if secondary is None else _log_provenance(secondary),
                    "recovered_dirty_pages": int(dirty_pages),
                    "original_hive_mutated": False,
                    "replayed_view_separated": True,
                }
                replayed_registry = registry_module.Registry(str(restored_path))
                replayed, warnings = self._extract_binary_hive_artifacts(
                    registry=replayed_registry,
                    evidence=evidence,
                    node=node,
                    source=source,
                    item_budget=item_budget,
                    view_source="REPLAYED_TRANSACTION_LOG",
                    transaction_provenance=provenance,
                )
        except Exception as error:
            return (
                issue(
                    severity="WARNING",
                    code="REGISTRY_TRANSACTION_LOG_REPLAY_FAILED",
                    message_key="warning.registry.transaction_log_replay_failed",
                    developer_message=(
                        "Registry transaction logs were discovered but could not be applied."
                    ),
                    node=node,
                    details={
                        "primary_log": str(primary),
                        "secondary_log": None if secondary is None else str(secondary),
                        "error_type": type(error).__name__,
                    },
                ),
                [],
            )
        original_keys = {_registry_logical_key(artifact) for artifact in original_artifacts}
        for artifact in replayed:
            logical_key = _registry_logical_key(artifact)
            artifact.fields["transaction_replay_provenance"] = provenance
            artifact.fields["recovered_candidate"] = logical_key not in original_keys
            artifact.fields["recovered_candidate_provenance"] = {
                "basis": "PRESENT_ONLY_IN_REPLAYED_VIEW"
                if logical_key not in original_keys
                else "PRESENT_IN_REPLAYED_VIEW",
                "confidence": "MEDIUM",
                "binary_deleted_cell_recovery": False,
            }
            artifact.raw_locator["details"]["registry_hive_view"] = "REPLAYED_TRANSACTION_LOG"
        if warnings:
            return warnings[0], replayed
        return None, replayed

    def _binary_sections(self, registry: Any, node: FileSystemNode) -> Iterable[_RegSection]:
        paths = _binary_target_paths(node.original_name)
        for path in paths:
            try:
                key = registry.open(path)
            except Exception:
                continue
            values: list[_RegValue] = []
            for value in key.values():
                values.append(
                    _RegValue(
                        name=str(value.name() or "@"),
                        value_type=str(value.value_type_str()),
                        data=value.value(),
                        raw_data=repr(value.value()),
                        line_no=0,
                    )
                )
            timestamp = key.timestamp()
            if isinstance(timestamp, datetime):
                timestamp_raw = timestamp.astimezone(UTC).isoformat()
            else:
                timestamp_raw = None
            section = _RegSection(
                path=_canonical_hive_path(node.original_name, path),
                line_no=0,
                deleted=False,
                values=tuple(values),
            )
            if timestamp_raw is not None:
                yield _section_with_last_write(section, timestamp_raw)
            else:
                yield section

    @staticmethod
    def _python_registry_version() -> str | None:
        try:
            return importlib.metadata.version("python-registry")
        except importlib.metadata.PackageNotFoundError:
            return None

    @staticmethod
    def _regipy_version() -> str | None:
        try:
            return importlib.metadata.version("regipy")
        except importlib.metadata.PackageNotFoundError:
            return None


def _decode_reg_text(raw: bytes) -> tuple[str, str]:
    if raw.startswith(b"\xff\xfe"):
        return raw.decode("utf-16"), "utf-16le-bom"
    if raw.startswith(b"\xef\xbb\xbf"):
        return raw.decode("utf-8-sig"), "utf-8-bom"
    if raw[:100].count(b"\x00") > 10:
        return raw.decode("utf-16le"), "utf-16le"
    try:
        return raw.decode("utf-8"), "utf-8"
    except UnicodeDecodeError:
        return raw.decode("utf-16le"), "utf-16le"


def _has_reg_header(text: str) -> bool:
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        return stripped in {"Windows Registry Editor Version 5.00", "REGEDIT4"}
    return False


def _parse_reg_sections(
    text: str, *, node: FileSystemNode
) -> tuple[list[_RegSection], list[ArtifactIssue]]:
    sections: list[_RegSection] = []
    warnings: list[ArtifactIssue] = []
    current_path: str | None = None
    current_deleted = False
    current_line = 0
    current_values: list[_RegValue] = []
    for line_no, line in _continued_lines(text):
        stripped = line.strip()
        if not stripped or stripped.startswith(";"):
            continue
        if stripped.startswith("[") and stripped.endswith("]"):
            if current_path is not None:
                sections.append(
                    _RegSection(
                        path=current_path,
                        line_no=current_line,
                        deleted=current_deleted,
                        values=tuple(current_values),
                    )
                )
            raw_path = stripped[1:-1].strip()
            current_deleted = raw_path.startswith("-")
            current_path = raw_path[1:] if current_deleted else raw_path
            current_line = line_no
            current_values = []
            continue
        if current_path is None:
            continue
        try:
            current_values.append(_parse_value_line(stripped, line_no=line_no))
        except ValueError as error:
            warnings.append(
                issue(
                    severity="WARNING",
                    code="REGISTRY_VALUE_PARSE_SKIPPED",
                    message_key="warning.registry_export.value_parse_skipped",
                    developer_message="Registry value line could not be parsed and was skipped.",
                    node=node,
                    details={"line_number": line_no, "error": str(error)},
                )
            )
    if current_path is not None:
        sections.append(
            _RegSection(
                path=current_path,
                line_no=current_line,
                deleted=current_deleted,
                values=tuple(current_values),
            )
        )
    return sections, warnings


def _continued_lines(text: str) -> Iterable[tuple[int, str]]:
    buffer = ""
    start_line = 1
    for line_no, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not buffer:
            start_line = line_no
        if stripped.endswith("\\"):
            buffer += stripped[:-1]
            continue
        if buffer:
            yield start_line, buffer + stripped
            buffer = ""
        else:
            yield line_no, line
    if buffer:
        yield start_line, buffer


def _parse_value_line(line: str, *, line_no: int) -> _RegValue:
    if line.startswith("@="):
        name = "@"
        raw_data = line[2:]
    else:
        match = re.match(r'^"((?:\\"|[^"])*)"\s*=\s*(.*)$', line)
        if match is None:
            raise ValueError("not a registry value assignment")
        name = _unescape_reg_string(match.group(1))
        raw_data = match.group(2)
    if raw_data == "-":
        return _RegValue(
            name=name,
            value_type="REG_DELETE",
            data=None,
            raw_data=raw_data,
            line_no=line_no,
            deleted=True,
        )
    if raw_data.startswith('"') and raw_data.endswith('"'):
        return _RegValue(
            name=name,
            value_type="REG_SZ",
            data=_unescape_reg_string(raw_data[1:-1]),
            raw_data=raw_data,
            line_no=line_no,
        )
    lowered = raw_data.casefold()
    if lowered.startswith("dword:"):
        return _RegValue(
            name=name,
            value_type="REG_DWORD",
            data=int(raw_data.split(":", 1)[1], 16),
            raw_data=raw_data,
            line_no=line_no,
        )
    if lowered.startswith("hex(b):"):
        data = _hex_bytes(raw_data.split(":", 1)[1])
        return _RegValue(
            name=name,
            value_type="REG_QWORD",
            data=int.from_bytes(data[:8].ljust(8, b"\x00"), "little"),
            raw_data=raw_data,
            line_no=line_no,
        )
    if lowered.startswith("hex(2):"):
        data = _hex_bytes(raw_data.split(":", 1)[1])
        return _RegValue(
            name=name,
            value_type="REG_EXPAND_SZ",
            data=_decode_utf16_reg_bytes(data),
            raw_data=raw_data,
            line_no=line_no,
        )
    if lowered.startswith("hex(7):"):
        data = _hex_bytes(raw_data.split(":", 1)[1])
        text = _decode_utf16_reg_bytes(data)
        return _RegValue(
            name=name,
            value_type="REG_MULTI_SZ",
            data=[item for item in text.split("\x00") if item],
            raw_data=raw_data,
            line_no=line_no,
        )
    if lowered.startswith("hex:") or lowered.startswith("hex("):
        return _RegValue(
            name=name,
            value_type="REG_BINARY",
            data=_hex_bytes(raw_data.split(":", 1)[1]),
            raw_data=raw_data,
            line_no=line_no,
        )
    raise ValueError("unsupported registry value syntax")


def _unescape_reg_string(value: str) -> str:
    return value.replace(r"\\", "\\").replace(r"\"", '"')


def _hex_bytes(value: str) -> bytes:
    parts = [part.strip() for part in value.replace("\\", "").split(",") if part.strip()]
    try:
        return bytes(int(part, 16) for part in parts)
    except ValueError as error:
        raise ValueError("invalid hex byte sequence") from error


def _decode_utf16_reg_bytes(value: bytes) -> str:
    if value.endswith(b"\x00\x00"):
        value = value[:-2]
    return value.decode("utf-16le", errors="replace")


def _registry_locator(
    *,
    node: FileSystemNode,
    evidence: Evidence,
    section: _RegSection,
    value: _RegValue | None,
    encoding: str,
) -> dict[str, Any]:
    reference = section.path if value is None else f"{section.path}\\{value.name}"
    return make_raw_locator(
        evidence_id=evidence.evidence_id,
        source_file_node_id=node.node_id,
        source_path=node.display_path,
        source_reference=reference,
        locator_type="LOGICAL_REGISTRY",
        offset=None,
        length=None,
        encoding=encoding,
        view_types=["TEXT"],
        content_sha256=None,
        limitations=[
            (
                "Registry logical locator does not invent byte offsets when the parser does "
                "not expose them."
            )
        ],
        details={
            "hive_path": node.display_path,
            "key_path": section.path,
            "value_name": None if value is None else value.name,
            "value_type": None if value is None else value.value_type,
            "line_number": section.line_no if value is None else value.line_no,
        },
    )


def _transaction_log_paths(hive_path: Path) -> tuple[Path | None, Path | None]:
    """Return adjacent primary/secondary hive transaction logs without following links."""

    candidates = (
        hive_path.with_name(f"{hive_path.name}.LOG1"),
        hive_path.with_name(f"{hive_path.name}.LOG"),
    )
    primary = next((candidate for candidate in candidates if _safe_adjacent_file(candidate)), None)
    secondary = hive_path.with_name(f"{hive_path.name}.LOG2")
    return primary, secondary if _safe_adjacent_file(secondary) else None


def _safe_adjacent_file(path: Path) -> bool:
    try:
        return path.exists() and path.is_file() and not path.is_symlink()
    except OSError:
        return False


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _log_provenance(path: Path) -> dict[str, Any]:
    return {
        "path": path.name,
        "size_bytes": path.stat().st_size,
        "sha256": _file_sha256(path),
    }


def _registry_logical_key(artifact: ArtifactRecord) -> tuple[str, str | None, str | None]:
    return (
        artifact.artifact_type.value,
        _string_or_none(artifact.fields.get("registry_path")),
        _string_or_none(artifact.fields.get("value_name")),
    )


def _normalized_registry_path(path: str) -> str:
    return path.replace("/", "\\").casefold()


def _is_autorun_path(path: str) -> bool:
    normalized = _normalized_registry_path(path)
    return any(normalized.endswith(suffix) for suffix in _AUTORUN_SUFFIXES)


def _is_timezone_path(path: str) -> bool:
    return _normalized_registry_path(path).endswith(_TIMEZONE_SUFFIX)


def _is_userassist_count_path(path: str) -> bool:
    normalized = _normalized_registry_path(path)
    return _USERASSIST_SEGMENT in normalized and normalized.endswith(r"\count")


def _root_key(path: str) -> str:
    return path.split("\\", 1)[0]


def _hive_type(path: str, filename: str) -> str:
    root = _root_key(path).upper()
    if root in {"HKEY_LOCAL_MACHINE", "HKLM"}:
        name = filename.upper()
        if name in {"SYSTEM", "SOFTWARE"}:
            return name
        return "MACHINE"
    if root in {"HKEY_CURRENT_USER", "HKCU"}:
        return "USER"
    if root in {"HKEY_USERS", "HKU"}:
        return "USER"
    return filename.upper()


def _user_scope(path: str) -> str:
    root = _root_key(path).upper()
    if root in {"HKEY_LOCAL_MACHINE", "HKLM"}:
        return "MACHINE"
    if root in {"HKEY_CURRENT_USER", "HKCU", "HKEY_USERS", "HKU"}:
        return "USER"
    return "UNKNOWN"


def _registry_view(path: str) -> str:
    return (
        "32_BIT_VIEW_CANDIDATE"
        if "\\wow6432node\\" in _normalized_registry_path(path)
        else "UNKNOWN"
    )


def _command_candidates(raw_command: str) -> tuple[str | None, str | None]:
    stripped = raw_command.strip()
    if not stripped:
        return None, None
    try:
        parts = shlex.split(stripped, posix=False)
    except ValueError:
        parts = []
    if parts:
        executable = parts[0].strip('"')
        arguments = stripped[len(parts[0]) :].strip() or None
        return executable, arguments
    if stripped.startswith('"'):
        end = stripped.find('"', 1)
        if end > 0:
            return stripped[1:end], stripped[end + 1 :].strip() or None
    executable, _, arguments = stripped.partition(" ")
    return executable, arguments or None


def _string_or_none(value: Any) -> str | None:
    if value is None:
        return None
    return str(value)


def _int_or_none(value: Any) -> int | None:
    try:
        return None if value is None else int(value)
    except (TypeError, ValueError):
        return None


def _bool_or_none(value: Any) -> bool | None:
    integer = _int_or_none(value)
    if integer is None:
        return None
    return bool(integer)


def _json_value_data(value: Any) -> Any:
    if isinstance(value, bytes):
        return {"encoding": "hex", "value_hex": value.hex()}
    return value


def _parse_usbstor_path(path: str) -> dict[str, str | None] | None:
    parts = path.replace("/", "\\").split("\\")
    lower = [part.casefold() for part in parts]
    try:
        system_index = lower.index("system")
        enum_index = lower.index("enum")
        usbstor_index = lower.index("usbstor")
    except ValueError:
        return None
    if enum_index <= system_index or usbstor_index <= enum_index or len(parts) <= usbstor_index + 2:
        return None
    device_family = parts[usbstor_index + 1]
    serial = parts[usbstor_index + 2]
    device_values = _parse_usb_device_family(device_family)
    control_set = parts[system_index + 1] if len(parts) > system_index + 1 else None
    return {
        "vendor_candidate": device_values.get("vendor"),
        "product_candidate": device_values.get("product"),
        "serial_candidate": serial,
        "device_instance": f"{device_family}\\{serial}",
        "hive_control_set": control_set,
    }


def _parse_usb_device_family(value: str) -> dict[str, str | None]:
    result: dict[str, str | None] = {"vendor": None, "product": None}
    for token in value.split("&"):
        if token.casefold().startswith("ven_"):
            result["vendor"] = token[4:]
        if token.casefold().startswith("prod_"):
            result["product"] = token[5:]
    return result


def _userassist_guid(path: str) -> str | None:
    for part in path.split("\\"):
        if part.startswith("{") and part.endswith("}"):
            return part
    return None


def _parse_userassist_bytes(
    raw_bytes: bytes,
) -> tuple[dict[str, Any], ArtifactParseStatus, dict[str, Any] | None]:
    if len(raw_bytes) < 8:
        return (
            {
                "run_count": None,
                "focus_count": None,
                "focus_time_ms": None,
                "last_execution_time_raw": None,
                "last_execution_time_utc": None,
                "structure_version_candidate": "UNKNOWN",
            },
            ArtifactParseStatus.UNSUPPORTED,
            {
                "code": "USERASSIST_STRUCTURE_UNSUPPORTED",
                "message_key": "warning.registry.userassist_structure_unsupported",
                "developer_message": "UserAssist value is too short for safe counter parsing.",
            },
        )
    run_count = int.from_bytes(raw_bytes[4:8], "little", signed=False)
    focus_count = (
        int.from_bytes(raw_bytes[8:12], "little", signed=False) if len(raw_bytes) >= 12 else None
    )
    focus_time = (
        int.from_bytes(raw_bytes[12:16], "little", signed=False) if len(raw_bytes) >= 16 else None
    )
    last_raw = None
    last_utc = None
    if len(raw_bytes) >= 68:
        raw_filetime = int.from_bytes(raw_bytes[60:68], "little", signed=False)
        parsed = filetime_to_utc(raw_filetime)
        if parsed is not None:
            last_raw = str(raw_filetime)
            last_utc = parsed.isoformat(timespec="microseconds").replace("+00:00", "Z")
    status = ArtifactParseStatus.SUCCESS if len(raw_bytes) >= 16 else ArtifactParseStatus.PARTIAL
    warning = None
    if len(raw_bytes) < 16:
        warning = {
            "code": "USERASSIST_PARTIAL_COUNTERS",
            "message_key": "warning.registry.userassist_partial_counters",
            "developer_message": "Only run count was decoded from the short UserAssist value.",
        }
    return (
        {
            "run_count": run_count,
            "focus_count": focus_count,
            "focus_time_ms": focus_time,
            "last_execution_time_raw": last_raw,
            "last_execution_time_utc": last_utc,
            "structure_version_candidate": "WIN7_PLUS_SAFE_RANGE"
            if len(raw_bytes) >= 16
            else "SHORT_SAFE_RANGE",
        },
        status,
        warning,
    )


def _binary_target_paths(filename: str) -> tuple[str, ...]:
    name = filename.upper()
    if name == "SOFTWARE":
        return (
            r"Microsoft\Windows\CurrentVersion\Run",
            r"Microsoft\Windows\CurrentVersion\RunOnce",
            r"Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
            r"Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
        )
    if name == "SYSTEM":
        return (
            r"ControlSet001\Control\TimeZoneInformation",
            r"ControlSet001\Enum\USBSTOR",
        )
    if name in {"NTUSER.DAT", "USRCLASS.DAT"}:
        return (
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
            r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist",
        )
    return ()


def _canonical_hive_path(filename: str, path: str) -> str:
    name = filename.upper()
    if name in {"SOFTWARE", "SYSTEM"}:
        return f"HKEY_LOCAL_MACHINE\\{name}\\{path}"
    return f"HKEY_CURRENT_USER\\{path}"


def _section_with_last_write(section: _RegSection, timestamp_raw: str) -> _RegSection:
    values = list(section.values)
    values.append(
        _RegValue(
            name="__key_last_write_time__",
            value_type="APEX_METADATA",
            data=timestamp_raw,
            raw_data=timestamp_raw,
            line_no=0,
        )
    )
    return _RegSection(
        path=section.path,
        line_no=section.line_no,
        deleted=section.deleted,
        values=tuple(values),
    )
