"""Windows Event Log artifact analyzer."""

from __future__ import annotations

import importlib
import importlib.metadata
import xml.etree.ElementTree as ET
from collections.abc import Iterable
from datetime import datetime
from pathlib import Path
from typing import Any

from apex_forensic._time import parse_timestamp
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

from .common import issue, make_artifact, make_raw_locator, sha256_hex, source_shell

_EVENT_ID_SUBTYPES = {
    4624: ("SECURITY_LOGON_SUCCESS", "Windows logon success"),
    4625: ("SECURITY_LOGON_FAILURE", "Windows logon failure"),
    4634: ("SECURITY_LOGOFF", "Windows logoff"),
    4648: ("SECURITY_EXPLICIT_CREDENTIAL_LOGON", "Explicit credential logon"),
    4688: ("SECURITY_PROCESS_CREATION", "Process creation"),
    4697: ("SECURITY_SERVICE_INSTALLED", "Service installed"),
    7045: ("SYSTEM_SERVICE_INSTALLED", "Service installed"),
    1102: ("SECURITY_AUDIT_LOG_CLEARED", "Audit log cleared"),
}
_SYSMON_SUBTYPES = {
    1: ("SYSMON_PROCESS_CREATE", "Sysmon process create"),
    3: ("SYSMON_NETWORK_CONNECTION", "Sysmon network connection"),
    11: ("SYSMON_FILE_CREATE", "Sysmon file create"),
    12: ("SYSMON_REGISTRY_OBJECT_CREATE_DELETE", "Sysmon registry object create/delete"),
    13: ("SYSMON_REGISTRY_VALUE_SET", "Sysmon registry value set"),
    22: ("SYSMON_DNS_QUERY", "Sysmon DNS query"),
}


class WindowsEventLogAnalyzer:
    """Read-only analyzer for exported Event XML and optional EVTX files."""

    analyzer_id = "windows.eventlog"
    analyzer_version = ENGINE_VERSION

    @property
    def parser_backend(self) -> str:
        return "apex.eventlog"

    @property
    def parser_backend_version(self) -> str:
        return ENGINE_VERSION

    def capabilities(self) -> ArtifactCapability:
        unavailable: list[str] = []
        warnings: list[dict[str, Any]] = []
        if self._python_evtx_version() is None:
            unavailable.append("EVTX_BINARY_PARSE")
            warnings.append(
                {
                    "code": "CAPABILITY_UNAVAILABLE",
                    "message_key": "warning.eventlog.python_evtx_unavailable",
                    "developer_message": (
                        "python-evtx is not installed; EVTX parsing is unavailable."
                    ),
                }
            )
        return ArtifactCapability(
            analyzer_id=self.analyzer_id,
            analyzer_version=self.analyzer_version,
            parser_backend=self.parser_backend,
            parser_backend_version=self.parser_backend_version,
            supported_source_kinds=(
                ArtifactSourceKind.EVENT_LOG_XML,
                ArtifactSourceKind.EVENT_LOG_EVTX,
            ),
            supported_artifact_types=(ArtifactType.EVENT_LOG_RECORD,),
            capabilities=("EVENT_XML", "EVENT_FIELD_EXTRACTION", "EVENT_SUBTYPE_CANDIDATES"),
            unavailable_capabilities=tuple(unavailable),
            warnings=tuple(warnings),
            metadata={"message_dll_rendering": False, "streaming": True},
        )

    def detect_source(self, node: FileSystemNode) -> ArtifactSource | None:
        if node.node_type is not FileSystemNodeType.FILE:
            return None
        extension = (node.extension or "").casefold()
        if extension == "xml":
            return source_shell(
                node=node,
                source_kind=ArtifactSourceKind.EVENT_LOG_XML,
                analyzer_id=self.analyzer_id,
                analyzer_version=self.analyzer_version,
                parser_backend="apex.event_xml",
                parser_backend_version=ENGINE_VERSION,
                priority=45,
            )
        if extension == "evtx":
            backend_version = self._python_evtx_version()
            return source_shell(
                node=node,
                source_kind=ArtifactSourceKind.EVENT_LOG_EVTX,
                analyzer_id=self.analyzer_id,
                analyzer_version=self.analyzer_version,
                parser_backend="python-evtx"
                if backend_version is not None
                else "python-evtx-unavailable",
                parser_backend_version=backend_version or "unavailable",
                priority=40,
            )
        return None

    def supports_source(self, source: ArtifactSource) -> bool:
        return source.source_kind in {
            ArtifactSourceKind.EVENT_LOG_XML,
            ArtifactSourceKind.EVENT_LOG_EVTX,
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
        if source.source_kind is ArtifactSourceKind.EVENT_LOG_XML:
            return self._analyze_exported_xml(
                evidence=evidence,
                node=node,
                source=source,
                file_path=file_path,
                item_budget=item_budget,
            )
        return self._analyze_evtx(
            evidence=evidence,
            node=node,
            source=source,
            file_path=file_path,
            item_budget=item_budget,
        )

    def _analyze_exported_xml(
        self,
        *,
        evidence: Evidence,
        node: FileSystemNode,
        source: ArtifactSource,
        file_path: Path,
        item_budget: int | None,
    ) -> ArtifactAnalysisResult:
        artifacts: list[ArtifactRecord] = []
        warnings: list[ArtifactIssue] = []
        try:
            for ordinal, event_xml in enumerate(_iter_event_xml(file_path), start=1):
                try:
                    artifacts.append(
                        _artifact_from_event_xml(
                            evidence=evidence,
                            node=node,
                            source=source,
                            event_xml=event_xml,
                            ordinal=ordinal,
                        )
                    )
                except ValueError as error:
                    warnings.append(
                        issue(
                            severity="WARNING",
                            code="EVENT_XML_RECORD_SKIPPED",
                            message_key="warning.eventlog.record_skipped",
                            developer_message="An exported event record could not be parsed.",
                            node=node,
                            details={"record_ordinal": ordinal, "error": str(error)},
                        )
                    )
                if item_budget is not None and len(artifacts) >= item_budget:
                    warnings.append(
                        issue(
                            severity="WARNING",
                            code="ARTIFACT_ITEM_BUDGET_REACHED",
                            message_key="warning.artifact.item_budget_reached",
                            developer_message=(
                                "Event XML analysis stopped at the configured item budget."
                            ),
                            node=node,
                            details={"item_budget": item_budget},
                        )
                    )
                    return ArtifactAnalysisResult(
                        artifacts=tuple(artifacts),
                        warnings=tuple(warnings),
                        coverage={"record_count": len(artifacts)},
                        parse_status=ArtifactParseStatus.PARTIAL,
                    )
        except ET.ParseError as error:
            warnings.append(
                issue(
                    severity="WARNING",
                    code="CORRUPT_EVENT_XML",
                    message_key="warning.eventlog.xml_corrupt",
                    developer_message="Exported event XML is corrupt or truncated.",
                    node=node,
                    details={"error": str(error)},
                )
            )
            return ArtifactAnalysisResult(
                artifacts=tuple(artifacts),
                warnings=tuple(warnings),
                coverage={"record_count": len(artifacts)},
                parse_status=ArtifactParseStatus.CORRUPT,
            )
        except OSError as error:
            return ArtifactAnalysisResult(
                errors=(
                    issue(
                        severity="ERROR",
                        code="EVENT_XML_READ_FAILED",
                        message_key="error.eventlog.xml_read_failed",
                        developer_message="Exported event XML could not be read.",
                        node=node,
                        details={"error": str(error)},
                    ),
                ),
                parse_status=ArtifactParseStatus.FAILED,
            )
        if not artifacts:
            warnings.append(
                issue(
                    severity="WARNING",
                    code="EVENT_XML_NO_RECORDS",
                    message_key="warning.eventlog.no_records",
                    developer_message="No Event elements were found in the XML source.",
                    node=node,
                )
            )
            return ArtifactAnalysisResult(
                warnings=tuple(warnings),
                coverage={"record_count": 0},
                parse_status=ArtifactParseStatus.UNSUPPORTED,
            )
        return ArtifactAnalysisResult(
            artifacts=tuple(artifacts),
            warnings=tuple(warnings),
            coverage={"record_count": len(artifacts)},
            parse_status=ArtifactParseStatus.SUCCESS,
        )

    def _analyze_evtx(
        self,
        *,
        evidence: Evidence,
        node: FileSystemNode,
        source: ArtifactSource,
        file_path: Path,
        item_budget: int | None,
    ) -> ArtifactAnalysisResult:
        backend_version = self._python_evtx_version()
        if backend_version is None:
            warning = issue(
                severity="WARNING",
                code="CAPABILITY_UNAVAILABLE",
                message_key="warning.eventlog.python_evtx_unavailable",
                developer_message="python-evtx is not installed; EVTX file was not parsed.",
                node=node,
                details={"optional_dependency": "python-evtx"},
            )
            return ArtifactAnalysisResult(
                warnings=(warning,),
                parse_status=ArtifactParseStatus.UNSUPPORTED,
                coverage={"source_kind": source.source_kind.value},
            )
        artifacts: list[ArtifactRecord] = []
        warnings: list[ArtifactIssue] = []
        try:
            evtx_module = importlib.import_module("Evtx.Evtx")
            with evtx_module.Evtx(str(file_path)) as log:
                for ordinal, record in enumerate(log.records(), start=1):
                    try:
                        artifacts.append(
                            _artifact_from_event_xml(
                                evidence=evidence,
                                node=node,
                                source=source,
                                event_xml=str(record.xml()),
                                ordinal=ordinal,
                            )
                        )
                    except Exception as error:
                        warnings.append(
                            issue(
                                severity="WARNING",
                                code="EVTX_RECORD_SKIPPED",
                                message_key="warning.eventlog.evtx_record_skipped",
                                developer_message=(
                                    "A binary EVTX record could not be parsed and was skipped."
                                ),
                                node=node,
                                details={"record_ordinal": ordinal, "error": str(error)},
                            )
                        )
                    if item_budget is not None and len(artifacts) >= item_budget:
                        return ArtifactAnalysisResult(
                            artifacts=tuple(artifacts),
                            warnings=tuple(warnings),
                            parse_status=ArtifactParseStatus.PARTIAL,
                            coverage={"record_count": len(artifacts)},
                        )
        except Exception as error:
            return ArtifactAnalysisResult(
                artifacts=tuple(artifacts),
                errors=(
                    issue(
                        severity="ERROR",
                        code="EVTX_PARSE_FAILED",
                        message_key="error.eventlog.evtx_parse_failed",
                        developer_message="EVTX parsing failed.",
                        node=node,
                        details={"error": str(error)},
                    ),
                ),
                parse_status=ArtifactParseStatus.CORRUPT
                if artifacts
                else ArtifactParseStatus.FAILED,
            )
        return ArtifactAnalysisResult(
            artifacts=tuple(artifacts),
            warnings=tuple(warnings),
            parse_status=ArtifactParseStatus.SUCCESS
            if artifacts
            else ArtifactParseStatus.UNSUPPORTED,
            coverage={"record_count": len(artifacts), "binary_backend": "python-evtx"},
        )

    @staticmethod
    def _python_evtx_version() -> str | None:
        try:
            return importlib.metadata.version("python-evtx")
        except importlib.metadata.PackageNotFoundError:
            return None


def _iter_event_xml(path: Path) -> Iterable[str]:
    for _, element in ET.iterparse(path, events=("end",)):
        if _local_name(element.tag) == "Event":
            yield ET.tostring(element, encoding="unicode")
            element.clear()


def _artifact_from_event_xml(
    *,
    evidence: Evidence,
    node: FileSystemNode,
    source: ArtifactSource,
    event_xml: str,
    ordinal: int,
) -> ArtifactRecord:
    try:
        element = ET.fromstring(event_xml)
    except ET.ParseError as error:
        raise ValueError("invalid Event XML") from error
    if _local_name(element.tag) != "Event":
        raise ValueError("XML element is not an Event")
    system = _first_child(element, "System")
    if system is None:
        raise ValueError("Event XML has no System element")
    system_time_raw = _attr(_first_child(system, "TimeCreated"), "SystemTime")
    observed_at = _parse_event_time(system_time_raw)
    event_id = _int_text(_first_child(system, "EventID"))
    channel = _text(_first_child(system, "Channel"))
    provider = _first_child(system, "Provider")
    provider_name = _attr(provider, "Name")
    provider_guid = _attr(provider, "Guid")
    record_id = _int_text(_first_child(system, "EventRecordID"))
    execution = _first_child(system, "Execution")
    correlation = _first_child(system, "Correlation")
    event_data = _event_data(element)
    user_data = _user_data(element)
    subtype, title_prefix = _event_subtype(channel, event_id)
    raw_locator = make_raw_locator(
        evidence_id=evidence.evidence_id,
        source_file_node_id=node.node_id,
        source_path=node.display_path,
        source_reference=f"record:{record_id}" if record_id is not None else f"ordinal:{ordinal}",
        locator_type="LOGICAL_EVENT_RECORD",
        offset=None,
        length=None,
        encoding="xml",
        view_types=["TEXT"],
        content_sha256=sha256_hex(event_xml.encode("utf-8")),
        limitations=[
            (
                "EVTX/XML logical locator records event identity; byte offsets are only stored "
                "when parser exposes them."
            )
        ],
        details={
            "record_id": record_id,
            "record_ordinal": ordinal,
            "channel": channel,
            "provider": provider_name,
            "event_id": event_id,
        },
    )
    fields = {
        "channel": channel,
        "provider_name": provider_name,
        "provider_guid": provider_guid,
        "event_id": event_id,
        "version": _int_text(_first_child(system, "Version")),
        "level": _int_text(_first_child(system, "Level")),
        "task": _int_text(_first_child(system, "Task")),
        "opcode": _int_text(_first_child(system, "Opcode")),
        "keywords": _text(_first_child(system, "Keywords")),
        "record_id": record_id,
        "computer": _text(_first_child(system, "Computer")),
        "user_sid": _attr(_first_child(system, "Security"), "UserID"),
        "process_id": _int_attr(execution, "ProcessID"),
        "thread_id": _int_attr(execution, "ThreadID"),
        "activity_id": _attr(correlation, "ActivityID"),
        "related_activity_id": _attr(correlation, "RelatedActivityID"),
        "raw_system_time": system_time_raw,
        "normalized_utc_time": None
        if observed_at is None
        else observed_at.isoformat(timespec="microseconds").replace("+00:00", "Z"),
        "event_data": event_data,
        "user_data": user_data,
        "raw_xml": event_xml,
        "source_file_path": node.display_path,
        "record_locator": raw_locator["source_reference"],
        "message_rendered": False,
        "maliciousness_asserted": False,
    }
    title_value = f"{title_prefix} ({event_id})" if event_id is not None else "Windows event record"
    return make_artifact(
        evidence=evidence,
        node=node,
        source=source,
        artifact_type=ArtifactType.EVENT_LOG_RECORD,
        artifact_subtype=subtype,
        fields=fields,
        raw_locator=raw_locator,
        title=title_value,
        summary=(
            "Windows event record observed from exported XML/EVTX without message DLL rendering."
        ),
        parse_status=ArtifactParseStatus.SUCCESS,
        confidence=0.9,
        observed_at_raw=system_time_raw,
        observed_at_utc=observed_at,
        timezone_source="EVENT_SYSTEM_TIME",
        timezone_confidence="HIGH" if observed_at is not None else "UNKNOWN",
    )


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _first_child(element: ET.Element, name: str) -> ET.Element | None:
    for child in element:
        if _local_name(child.tag) == name:
            return child
    return None


def _text(element: ET.Element | None) -> str | None:
    if element is None or element.text is None:
        return None
    return element.text


def _attr(element: ET.Element | None, name: str) -> str | None:
    if element is None:
        return None
    return element.attrib.get(name)


def _int_text(element: ET.Element | None) -> int | None:
    value = _text(element)
    if value is None:
        return None
    try:
        return int(value)
    except ValueError:
        return None


def _int_attr(element: ET.Element | None, name: str) -> int | None:
    value = _attr(element, name)
    if value is None:
        return None
    try:
        return int(value)
    except ValueError:
        return None


def _parse_event_time(value: str | None) -> datetime | None:
    if value is None:
        return None
    try:
        return parse_timestamp(value)
    except ValueError:
        return None


def _event_data(element: ET.Element) -> dict[str, Any]:
    event_data = _first_child(element, "EventData")
    if event_data is None:
        return {}
    values: dict[str, Any] = {}
    ordinal = 0
    for child in event_data:
        if _local_name(child.tag) != "Data":
            continue
        name = child.attrib.get("Name")
        if not name:
            name = f"Data{ordinal}"
            ordinal += 1
        values[name] = child.text
    return values


def _user_data(element: ET.Element) -> dict[str, Any]:
    user_data = _first_child(element, "UserData")
    if user_data is None:
        return {}
    return {
        f"{_local_name(child.tag)}#{index}": _element_to_data(child)
        for index, child in enumerate(user_data)
    }


def _element_to_data(element: ET.Element) -> Any:
    children = list(element)
    if not children:
        return element.text
    return {_local_name(child.tag): _element_to_data(child) for child in children} | (
        {"_attributes": dict(element.attrib)} if element.attrib else {}
    )


def _event_subtype(channel: str | None, event_id: int | None) -> tuple[str, str]:
    if event_id is None:
        return "EVENT_RECORD", "Windows event record"
    if channel == "Microsoft-Windows-Sysmon/Operational" and event_id in _SYSMON_SUBTYPES:
        return _SYSMON_SUBTYPES[event_id]
    if event_id in _EVENT_ID_SUBTYPES:
        return _EVENT_ID_SUBTYPES[event_id]
    return f"EVENT_ID_{event_id}", "Windows event record"
