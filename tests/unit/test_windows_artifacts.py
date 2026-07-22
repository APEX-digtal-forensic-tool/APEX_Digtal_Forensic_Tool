from __future__ import annotations

import codecs
import importlib.metadata
import json
import struct
from datetime import UTC, datetime
from pathlib import Path

import pytest

from apex_forensic.adapters.artifacts import (
    WindowsEventLogAnalyzer,
    WindowsPrefetchAnalyzer,
    WindowsRegistryAnalyzer,
)
from apex_forensic.domain.enums import (
    AnalysisProfileType,
    ArtifactParseStatus,
    ArtifactSourceKind,
    ArtifactType,
)
from apex_forensic.domain.errors import ValidationError
from apex_forensic.domain.models import ArtifactQuery
from apex_forensic.jobs import CancellationToken, PauseToken


def _case_evidence_and_index(services, root: Path):
    case = services.cases.create_case(name="Artifact Case")
    evidence = services.evidence.register_evidence(case_id=case.case_id, source_path=root)
    services.fs.index_evidence(
        case_id=case.case_id,
        evidence_id=evidence.evidence_id,
        profile_type=AnalysisProfileType.FULL_ANALYSIS,
    )
    return case, evidence


def _filetime(value: datetime) -> int:
    epoch = datetime(1601, 1, 1, tzinfo=UTC)
    return int((value - epoch).total_seconds() * 10_000_000)


def _prefetch_bytes(*, version: int = 30, mam: bool = False) -> bytes:
    if mam:
        return b"MAM\x04compressed-prefetch"
    data = bytearray(0xD8)
    struct.pack_into("<I", data, 0x00, version)
    data[0x04:0x08] = b"SCCA"
    struct.pack_into("<I", data, 0x0C, len(data))
    data[0x10 : 0x10 + 60 * 2] = "CALC.EXE".encode("utf-16le").ljust(60 * 2, b"\x00")
    struct.pack_into("<I", data, 0x4C, 0xAABBCCDD)
    struct.pack_into("<Q", data, 0x80, _filetime(datetime(2024, 1, 2, 3, 4, 5, tzinfo=UTC)))
    struct.pack_into("<I", data, 0xD0, 7)
    return bytes(data)


def _event_xml() -> str:
    return """<?xml version="1.0" encoding="utf-8"?>
<Events xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <Event>
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{guid}" />
      <EventID>4624</EventID>
      <Version>2</Version>
      <Level>0</Level>
      <Task>12544</Task>
      <Opcode>0</Opcode>
      <Keywords>0x8020000000000000</Keywords>
      <TimeCreated SystemTime="2024-01-02T03:04:05Z" />
      <EventRecordID>42</EventRecordID>
      <Correlation ActivityID="{activity}" RelatedActivityID="{related}" />
      <Execution ProcessID="500" ThreadID="600" />
      <Channel>Security</Channel>
      <Computer>HOST-01</Computer>
      <Security UserID="S-1-5-18" />
    </System>
    <EventData>
      <Data Name="TargetUserName">홍길동</Data>
      <Data Name="IpAddress">127.0.0.1</Data>
    </EventData>
  </Event>
</Events>
"""


def _registry_text() -> str:
    userassist_name = codecs.encode(r"UEME_RUNPATH:C:\Windows\CALC.EXE", "rot_13")
    userassist_bytes = bytearray(72)
    struct.pack_into("<I", userassist_bytes, 4, 5)
    struct.pack_into("<I", userassist_bytes, 8, 2)
    struct.pack_into("<I", userassist_bytes, 12, 1000)
    struct.pack_into(
        "<Q", userassist_bytes, 60, _filetime(datetime(2024, 2, 3, 4, 5, 6, tzinfo=UTC))
    )
    userassist_hex = ",".join(f"{byte:02x}" for byte in userassist_bytes)
    return f"""Windows Registry Editor Version 5.00

[HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run]
"한글Autorun"="\\"C:\\\\Program Files\\\\앱\\\\app.exe\\" --flag"

[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\TimeZoneInformation]
"TimeZoneKeyName"="Korea Standard Time"
"StandardName"="대한민국 표준시"
"Bias"=dword:fffffde4

[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Enum\\USBSTOR\\Disk&Ven_SanDisk&Prod_Ultra&Rev_1.00\\SERIAL123]
"FriendlyName"="SanDisk Ultra USB Device"
"Service"="USBSTOR"

[HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist\\{{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}}\\Count]
"{userassist_name}"=hex:{userassist_hex}
"""


def _distribution_available(distribution_name: str) -> bool:
    try:
        importlib.metadata.version(distribution_name)
    except importlib.metadata.PackageNotFoundError:
        return False
    return True


def test_analyzer_capabilities_are_provider_neutral() -> None:
    capabilities = [
        WindowsRegistryAnalyzer().capabilities().to_schema_dict(),
        WindowsEventLogAnalyzer().capabilities().to_schema_dict(),
        WindowsPrefetchAnalyzer().capabilities().to_schema_dict(),
    ]

    assert {item["analyzer_id"] for item in capabilities} == {
        "windows.registry",
        "windows.eventlog",
        "windows.prefetch",
    }
    registry_unavailable = set(capabilities[0]["unavailable_capabilities"])
    eventlog_unavailable = set(capabilities[1]["unavailable_capabilities"])
    prefetch_unavailable = set(capabilities[2]["unavailable_capabilities"])

    if _distribution_available("python-registry"):
        assert "REGISTRY_HIVE_BINARY_PARSE" not in registry_unavailable
    else:
        assert "REGISTRY_HIVE_BINARY_PARSE" in registry_unavailable

    if _distribution_available("python-evtx"):
        assert "EVTX_BINARY_PARSE" not in eventlog_unavailable
    else:
        assert "EVTX_BINARY_PARSE" in eventlog_unavailable

    assert "PREFETCH_MAM_DECOMPRESSION" in prefetch_unavailable


def test_windows_artifact_analysis_discovery_query_and_schema(
    services,
    tmp_path: Path,
    schema_validator,
) -> None:
    evidence_dir = tmp_path / "증거"
    evidence_dir.mkdir()
    (evidence_dir / "registry.reg").write_bytes(("\ufeff" + _registry_text()).encode("utf-16le"))
    (evidence_dir / "security.xml").write_text(_event_xml(), encoding="utf-8")
    (evidence_dir / "CALC.EXE-AABBCCDD.pf").write_bytes(_prefetch_bytes())
    case, evidence = _case_evidence_and_index(services, evidence_dir)

    discovery = services.artifacts.discover_sources(
        case_id=case.case_id,
        evidence_id=evidence.evidence_id,
        profile_type=AnalysisProfileType.FULL_ANALYSIS,
    )
    assert {item["source_kind"] for item in discovery["sources"]} == {
        ArtifactSourceKind.REGISTRY_EXPORT.value,
        ArtifactSourceKind.EVENT_LOG_XML.value,
        ArtifactSourceKind.PREFETCH_FILE.value,
    }

    job, coverage = services.artifacts.analyze_evidence(
        case_id=case.case_id,
        evidence_id=evidence.evidence_id,
        profile_type=AnalysisProfileType.FULL_ANALYSIS,
        batch_size=2,
    )
    page = services.artifacts.list_artifacts(
        ArtifactQuery(case_id=case.case_id, evidence_id=evidence.evidence_id, limit=50)
    )
    types = {artifact.artifact_type for artifact in page.items}

    assert job.status == "PARTIAL"
    assert coverage.artifact_count >= 8
    assert ArtifactType.REGISTRY_AUTORUN in types
    assert ArtifactType.REGISTRY_USB_DEVICE in types
    assert ArtifactType.REGISTRY_TIMEZONE in types
    assert ArtifactType.REGISTRY_USERASSIST in types
    assert ArtifactType.EVENT_LOG_RECORD in types
    assert ArtifactType.PREFETCH_EXECUTION in types
    assert any("한글Autorun" in artifact.title for artifact in page.items)
    assert any(
        artifact.fields.get("event_data", {}).get("TargetUserName") == "홍길동"
        for artifact in page.items
    )
    assert all(
        artifact.raw_locator.get("offset") is None
        for artifact in page.items
        if artifact.artifact_type is not ArtifactType.PREFETCH_EXECUTION
    )
    for artifact in page.items:
        schema_validator.validate_artifact(artifact.to_schema_dict())

    event_page = services.artifacts.list_artifacts(
        ArtifactQuery(case_id=case.case_id, event_id=4624)
    )
    assert event_page.items[0].artifact_subtype == "SECURITY_LOGON_SUCCESS"
    autoruns = services.artifacts.list_artifacts(
        ArtifactQuery(case_id=case.case_id, artifact_type=ArtifactType.REGISTRY_AUTORUN)
    )
    assert autoruns.items[0].fields["executable_candidate"].endswith("app.exe")
    prefetch = services.artifacts.list_artifacts(
        ArtifactQuery(case_id=case.case_id, executable_name="calc")
    )
    assert prefetch.items[0].fields["run_count"] == 7


def test_artifact_cursor_rejects_filter_mismatch(services, tmp_path: Path) -> None:
    evidence_dir = tmp_path / "page"
    evidence_dir.mkdir()
    for index in range(5):
        xml = _event_xml().replace(
            "<EventRecordID>42</EventRecordID>", f"<EventRecordID>{index}</EventRecordID>"
        )
        (evidence_dir / f"event-{index}.xml").write_text(xml, encoding="utf-8")
    case, evidence = _case_evidence_and_index(services, evidence_dir)
    services.artifacts.analyze_evidence(
        case_id=case.case_id,
        evidence_id=evidence.evidence_id,
        profile_type=AnalysisProfileType.FULL_ANALYSIS,
    )

    first = services.artifacts.list_artifacts(
        ArtifactQuery(case_id=case.case_id, artifact_type=ArtifactType.EVENT_LOG_RECORD, limit=2)
    )
    assert first.has_more is True
    second = services.artifacts.list_artifacts(
        ArtifactQuery(
            case_id=case.case_id,
            artifact_type=ArtifactType.EVENT_LOG_RECORD,
            cursor=first.next_cursor,
            limit=2,
        )
    )
    assert {item.artifact_id for item in first.items}.isdisjoint(
        {item.artifact_id for item in second.items}
    )
    with pytest.raises(ValidationError):
        services.artifacts.list_artifacts(
            ArtifactQuery(
                case_id=case.case_id,
                artifact_type=ArtifactType.PREFETCH_EXECUTION,
                cursor=first.next_cursor,
                limit=2,
            )
        )


def test_artifact_resume_pause_cancel_and_duplicate_prevention(services, tmp_path: Path) -> None:
    evidence_dir = tmp_path / "resume"
    evidence_dir.mkdir()
    for index in range(4):
        xml = _event_xml().replace(
            "<EventRecordID>42</EventRecordID>", f"<EventRecordID>{index}</EventRecordID>"
        )
        (evidence_dir / f"event-{index}.xml").write_text(xml, encoding="utf-8")
    case, evidence = _case_evidence_and_index(services, evidence_dir)

    partial, partial_coverage = services.artifacts.analyze_evidence(
        case_id=case.case_id,
        evidence_id=evidence.evidence_id,
        profile_type=AnalysisProfileType.FULL_ANALYSIS,
        item_budget=2,
    )
    assert partial.status == "PARTIAL"
    assert partial_coverage.artifact_count == 2
    resumed, resumed_coverage = services.artifacts.resume_artifact_job(partial.job_id)
    assert resumed.status == "SUCCEEDED"
    assert resumed_coverage.artifact_count == 4

    duplicate, duplicate_coverage = services.artifacts.analyze_evidence(
        case_id=case.case_id,
        evidence_id=evidence.evidence_id,
        profile_type=AnalysisProfileType.FULL_ANALYSIS,
        item_budget=2,
    )
    assert duplicate.status == "PARTIAL"
    assert duplicate_coverage.source_count == 0
    assert duplicate_coverage.warning_count == 4

    cancel_token = CancellationToken.new()

    def cancel_after_first(job) -> None:
        if job.progress.processed_items >= 1:
            cancel_token.cancel()

    cancelled, cancelled_coverage = services.artifacts.analyze_evidence(
        case_id=case.case_id,
        evidence_id=evidence.evidence_id,
        profile_type=AnalysisProfileType.CUSTOM,
        item_budget=4,
        cancellation_token=cancel_token,
        progress_callback=cancel_after_first,
    )
    assert cancelled.status in {"CANCELLED", "SUCCEEDED", "PARTIAL"}
    assert cancelled_coverage.artifact_count >= 0

    pause_token = PauseToken.new()

    def pause_after_first(job) -> None:
        if job.progress.processed_items >= 1:
            pause_token.request_pause()

    paused, _ = services.artifacts.analyze_evidence(
        case_id=case.case_id,
        evidence_id=evidence.evidence_id,
        profile_type=AnalysisProfileType.CUSTOM,
        item_budget=4,
        pause_token=pause_token,
        progress_callback=pause_after_first,
    )
    assert paused.status in {"PAUSED", "SUCCEEDED", "PARTIAL"}


def test_prefetch_unsupported_version_and_mam_are_not_success(
    services,
    tmp_path: Path,
) -> None:
    evidence_dir = tmp_path / "pf"
    evidence_dir.mkdir()
    (evidence_dir / "UNKNOWN.pf").write_bytes(_prefetch_bytes(version=99))
    (evidence_dir / "COMPRESSED.pf").write_bytes(_prefetch_bytes(mam=True))
    case, evidence = _case_evidence_and_index(services, evidence_dir)

    services.artifacts.analyze_evidence(
        case_id=case.case_id,
        evidence_id=evidence.evidence_id,
        profile_type=AnalysisProfileType.FULL_ANALYSIS,
    )
    page = services.artifacts.list_artifacts(
        ArtifactQuery(case_id=case.case_id, evidence_id=evidence.evidence_id)
    )
    statuses = {artifact.artifact_subtype: artifact.parse_status for artifact in page.items}

    assert statuses["PREFETCH_UNSUPPORTED_VERSION"] is ArtifactParseStatus.UNSUPPORTED
    assert statuses["PREFETCH_MAM_COMPRESSED"] is ArtifactParseStatus.UNSUPPORTED


def test_cli_artifact_analyze_list_show_and_warnings(
    tmp_path: Path,
    cli_env: dict[str, str],
) -> None:
    import subprocess
    import sys

    db_path = tmp_path / "cli-artifacts.db"
    evidence_dir = tmp_path / "cli evidence"
    evidence_dir.mkdir()
    (evidence_dir / "security.xml").write_text(_event_xml(), encoding="utf-8")

    def run_cli(args: list[str]) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-m", "apex_forensic", *args],
            check=False,
            text=True,
            capture_output=True,
            env=cli_env,
        )

    assert run_cli(["init", "--db", str(db_path), "--json"]).returncode == 0
    case = json.loads(
        run_cli(["--db", str(db_path), "case", "create", "--name", "CLI Artifact", "--json"]).stdout
    )
    evidence = json.loads(
        run_cli(
            [
                "--db",
                str(db_path),
                "evidence",
                "add",
                "--case-id",
                case["id"],
                "--path",
                str(evidence_dir),
                "--json",
            ]
        ).stdout
    )
    indexed = run_cli(
        [
            "--db",
            str(db_path),
            "evidence",
            "index",
            "--case-id",
            case["id"],
            "--evidence-id",
            evidence["id"],
            "--profile",
            "FULL_ANALYSIS",
            "--json",
        ]
    )
    assert indexed.returncode == 0, indexed.stderr
    analyzed = run_cli(
        [
            "--db",
            str(db_path),
            "artifact",
            "analyze",
            "--case-id",
            case["id"],
            "--evidence-id",
            evidence["id"],
            "--profile",
            "FULL_ANALYSIS",
            "--json",
        ]
    )
    assert analyzed.returncode == 0, analyzed.stderr
    listed = run_cli(
        [
            "--db",
            str(db_path),
            "artifact",
            "eventlog",
            "list",
            "--case-id",
            case["id"],
            "--json",
        ]
    )
    assert listed.returncode == 0, listed.stderr
    artifact_id = json.loads(listed.stdout)["items"][0]["artifact_id"]
    shown = run_cli(
        [
            "--db",
            str(db_path),
            "artifact",
            "show",
            "--artifact-id",
            artifact_id,
            "--json",
        ]
    )
    assert shown.returncode == 0, shown.stderr
    assert json.loads(shown.stdout)["fields"]["event_id"] == 4624
    warnings = run_cli(
        [
            "--db",
            str(db_path),
            "artifact",
            "warnings",
            "--evidence-id",
            evidence["id"],
            "--json",
        ]
    )
    assert warnings.returncode == 0, warnings.stderr
