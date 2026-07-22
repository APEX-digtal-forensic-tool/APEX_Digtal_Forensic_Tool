from __future__ import annotations

import struct
from datetime import UTC, datetime
from pathlib import Path

from apex_forensic.config import build_services
from apex_forensic.domain.enums import AnalysisProfileType, ArtifactType
from apex_forensic.domain.models import ArtifactQuery


def _filetime(value: datetime) -> int:
    epoch = datetime(1601, 1, 1, tzinfo=UTC)
    return int((value - epoch).total_seconds() * 10_000_000)


def _prefetch_bytes() -> bytes:
    data = bytearray(0xD8)
    struct.pack_into("<I", data, 0x00, 30)
    data[0x04:0x08] = b"SCCA"
    struct.pack_into("<I", data, 0x0C, len(data))
    data[0x10 : 0x10 + 60 * 2] = "APP.EXE".encode("utf-16le").ljust(60 * 2, b"\x00")
    struct.pack_into("<I", data, 0x4C, 0x01020304)
    struct.pack_into("<Q", data, 0x80, _filetime(datetime(2024, 3, 4, 5, 6, 7, tzinfo=UTC)))
    struct.pack_into("<I", data, 0xD0, 3)
    return bytes(data)


def _registry_text() -> str:
    return """Windows Registry Editor Version 5.00

[HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run]
"한글Run"="\\"C:\\\\Program Files\\\\앱\\\\app.exe\\" --flag"
"""


def _event_xml() -> str:
    return """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon" />
    <EventID>1</EventID>
    <TimeCreated SystemTime="2024-03-04T05:06:07Z" />
    <EventRecordID>100</EventRecordID>
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
    <Computer>HOST</Computer>
  </System>
  <EventData>
    <Data Name="Image">C:\\Program Files\\앱\\app.exe</Data>
  </EventData>
</Event>
"""


def test_artifact_sqlite_reopen_resume_and_unicode_round_trip(tmp_path: Path) -> None:
    db_path = tmp_path / "artifacts.db"
    evidence_dir = tmp_path / "증거 소스"
    evidence_dir.mkdir()
    (evidence_dir / "registry.reg").write_text(_registry_text(), encoding="utf-8")
    (evidence_dir / "sysmon.xml").write_text(_event_xml(), encoding="utf-8")
    (evidence_dir / "APP.EXE-01020304.pf").write_bytes(_prefetch_bytes())

    services = build_services(db_path)
    case = services.cases.create_case(name="Artifact 통합")
    evidence = services.evidence.register_evidence(
        case_id=case.case_id,
        source_path=evidence_dir,
    )
    services.fs.index_evidence(
        case_id=case.case_id,
        evidence_id=evidence.evidence_id,
        profile_type=AnalysisProfileType.FULL_ANALYSIS,
    )
    partial, _ = services.artifacts.analyze_evidence(
        case_id=case.case_id,
        evidence_id=evidence.evidence_id,
        profile_type=AnalysisProfileType.FULL_ANALYSIS,
        item_budget=1,
    )
    services.close()

    reopened = build_services(db_path)
    try:
        resumed, coverage = reopened.artifacts.resume_artifact_job(partial.job_id)
        page = reopened.artifacts.list_artifacts(
            ArtifactQuery(
                case_id=case.case_id,
                evidence_id=evidence.evidence_id,
                limit=50,
            )
        )
        types = {artifact.artifact_type for artifact in page.items}

        assert resumed.status == "SUCCEEDED"
        assert coverage.artifact_count >= 5
        assert ArtifactType.REGISTRY_AUTORUN in types
        assert ArtifactType.EVENT_LOG_RECORD in types
        assert ArtifactType.PREFETCH_EXECUTION in types
        assert any("한글Run" in artifact.title for artifact in page.items)
        assert any("앱" in str(artifact.fields) for artifact in page.items)
    finally:
        reopened.close()
