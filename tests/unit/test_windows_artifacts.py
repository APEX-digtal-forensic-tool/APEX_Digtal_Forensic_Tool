from __future__ import annotations

import codecs
import hashlib
import importlib.metadata
import importlib.util
import json
import lzma
import platform
import shutil
import struct
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest

import apex_forensic.adapters.artifacts.windows.eventlog as eventlog_module
from apex_forensic.adapters.artifacts import (
    WindowsEventLogAnalyzer,
    WindowsEventMessageRenderer,
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

_REGISTRY_FIXTURE_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "registry"


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
        return b"MAM\x04" + struct.pack("<I", 128 * 1024 * 1024) + b"compressed-prefetch"
    data = bytearray(0xD8)
    struct.pack_into("<I", data, 0x00, version)
    data[0x04:0x08] = b"SCCA"
    struct.pack_into("<I", data, 0x0C, len(data))
    data[0x10 : 0x10 + 60 * 2] = "CALC.EXE".encode("utf-16le").ljust(60 * 2, b"\x00")
    struct.pack_into("<I", data, 0x4C, 0xAABBCCDD)
    struct.pack_into("<Q", data, 0x80, _filetime(datetime(2024, 1, 2, 3, 4, 5, tzinfo=UTC)))
    struct.pack_into("<I", data, 0xD0, 7)
    return bytes(data)


def _literal_lzxpress_huffman(data: bytes) -> bytes:
    """Build a valid LZXPRESS-Huffman stream containing only literal symbols."""

    tree = bytes([0x88] * 128 + [0x00] * 128)
    bits = "".join(f"{byte:08b}" for byte in data)
    while len(bits) % 16:
        bits += "0"
    payload = bytearray()
    for offset in range(0, len(bits), 16):
        word = int(bits[offset : offset + 16], 2)
        payload.extend([word & 0xFF, (word >> 8) & 0xFF])
    return tree + bytes(payload) + b"\x00\x00"


def _mam_prefetch_bytes() -> bytes:
    decompressed = _prefetch_bytes() + b"\x00"
    return b"MAM\x04" + struct.pack("<I", len(decompressed)) + _literal_lzxpress_huffman(
        decompressed
    )


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
    <RenderingInfo Culture="en-US">
      <Message>An account was successfully logged on.</Message>
    </RenderingInfo>
  </Event>
</Events>
"""


def test_event_xml_oversize_is_a_structured_failure(
    services,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evidence_dir = tmp_path / "oversize-event"
    evidence_dir.mkdir()
    event_path = evidence_dir / "oversize.xml"
    event_path.write_text(_event_xml(), encoding="utf-8")
    monkeypatch.setattr(eventlog_module, "MAX_EVENT_XML_BYTES", 128)
    case, evidence = _case_evidence_and_index(services, evidence_dir)

    job, coverage = services.artifacts.analyze_evidence(
        case_id=case.case_id,
        evidence_id=evidence.evidence_id,
        profile_type=AnalysisProfileType.FULL_ANALYSIS,
        analyzers=["windows.eventlog"],
    )

    issues = services.artifacts.list_warnings(job_id=job.job_id)
    assert job.status == "PARTIAL"
    assert coverage.error_count == 1
    assert [item["code"] for item in issues] == ["EVENT_XML_INPUT_TOO_LARGE"]


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
"StandardBias"=dword:00000000
"DaylightBias"=dword:ffffffc4
"DynamicDaylightTimeDisabled"=dword:00000000

[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Enum\\USBSTOR\\Disk&Ven_SanDisk&Prod_Ultra&Rev_1.00\\SERIAL123]
"FriendlyName"="SanDisk Ultra USB Device"
"Service"="USBSTOR"

[HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist\\{{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}}\\Count]
"{userassist_name}"=hex:{userassist_hex}

[-HKEY_CURRENT_USER\\Software\\DeletedApp]

[HKEY_CURRENT_USER\\Software\\DeletedValue]
"Obsolete"=-
"""


def _distribution_available(distribution_name: str) -> bool:
    try:
        importlib.metadata.version(distribution_name)
    except importlib.metadata.PackageNotFoundError:
        return False
    return True


def _decompress_fixture(name: str, destination: Path) -> None:
    with lzma.open(_REGISTRY_FIXTURE_DIR / name, "rb") as source, destination.open(
        "wb"
    ) as output:
        shutil.copyfileobj(source, output)


def _fixture_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


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

    if _distribution_available("regipy"):
        assert "REGISTRY_TRANSACTION_LOG_REPLAY" not in registry_unavailable
        assert "REGISTRY_TRANSACTION_LOG_REPLAY" in capabilities[0]["capabilities"]
        assert capabilities[0]["metadata"]["transaction_log_recovery"]["status"] == (
            "OPTIONAL_RUNTIME"
        )
    else:
        assert "REGISTRY_TRANSACTION_LOG_REPLAY" in registry_unavailable
        assert capabilities[0]["metadata"]["transaction_log_recovery"]["status"] == (
            "CAPABILITY_UNAVAILABLE"
        )

    if _distribution_available("dissect.util"):
        assert "PREFETCH_MAM_DECOMPRESSION" not in prefetch_unavailable
        assert "PREFETCH_MAM_DECOMPRESSION" in capabilities[2]["capabilities"]
        assert capabilities[2]["metadata"]["mam"]["decompression"] == "OPTIONAL_RUNTIME"
    else:
        assert "PREFETCH_MAM_DECOMPRESSION" in prefetch_unavailable
        assert capabilities[2]["metadata"]["mam"]["decompression"] == "CAPABILITY_UNAVAILABLE"
    assert "REGISTRY_BINARY_DELETED_CELL_RECOVERY" not in registry_unavailable
    assert "REGISTRY_BINARY_DELETED_CELL_RECOVERY" in capabilities[0]["capabilities"]
    assert capabilities[0]["metadata"]["deleted_key_recovery"]["binary_deleted_cells"] == (
        "IMPLEMENTED_RUNTIME"
    )
    assert "REGISTRY_EXPORT_DELETED_DIRECTIVE_CANDIDATES" in capabilities[0]["capabilities"]
    event_message_capability = "EVENT_MESSAGE_RENDERING_WINDOWS_ADAPTER"

    if sys.platform == "win32" and _distribution_available("pywin32"):
        assert event_message_capability not in eventlog_unavailable
        assert event_message_capability in capabilities[1]["capabilities"]
    else:
        assert event_message_capability in eventlog_unavailable
    assert capabilities[1]["metadata"]["message_dll_rendering"]["trust_boundary"] == (
        "Evidence DLLs are never loaded or executed."
    )
    assert capabilities[2]["metadata"]["mam"]["compression_bomb_defense"] is True


def test_event_message_renderer_non_windows_boundary() -> None:
    rendered = WindowsEventMessageRenderer().render(
        provider_name="Microsoft-Windows-Security-Auditing",
        event_id=4624,
        locale="en-US",
        event_data={"TargetUserName": "tester"},
    )

    if WindowsEventMessageRenderer.is_available():
        assert rendered["message_rendering"]["status"] in {
            "WINDOWS_ADAPTER_RENDERED",
            "WINDOWS_ADAPTER_RENDER_FAILED",
        }
    else:
        assert rendered["message_rendering"]["status"] == "WINDOWS_ADAPTER_UNAVAILABLE"
    assert rendered["message_rendering"]["evidence_dll_loaded"] is False
    assert rendered["message_rendering"]["message_dll_loaded"] is False


def test_event_message_renderer_pywin32_call_contract(monkeypatch: pytest.MonkeyPatch) -> None:
    class _FakeHandle:
        def __init__(self, name: str) -> None:
            self.name = name

        def Close(self) -> None:  # noqa: N802
            return

    class _FakeWin32Evtlog:
        EvtFormatMessageEvent = 1
        EvtFormatMessageId = 8

        def __init__(self) -> None:
            self.metadata_handle = _FakeHandle("metadata")
            self.event_handle = _FakeHandle("event")
            self.calls: list[tuple[str, tuple[object, ...]]] = []

        def EvtOpenPublisherMetadata(self, provider_name: str) -> object:  # noqa: N802
            self.calls.append(("open", (provider_name,)))
            return self.metadata_handle

        def EvtFormatMessage(self, *args: object) -> str:  # noqa: N802
            self.calls.append(("format", args))
            metadata = args[0]
            event = args[1]
            flags = args[2]
            assert metadata is self.metadata_handle
            if flags == self.EvtFormatMessageId:
                assert event is None
                assert len(args) == 4
                resource_id = args[3]
                assert resource_id == 4624
                return "Rendered by message id"
            assert flags == self.EvtFormatMessageEvent
            assert len(args) == 3
            assert event is self.event_handle
            return "Rendered by event handle"

        def EvtClose(self, handle: object) -> None:  # noqa: N802
            self.calls.append(("close", (handle,)))

    fake_win32evtlog = _FakeWin32Evtlog()
    real_import_module = eventlog_module.importlib.import_module

    def _import_module(name: str, package: str | None = None) -> object:
        if name == "win32evtlog":
            return fake_win32evtlog
        return real_import_module(name, package)

    monkeypatch.setattr(eventlog_module.platform, "system", lambda: "Windows")
    monkeypatch.setattr(eventlog_module.importlib, "import_module", _import_module)

    message_id_rendered = WindowsEventMessageRenderer().render(
        provider_name="Microsoft-Windows-Security-Auditing",
        event_id=4624,
        locale="en-US",
        event_data={"TargetUserName": "tester"},
    )
    event_handle_rendered = WindowsEventMessageRenderer().render_event_handle(
        provider_name="Microsoft-Windows-Security-Auditing",
        event_handle=fake_win32evtlog.event_handle,
        locale="en-US",
    )

    assert message_id_rendered["message_rendered"] is True
    assert message_id_rendered["message_rendering"]["render_mode"] == "MESSAGE_ID"
    assert event_handle_rendered["message_rendered"] is True
    assert event_handle_rendered["message_rendering"]["render_mode"] == "EVENT_HANDLE"
    assert ("format", (fake_win32evtlog.metadata_handle, None, 8, 4624)) in (
        fake_win32evtlog.calls
    )
    assert ("format", (fake_win32evtlog.metadata_handle, fake_win32evtlog.event_handle, 1)) in (
        fake_win32evtlog.calls
    )
    assert ("close", (fake_win32evtlog.metadata_handle,)) in fake_win32evtlog.calls


def test_windows_event_message_verification_tool_non_windows_boundary() -> None:
    spec = importlib.util.spec_from_file_location(
        "verify_windows_event_message_renderer",
        Path("tools/verify_windows_event_message_renderer.py"),
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    result = module.verify_latest_matching_event(
        channel="System",
        provider_name="Microsoft-Windows-Kernel-General",
        event_id=12,
        locale="en-US",
        max_events=1,
    )

    if platform.system() == "Windows" and WindowsEventMessageRenderer.is_available():
        assert result["message_rendering"]["status"] in {
            "WINDOWS_ADAPTER_RENDERED",
            "WINDOWS_ADAPTER_RENDER_FAILED",
            "NO_MATCHING_EVENTS",
            "WINDOWS_EVENT_QUERY_FAILED",
        }
    else:
        assert result["message_rendering"]["status"] in {
            "WINDOWS_HOST_REQUIRED",
            "PYWIN32_UNAVAILABLE",
        }
    assert result["message_rendering"]["render_mode"] == "EVENT_HANDLE"


def test_windows_event_message_verification_tool_preserves_evt_next_handle_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    spec = importlib.util.spec_from_file_location(
        "verify_windows_event_message_renderer",
        Path("tools/verify_windows_event_message_renderer.py"),
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    class _FakeHandle:
        def __init__(self, name: str) -> None:
            self.name = name

        def Close(self) -> None:  # noqa: N802
            return

    class _FakeWin32Evtlog:
        EvtQueryChannelPath = 1
        EvtQueryReverseDirection = 2
        EvtFormatMessageEvent = 4

        def __init__(self) -> None:
            self.query_handle = _FakeHandle("query")
            self.event_handle = _FakeHandle("event")
            self.metadata_handle = _FakeHandle("metadata")
            self.format_args: tuple[object, ...] | None = None
            self.closed: list[object] = []

        def EvtQuery(self, channel: str, flags: int, query: str) -> object:  # noqa: N802
            assert channel == "System"
            assert flags == self.EvtQueryChannelPath | self.EvtQueryReverseDirection
            assert "Microsoft-Windows-Kernel-General" in query
            assert "EventID=12" in query
            return self.query_handle

        def EvtNext(self, query_handle: object, count: int) -> list[object]:  # noqa: N802
            assert query_handle is self.query_handle
            assert count == 1
            return [self.event_handle]

        def EvtOpenPublisherMetadata(self, provider_name: str) -> object:  # noqa: N802
            assert provider_name == "Microsoft-Windows-Kernel-General"
            return self.metadata_handle

        def EvtFormatMessage(self, *args: object) -> str:  # noqa: N802
            self.format_args = args
            assert args == (
                self.metadata_handle,
                self.event_handle,
                self.EvtFormatMessageEvent,
            )
            return "Rendered event message"

        def EvtClose(self, handle: object) -> None:  # noqa: N802
            self.closed.append(handle)

    fake_win32evtlog = _FakeWin32Evtlog()
    monkeypatch.setattr(module.platform, "system", lambda: "Windows")
    monkeypatch.setattr(eventlog_module.platform, "system", lambda: "Windows")
    monkeypatch.setitem(sys.modules, "win32evtlog", fake_win32evtlog)

    result = module.verify_latest_matching_event(
        channel="System",
        provider_name="Microsoft-Windows-Kernel-General",
        event_id=12,
        locale="en-US",
        max_events=1,
    )

    assert result["message_rendered"] is True
    assert result["rendered_message"] == "Rendered event message"
    assert fake_win32evtlog.format_args == (
        fake_win32evtlog.metadata_handle,
        fake_win32evtlog.event_handle,
        fake_win32evtlog.EvtFormatMessageEvent,
    )
    assert fake_win32evtlog.metadata_handle in fake_win32evtlog.closed
    assert fake_win32evtlog.event_handle in fake_win32evtlog.closed
    assert fake_win32evtlog.query_handle in fake_win32evtlog.closed
    assert result["message_rendering"]["handle_diagnostics"]["event_handle"] == {
        "type": "_FakeHandle",
        "has_close": True,
    }


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
    rendered_event = next(
        artifact
        for artifact in page.items
        if artifact.artifact_type is ArtifactType.EVENT_LOG_RECORD
    )
    assert rendered_event.fields["message_rendered"] is True
    assert rendered_event.fields["rendered_message"] == "An account was successfully logged on."
    assert rendered_event.fields["message_rendering"]["status"] == "SOURCE_RENDERING_INFO"
    assert rendered_event.fields["message_rendering"]["evidence_dll_loaded"] is False
    timezone_artifact = next(
        artifact
        for artifact in page.items
        if artifact.artifact_type is ArtifactType.REGISTRY_TIMEZONE
    )
    assert timezone_artifact.fields["timezone_resolver"]["source"] == (
        "WINDOWS_TIMEZONE_CANDIDATE"
    )
    assert timezone_artifact.fields["timezone_resolver"]["iana_candidate"] == "Asia/Seoul"
    assert timezone_artifact.fields["timezone_resolver"]["dynamic_dst"][
        "dynamic_daylight_time_disabled"
    ] is False
    assert timezone_artifact.fields["timezone_resolver"]["analyst_override"]["applied"] is False
    assert all(
        artifact.raw_locator.get("offset") is None
        for artifact in page.items
        if artifact.artifact_type is not ArtifactType.PREFETCH_EXECUTION
    )
    deleted_registry = [
        artifact
        for artifact in page.items
        if artifact.artifact_subtype.startswith("REGISTRY_EXPORT_DELETED_")
    ]
    assert {artifact.artifact_subtype for artifact in deleted_registry} == {
        "REGISTRY_EXPORT_DELETED_KEY_CANDIDATE",
        "REGISTRY_EXPORT_DELETED_VALUE_CANDIDATE",
    }
    assert all(artifact.fields["deleted_candidate"] is True for artifact in deleted_registry)
    assert all(
        artifact.fields["deleted_candidate_provenance"]["basis"]
        == "REG_EXPORT_DELETE_DIRECTIVE"
        for artifact in deleted_registry
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


@pytest.mark.skipif(
    not (
        _distribution_available("python-registry")
        and _distribution_available("regipy")
    ),
    reason="python-registry and regipy are required for binary hive replay.",
)
def test_registry_transaction_log_replay_runtime_fixture(
    services,
    tmp_path: Path,
    schema_validator,
) -> None:
    evidence_dir = tmp_path / "registry-replay"
    evidence_dir.mkdir()
    hive_path = evidence_dir / "NTUSER.DAT"
    primary_log = evidence_dir / "NTUSER.DAT.LOG1"
    secondary_log = evidence_dir / "NTUSER.DAT.LOG2"
    _decompress_fixture("transactions_NTUSER.DAT.xz", hive_path)
    _decompress_fixture("transactions_ntuser.dat.log1.xz", primary_log)
    _decompress_fixture("transactions_ntuser.dat.log2.xz", secondary_log)
    original_hive_sha256 = _fixture_sha256(hive_path)
    case, evidence = _case_evidence_and_index(services, evidence_dir)

    discovery = services.artifacts.discover_sources(
        case_id=case.case_id,
        evidence_id=evidence.evidence_id,
        profile_type=AnalysisProfileType.FULL_ANALYSIS,
    )
    assert {
        source["source_kind"]
        for source in discovery["sources"]
    } == {ArtifactSourceKind.REGISTRY_HIVE.value}

    job, coverage = services.artifacts.analyze_evidence(
        case_id=case.case_id,
        evidence_id=evidence.evidence_id,
        profile_type=AnalysisProfileType.FULL_ANALYSIS,
    )
    assert job.status == "SUCCEEDED"
    assert coverage.warning_count == 0
    assert _fixture_sha256(hive_path) == original_hive_sha256

    page = services.artifacts.list_artifacts(
        ArtifactQuery(case_id=case.case_id, evidence_id=evidence.evidence_id, limit=100)
    )
    original_artifacts = [
        artifact
        for artifact in page.items
        if artifact.fields.get("registry_hive_view") == "ORIGINAL_HIVE"
    ]
    replayed_artifacts = [
        artifact
        for artifact in page.items
        if artifact.fields.get("registry_hive_view") == "REPLAYED_TRANSACTION_LOG"
    ]
    assert original_artifacts
    assert replayed_artifacts
    assert {artifact.fields["registry_path"] for artifact in replayed_artifacts}
    for artifact in replayed_artifacts:
        provenance = artifact.fields["transaction_replay_provenance"]
        assert provenance["status"] == "APPLIED"
        assert provenance["adapter"] == "regipy.recovery.apply_transaction_logs"
        assert provenance["base_hive_sha256"] == original_hive_sha256
        assert provenance["primary_log"]["path"] == "NTUSER.DAT.LOG1"
        assert provenance["primary_log"]["sha256"] == _fixture_sha256(primary_log)
        assert provenance["secondary_log"]["path"] == "NTUSER.DAT.LOG2"
        assert provenance["secondary_log"]["sha256"] == _fixture_sha256(secondary_log)
        assert provenance["recovered_dirty_pages"] > 0
        assert provenance["original_hive_mutated"] is False
        assert provenance["replayed_view_separated"] is True
        assert artifact.fields["recovered_candidate_provenance"][
            "binary_deleted_cell_recovery"
        ] is False
        assert artifact.raw_locator["details"]["registry_hive_view"] == (
            "REPLAYED_TRANSACTION_LOG"
        )
        schema_validator.validate_artifact(artifact.to_schema_dict())


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
    (evidence_dir / "VALID-MAM.pf").write_bytes(_mam_prefetch_bytes())
    (evidence_dir / "CORRUPT-MAM.pf").write_bytes(
        b"MAM\x04" + struct.pack("<I", 64) + b"not-a-valid-lzxpress-huffman-stream"
    )
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
    mam = next(
        artifact
        for artifact in page.items
        if artifact.artifact_subtype == "PREFETCH_MAM_COMPRESSED"
        and artifact.fields["mam_header"]["declared_decompressed_size"] == 128 * 1024 * 1024
    )
    assert mam.parse_status is ArtifactParseStatus.UNSUPPORTED
    assert mam.fields["mam_header"]["warning_code"] == "MAM_DECLARED_SIZE_LIMIT_EXCEEDED"
    assert mam.fields["decompressed_buffer_hash"] is None
    valid_mam = next(
        artifact
        for artifact in page.items
        if artifact.artifact_subtype == "PREFETCH_V30"
        and artifact.fields.get("compression") == "MAM"
    )
    assert valid_mam.parse_status is ArtifactParseStatus.SUCCESS
    assert valid_mam.fields["decompression_status"] == "DECOMPRESSED"
    assert len(valid_mam.fields["decompressed_buffer_hash"]) == 64
    assert valid_mam.fields["run_count"] == 7
    assert valid_mam.fields["mam_header"]["supported_algorithm"] is True
    corrupt_mam = next(
        artifact
        for artifact in page.items
        if artifact.artifact_subtype == "PREFETCH_MAM_COMPRESSED"
        and artifact.fields["mam_header"]["declared_decompressed_size"] == 64
    )
    expected_status = "CORRUPT" if _distribution_available("dissect.util") else (
        "CAPABILITY_UNAVAILABLE"
    )
    assert corrupt_mam.fields["mam_header"]["decompression_status"] == expected_status
    if _distribution_available("dissect.util"):
        assert corrupt_mam.parse_status is ArtifactParseStatus.CORRUPT


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
