from __future__ import annotations

import copy
import struct
from pathlib import Path

import pytest

from apex_forensic.application.services.file_system_index import FileSystemIndexService
from apex_forensic.domain.enums import AnalysisProfileType, CustodyEventType, FileSystemNodeType
from apex_forensic.domain.errors import (
    StateConflictError,
    UnsupportedCapabilityError,
    ValidationError,
)

pytestmark = pytest.mark.usefixtures("services")


def _requires_pytsk3() -> None:
    pytest.importorskip("pytsk3")


def _write_fat12_image(path: Path) -> None:
    bytes_per_sector = 512
    total_sectors = 2880
    reserved_sectors = 1
    fat_count = 2
    sectors_per_fat = 9
    root_entries = 224
    image = bytearray(total_sectors * bytes_per_sector)
    boot = bytearray(bytes_per_sector)
    boot[0:3] = b"\xeb\x3c\x90"
    boot[3:11] = b"MSDOS5.0"
    struct.pack_into("<H", boot, 11, bytes_per_sector)
    boot[13] = 1
    struct.pack_into("<H", boot, 14, reserved_sectors)
    boot[16] = fat_count
    struct.pack_into("<H", boot, 17, root_entries)
    struct.pack_into("<H", boot, 19, total_sectors)
    boot[21] = 0xF0
    struct.pack_into("<H", boot, 22, sectors_per_fat)
    struct.pack_into("<H", boot, 24, 18)
    struct.pack_into("<H", boot, 26, 2)
    boot[38] = 0x29
    boot[43:54] = b"NO NAME    "
    boot[54:62] = b"FAT12   "
    boot[510:512] = b"\x55\xaa"
    image[:bytes_per_sector] = boot
    for fat_index in range(fat_count):
        fat_offset = (reserved_sectors + fat_index * sectors_per_fat) * bytes_per_sector
        fat = bytearray(sectors_per_fat * bytes_per_sector)
        fat[0:3] = b"\xf0\xff\xff"
        fat[3] = 0xFF
        fat[4] = 0xFF
        fat[5] = 0xFF
        image[fat_offset : fat_offset + len(fat)] = fat
    root_offset = (reserved_sectors + fat_count * sectors_per_fat) * bytes_per_sector
    live = bytearray(32)
    live[0:11] = b"LIVE    TXT"
    live[11] = 0x20
    struct.pack_into("<H", live, 26, 2)
    struct.pack_into("<I", live, 28, 4)
    image[root_offset : root_offset + 32] = live
    deleted = bytearray(32)
    deleted[0] = 0xE5
    deleted[1:11] = b"ELETED  TXT"
    deleted[11] = 0x20
    struct.pack_into("<H", deleted, 26, 3)
    struct.pack_into("<I", deleted, 28, 7)
    image[root_offset + 32 : root_offset + 64] = deleted
    data_region_offset = (
        reserved_sectors
        + fat_count * sectors_per_fat
        + (root_entries * 32 + bytes_per_sector - 1) // bytes_per_sector
    ) * bytes_per_sector
    image[data_region_offset : data_region_offset + 4] = b"LIVE"
    image[data_region_offset + 512 : data_region_offset + 519] = b"DELETED"
    path.write_bytes(image)


def test_pytsk_provider_indexes_fat_image_files_deleted_entries_extents_and_slack(
    services,
    tmp_path: Path,
) -> None:
    _requires_pytsk3()
    image = tmp_path / "fat12.img"
    _write_fat12_image(image)
    case = services.cases.create_case(name="Image FS Case")
    evidence = services.evidence.register_evidence(case_id=case.case_id, source_path=image)

    job, coverage = services.fs.index_evidence(
        case_id=case.case_id,
        evidence_id=evidence.evidence_id,
        profile_type=AnalysisProfileType.FULL_ANALYSIS,
    )
    nodes = services.fs.list_nodes(evidence_id=evidence.evidence_id, all_nodes=True).items
    by_name = {node.original_name: node for node in nodes}

    assert job.status == "SUCCEEDED"
    assert coverage.status == "COMPLETE"
    assert "volume-0" in by_name
    assert by_name["volume-0"].fs_metadata["filesystem_type"] == "FAT12"
    assert by_name["LIVE.TXT"].node_type is FileSystemNodeType.FILE
    assert by_name["LIVE.TXT"].file_size == 4
    assert by_name["LIVE.TXT"].provider_id == "apex.pytsk_filesystem_provider"
    assert by_name["LIVE.TXT"].provider_metadata["extents"][0]["byte_length"] == 512
    assert by_name["LIVE.TXT"].provider_metadata["slack"]["byte_length"] == 508
    deleted = next(node for node in nodes if node.original_name.endswith("ELETEDTX"))
    assert deleted.is_deleted is True
    assert deleted.provider_metadata["deleted_metadata_confidence"] == "CANDIDATE"
    assert deleted.is_readable is False


def test_deleted_file_recovery_and_range_export_create_bounded_derived_outputs(
    services,
    tmp_path: Path,
) -> None:
    _requires_pytsk3()
    image = tmp_path / "recover.img"
    _write_fat12_image(image)
    case = services.cases.create_case(name="Recover Case")
    evidence = services.evidence.register_evidence(case_id=case.case_id, source_path=image)
    services.fs.index_evidence(
        case_id=case.case_id,
        evidence_id=evidence.evidence_id,
        profile_type=AnalysisProfileType.FULL_ANALYSIS,
    )
    nodes = services.fs.list_nodes(evidence_id=evidence.evidence_id, all_nodes=True).items
    deleted = next(node for node in nodes if node.is_deleted)
    output_root = tmp_path / "derived"

    recovered = services.images.recover_deleted_file(
        node_id=deleted.node_id,
        output_root=output_root,
    )
    recovered_path = Path(recovered["output_path"])
    assert recovered["recovered_bytes"] == 7
    assert recovered["partial"] is False
    assert recovered_path.read_bytes() == b"DELETED"
    assert recovered_path.parent == output_root.resolve()
    with pytest.raises(StateConflictError):
        services.images.recover_deleted_file(node_id=deleted.node_id, output_root=output_root)

    live = next(node for node in nodes if node.original_name == "LIVE.TXT")
    extent = live.provider_metadata["extents"][0]
    exported = services.images.export_range(
        evidence_id=evidence.evidence_id,
        offset=extent["byte_offset"],
        length=4,
        output_root=output_root,
        filename="../range.bin",
    )
    assert Path(exported["output_path"]).parent == output_root.resolve()
    assert Path(exported["output_path"]).read_bytes() == b"LIVE"
    slack = services.images.export_file_slack(
        node_id=live.node_id,
        output_root=output_root,
        filename="live.slack",
    )
    assert slack["exported_bytes"] == 508
    assert Path(slack["output_path"]).read_bytes() == b"\x00" * 508
    assert slack["zero_filled"] is True
    events = services.custody.list_events(evidence.evidence_id)
    assert [
        event.to_schema_dict()["event_type"] for event in events
    ].count(CustodyEventType.EXPORTED.value) == 3


def test_deleted_file_recovery_cleans_temporary_output_on_reader_failure(
    services,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _requires_pytsk3()
    image = tmp_path / "recover-failure.img"
    _write_fat12_image(image)
    case = services.cases.create_case(name="Recover Failure Case")
    evidence = services.evidence.register_evidence(case_id=case.case_id, source_path=image)
    services.fs.index_evidence(
        case_id=case.case_id,
        evidence_id=evidence.evidence_id,
        profile_type=AnalysisProfileType.FULL_ANALYSIS,
    )
    nodes = services.fs.list_nodes(evidence_id=evidence.evidence_id, all_nodes=True).items
    deleted = next(node for node in nodes if node.is_deleted)
    patched = copy.deepcopy(deleted)
    patched.file_size = 8
    patched.provider_metadata["extents"] = [
        {"file_offset": 0, "byte_offset": 0, "byte_length": 4},
        {"file_offset": 4, "byte_offset": 4, "byte_length": 4},
    ]
    original_get_fs_node = services.repository.get_fs_node

    def get_fs_node(node_id: str):
        if node_id == deleted.node_id:
            return patched
        return original_get_fs_node(node_id)

    class FailingReader:
        reader_id = "test.failing_reader"
        reader_version = "1"

        def __enter__(self):
            return self

        def __exit__(self, *_args) -> None:
            return None

        def read_at(self, offset: int, length: int) -> bytes:
            if offset == 0:
                return b"A" * min(length, 4)
            raise ValidationError("Injected range failure.", target="offset")

    monkeypatch.setattr(services.repository, "get_fs_node", get_fs_node)
    monkeypatch.setattr(services.images, "_reader_for_evidence", lambda _evidence: FailingReader())
    output_root = tmp_path / "failed-derived"

    with pytest.raises(ValidationError):
        services.images.recover_deleted_file(
            node_id=deleted.node_id,
            output_root=output_root,
            filename="partial.bin",
        )

    assert not (output_root / "partial.bin").exists()
    assert list(output_root.iterdir()) == []


def test_filesystem_service_can_resume_pytsk_image_index(services, tmp_path: Path) -> None:
    _requires_pytsk3()
    image = tmp_path / "resume.img"
    _write_fat12_image(image)
    case = services.cases.create_case(name="Image Resume")
    evidence = services.evidence.register_evidence(case_id=case.case_id, source_path=image)

    job, _ = services.fs.index_evidence(
        case_id=case.case_id,
        evidence_id=evidence.evidence_id,
        profile_type=AnalysisProfileType.FULL_ANALYSIS,
        item_budget=1,
    )
    resumed, coverage = services.fs.resume_index_job(job.job_id)

    assert job.status == "PARTIAL"
    assert resumed.status == "SUCCEEDED"
    assert coverage.status == "COMPLETE"


def test_pytsk_missing_dependency_is_reported_as_capability_unavailable(
    services,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    image = tmp_path / "missing-pytsk.img"
    _write_fat12_image(image)
    case = services.cases.create_case(name="Missing pytsk")
    evidence = services.evidence.register_evidence(case_id=case.case_id, source_path=image)
    from apex_forensic.adapters.filesystem import LogicalDirectoryFileSystemProvider
    from apex_forensic.adapters.filesystem.pytsk import PyTskFileSystemProvider
    from apex_forensic.adapters.system import SystemClock, UuidGenerator

    def missing_import(name: str):
        if name == "pytsk3":
            raise ModuleNotFoundError(name)
        return __import__(name)

    monkeypatch.setattr("importlib.import_module", missing_import)
    service = FileSystemIndexService(
        case_repository=services.repository,
        evidence_repository=services.repository,
        repository=services.repository,
        provider=LogicalDirectoryFileSystemProvider(),
        additional_providers=(PyTskFileSystemProvider(),),
        clock=SystemClock(),
        id_generator=UuidGenerator(),
    )

    with pytest.raises(UnsupportedCapabilityError) as error:
        service.index_evidence(
            case_id=case.case_id,
            evidence_id=evidence.evidence_id,
            profile_type=AnalysisProfileType.FULL_ANALYSIS,
        )
    assert error.value.code == "CAPABILITY_UNAVAILABLE"
    assert error.value.details["required_capability"] == "PYTSK3"
