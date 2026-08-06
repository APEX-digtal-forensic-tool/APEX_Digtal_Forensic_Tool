from __future__ import annotations

from pathlib import Path

from apex_forensic.adapters.artifacts.windows.registry_carving import RegistryDeletedCellCarver
from apex_forensic.domain.enums import AnalysisProfileType, ArtifactType
from apex_forensic.domain.models import ArtifactQuery


def _align(value: int) -> int:
    return (value + 7) & ~7


def _cell(body: bytes, *, free: bool = True) -> bytes:
    size = _align(len(body) + 4)
    signed = size if free else -size
    return signed.to_bytes(4, "little", signed=True) + body.ljust(size - 4, b"\x00")


def _nk(name: str) -> bytes:
    raw_name = name.encode("latin-1")
    body = bytearray(76 + len(raw_name))
    body[0:2] = b"nk"
    body[2:4] = (0x20).to_bytes(2, "little")
    body[16:20] = (0xFFFF_FFFF).to_bytes(4, "little")
    body[72:74] = len(raw_name).to_bytes(2, "little")
    body[76:] = raw_name
    return bytes(body)


def _vk(name: str, value: int) -> bytes:
    raw_name = name.encode("latin-1")
    body = bytearray(20 + len(raw_name))
    body[0:2] = b"vk"
    body[2:4] = len(raw_name).to_bytes(2, "little")
    body[4:8] = (0x8000_0004).to_bytes(4, "little")
    body[8:12] = value.to_bytes(4, "little")
    body[12:16] = (4).to_bytes(4, "little")
    body[16:18] = (1).to_bytes(2, "little")
    body[20:] = raw_name
    return bytes(body)


def _synthetic_hive() -> bytes:
    header = bytearray(4096)
    header[0:4] = b"regf"
    hbin_size = 4096
    hbin = bytearray(hbin_size)
    hbin[0:4] = b"hbin"
    hbin[8:12] = hbin_size.to_bytes(4, "little")
    cursor = 32
    for body in (
        _nk("DeletedKey"),
        _vk("DeletedValue", 7),
        b"not-a-registry-cell",
        _nk("AllocatedKey"),
    ):
        cell = _cell(body, free=body != _nk("AllocatedKey"))
        hbin[cursor : cursor + len(cell)] = cell
        cursor += len(cell)
    hbin[cursor + 8 : cursor + 10] = b"sk"
    return bytes(header + hbin)


def _hive_from_hbin(hbin: bytes) -> bytes:
    header = bytearray(4096)
    header[0:4] = b"regf"
    return bytes(header + hbin)


def test_registry_deleted_cell_carver_recovers_free_cell_candidates(tmp_path: Path) -> None:
    hive = tmp_path / "NTUSER.DAT"
    hive.write_bytes(_synthetic_hive())

    report = RegistryDeletedCellCarver().carve(hive)

    assert report.status == "SUCCESS"
    assert report.coverage["free_cell_count"] >= 3
    assert {(item.candidate_type, item.name) for item in report.candidates} >= {
        ("NK", "DeletedKey"),
        ("VK", "DeletedValue"),
    }
    value = next(item for item in report.candidates if item.candidate_type == "VK")
    assert value.value_type == "REG_DWORD"
    assert value.value_data == 7
    assert value.confidence == "HIGH"
    assert all(item.name != "AllocatedKey" for item in report.candidates)


def test_registry_deleted_cell_carver_recovers_slack_candidate(tmp_path: Path) -> None:
    hive = tmp_path / "NTUSER.DAT"
    hive.write_bytes(_synthetic_hive())

    report = RegistryDeletedCellCarver().carve(hive)

    assert any(
        item.candidate_type == "SK" and item.source_region == "HBIN_SLACK"
        for item in report.candidates
    )
    assert report.coverage["hbin_slack_bytes"] > 0


def test_registry_deleted_cell_carver_rejects_false_positive_and_bad_bounds(
    tmp_path: Path,
) -> None:
    false_positive = tmp_path / "false-positive.dat"
    hbin = bytearray(4096)
    hbin[0:4] = b"hbin"
    hbin[8:12] = len(hbin).to_bytes(4, "little")
    body = bytearray(76)
    body[0:2] = b"nk"
    body[72:74] = (4096).to_bytes(2, "little")
    hbin[32 : 32 + len(_cell(bytes(body)))] = _cell(bytes(body))
    false_positive.write_bytes(_hive_from_hbin(bytes(hbin)))
    invalid_bounds = tmp_path / "bad-bounds.dat"
    bad_hbin = bytearray(128)
    bad_hbin[0:4] = b"hbin"
    bad_hbin[8:12] = (4096).to_bytes(4, "little")
    invalid_bounds.write_bytes(_hive_from_hbin(bytes(bad_hbin)))

    false_report = RegistryDeletedCellCarver().carve(false_positive)
    bounds_report = RegistryDeletedCellCarver().carve(invalid_bounds)

    assert false_report.status == "PARTIAL"
    assert false_report.candidates == ()
    assert false_report.coverage["free_cell_count"] == 1
    assert bounds_report.status == "PARTIAL"
    assert bounds_report.warnings[0]["code"] == "REGISTRY_HBIN_SIZE_INVALID"


def test_registry_deleted_cell_carving_integrates_as_candidate_artifacts(
    services,
    tmp_path: Path,
) -> None:
    evidence_dir = tmp_path / "registry"
    evidence_dir.mkdir()
    (evidence_dir / "NTUSER.DAT").write_bytes(_synthetic_hive())
    case = services.cases.create_case(name="Registry Carving Case")
    evidence = services.evidence.register_evidence(case_id=case.case_id, source_path=evidence_dir)
    services.fs.index_evidence(
        case_id=case.case_id,
        evidence_id=evidence.evidence_id,
        profile_type=AnalysisProfileType.FULL_ANALYSIS,
    )

    services.artifacts.analyze_evidence(
        case_id=case.case_id,
        evidence_id=evidence.evidence_id,
        profile_type=AnalysisProfileType.FULL_ANALYSIS,
        analyzers=["windows.registry"],
    )

    page = services.artifacts.list_artifacts(
        ArtifactQuery(case_id=case.case_id, artifact_type=ArtifactType.REGISTRY_VALUE)
    )
    carved = [
        item
        for item in page.items
        if item.artifact_subtype == "REGISTRY_BINARY_DELETED_VK_CANDIDATE"
    ]
    assert len(carved) == 1
    artifact = carved[0]
    assert artifact.parse_status.value == "PARTIAL"
    assert artifact.fields["deleted_candidate"] is True
    assert artifact.fields["candidate_semantics"] == "DELETED_CELL_CANDIDATE_NOT_OBSERVED_FACT"
    assert artifact.fields["value_name"] == "DeletedValue"
    assert artifact.raw_locator["offset"] is not None
