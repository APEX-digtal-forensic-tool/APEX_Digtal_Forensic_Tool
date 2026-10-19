from __future__ import annotations

import hashlib
import shutil
import sqlite3
import struct
import subprocess
from io import BytesIO
from pathlib import Path

import pytest
from test_image_filesystem_provider import _write_fat12_image

from apex_forensic.adapters.filesystem.content import EvidenceFileContent
from apex_forensic.application.services.context import SafeRawRangeReader
from apex_forensic.application.services.image_inspection import ImageInspectionService
from apex_forensic.domain.enums import AnalysisProfileType, ArtifactType
from apex_forensic.domain.errors import OperationCancelledError, RawReadError
from apex_forensic.domain.models import ArtifactQuery
from apex_forensic.jobs import CancellationToken


def write_content_image(path: Path, files: dict[str, bytes]) -> None:
    """Small FAT12 fixture with long Unicode names and deliberately fragmented chains."""
    _write_fat12_image(path)
    image = bytearray(path.read_bytes())
    root = bytearray(224 * 32)
    fat = bytearray(9 * 512)
    fat[:3] = b"\xf0\xff\xff"
    next_cluster, entry_offset = 2, 0

    def set_fat(cluster: int, value: int) -> None:
        position = cluster * 3 // 2
        pair = int.from_bytes(fat[position : position + 2], "little")
        pair = (pair & 0xF) | (value << 4) if cluster & 1 else (pair & 0xF000) | value
        fat[position : position + 2] = pair.to_bytes(2, "little")

    for index, (name, payload) in enumerate(files.items()):
        short = f"FILE{index:04d}".encode() + b"DAT"
        checksum = 0
        for byte in short:
            checksum = (((checksum & 1) << 7) + (checksum >> 1) + byte) & 255
        encoded = name.encode("utf-16le") + b"\0\0"
        encoded += b"\xff\xff" * ((-len(encoded) // 2) % 13)
        count = len(encoded) // 26
        for ordinal in range(count, 0, -1):
            entry = bytearray(32)
            entry[0] = ordinal | (0x40 if ordinal == count else 0)
            entry[11], entry[13] = 0x0F, checksum
            chunk = encoded[(ordinal - 1) * 26 : ordinal * 26]
            entry[1:11], entry[14:26], entry[28:32] = chunk[:10], chunk[10:22], chunk[22:]
            root[entry_offset : entry_offset + 32] = entry
            entry_offset += 32
        clusters = list(range(next_cluster, next_cluster + 2 * ((len(payload) + 511) // 512), 2))
        next_cluster = (clusters[-1] + 2) if clusters else next_cluster
        entry = bytearray(32)
        entry[:11], entry[11] = short, 0x20
        struct.pack_into("<H", entry, 24, (2026 - 1980) << 9 | 1 << 5 | 1)
        struct.pack_into("<H", entry, 26, clusters[0] if clusters else 0)
        struct.pack_into("<I", entry, 28, len(payload))
        root[entry_offset : entry_offset + 32] = entry
        entry_offset += 32
        for position, cluster in enumerate(clusters):
            set_fat(cluster, clusters[position + 1] if position + 1 < len(clusters) else 0xFFF)
            start = (33 + cluster - 2) * 512
            chunk = payload[position * 512 : (position + 1) * 512]
            image[start : start + len(chunk)] = chunk
    image[512 : 10 * 512] = fat
    image[10 * 512 : 19 * 512] = fat
    image[19 * 512 : 33 * 512] = root
    path.write_bytes(image)


def index_image(services, image):
    pytest.importorskip("pytsk3")
    case = services.cases.create_case(name="Image content integration")
    evidence = services.evidence.register_evidence(case_id=case.case_id, source_path=image)
    job, _ = services.fs.index_evidence(
        case_id=case.case_id,
        evidence_id=evidence.evidence_id,
        profile_type=AnalysisProfileType.FULL_ANALYSIS,
    )
    assert job.status == "SUCCEEDED", job.errors
    nodes = services.repository.list_fs_nodes_for_evidence(evidence.evidence_id)
    return case, evidence, {node.original_name: node for node in nodes}


def test_text_preview_handles_multibyte_boundary_and_binary_nul():
    text = "한글문서" * 1000
    preview, kind = SafeRawRangeReader._text_preview(text.encode(), None)
    assert kind == "text/plain"
    assert preview and text.startswith(preview)
    assert SafeRawRangeReader._text_preview(b"binary\x00data", None)[0] is None
    assert SafeRawRangeReader._text_preview(b"literal\\x00text", None)[0] == "literal\\x00text"
    assert SafeRawRangeReader._text_preview("한글 문서".encode("utf-16"), None)[0] == "한글 문서"


@pytest.fixture
def content_case(services, tmp_path):
    image_module = pytest.importorskip("PIL.Image")
    buffer = BytesIO()
    with image_module.new("RGB", (16, 16), (255, 0, 128)) as image:
        image.save(buffer, format="PNG")
    files = {
        "문서.txt": "실제 이미지 내부 문서입니다.\n".encode() + b"fragmented content\n" * 800,
        "photo.png": buffer.getvalue(),
        "empty.txt": b"",
    }
    path = tmp_path / "content.img"
    write_content_image(path, files)
    return (*index_image(services, path), files, path)


@pytest.mark.parametrize("offset,length", [(0, 50), (508, 30), (4096, 4096), (14390, 1000)])
def test_unicode_fragmented_image_text_and_hex(services, content_case, offset, length):
    case, _, nodes, files, path = content_case
    before = hashlib.sha256(path.read_bytes()).hexdigest()
    expected = files["문서.txt"][offset : offset + length]
    raw = services.views.raw_read(
        case_id=case.case_id,
        resource_type="FILE_SYSTEM_NODE",
        resource_id=nodes["문서.txt"].node_id,
        offset=offset,
        length=length,
    )
    assert bytes.fromhex(raw.hex_preview) == expected
    assert raw.returned_length == len(expected)
    assert raw.total_length == len(files["문서.txt"])
    assert raw.hash["range_sha256"] == hashlib.sha256(expected).hexdigest()
    assert hashlib.sha256(path.read_bytes()).hexdigest() == before


def test_empty_eof_invalid_range_and_cancellation(services, content_case):
    case, evidence, nodes, files, _ = content_case
    node = nodes["empty.txt"]
    assert EvidenceFileContent.read(evidence, node, offset=0, length=4) == b""
    node = nodes["문서.txt"]
    assert EvidenceFileContent.read(evidence, node, offset=len(files["문서.txt"]), length=4) == b""
    with pytest.raises(RawReadError, match="EOF"):
        EvidenceFileContent.read(evidence, node, offset=len(files["문서.txt"]) + 1, length=4)
    token = CancellationToken.new()
    token.cancel()
    with pytest.raises(OperationCancelledError) as error:
        services.views.raw_read(
            case_id=case.case_id,
            resource_type="FILE_SYSTEM_NODE",
            resource_id=node.node_id,
            cancellation_token=token,
        )
    assert error.value.code == "OPERATION_CANCELLED"


def test_image_preview_channels_bits_and_artifact_analysis(services, content_case):
    case, evidence, nodes, files, _ = content_case
    inspection = ImageInspectionService(services.repository)
    args = {
        "case_id": case.case_id,
        "resource_type": "FILE_SYSTEM_NODE",
        "resource_id": nodes["photo.png"].node_id,
    }
    result = inspection.inspect(**args)
    assert result["width"] == result["height"] == 16
    assert result["source_sha256"] == hashlib.sha256(files["photo.png"]).hexdigest()
    assert inspection.inspect(**args, channel="R", bit=0)["image_url"].startswith("data:image/png;")
    extraction = inspection.inspect(**args, action="EXTRACT", channels="R", bit=0, byte_limit=2)
    assert extraction["hex"] == "ffff"
    job, coverage = services.artifacts.analyze_evidence(
        case_id=case.case_id,
        evidence_id=evidence.evidence_id,
        profile_type=AnalysisProfileType.FULL_ANALYSIS,
    )
    assert not job.errors, job.errors
    assert coverage.artifact_count >= 1
    artifacts = services.artifacts.list_artifacts(
        ArtifactQuery(
            case_id=case.case_id,
            evidence_id=evidence.evidence_id,
            artifact_type=ArtifactType.MEDIA_IMAGE,
        )
    ).items
    assert len(artifacts) == 1
    by_artifact = inspection.inspect(
        case_id=case.case_id,
        resource_type="ARTIFACT",
        resource_id=artifacts[0].artifact_id,
    )
    assert by_artifact["source_sha256"] == result["source_sha256"]


def test_materialization_is_deleted_even_when_parser_fails(content_case):
    _, evidence, nodes, files, _ = content_case
    with (
        pytest.raises(RuntimeError),
        EvidenceFileContent.materialize(evidence, nodes["문서.txt"]) as copy,
    ):
        assert copy.read_bytes() == files["문서.txt"]
        raise RuntimeError("Parser failed")
    assert not copy.exists()


def test_locator_tampering_cannot_select_another_image_file(services, content_case):
    case, _, nodes, _, _ = content_case
    node = nodes["문서.txt"]
    reader = SafeRawRangeReader(
        repository=services.repository,
        clock=services.views._clock,
        id_generator=services.views._id_generator,
    )
    locator = dict(nodes["photo.png"].raw_locator, source_id=node.node_id, offset=0, length=4)
    with pytest.raises(RawReadError) as error:
        reader.read_locator(
            case_id=case.case_id,
            resource_type="FILE_SYSTEM_NODE",
            resource_id=node.node_id,
            raw_locator=locator,
            length=4,
        )
    assert error.value.code == "RAW_SOURCE_OUTSIDE_EVIDENCE"
    other = services.cases.create_case(name="Other case")
    with pytest.raises(RawReadError) as error:
        reader.read_locator(
            case_id=other.case_id,
            resource_type="FILE_SYSTEM_NODE",
            resource_id=node.node_id,
            raw_locator=locator,
        )
    assert error.value.code == "RAW_SOURCE_OUTSIDE_EVIDENCE"


def test_image_content_through_local_api_and_file_citation_contract(
    content_case,
    tmp_path,
    schema_validator,
):
    from fastapi.testclient import TestClient

    from apex_desktop.app import create_app

    case, _, nodes, files, _ = content_case
    token = "test-local-token-" * 3
    with TestClient(
        create_app(tmp_path, token),
        base_url="http://127.0.0.1",
        headers={"Authorization": f"Bearer {token}"},
    ) as client:
        selected = {
            "case_id": case.case_id,
            "resource_type": "FILE_SYSTEM_NODE",
            "resource_id": nodes["문서.txt"].node_id,
        }
        view = client.post("/v1/operations/view", json=selected).json()["data"]
        assert "view.raw-read" in view["available_actions"]
        assert view["citations"]
        schema_validator.validate("citation.schema.json", view["citations"][0])
        raw = client.post(
            "/v1/operations/raw.read", json={**selected, "offset": 512, "length": 64}
        ).json()["data"]
        schema_validator.validate("raw-view.schema.json", raw)
        assert bytes.fromhex(raw["hex_preview"]) == files["문서.txt"][512:576]
        preview = client.post(
            "/v1/operations/media.inspect",
            json={**selected, "resource_id": nodes["photo.png"].node_id},
        ).json()["data"]
        assert preview["width"] == 16


def test_ext4_sparse_and_browser_image_analysis(services, tmp_path):
    mkfs = shutil.which("mkfs.ext4")
    if not mkfs:
        pytest.skip("EXT4 fixture construction requires mkfs.ext4")
    source = tmp_path / "contents"
    profile = source / "Users/alice/AppData/Local/Google/Chrome/User Data/Default"
    profile.mkdir(parents=True)
    with sqlite3.connect(profile / "History") as db:
        db.execute(
            "CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT, title TEXT, "
            "visit_count INTEGER, typed_count INTEGER, last_visit_time INTEGER, hidden INTEGER)"
        )
        db.execute(
            "INSERT INTO urls VALUES (1, 'https://example.test/image-content', "
            "'image-history', 1, 0, 13300000000000000, 0)"
        )
        db.execute(
            "CREATE TABLE visits (id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER, "
            "from_visit INTEGER, transition INTEGER)"
        )
        db.execute("INSERT INTO visits VALUES (1, 1, 13300000000000000, 0, 1)")
    with (source / "sparse.txt").open("wb") as handle:
        handle.write(b"HEAD")
        handle.seek(8192)
        handle.write(b"TAIL")
    image = tmp_path / "ext4.img"
    with image.open("wb") as handle:
        handle.truncate(32 * 1024 * 1024)
    subprocess.run([mkfs, "-q", "-F", "-d", str(source), str(image)], check=True)
    case, evidence, nodes = index_image(services, image)
    assert EvidenceFileContent.read(
        evidence, nodes["sparse.txt"], offset=4096, length=4096
    ) == bytes(4096)
    assert EvidenceFileContent.read(evidence, nodes["sparse.txt"], offset=8192, length=4) == b"TAIL"
    job, coverage = services.artifacts.analyze_evidence(
        case_id=case.case_id,
        evidence_id=evidence.evidence_id,
        profile_type=AnalysisProfileType.FULL_ANALYSIS,
    )
    assert not job.errors, job.errors
    artifacts = services.artifacts.list_artifacts(ArtifactQuery(case_id=case.case_id)).items
    assert any("https://example.test/image-content" in str(item.fields) for item in artifacts)
    assert coverage.artifact_count >= 1
