"""ENG-01: an image changed after registration must not be read through the old index."""

import os
import shutil

import pytest
from test_image_content import index_image, write_content_image

from apex_forensic.adapters.evidence.identity import IDENTITY_KEY
from apex_forensic.domain.errors import RawReadError, ValidationError

ORIGINAL = b"original-image-marker"
MODIFIED = b"modified-image-marker"


@pytest.fixture
def indexed(services, tmp_path):
    image = tmp_path / "content.img"
    write_content_image(image, {"document.txt": ORIGINAL})
    case, evidence, nodes = index_image(services, image)
    return services, image, case, evidence, nodes["document.txt"]


def read(services, case, node):
    return services.views.raw_read(
        case_id=case.case_id, resource_type="FILE_SYSTEM_NODE", resource_id=node.node_id
    )


def edit_in_place(image, *, bump_mtime=True):
    data = image.read_bytes()
    assert data.count(ORIGINAL) == 1
    stat = image.stat()
    with image.open("r+b") as handle:
        handle.seek(data.index(ORIGINAL))
        handle.write(MODIFIED)
    if bump_mtime:
        os.utime(image, ns=(stat.st_atime_ns, stat.st_mtime_ns + 2_000_000_000))


def test_registration_records_a_baseline(indexed):
    _, _, _, evidence, _ = indexed
    files = evidence.metadata[IDENTITY_KEY]["files"]
    assert [f["name"] for f in files] == ["content.img"]


def test_unchanged_image_still_reads(indexed):
    services, _, case, _, node = indexed
    assert read(services, case, node).text_preview == ORIGINAL.decode()


def test_image_change_before_read_must_be_rejected(indexed):
    services, image, case, _, node = indexed
    assert read(services, case, node).text_preview == ORIGINAL.decode()
    edit_in_place(image)
    with pytest.raises(RawReadError) as error:
        read(services, case, node)
    assert error.value.code == "RAW_SOURCE_CHANGED"


def test_replaced_image_file_is_rejected(indexed, tmp_path):
    services, image, case, _, node = indexed
    replacement = tmp_path / "replacement.img"
    shutil.copy2(image, replacement)
    replacement.replace(image)
    with pytest.raises(RawReadError) as error:
        read(services, case, node)
    assert error.value.code == "RAW_SOURCE_CHANGED"


def test_changed_image_blocks_other_image_reads(indexed):
    services, image, _, evidence, _ = indexed
    edit_in_place(image)
    with pytest.raises(RawReadError):
        services.images.read_range(evidence_id=evidence.evidence_id, offset=0, length=16)


def test_change_during_registration_is_refused(services, tmp_path, monkeypatch):
    from apex_forensic.application.services import evidence_manager

    image = tmp_path / "racing.img"
    write_content_image(image, {"document.txt": ORIGINAL})
    real = evidence_manager.source_identity
    calls = []

    def changing(path, evidence_type):
        calls.append(path)
        if len(calls) == 2:
            edit_in_place(image)
        return real(path, evidence_type)

    monkeypatch.setattr(evidence_manager, "source_identity", changing)
    case = services.cases.create_case(name="race")
    with pytest.raises(ValidationError):
        services.evidence.register_evidence(case_id=case.case_id, source_path=image)


@pytest.mark.parametrize("name", ["compressed.E01", "disk.vhdx"])
def test_changed_container_is_rejected(services, tmp_path, name):
    pytest.importorskip("dissect.evidence")
    from test_container_workflows import fixture_image

    image = fixture_image(tmp_path, name)
    case, _, nodes = index_image(services, image)
    node = nodes["문서.txt"]
    assert read(services, case, node).text_preview == "E01 가상 디스크의 실제 내용"
    stat = image.stat()
    os.utime(image, ns=(stat.st_atime_ns, stat.st_mtime_ns + 2_000_000_000))
    with pytest.raises(RawReadError) as error:
        read(services, case, node)
    assert error.value.code == "RAW_SOURCE_CHANGED"
