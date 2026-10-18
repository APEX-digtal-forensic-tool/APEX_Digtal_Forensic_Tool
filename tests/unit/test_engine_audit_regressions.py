"""Regression coverage for the eight engine findings from the September audit."""

from __future__ import annotations

import hashlib
import os
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest
from test_image_filesystem_provider import _write_fat12_image

from apex_forensic.adapters.evidence import RawImageReader
from apex_forensic.adapters.filesystem.pytsk import PyTskFileSystemProvider
from apex_forensic.application.services.context import SafeRawRangeReader
from apex_forensic.domain.enums import AnalysisProfileType, EvidenceFormat
from apex_forensic.domain.errors import RawReadError, StateConflictError, ValidationError
from apex_forensic.domain.models import CustodyEvent
from apex_forensic.domain.services.canonical import canonical_sha256


@pytest.fixture
def image_case(services, tmp_path):
    pytest.importorskip("pytsk3")
    image = tmp_path / "USB.img"
    _write_fat12_image(image)
    case = services.cases.create_case(name="Engine audit regressions")
    evidence = services.evidence.register_evidence(case_id=case.case_id, source_path=image)
    job, _ = services.fs.index_evidence(
        case_id=case.case_id,
        evidence_id=evidence.evidence_id,
        profile_type=AnalysisProfileType.FULL_ANALYSIS,
    )
    assert job.status == "SUCCEEDED"
    nodes = services.fs.list_nodes(evidence_id=evidence.evidence_id, all_nodes=True).items
    return case, evidence, nodes, image


@pytest.mark.parametrize("operation", ["range", "recovery", "slack"])
@pytest.mark.parametrize("alias", ["original", "hardlink", "symlink"])
def test_exports_never_replace_evidence(services, image_case, operation, alias, tmp_path):
    _, evidence, nodes, image = image_case
    destination = image
    if alias != "original":
        destination = tmp_path / "alias.img"
        try:
            if alias == "hardlink":
                os.link(image, destination)
            else:
                destination.symlink_to(image)
        except OSError as error:
            pytest.skip(f"Filesystem does not support this alias: {error}")
    before = image.read_bytes()
    options = {"output_root": tmp_path, "filename": destination.name, "overwrite": True}
    with pytest.raises(ValidationError):
        if operation == "range":
            services.images.export_range(
                evidence_id=evidence.evidence_id, offset=0, length=4, **options
            )
        elif operation == "recovery":
            deleted = next(node for node in nodes if node.is_deleted)
            services.images.recover_deleted_file(node_id=deleted.node_id, **options)
        else:
            live = next(node for node in nodes if node.original_name == "LIVE.TXT")
            services.images.export_file_slack(node_id=live.node_id, **options)
    assert image.read_bytes() == before
    assert destination.read_bytes() == before
    assert not list(tmp_path.glob(".*.tmp"))


def test_exports_protect_other_case_sources_and_directory_before_mkdir(
    services, image_case, tmp_path
):
    _, evidence, _, image = image_case
    other = services.cases.create_case(name="Other case")
    foreign = tmp_path / "foreign.img"
    foreign.write_bytes(b"foreign evidence")
    services.evidence.register_evidence(case_id=other.case_id, source_path=foreign)
    with pytest.raises(ValidationError):
        services.images.export_range(
            evidence_id=evidence.evidence_id,
            offset=0,
            length=4,
            output_root=tmp_path,
            filename=foreign.name,
            overwrite=True,
        )
    assert foreign.read_bytes() == b"foreign evidence"
    folder = tmp_path / "directory-evidence"
    folder.mkdir()
    (folder / "source.txt").write_bytes(b"original")
    services.evidence.register_evidence(case_id=other.case_id, source_path=folder)
    with pytest.raises(ValidationError):
        services.images.export_range(
            evidence_id=evidence.evidence_id,
            offset=0,
            length=4,
            output_root=folder / "new-dir",
            filename="derived.bin",
        )
    assert not (folder / "new-dir").exists()
    # Overwriting an ordinary derived file remains supported.
    target = tmp_path / "allowed.bin"
    target.write_bytes(b"old output")
    result = services.images.export_range(
        evidence_id=evidence.evidence_id,
        offset=0,
        length=4,
        output_root=tmp_path,
        filename=target.name,
        overwrite=True,
    )
    assert target.read_bytes() == image.read_bytes()[:4]
    assert result["exported_bytes"] == 4


def test_exports_protect_ewf_segments_even_with_incomplete_chain(services, image_case, tmp_path):
    _, evidence, _, _ = image_case
    case = services.cases.create_case(name="Split EWF case")
    first = tmp_path / "split.raw"
    first.write_bytes(b"first")
    # Use a registered synthetic row: protection must not require native libewf.
    source = services.evidence.register_evidence(
        case_id=case.case_id,
        source_path=first,
    )
    first = first.rename(tmp_path / "split.E01")
    source.source_path = first
    source.evidence_type = EvidenceFormat.E01
    services.repository.update_evidence(source)
    segment = tmp_path / "split.e03"
    segment.write_bytes(b"third")
    with pytest.raises(ValidationError):
        services.images.export_range(
            evidence_id=evidence.evidence_id,
            offset=0,
            length=4,
            output_root=tmp_path,
            filename=segment.name,
            overwrite=True,
        )
    assert first.read_bytes() == b"first"
    assert segment.read_bytes() == b"third"


@pytest.mark.parametrize("name", [".secret", ".config/settings", "...name"])
def test_hidden_file_raw_read_preserves_exact_source(services, tmp_path, name):
    folder = tmp_path / "logical"
    hidden = folder / name
    hidden.parent.mkdir(parents=True, exist_ok=True)
    hidden.write_bytes(b"HIDDEN_SOURCE")
    other = folder / name.lstrip(".")
    other.parent.mkdir(parents=True, exist_ok=True)
    other.write_bytes(b"WRONG__SOURCE")
    case = services.cases.create_case(name="Hidden path")
    evidence = services.evidence.register_evidence(case_id=case.case_id, source_path=folder)
    services.fs.index_evidence(
        case_id=case.case_id,
        evidence_id=evidence.evidence_id,
        profile_type=AnalysisProfileType.FULL_ANALYSIS,
    )
    node = next(
        n
        for n in services.repository.list_fs_nodes_for_evidence(evidence.evidence_id)
        if n.original_relative_path == name
    )
    result = services.views.raw_read(
        case_id=case.case_id,
        resource_type="FILE_SYSTEM_NODE",
        resource_id=node.node_id,
        length=13,
    )
    assert result.text_preview == "HIDDEN_SOURCE"
    assert result.hash["range_sha256"] == hashlib.sha256(hidden.read_bytes()).hexdigest()
    assert Path(result.source_path) == hidden.resolve()


@pytest.mark.parametrize("path", ["../secret", "a/../../secret", "/outside", "..\\secret"])
def test_raw_path_still_rejects_traversal(path):
    with pytest.raises(RawReadError):
        SafeRawRangeReader._clean_relative_path(path)


@pytest.mark.parametrize(
    "runs,expected,missing",
    [
        ([(0, 0, 4), (8, 8, 4)], b"abcd\0\0\0\0ijkl", [(4, 4)]),
        ([(4, 4, 4)], b"\0\0\0\0efgh\0\0\0\0", [(0, 4), (8, 4)]),
        ([(0, 0, 4), (4, 4, 8)], b"abcdefghijkl", []),
        ([(0, 10, 4), (8, 0, 4)], b"kl\0\0\0\0\0\0abcd", [(2, 2), (4, 4)]),
    ],
)
def test_recovery_preserves_holes_counts_and_output_hash(
    services,
    image_case,
    tmp_path,
    monkeypatch,
    runs,
    expected,
    missing,
):
    _, _, nodes, _ = image_case
    node = next(n for n in nodes if n.is_deleted)
    node.file_size = 12
    node.provider_metadata["extents"] = [
        {"file_offset": f, "byte_offset": b, "byte_length": n} for f, b, n in runs
    ]
    services.repository.upsert_fs_node(node)
    data = tmp_path / "recovery-input.raw"
    data.write_bytes(b"abcdefghijkl")
    monkeypatch.setattr(services.images, "_reader_for_evidence", lambda _: RawImageReader(data))
    result = services.images.recover_deleted_file(
        node_id=node.node_id, output_root=tmp_path / "out"
    )
    assert Path(result["output_path"]).read_bytes() == expected
    assert result["logical_size"] == result["output_size"] == 12
    assert result["recovered_bytes"] == 12 - sum(size for _, size in missing)
    assert result["missing_ranges"] == [{"file_offset": f, "byte_length": n} for f, n in missing]
    assert result["partial"] is bool(missing)
    assert result["missing_range_policy"] == "ZERO_FILL"
    assert result["sha256"] == hashlib.sha256(expected).hexdigest()


@pytest.mark.parametrize(
    "runs",
    [
        [(0, 0, 4), (3, 4, 4)],
        [(-1, 0, 4)],
        [(0, -1, 4)],
        [(12, 0, 4)],
        [(0, 0, 0)],
    ],
)
def test_recovery_rejects_invalid_runs_without_publishing(services, image_case, tmp_path, runs):
    _, _, nodes, _ = image_case
    node = next(n for n in nodes if n.is_deleted)
    node.file_size = 12
    node.provider_metadata["extents"] = [
        {"file_offset": f, "byte_offset": b, "byte_length": n} for f, b, n in runs
    ]
    services.repository.upsert_fs_node(node)
    with pytest.raises(ValidationError):
        services.images.recover_deleted_file(node_id=node.node_id, output_root=tmp_path / "out")
    assert not list((tmp_path / "out").iterdir())


def test_new_and_previously_indexed_image_nodes_follow_schema(
    services, image_case, schema_validator
):
    _, evidence, nodes, _ = image_case
    for node in nodes:
        schema_validator.validate_file_system_node(node.to_schema_dict())
    # Old databases remain readable without reindexing or dropping schema checks.
    with services.repository.connection:
        services.repository.connection.execute(
            "UPDATE fs_nodes SET mime_confidence = CASE WHEN mime_candidate IS NULL "
            "THEN 'NONE' ELSE 'EXTENSION' END WHERE evidence_id = ?",
            (evidence.evidence_id,),
        )
    restored = services.repository.list_fs_nodes_for_evidence(evidence.evidence_id)
    for node in restored:
        schema_validator.validate_file_system_node(node.to_schema_dict())
        assert node.mime_confidence == ("LOW" if node.mime_candidate else "UNKNOWN")


def test_directory_and_range_reads_do_not_hash_whole_image(services, image_case, monkeypatch):
    _, evidence, nodes, _ = image_case

    def forbidden_hash(_):
        pytest.fail("A bounded read must not compute a whole-image fingerprint")

    monkeypatch.setattr(RawImageReader, "_compute_source_fingerprint", forbidden_hash)
    provider = PyTskFileSystemProvider()
    parent = next(n for n in nodes if n.original_name == "volume-0")
    for _ in range(3):
        assert provider.iter_directory_entries(evidence, parent, index_revision=1)
        assert (
            services.images.read_range(evidence_id=evidence.evidence_id, offset=0, length=4)[
                "returned_length"
            ]
            == 4
        )


def test_explicit_fingerprint_rehashes_even_when_source_metadata_is_unchanged(
    tmp_path, monkeypatch
):
    image = tmp_path / "image.raw"
    image.write_bytes(b"before")
    original = RawImageReader._compute_source_fingerprint
    calls = []

    def counted(reader):
        calls.append(1)
        return original(reader)

    monkeypatch.setattr(RawImageReader, "_compute_source_fingerprint", counted)
    with RawImageReader(image) as reader:
        assert not calls
        first = reader.source_fingerprint
        assert first["sha256"] == hashlib.sha256(b"before").hexdigest()
        assert reader.source_fingerprint["sha256"] == first["sha256"]
        assert len(calls) == 2
        stat = image.stat()
        image.write_bytes(b"after!")
        os.utime(image, ns=(stat.st_atime_ns, stat.st_mtime_ns))
        assert reader.source_fingerprint["sha256"] == hashlib.sha256(b"after!").hexdigest()
        assert len(calls) == 3
    with RawImageReader(image) as reader:
        _ = reader.source_fingerprint
    assert len(calls) == 4


def test_fingerprint_rejects_source_changed_during_hash(tmp_path, monkeypatch):
    image = tmp_path / "changing.raw"
    image.write_bytes(b"before")
    original = RawImageReader._compute_source_fingerprint

    def changed(reader):
        result = original(reader)
        image.write_bytes(b"modified-length")
        return result

    monkeypatch.setattr(RawImageReader, "_compute_source_fingerprint", changed)
    with RawImageReader(image) as reader, pytest.raises(StateConflictError):
        _ = reader.source_fingerprint


@pytest.mark.parametrize("different_case", [False, True])
def test_custody_rejects_foreign_evidence_corrections(services, image_case, different_case):
    case, evidence, _, image = image_case
    other_case = services.cases.create_case(name="Other") if different_case else case
    other = services.evidence.register_evidence(case_id=other_case.case_id, source_path=image)
    target = services.custody.list_events(other.evidence_id)[0]
    before = services.custody.list_events(evidence.evidence_id)
    with pytest.raises(ValidationError):
        services.custody.add_correction(
            evidence_id=evidence.evidence_id,
            correction_of_event_id=target.event_id,
            actor_name="Analyst",
            reason="Correction",
        )
    assert len(services.custody.list_events(evidence.evidence_id)) == len(before)
    assert services.custody.verify_chain(evidence.evidence_id)
    # Simulate a historically persisted, correctly hashed but foreign reference.
    bad = before[-1].to_schema_dict().copy()
    bad.update(
        event_id="foreign-correction",
        event_type="CORRECTION",
        correction_of_event_id=target.event_id,
        immutable_revision=len(before) + 1,
        previous_event_hash=before[-1].event_hash,
    )
    bad["event_hash"] = canonical_sha256(bad, exclude_keys={"event_hash"})
    services.repository.save_custody_event(CustodyEvent(bad))
    assert not services.custody.verify_chain(evidence.evidence_id)


@pytest.mark.parametrize("value", [253402300800, 9223372036854775807, "bad", None, float("inf")])
def test_bad_timestamps_do_not_raise(value):
    assert PyTskFileSystemProvider._timestamp(value) is None
    assert PyTskFileSystemProvider._timestamp(1) == datetime(1970, 1, 1, 0, 0, 1, tzinfo=UTC)


def test_invalid_timestamp_is_preserved_with_warning_and_other_files_survive(
    image_case, monkeypatch
):
    _, evidence, nodes, _ = image_case
    module = pytest.importorskip("pytsk3")
    provider = PyTskFileSystemProvider()
    parent = next(n for n in nodes if n.original_name == "volume-0")

    class Entry:
        def __init__(self, name, timestamp):
            self.info = SimpleNamespace(
                name=SimpleNamespace(name=name, flags=0),
                meta=SimpleNamespace(
                    type=module.TSK_FS_META_TYPE_REG,
                    crtime=timestamp,
                    mtime=1,
                    atime=1,
                    ctime=1,
                    size=4,
                    addr=name.decode(),
                ),
            )

        def __iter__(self):
            return iter(())

    fs = SimpleNamespace(info=SimpleNamespace(block_size=512))
    fs.open_dir = lambda **_: [Entry(b"BAD.TXT", 253402300800), Entry(b"GOOD.TXT", 1)]
    monkeypatch.setattr(provider, "_open_fs", lambda *_: fs)
    results = provider.iter_directory_entries(evidence, parent, index_revision=1)
    by_name = {node.original_name: node for node in results}
    bad = by_name["BAD.TXT"]
    assert bad.raw_timestamps["crtime"] == 253402300800
    assert bad.utc_timestamps["created"] is None
    assert bad.is_partial
    assert bad.provider_metadata["timestamp_warnings"][0]["field"] == "crtime"
    assert by_name["GOOD.TXT"].utc_timestamps["created"] is not None
    assert not by_name["GOOD.TXT"].is_partial


def test_image_raw_read_is_not_advertised_or_interpreted_as_host_path(services, image_case):
    case, _, nodes, _ = image_case
    for node in nodes:
        projection = services.views.project(
            case_id=case.case_id,
            resource_type="FILE_SYSTEM_NODE",
            resource_id=node.node_id,
            view_mode="RAW",
        )
        assert "view.raw-read" not in projection.available_actions
        with pytest.raises(RawReadError) as error:
            services.views.raw_read(
                case_id=case.case_id,
                resource_type="FILE_SYSTEM_NODE",
                resource_id=node.node_id,
                length=4,
            )
        assert error.value.code == "RAW_LOCATOR_UNSUPPORTED"


def test_logical_single_file_raw_read_remains_available(services, tmp_path):
    source = tmp_path / "standalone.txt"
    source.write_bytes(b"logical file")
    case = services.cases.create_case(name="Logical single file")
    evidence = services.evidence.register_evidence(case_id=case.case_id, source_path=source)
    services.fs.index_evidence(
        case_id=case.case_id,
        evidence_id=evidence.evidence_id,
        profile_type=AnalysisProfileType.FULL_ANALYSIS,
    )
    node = services.repository.list_fs_nodes_for_evidence(evidence.evidence_id)[0]
    args = {
        "case_id": case.case_id,
        "resource_type": "FILE_SYSTEM_NODE",
        "resource_id": node.node_id,
    }
    assert "view.raw-read" in services.views.project(**args, view_mode="RAW").available_actions
    assert services.views.raw_read(**args, length=12).text_preview == "logical file"


def test_recovery_streams_large_extent_with_bounded_reads(
    services, image_case, tmp_path, monkeypatch
):
    from apex_forensic.ports.evidence_reader import MAX_EVIDENCE_READ_SIZE

    _, _, nodes, _ = image_case
    node = next(n for n in nodes if n.is_deleted)
    payload = b"X" * (MAX_EVIDENCE_READ_SIZE + 5)
    source = tmp_path / "large-run.raw"
    source.write_bytes(payload)
    node.file_size = len(payload)
    node.provider_metadata["extents"] = [
        {"file_offset": 0, "byte_offset": 0, "byte_length": len(payload)}
    ]
    services.repository.upsert_fs_node(node)
    monkeypatch.setattr(services.images, "_reader_for_evidence", lambda _: RawImageReader(source))
    result = services.images.recover_deleted_file(
        node_id=node.node_id, output_root=tmp_path / "out"
    )
    assert Path(result["output_path"]).read_bytes() == payload
    assert result["recovered_bytes"] == len(payload)
    assert not result["partial"]


def test_empty_recovery_removes_zero_filled_temporary_output(
    services, image_case, tmp_path, monkeypatch
):
    _, _, nodes, _ = image_case
    node = next(n for n in nodes if n.is_deleted)
    node.file_size = 12
    node.provider_metadata["extents"] = [{"file_offset": 4, "byte_offset": 0, "byte_length": 4}]
    services.repository.upsert_fs_node(node)
    source = tmp_path / "empty.raw"
    source.write_bytes(b"")
    monkeypatch.setattr(services.images, "_reader_for_evidence", lambda _: RawImageReader(source))
    with pytest.raises(ValidationError):
        services.images.recover_deleted_file(node_id=node.node_id, output_root=tmp_path / "out")
    assert list((tmp_path / "out").iterdir()) == []
