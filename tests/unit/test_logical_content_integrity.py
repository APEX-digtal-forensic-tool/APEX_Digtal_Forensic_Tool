"""Logical files must obey the same snapshot boundaries as files inside images."""

import os
from contextlib import contextmanager
from types import SimpleNamespace

import pytest

from apex_forensic.adapters.filesystem.content import CHUNK_SIZE, EvidenceFileContent
from apex_forensic.domain.enums import AnalysisProfileType
from apex_forensic.domain.errors import RawReadError
from apex_forensic.jobs import CancellationToken


def stat_with(info, **changes):
    values = {name: getattr(info, name) for name in dir(info) if name.startswith("st_")}
    return SimpleNamespace(**(values | changes))


def indexed(services, path, payload):
    path.write_bytes(payload)
    case = services.cases.create_case(name="Logical source integrity")
    evidence = services.evidence.register_evidence(case_id=case.case_id, source_path=path)
    services.fs.index_evidence(
        case_id=case.case_id,
        evidence_id=evidence.evidence_id,
        profile_type=AnalysisProfileType.FULL_ANALYSIS,
    )
    node = services.repository.list_fs_nodes_for_evidence(evidence.evidence_id)[0]
    return evidence, node


@pytest.mark.parametrize("replacement", [b"longer than indexed", b"x", b"", b"modified"])
def test_changed_logical_size_cannot_return_truncated_or_empty_success(
    services, tmp_path, replacement
):
    path = tmp_path / "source.txt"
    evidence, node = indexed(services, path, b"original")
    before = path.stat()
    path.write_bytes(replacement)
    os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns + 2_000_000_000))
    with pytest.raises(RawReadError) as changed:
        b"".join(EvidenceFileContent.chunks(evidence, node, limit=1024))
    assert changed.value.code == "RAW_SOURCE_CHANGED"
    with pytest.raises(RawReadError) as changed:
        services.views.raw_read(
            case_id=evidence.case_id,
            resource_type="FILE_SYSTEM_NODE",
            resource_id=node.node_id,
            offset=0,
            length=4,
        )
    assert changed.value.code == "RAW_SOURCE_CHANGED"


def test_same_size_modification_during_stream_is_rejected(services, tmp_path):
    path = tmp_path / "source.txt"
    evidence, node = indexed(services, path, b"A" * (2 * CHUNK_SIZE))
    chunks = EvidenceFileContent.chunks(evidence, node, limit=3 * CHUNK_SIZE)
    assert next(chunks) == b"A" * CHUNK_SIZE
    before = path.stat()
    with path.open("r+b") as handle:
        handle.seek(CHUNK_SIZE)
        handle.write(b"B" * CHUNK_SIZE)
    # Make timestamp movement deterministic, even on a coarse host filesystem.
    os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns + 2_000_000_000))
    with pytest.raises(RawReadError) as changed:
        b"".join(chunks)
    assert changed.value.code == "RAW_SOURCE_CHANGED"


def test_logical_materialization_is_private_and_removed_after_use(services, tmp_path):
    path = tmp_path / "source.wav"
    evidence, node = indexed(services, path, b"original audio bytes")
    with EvidenceFileContent.materialize(evidence, node) as snapshot:
        assert snapshot != path
        assert snapshot.read_bytes() == b"original audio bytes"
        snapshot.write_bytes(b"parser writes must not reach evidence")
        assert path.read_bytes() == b"original audio bytes"
    assert not snapshot.exists()


def test_cancelled_logical_materialization_never_yields_source(services, tmp_path):
    path = tmp_path / "source.wav"
    evidence, node = indexed(services, path, b"original")
    token = CancellationToken.new()
    token.cancel()
    with (
        pytest.raises(RawReadError) as cancelled,
        EvidenceFileContent.materialize(evidence, node, cancellation_token=token),
    ):
        pytest.fail("A cancelled extraction must not start its parser")
    assert cancelled.value.code == "RAW_READ_CANCELLED"


@pytest.mark.parametrize("change_during_read", [False, True])
def test_handle_ctime_is_compared_with_handle_not_path(
    services, tmp_path, monkeypatch, change_during_read
):
    evidence, node = indexed(services, tmp_path / "source.txt", b"original")
    original_fstat = os.fstat
    calls = 0

    def handle_stat(fd):
        nonlocal calls
        calls += 1
        info = original_fstat(fd)
        # Python 3.12 on Windows can report change time for fstat and birth
        # time for path.stat. Only a change between like observations is drift.
        delta = 5_000_000_000 + (calls if change_during_read else 0)
        return stat_with(info, st_ctime_ns=info.st_ctime_ns + delta)

    monkeypatch.setattr(os, "fstat", handle_stat)
    if change_during_read:
        with pytest.raises(RawReadError) as changed:
            EvidenceFileContent.read(evidence, node, offset=0, length=8)
        assert changed.value.code == "RAW_SOURCE_CHANGED"
    else:
        assert EvidenceFileContent.read(evidence, node, offset=0, length=8) == b"original"


def test_legacy_windows_unknown_identity_remains_readable(services, tmp_path):
    evidence, node = indexed(services, tmp_path / "source.txt", b"original")
    node.platform = "win32"
    node.fs_metadata.update(inode=0, device=0)
    assert EvidenceFileContent.read(evidence, node, offset=0, length=8) == b"original"
    # Known identities must still match; zero means unknown only for the legacy pair.
    node.fs_metadata["inode"] = 987654321
    with pytest.raises(RawReadError) as changed:
        EvidenceFileContent.read(evidence, node, offset=0, length=8)
    assert changed.value.code == "RAW_SOURCE_CHANGED"


def test_directory_index_uses_real_identity_when_direntry_has_zeroes(
    services, tmp_path, monkeypatch
):
    directory = tmp_path / "evidence"
    directory.mkdir()
    path = directory / "source.txt"
    path.write_bytes(b"original")
    original_scandir = os.scandir

    class WindowsEntry:
        def __init__(self, entry):
            self.entry = entry

        def __getattr__(self, name):
            return getattr(self.entry, name)

        def stat(self, **kwargs):
            return stat_with(self.entry.stat(**kwargs), st_ino=0, st_dev=0, st_nlink=0)

    @contextmanager
    def windows_scandir(root):
        with original_scandir(root) as entries:
            yield (WindowsEntry(entry) for entry in entries)

    monkeypatch.setattr(os, "scandir", windows_scandir)
    case = services.cases.create_case(name="Windows directory identity")
    evidence = services.evidence.register_evidence(case_id=case.case_id, source_path=directory)
    services.fs.index_evidence(
        case_id=case.case_id,
        evidence_id=evidence.evidence_id,
        profile_type=AnalysisProfileType.FULL_ANALYSIS,
    )
    node = next(
        node for node in services.repository.list_fs_nodes_for_evidence(evidence.evidence_id)
        if node.original_name == path.name
    )
    assert node.fs_metadata["inode"] == path.stat().st_ino
    assert node.fs_metadata["device"] == path.stat().st_dev
    assert EvidenceFileContent.read(evidence, node, offset=0, length=8) == b"original"
