"""Logical files must obey the same snapshot boundaries as files inside images."""

import os

import pytest

from apex_forensic.adapters.filesystem.content import CHUNK_SIZE, EvidenceFileContent
from apex_forensic.domain.enums import AnalysisProfileType
from apex_forensic.domain.errors import RawReadError
from apex_forensic.jobs import CancellationToken


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
