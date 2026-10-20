"""Registered image identity must cover all readers and survive application restarts."""

import hashlib
import os

import pytest
from test_container_workflows import fixture_image
from test_image_content import index_image, write_content_image
from test_image_filesystem_provider import _write_fat12_image

from apex_forensic.adapters.evidence.factory import evidence_reader
from apex_forensic.adapters.evidence.guarded import GuardedEvidenceReader
from apex_forensic.adapters.evidence.raw import RawImageReader
from apex_forensic.adapters.evidence.source_identity import (
    SOURCE_IDENTITY_KEY,
    assert_source_identity,
    capture_source_identity,
)
from apex_forensic.adapters.filesystem.content import EvidenceFileContent
from apex_forensic.application.services.carving import CarvingService
from apex_forensic.application.services.file_streams import FileStreamService
from apex_forensic.config import build_services
from apex_forensic.domain.enums import EvidenceFormat, HashAlgorithm
from apex_forensic.domain.errors import RawReadError, StateConflictError, ValidationError


def change_bytes(path, original, replacement):
    assert len(original) == len(replacement)
    st = path.stat()
    data = path.read_bytes()
    assert original in data
    path.write_bytes(data.replace(original, replacement))
    os.utime(path, ns=(st.st_atime_ns, st.st_mtime_ns + 2_000_000_000))


@pytest.fixture
def image_case(services, tmp_path):
    image = tmp_path / "source.img"
    write_content_image(image, {"문서.txt": b"original-image-marker"})
    return (*index_image(services, image), image)


def test_changed_indexed_image_is_rejected_after_database_reopen(services, image_case, tmp_path):
    case, _, nodes, image = image_case
    args = {
        "case_id": case.case_id,
        "resource_type": "FILE_SYSTEM_NODE",
        "resource_id": nodes["문서.txt"].node_id,
    }
    assert services.views.raw_read(**args).text_preview == "original-image-marker"
    before = hashlib.sha256(image.read_bytes()).hexdigest()
    change_bytes(image, b"original-image-marker", b"modified-image-marker")
    assert hashlib.sha256(image.read_bytes()).hexdigest() != before
    reopened = build_services(tmp_path / "apex.db", initialize=False)
    try:
        with pytest.raises(RawReadError) as error:
            reopened.views.raw_read(**args)
        assert error.value.code == "RAW_SOURCE_CHANGED"
    finally:
        reopened.close()


@pytest.mark.parametrize("name", ["compressed.E01", "disk.vhd", "disk.vhdx"])
def test_container_change_before_read_is_rejected(services, tmp_path, name):
    image = fixture_image(tmp_path, name)
    case, _, nodes = index_image(services, image)
    args = {
        "case_id": case.case_id,
        "resource_type": "FILE_SYSTEM_NODE",
        "resource_id": nodes["문서.txt"].node_id,
    }
    assert services.views.raw_read(**args).text_preview == "E01 가상 디스크의 실제 내용"
    st = image.stat()
    os.utime(image, ns=(st.st_atime_ns, st.st_mtime_ns + 2_000_000_000))
    with pytest.raises(RawReadError, match="registered identity"):
        services.views.raw_read(**args)


def test_same_size_replacement_with_preserved_mtime_is_rejected(image_case):
    _, evidence, nodes, image = image_case
    st = image.stat()
    replacement = image.with_name("replacement.img")
    replacement.write_bytes(image.read_bytes())
    os.utime(replacement, ns=(st.st_atime_ns, st.st_mtime_ns))
    replacement.replace(image)
    with pytest.raises(RawReadError):
        EvidenceFileContent.read(evidence, nodes["문서.txt"], offset=0, length=4)


def test_tsk_cached_read_scope_checks_source_on_exit(image_case):
    _, evidence, nodes, image = image_case
    with (
        pytest.raises(RawReadError),
        EvidenceFileContent.open(evidence, nodes["문서.txt"]) as handle,
    ):
        assert bytes(handle.read_random(0, 8)) == b"original"
        change_bytes(image, b"original-image-marker", b"modified-image-marker")
        # No second read: TSK's cached bytes must not bypass the exit check.


def test_bounded_raw_reader_detects_changes_during_a_read(image_case, monkeypatch):
    _, evidence, _, image = image_case
    original_read = RawImageReader.read_at

    def changed_read(reader, offset, length):
        data = original_read(reader, offset, length)
        change_bytes(image, b"original-image-marker", b"modified-image-marker")
        return data

    reader = evidence_reader(evidence).open_readonly()
    try:
        monkeypatch.setattr(RawImageReader, "read_at", changed_read)
        with pytest.raises(RawReadError):
            reader.read_at(0, 512)
    finally:
        reader.close()


def test_new_small_reads_do_not_rehash_whole_image(image_case, monkeypatch):
    _, evidence, nodes, _ = image_case

    def forbidden_hash(_reader):
        pytest.fail("Small content reads must not hash the whole source")

    monkeypatch.setattr(RawImageReader, "source_fingerprint", property(forbidden_hash))
    for offset in (0, 3, 8):
        assert EvidenceFileContent.read(evidence, nodes["문서.txt"], offset=offset, length=4)


@pytest.mark.parametrize("change", ["edit", "remove", "add", "replace"])
def test_ewf_identity_covers_secondary_segments_and_membership(tmp_path, change):
    # Test the physical chain guard independently of EWF decoding. Real single-E01
    # decoding and file content are covered by test_container_change_before_read.
    first, second = tmp_path / "split.E01", tmp_path / "split.E02"
    first.write_bytes(b"synthetic first segment")
    second.write_bytes(b"original second segment")
    baseline = capture_source_identity(first, EvidenceFormat.E01)
    assert len(baseline["sources"]) == 2
    assert_source_identity(first, EvidenceFormat.E01, baseline)
    if change == "edit":
        change_bytes(second, b"original", b"modified")
    elif change == "remove":
        second.unlink()
    elif change == "add":
        (tmp_path / "split.E03").write_bytes(b"unexpected third segment")
    else:
        old = second.stat()
        alternate = tmp_path / "alternate"
        alternate.write_bytes(second.read_bytes())
        os.utime(alternate, ns=(old.st_atime_ns, old.st_mtime_ns))
        alternate.replace(second)
    with pytest.raises(RawReadError):
        assert_source_identity(first, EvidenceFormat.E01, baseline)


@pytest.mark.parametrize("operation", ["range", "slack", "recovery", "physical_recovery", "carve"])
def test_changed_source_cannot_create_successful_exports(services, tmp_path, operation):
    image = tmp_path / "deleted.img"
    _write_fat12_image(image)
    _, evidence, nodes = index_image(services, image)
    change_bytes(image, b"LIVE", b"EDIT")
    output = tmp_path / "derived"
    live = nodes["LIVE.TXT"]
    deleted = next(node for node in nodes.values() if node.is_deleted)
    with pytest.raises(RawReadError):
        if operation == "range":
            services.images.export_range(
                evidence_id=evidence.evidence_id, offset=0, length=10, output_root=output
            )
        elif operation == "slack":
            services.images.export_file_slack(node_id=live.node_id, output_root=output)
        elif operation in {"recovery", "physical_recovery"}:
            services.images.recover_deleted_file(
                node_id=deleted.node_id, output_root=output, use_filesystem=operation == "recovery"
            )
        else:
            CarvingService(services.images).carve(
                evidence_id=evidence.evidence_id, output_root=output, scope="IMAGE"
            )
    # Carving retains an explicit failed/partial manifest; never a recovered payload.
    assert all(path.name == "manifest.json" for path in output.rglob("*") if path.is_file())


def test_ads_read_and_export_reject_changed_image(services, tmp_path):
    image = fixture_image(tmp_path, "streams.img")
    case, _, nodes = index_image(services, image)
    streams = FileStreamService(services.repository, services.images)
    args = {"case_id": case.case_id, "node_id": nodes["document.txt"].node_id}
    stream_id = next(s["id"] for s in streams.list(**args)["streams"] if s["name"] == "hidden")
    change_bytes(image, b"ADS secret forensic stream", b"ADS edited forensic stream")
    for action in (
        lambda: streams.read(**args, stream_id=stream_id),
        lambda: streams.export(**args, stream_id=stream_id, output_root=tmp_path / "out"),
    ):
        with pytest.raises(RawReadError):
            action()
    assert not list((tmp_path / "out").glob("*.bin"))


def test_registration_refuses_source_changed_while_hashing(services, tmp_path, monkeypatch):
    source = tmp_path / "changing.img"
    source.write_bytes(b"original bytes")
    case = services.cases.create_case(name="Registration mutation")
    fingerprint = RawImageReader.source_fingerprint.fget

    def change_after_hash(reader):
        result = fingerprint(reader)
        change_bytes(source, b"original", b"modified")
        return result

    monkeypatch.setattr(RawImageReader, "source_fingerprint", property(change_after_hash))
    with pytest.raises(RawReadError):
        services.evidence.register_evidence(case_id=case.case_id, source_path=source)
    assert services.evidence.list_evidence(case.case_id) == []


@pytest.mark.parametrize("changed", [False, True])
def test_legacy_single_image_requires_original_sha256_match(services, image_case, changed):
    _, evidence, nodes, image = image_case
    del evidence.metadata[SOURCE_IDENTITY_KEY]
    services.repository.update_evidence(evidence)
    with pytest.raises(RawReadError) as error:
        EvidenceFileContent.read(evidence, nodes["문서.txt"], offset=0, length=4)
    assert error.value.details["reason"] == "SOURCE_IDENTITY_REQUIRED"
    if changed:
        change_bytes(image, b"original-image-marker", b"modified-image-marker")
    services.evidence.calculate_hash(
        evidence_id=evidence.evidence_id, algorithm=HashAlgorithm.SHA256
    )
    refreshed = services.evidence.get_evidence(evidence.evidence_id)
    if changed:
        assert SOURCE_IDENTITY_KEY not in refreshed.metadata
        with pytest.raises(RawReadError):
            EvidenceFileContent.read(refreshed, nodes["문서.txt"], offset=0, length=4)
    else:
        assert SOURCE_IDENTITY_KEY in refreshed.metadata
        assert (
            EvidenceFileContent.read(refreshed, nodes["문서.txt"], offset=0, length=8)
            == b"original"
        )


def test_source_read_handle_closes_on_open_validation_failure(image_case, monkeypatch):
    _, evidence, _, image = image_case
    native = RawImageReader(image)
    original_open = native.open_readonly

    def changed_open():
        result = original_open()
        change_bytes(image, b"original-image-marker", b"modified-image-marker")
        return result

    monkeypatch.setattr(native, "open_readonly", changed_open)
    with pytest.raises(RawReadError):
        GuardedEvidenceReader(native, evidence).open_readonly()
    assert native._closed and native._fd is None


def test_legacy_ewf_cannot_trust_other_segments_using_only_first_segment_hash(services, tmp_path):
    first, second = tmp_path / "split.E01", tmp_path / "split.E02"
    first.write_bytes(b"synthetic first segment")
    second.write_bytes(b"original second segment")
    case = services.cases.create_case(name="Legacy segmented fingerprint")
    evidence = services.evidence.register_evidence(case_id=case.case_id, source_path=first)
    del evidence.metadata[SOURCE_IDENTITY_KEY]
    services.repository.update_evidence(evidence)
    change_bytes(second, b"original", b"modified")
    record, job = services.evidence.calculate_hash(
        evidence_id=evidence.evidence_id, algorithm=HashAlgorithm.SHA256
    )
    assert record.digest == evidence.fingerprint.value
    refreshed = services.evidence.get_evidence(evidence.evidence_id)
    assert SOURCE_IDENTITY_KEY not in refreshed.metadata
    assert job.warnings[0]["details"]["reason"] == "SOURCE_IDENTITY_REQUIRED"
    with pytest.raises(RawReadError):
        evidence_reader(refreshed).open_readonly()


def test_hash_recalculation_never_rebases_an_existing_identity(services, image_case):
    _, evidence, _, image = image_case
    before = evidence.metadata[SOURCE_IDENTITY_KEY]
    change_bytes(image, b"original-image-marker", b"modified-image-marker")
    services.evidence.calculate_hash(
        evidence_id=evidence.evidence_id, algorithm=HashAlgorithm.SHA256
    )
    refreshed = services.evidence.get_evidence(evidence.evidence_id)
    assert refreshed.metadata[SOURCE_IDENTITY_KEY] == before
    with pytest.raises(RawReadError):
        evidence_reader(refreshed).open_readonly()


def test_duplicate_ewf_segment_numbers_are_not_silently_ignored(tmp_path):
    first, duplicate = tmp_path / "split.E01", tmp_path / "split.e01"
    first.write_bytes(b"first")
    if duplicate.exists():
        pytest.skip("Case-insensitive filesystem cannot contain these duplicate names")
    duplicate.write_bytes(b"duplicate")
    with pytest.raises(RawReadError):
        capture_source_identity(first, EvidenceFormat.E01)


@pytest.mark.parametrize("condition", ["changed", "missing", "legacy"])
def test_rejected_image_index_persists_failed_job_after_reopen(
    services, tmp_path, condition, schema_validator
):
    image = tmp_path / "rejected.img"
    write_content_image(image, {"document.txt": b"original-image-marker"})
    case = services.cases.create_case(name="Index initialization rejection")
    evidence = services.evidence.register_evidence(case_id=case.case_id, source_path=image)
    if condition == "changed":
        change_bytes(image, b"original-image-marker", b"modified-image-marker")
    elif condition == "missing":
        image.unlink()
    else:
        del evidence.metadata[SOURCE_IDENTITY_KEY]
        services.repository.update_evidence(evidence)
    with pytest.raises(RawReadError) as rejected:
        services.fs.index_evidence(case_id=case.case_id, evidence_id=evidence.evidence_id)
    assert rejected.value.code == "RAW_SOURCE_CHANGED"

    reopened = build_services(tmp_path / "apex.db", initialize=False)
    try:
        rows = reopened.repository.list_fs_index_jobs_for_evidence(evidence.evidence_id)
        assert len(rows) == 1
        job_id = rows[0]["job_id"]
        status = reopened.fs.index_status(job_id)
        job, coverage = status["job"], status["coverage"]
        assert job["status"] == status["index_job"]["status"] == coverage["status"] == "FAILED"
        assert job["finished_at"] is not None
        assert job["checkpoint_available"] is False
        assert job["errors"] == [rejected.value.to_api_error()]
        assert job["progress"]["error_count"] == coverage["error_count"] == 1
        assert coverage["discovered_items"] == 0
        schema_validator.validate_job(job)
        with pytest.raises(StateConflictError, match="no resumable checkpoint"):
            reopened.fs.resume_index_job(job_id)
        assert reopened.fs.index_status(job_id)["job"] == job
        if condition == "legacy":
            # Validating the original bytes allows a fresh job, never a fabricated resume.
            reopened.evidence.calculate_hash(
                evidence_id=evidence.evidence_id, algorithm=HashAlgorithm.SHA256
            )
            new_job, _ = reopened.fs.index_evidence(
                case_id=case.case_id, evidence_id=evidence.evidence_id
            )
            assert new_job.job_id != job_id and new_job.status == "PARTIAL"
    finally:
        reopened.close()


@pytest.mark.parametrize("stage", ["root", "selected_scope"])
def test_index_setup_failure_cannot_resume_an_incomplete_queue(
    services, image_case, monkeypatch, stage
):
    from apex_forensic.adapters.filesystem.pytsk import PyTskFileSystemProvider

    case, evidence, _, _ = image_case
    error = RuntimeError("provider failed") if stage == "root" else ValidationError("bad scope")

    def fail(*args, **kwargs):
        raise error

    if stage == "root":
        monkeypatch.setattr(PyTskFileSystemProvider, "get_root_node", fail)
    else:
        monkeypatch.setattr(services.fs, "_prepare_selected_scopes", fail)
    with pytest.raises(type(error)) as rejected:
        services.fs.index_evidence(case_id=case.case_id, evidence_id=evidence.evidence_id)
    assert rejected.value is error
    rows = services.repository.list_fs_index_jobs_for_evidence(evidence.evidence_id)
    failed = [row for row in rows if row["status"] == "FAILED"]
    assert len(failed) == 1
    status = services.fs.index_status(failed[0]["job_id"])
    assert status["coverage"]["status"] == "FAILED"
    assert status["coverage"]["discovered_items"] == (0 if stage == "root" else 1)
    assert status["job"]["checkpoint_available"] is False
    assert status["job"]["errors"][0]["code"] == (
        "FS_INDEX_INITIALIZATION_FAILED" if stage == "root" else "VALIDATION_ERROR"
    )
    if stage == "selected_scope":
        assert services.repository.count_pending_fs_queue(failed[0]["job_id"]) > 0
    with pytest.raises(StateConflictError, match="no resumable checkpoint"):
        services.fs.resume_index_job(failed[0]["job_id"])
    # Re-labelling a failed setup as paused/cancelled must not enable a partial queue.
    for action in (services.fs.pause_index_job, services.fs.cancel_index_job):
        with pytest.raises(StateConflictError):
            action(failed[0]["job_id"])
    assert services.fs.index_status(failed[0]["job_id"])["job"] == status["job"]
