from __future__ import annotations

from pathlib import Path

import pytest

from apex_forensic.adapters.filesystem import LogicalDirectoryFileSystemProvider
from apex_forensic.adapters.system import SystemClock, UuidGenerator
from apex_forensic.application.services.file_system_index import FileSystemIndexService
from apex_forensic.domain.enums import AnalysisProfileType, FileSystemNodeType
from apex_forensic.domain.errors import (
    StateConflictError,
    UnsupportedCapabilityError,
    ValidationError,
)
from apex_forensic.jobs import CancellationToken, PauseToken
from apex_forensic.ports.filesystem_provider import ProviderScanIssue


def _case_and_directory(services, root: Path):
    case = services.cases.create_case(name="FS Case")
    evidence = services.evidence.register_evidence(case_id=case.case_id, source_path=root)
    return case, evidence


def test_filesystem_node_serialization_and_schema_validation(
    services,
    tmp_path: Path,
    schema_validator,
) -> None:
    evidence_dir = tmp_path / "증거 자료"
    evidence_dir.mkdir()
    (evidence_dir / "한글 파일 (1).txt").write_text("metadata only", encoding="utf-8")
    case, evidence = _case_and_directory(services, evidence_dir)

    job, coverage = services.fs.index_evidence(
        case_id=case.case_id,
        evidence_id=evidence.evidence_id,
        profile_type=AnalysisProfileType.FULL_ANALYSIS,
    )
    page = services.fs.list_nodes(evidence_id=evidence.evidence_id, all_nodes=True)

    assert job.status == "SUCCEEDED"
    assert coverage.status == "COMPLETE"
    assert [
        node.original_name for node in page.items if node.node_type is FileSystemNodeType.FILE
    ] == ["한글 파일 (1).txt"]
    schema_validator.validate_job(job.to_schema_dict())
    schema_validator.validate_file_system_node(page.items[0].to_schema_dict())
    schema_validator.validate_file_tree_page(page.to_schema_dict())


def test_logical_provider_root_metadata_unicode_sorting_and_symlink_policy(
    services,
    tmp_path: Path,
) -> None:
    evidence_dir = tmp_path / "root"
    evidence_dir.mkdir()
    (evidence_dir / "b.txt").write_text("b", encoding="utf-8")
    (evidence_dir / "A.txt").write_text("a", encoding="utf-8")
    (evidence_dir / "한글 (원본).log").write_text("k", encoding="utf-8")
    target_dir = evidence_dir / "target"
    target_dir.mkdir()
    symlink_path = evidence_dir / "link-to-target"
    symlink_created = False
    try:
        symlink_path.symlink_to(target_dir, target_is_directory=True)
        symlink_created = True
    except (OSError, NotImplementedError):
        pass
    _, evidence = _case_and_directory(services, evidence_dir)
    provider = LogicalDirectoryFileSystemProvider()

    root = provider.get_root_node(evidence, index_revision=1)
    entries = [
        item
        for item in provider.iter_directory_entries(evidence, root, index_revision=1)
        if not isinstance(item, ProviderScanIssue)
    ]

    assert root.node_type is FileSystemNodeType.ROOT
    assert [item.original_name for item in entries] == sorted(
        [item.original_name for item in entries],
        key=lambda value: value.casefold(),
    )
    korean = next(item for item in entries if item.original_name.startswith("한글"))
    assert korean.original_relative_path == "한글 (원본).log"
    assert korean.extension == "log"
    assert korean.mime_candidate in {"text/plain", "application/octet-stream", None}
    if symlink_created:
        link = next(item for item in entries if item.original_name == "link-to-target")
        assert link.node_type is FileSystemNodeType.SYMLINK
        assert link.is_link is True
        assert link.is_traversed is False


def test_selected_scope_rejects_root_escape(services, tmp_path: Path) -> None:
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    case, evidence = _case_and_directory(services, evidence_dir)

    with pytest.raises(ValidationError):
        services.fs.index_evidence(
            case_id=case.case_id,
            evidence_id=evidence.evidence_id,
            profile_type=AnalysisProfileType.SELECTED_SCOPE,
            selected_paths=["../outside"],
        )


def test_quick_triage_returns_partial_without_hashing_directory(services, tmp_path: Path) -> None:
    evidence_dir = tmp_path / "quick"
    nested = evidence_dir / "dir" / "nested"
    nested.mkdir(parents=True)
    (nested / "deep.txt").write_text("deep", encoding="utf-8")
    case, evidence = _case_and_directory(services, evidence_dir)

    job, coverage = services.fs.index_evidence(
        case_id=case.case_id,
        evidence_id=evidence.evidence_id,
        profile_type=AnalysisProfileType.QUICK_TRIAGE,
    )
    page = services.fs.list_nodes(evidence_id=evidence.evidence_id, all_nodes=True)
    reloaded = services.evidence.get_evidence(evidence.evidence_id)

    assert job.status == "PARTIAL"
    assert coverage.status == "PARTIAL"
    assert "/dir/nested/deep.txt" not in {node.display_path for node in page.items}
    assert any(node.is_partial for node in page.items if node.display_path == "/dir")
    assert reloaded.hashes == []


def test_selected_scope_is_prioritized_before_background_scope(services, tmp_path: Path) -> None:
    evidence_dir = tmp_path / "selected"
    selected = evidence_dir / "selected"
    other = evidence_dir / "other"
    selected.mkdir(parents=True)
    other.mkdir()
    (selected / "first.txt").write_text("selected", encoding="utf-8")
    (other / "later.txt").write_text("other", encoding="utf-8")
    case, evidence = _case_and_directory(services, evidence_dir)

    job, _ = services.fs.index_evidence(
        case_id=case.case_id,
        evidence_id=evidence.evidence_id,
        profile_type=AnalysisProfileType.SELECTED_SCOPE,
        selected_paths=["selected"],
        item_budget=1,
    )
    paths = {
        node.display_path
        for node in services.fs.list_nodes(evidence_id=evidence.evidence_id, all_nodes=True).items
    }

    assert job.status == "PARTIAL"
    assert "/selected/first.txt" in paths
    assert "/other/later.txt" not in paths


def test_full_analysis_item_budget_resume_and_duplicate_prevention(
    services, tmp_path: Path
) -> None:
    evidence_dir = tmp_path / "resume"
    evidence_dir.mkdir()
    for index in range(5):
        (evidence_dir / f"file-{index}.txt").write_text(str(index), encoding="utf-8")
    case, evidence = _case_and_directory(services, evidence_dir)

    job, coverage = services.fs.index_evidence(
        case_id=case.case_id,
        evidence_id=evidence.evidence_id,
        profile_type=AnalysisProfileType.FULL_ANALYSIS,
        item_budget=2,
    )
    assert job.status == "PARTIAL"
    assert coverage.status == "PARTIAL"
    assert job.checkpoint_available is True

    resumed, resumed_coverage = services.fs.resume_index_job(job.job_id)
    nodes = services.fs.list_nodes(evidence_id=evidence.evidence_id, all_nodes=True).items
    services.fs.index_evidence(
        case_id=case.case_id,
        evidence_id=evidence.evidence_id,
        profile_type=AnalysisProfileType.FULL_ANALYSIS,
    )
    nodes_after_second_run = services.fs.list_nodes(
        evidence_id=evidence.evidence_id, all_nodes=True
    ).items

    assert resumed.status == "SUCCEEDED"
    assert resumed_coverage.status == "COMPLETE"
    assert len(nodes) == 6
    assert len({node.original_relative_path for node in nodes_after_second_run}) == 6
    with pytest.raises(StateConflictError):
        services.fs.resume_index_job(resumed.job_id)


def test_cancel_and_pause_preserve_partial_results_and_resume(services, tmp_path: Path) -> None:
    evidence_dir = tmp_path / "cancel"
    evidence_dir.mkdir()
    for index in range(10):
        (evidence_dir / f"file-{index}.txt").write_text("x", encoding="utf-8")
    case, evidence = _case_and_directory(services, evidence_dir)
    cancel_token = CancellationToken.new()

    def cancel_after_first(job) -> None:
        if job.progress.discovered_items >= 2:
            cancel_token.cancel()

    cancelled, _ = services.fs.index_evidence(
        case_id=case.case_id,
        evidence_id=evidence.evidence_id,
        profile_type=AnalysisProfileType.FULL_ANALYSIS,
        batch_size=1,
        cancellation_token=cancel_token,
        progress_callback=cancel_after_first,
    )
    partial_count = len(
        services.fs.list_nodes(evidence_id=evidence.evidence_id, all_nodes=True).items
    )
    resumed, _ = services.fs.resume_index_job(cancelled.job_id)

    assert cancelled.status == "CANCELLED"
    assert 1 < partial_count < 11
    assert resumed.status == "SUCCEEDED"

    pause_dir = tmp_path / "pause"
    pause_dir.mkdir()
    for index in range(3):
        (pause_dir / f"p-{index}.txt").write_text("x", encoding="utf-8")
    pause_case, pause_evidence = _case_and_directory(services, pause_dir)
    pause_token = PauseToken.new()

    def pause_after_first(job) -> None:
        if job.progress.discovered_items >= 2:
            pause_token.request_pause()

    paused, _ = services.fs.index_evidence(
        case_id=pause_case.case_id,
        evidence_id=pause_evidence.evidence_id,
        profile_type=AnalysisProfileType.FULL_ANALYSIS,
        batch_size=1,
        pause_token=pause_token,
        progress_callback=pause_after_first,
    )
    resumed_pause, _ = services.fs.resume_index_job(paused.job_id)
    assert paused.status == "PAUSED"
    assert resumed_pause.status == "SUCCEEDED"


def test_stable_cursor_invalid_cursor_and_filter_mismatch(services, tmp_path: Path) -> None:
    evidence_dir = tmp_path / "page"
    evidence_dir.mkdir()
    for index in range(25):
        (evidence_dir / f"{index:02d}.txt").write_text("x", encoding="utf-8")
    case, evidence = _case_and_directory(services, evidence_dir)
    services.fs.index_evidence(
        case_id=case.case_id,
        evidence_id=evidence.evidence_id,
        profile_type=AnalysisProfileType.FULL_ANALYSIS,
    )

    seen: list[str] = []
    cursor = None
    while True:
        page = services.fs.list_nodes(
            evidence_id=evidence.evidence_id,
            all_nodes=True,
            cursor=cursor,
            limit=7,
        )
        seen.extend(node.node_id for node in page.items)
        if not page.page.has_more:
            break
        cursor = page.page.next_cursor

    assert len(seen) == len(set(seen)) == 26
    with pytest.raises(ValidationError):
        services.fs.list_nodes(evidence_id=evidence.evidence_id, all_nodes=True, cursor="not-valid")
    filtered = services.fs.list_nodes(
        evidence_id=evidence.evidence_id,
        all_nodes=True,
        extension="txt",
        limit=5,
    )
    assert filtered.page.next_cursor is not None
    with pytest.raises(ValidationError):
        services.fs.list_nodes(
            evidence_id=evidence.evidence_id,
            all_nodes=True,
            cursor=filtered.page.next_cursor,
        )


def test_bounded_queue_records_warning(services, tmp_path: Path) -> None:
    evidence_dir = tmp_path / "bounded"
    for name in ["a", "b"]:
        directory = evidence_dir / name
        directory.mkdir(parents=True)
        (directory / "file.txt").write_text("x", encoding="utf-8")
    case, evidence = _case_and_directory(services, evidence_dir)

    job, coverage = services.fs.index_evidence(
        case_id=case.case_id,
        evidence_id=evidence.evidence_id,
        profile_type=AnalysisProfileType.FULL_ANALYSIS,
        max_queue_size=1,
    )

    assert job.status == "PARTIAL"
    assert coverage.status == "PARTIAL"
    assert any(warning["code"] == "WORK_QUEUE_FULL" for warning in job.warnings)


def test_disk_image_provider_returns_capability_unavailable(services, tmp_path: Path) -> None:
    image = tmp_path / "disk.e01"
    image.write_bytes(b"image metadata only")
    case = services.cases.create_case(name="Image Case")
    evidence = services.evidence.register_evidence(case_id=case.case_id, source_path=image)

    with pytest.raises(UnsupportedCapabilityError) as error:
        services.fs.index_evidence(case_id=case.case_id, evidence_id=evidence.evidence_id)

    assert error.value.code == "CAPABILITY_UNAVAILABLE"


class _WarningProvider(LogicalDirectoryFileSystemProvider):
    def iter_directory_entries(self, evidence, parent, *, index_revision, after_cursor=None):
        return [
            ProviderScanIssue(
                severity="WARNING",
                code="FILE_CHANGED_DURING_SCAN",
                message_key="warning.fs.file_changed_during_scan",
                developer_message="Synthetic file change warning.",
                path=parent.display_path,
                node_id=parent.node_id,
            )
        ]


def test_scan_warning_is_recorded_without_failing_job(services, tmp_path: Path) -> None:
    evidence_dir = tmp_path / "warning"
    evidence_dir.mkdir()
    case, evidence = _case_and_directory(services, evidence_dir)
    service = FileSystemIndexService(
        case_repository=services.repository,
        evidence_repository=services.repository,
        repository=services.repository,
        provider=_WarningProvider(),
        clock=SystemClock(),
        id_generator=UuidGenerator(),
    )

    job, coverage = service.index_evidence(
        case_id=case.case_id,
        evidence_id=evidence.evidence_id,
        profile_type=AnalysisProfileType.FULL_ANALYSIS,
    )

    assert job.status == "PARTIAL"
    assert coverage.warning_count == 1
    assert (
        services.repository.list_fs_scan_events(job.job_id)[0]["code"] == "FILE_CHANGED_DURING_SCAN"
    )
