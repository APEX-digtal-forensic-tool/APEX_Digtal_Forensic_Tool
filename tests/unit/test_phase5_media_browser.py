from __future__ import annotations

import json
import os
import sqlite3
import sys
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path

import pytest

from apex_forensic.adapters.artifacts import media as media_adapter
from apex_forensic.config import build_services
from apex_forensic.domain.enums import (
    AnalysisProfileType,
    ArtifactParseStatus,
    ArtifactType,
    TimelineEventType,
)
from apex_forensic.domain.models import ArtifactQuery, MachineExtractedCandidate
from apex_forensic.jobs import CancellationToken, PauseToken


def _case_evidence_and_index(services, root: Path):
    case = services.cases.create_case(name="Phase 5 Case")
    evidence = services.evidence.register_evidence(case_id=case.case_id, source_path=root)
    services.fs.index_evidence(
        case_id=case.case_id,
        evidence_id=evidence.evidence_id,
        profile_type=AnalysisProfileType.FULL_ANALYSIS,
    )
    return case, evidence


def _webkit_time(value: datetime) -> int:
    epoch = datetime(1601, 1, 1, tzinfo=UTC)
    return int((value - epoch).total_seconds() * 1_000_000)


def _mp4_time(value: datetime) -> int:
    epoch = datetime(1904, 1, 1, tzinfo=UTC)
    return int((value - epoch).total_seconds())


def _mp4_box(box_type: bytes, payload: bytes) -> bytes:
    return (len(payload) + 8).to_bytes(4, "big") + box_type + payload


def _minimal_mp4() -> bytes:
    created = _mp4_time(datetime(2024, 1, 2, 3, 4, 5, tzinfo=UTC))
    mvhd = (
        b"\x00\x00\x00\x00"
        + created.to_bytes(4, "big")
        + created.to_bytes(4, "big")
        + (1000).to_bytes(4, "big")
        + (125000).to_bytes(4, "big")
    )
    sample_entry = bytearray(40)
    sample_entry[0:4] = len(sample_entry).to_bytes(4, "big")
    sample_entry[4:8] = b"avc1"
    sample_entry[32:34] = (1920).to_bytes(2, "big")
    sample_entry[34:36] = (1080).to_bytes(2, "big")
    stsd = b"\x00\x00\x00\x00" + (1).to_bytes(4, "big") + bytes(sample_entry)
    stbl = _mp4_box(b"stbl", _mp4_box(b"stsd", stsd))
    minf = _mp4_box(b"minf", stbl)
    mdia = _mp4_box(b"mdia", minf)
    trak = _mp4_box(b"trak", mdia)
    return _mp4_box(b"ftyp", b"isom\x00\x00\x02\x00isommp42") + _mp4_box(
        b"moov", _mp4_box(b"mvhd", mvhd) + trak
    )


def _ifd(entries: list[tuple[int, int, int, bytes]], base_offset: int) -> bytes:
    header_size = 2 + (len(entries) * 12) + 4
    values = bytearray()
    output = bytearray()
    output.extend(len(entries).to_bytes(2, "little"))
    for tag, value_type, count, raw in sorted(entries):
        output.extend(tag.to_bytes(2, "little"))
        output.extend(value_type.to_bytes(2, "little"))
        output.extend(count.to_bytes(4, "little"))
        if len(raw) <= 4:
            output.extend(raw.ljust(4, b"\x00"))
        else:
            value_offset = base_offset + header_size + len(values)
            output.extend(value_offset.to_bytes(4, "little"))
            values.extend(raw)
    output.extend((0).to_bytes(4, "little"))
    output.extend(values)
    return bytes(output)


def _ascii_entry(value: str) -> tuple[int, bytes]:
    raw = value.encode("ascii") + b"\x00"
    return len(raw), raw


def _rational(values: list[tuple[int, int]]) -> bytes:
    raw = bytearray()
    for numerator, denominator in values:
        raw.extend(numerator.to_bytes(4, "little"))
        raw.extend(denominator.to_bytes(4, "little"))
    return bytes(raw)


def _jpeg_with_exif(
    *,
    width: int = 2,
    height: int = 3,
    datetime_original: str = "2024:01:02 03:04:05",
    offset_time_original: str = "+09:00",
) -> bytes:
    exif_offset = 8 + 30
    date_count, date_raw = _ascii_entry(datetime_original)
    offset_count, offset_raw = _ascii_entry(offset_time_original)
    exif_ifd = _ifd(
        [
            (0x9003, 2, date_count, date_raw),
            (0x9011, 2, offset_count, offset_raw),
            (0xA002, 4, 1, width.to_bytes(4, "little")),
            (0xA003, 4, 1, height.to_bytes(4, "little")),
        ],
        exif_offset,
    )
    gps_offset = exif_offset + len(exif_ifd)
    gps_date_count, gps_date_raw = _ascii_entry("2024:01:02")
    gps_ifd = _ifd(
        [
            (0x0001, 2, 2, b"N\x00"),
            (0x0002, 5, 3, _rational([(37, 1), (30, 1), (0, 1)])),
            (0x0003, 2, 2, b"E\x00"),
            (0x0004, 5, 3, _rational([(127, 1), (0, 1), (0, 1)])),
            (0x0007, 5, 3, _rational([(12, 1), (34, 1), (56, 1)])),
            (0x001D, 2, gps_date_count, gps_date_raw),
        ],
        gps_offset,
    )
    ifd0 = _ifd(
        [
            (0x8769, 4, 1, exif_offset.to_bytes(4, "little")),
            (0x8825, 4, 1, gps_offset.to_bytes(4, "little")),
        ],
        8,
    )
    tiff = b"II*\x00" + (8).to_bytes(4, "little") + ifd0 + exif_ifd + gps_ifd
    app1_payload = b"Exif\x00\x00" + tiff
    app1 = b"\xff\xe1" + (len(app1_payload) + 2).to_bytes(2, "big") + app1_payload
    sof0_payload = (
        b"\x08"
        + height.to_bytes(2, "big")
        + width.to_bytes(2, "big")
        + b"\x03\x01\x11\x00\x02\x11\x00\x03\x11\x00"
    )
    sof0 = b"\xff\xc0" + (len(sof0_payload) + 2).to_bytes(2, "big") + sof0_payload
    return b"\xff\xd8" + app1 + sof0 + b"\xff\xd9"


def _create_chromium_history(path: Path) -> None:
    connection = sqlite3.connect(path)
    try:
        connection.executescript(
            """
            CREATE TABLE urls (
                id INTEGER PRIMARY KEY,
                url TEXT,
                title TEXT,
                visit_count INTEGER,
                typed_count INTEGER,
                last_visit_time INTEGER
            );
            CREATE TABLE visits (
                id INTEGER PRIMARY KEY,
                url INTEGER,
                visit_time INTEGER,
                from_visit INTEGER,
                transition INTEGER
            );
            CREATE TABLE keyword_search_terms(term TEXT, url_id INTEGER);
            CREATE TABLE downloads (
                id INTEGER PRIMARY KEY,
                current_path TEXT,
                target_path TEXT,
                start_time INTEGER,
                end_time INTEGER,
                received_bytes INTEGER,
                total_bytes INTEGER,
                state INTEGER,
                danger_type INTEGER,
                interrupt_reason INTEGER,
                tab_url TEXT,
                tab_referrer_url TEXT
            );
            CREATE TABLE downloads_url_chains(id INTEGER, chain_index INTEGER, url TEXT);
            """
        )
        visit_time = _webkit_time(datetime(2024, 1, 2, 3, 4, 5, tzinfo=UTC))
        download_time = _webkit_time(datetime(2024, 1, 3, 4, 5, 6, tzinfo=UTC))
        connection.execute(
            "INSERT INTO urls VALUES (?, ?, ?, ?, ?, ?)",
            (1, "https://example.com/?q=apex", "Example", 3, 1, visit_time),
        )
        connection.execute(
            "INSERT INTO visits VALUES (?, ?, ?, ?, ?)",
            (7, 1, visit_time, 0, 805306368),
        )
        connection.execute("INSERT INTO keyword_search_terms VALUES (?, ?)", ("apex forensic", 1))
        connection.execute(
            "INSERT INTO downloads VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                11,
                "/tmp/current.bin",
                "/home/user/Downloads/report.pdf",
                download_time,
                download_time + 10,
                512,
                1024,
                1,
                0,
                0,
                "https://example.com",
                "https://referrer.example",
            ),
        )
        connection.execute(
            "INSERT INTO downloads_url_chains VALUES (?, ?, ?)",
            (11, 0, "https://example.com/report.pdf"),
        )
        connection.commit()
    finally:
        connection.close()


def _append_chromium_visit(
    connection: sqlite3.Connection,
    *,
    url_id: int,
    visit_id: int,
    url: str,
    title: str,
) -> None:
    visit_time = _webkit_time(datetime(2024, 2, 3, 4, 5, 6, tzinfo=UTC))
    connection.execute(
        "INSERT INTO urls VALUES (?, ?, ?, ?, ?, ?)",
        (url_id, url, title, 1, 0, visit_time),
    )
    connection.execute(
        "INSERT INTO visits VALUES (?, ?, ?, ?, ?)",
        (visit_id, url_id, visit_time, 0, 805306368),
    )
    connection.commit()


def _create_chromium_history_with_visits(path: Path, count: int) -> None:
    _create_chromium_history(path)
    connection = sqlite3.connect(path)
    try:
        for index in range(2, count + 1):
            _append_chromium_visit(
                connection,
                url_id=index,
                visit_id=100 + index,
                url=f"https://example.com/page-{index}",
                title=f"Page {index}",
            )
    finally:
        connection.close()


def _create_firefox_places(path: Path) -> None:
    connection = sqlite3.connect(path)
    try:
        connection.executescript(
            """
            CREATE TABLE moz_places (
                id INTEGER PRIMARY KEY,
                url TEXT,
                title TEXT,
                visit_count INTEGER,
                last_visit_date INTEGER
            );
            CREATE TABLE moz_historyvisits (
                id INTEGER PRIMARY KEY,
                place_id INTEGER,
                visit_date INTEGER,
                from_visit INTEGER,
                visit_type INTEGER
            );
            CREATE TABLE moz_anno_attributes (id INTEGER PRIMARY KEY, name TEXT);
            CREATE TABLE moz_annos (
                id INTEGER PRIMARY KEY,
                place_id INTEGER,
                anno_attribute_id INTEGER,
                content TEXT,
                dateAdded INTEGER,
                lastModified INTEGER
            );
            CREATE TABLE moz_inputhistory (place_id INTEGER, input TEXT, use_count INTEGER);
            """
        )
        visit = int(datetime(2024, 1, 2, 3, 4, 5, tzinfo=UTC).timestamp() * 1_000_000)
        connection.execute(
            "INSERT INTO moz_places VALUES (?, ?, ?, ?, ?)",
            (1, "https://search.example/?q=typed", "Search Page", 1, visit),
        )
        connection.execute(
            "INSERT INTO moz_historyvisits VALUES (?, ?, ?, ?, ?)",
            (5, 1, visit, 0, 1),
        )
        connection.execute(
            "INSERT INTO moz_anno_attributes VALUES (?, ?)",
            (7, "downloads/destinationFileName"),
        )
        connection.execute(
            "INSERT INTO moz_annos VALUES (?, ?, ?, ?, ?, ?)",
            (9, 1, 7, "download.bin", visit, visit),
        )
        connection.execute(
            "INSERT INTO moz_inputhistory VALUES (?, ?, ?)",
            (1, "typed query", 3),
        )
        connection.commit()
    finally:
        connection.close()


def _bmp_header(*, width: int, height: int) -> bytes:
    header = bytearray(b"BM" + (54).to_bytes(4, "little") + b"\x00\x00\x00\x00")
    header.extend((54).to_bytes(4, "little"))
    header.extend((40).to_bytes(4, "little"))
    header.extend(width.to_bytes(4, "little", signed=True))
    header.extend(height.to_bytes(4, "little", signed=True))
    header.extend((1).to_bytes(2, "little"))
    header.extend((24).to_bytes(2, "little"))
    header.extend((0).to_bytes(4, "little"))
    header.extend((0).to_bytes(4, "little"))
    header.extend((2835).to_bytes(4, "little"))
    header.extend((2835).to_bytes(4, "little"))
    header.extend((0).to_bytes(4, "little"))
    header.extend((0).to_bytes(4, "little"))
    return bytes(header)


def test_phase5_media_browser_artifacts_query_schema_and_resilience(
    services,
    tmp_path: Path,
    schema_validator,
) -> None:
    evidence_dir = tmp_path / "phase5"
    media_dir = evidence_dir / "media"
    browser_dir = evidence_dir / "Chrome" / "Default"
    bad_browser_dir = evidence_dir / "Browser" / "Bad"
    media_dir.mkdir(parents=True)
    browser_dir.mkdir(parents=True)
    bad_browser_dir.mkdir(parents=True)
    (media_dir / "photo.jpg").write_bytes(_jpeg_with_exif())
    (media_dir / "clip.mp4").write_bytes(_minimal_mp4())
    (media_dir / "sound.mp3").write_bytes(b"ID3\x04\x00\x00\x00\x00\x00\x00")
    (media_dir / "broken.jpg").write_bytes(b"not a jpeg")
    _create_chromium_history(browser_dir / "History")
    (bad_browser_dir / "History").write_bytes(b"not sqlite")

    case, evidence = _case_evidence_and_index(services, evidence_dir)
    discovery = services.artifacts.discover_sources(
        case_id=case.case_id,
        evidence_id=evidence.evidence_id,
        profile_type=AnalysisProfileType.FULL_ANALYSIS,
    )
    source_kinds = {item["source_kind"] for item in discovery["sources"]}
    assert {"IMAGE_FILE", "VIDEO_FILE", "AUDIO_FILE", "BROWSER_SQLITE_DB"}.issubset(source_kinds)

    job, coverage = services.artifacts.analyze_evidence(
        case_id=case.case_id,
        evidence_id=evidence.evidence_id,
        profile_type=AnalysisProfileType.FULL_ANALYSIS,
    )
    page = services.artifacts.list_artifacts(
        ArtifactQuery(case_id=case.case_id, evidence_id=evidence.evidence_id, limit=100)
    )
    types = {artifact.artifact_type for artifact in page.items}

    assert job.status == "PARTIAL"
    assert coverage.artifact_count >= 8
    assert ArtifactType.MEDIA_IMAGE in types
    assert ArtifactType.MEDIA_VIDEO in types
    assert ArtifactType.MEDIA_AUDIO in types
    assert ArtifactType.BROWSER_PROFILE in types
    assert ArtifactType.BROWSER_VISIT in types
    assert ArtifactType.BROWSER_SEARCH in types
    assert ArtifactType.BROWSER_DOWNLOAD in types
    assert any(artifact.parse_status is ArtifactParseStatus.CORRUPT for artifact in page.items)

    image = next(
        artifact
        for artifact in page.items
        if artifact.artifact_type is ArtifactType.MEDIA_IMAGE
        and artifact.source_path.endswith("photo.jpg")
    )
    assert image.fields["gps_raw"]["latitude_ref"] == "N"
    assert image.fields["gps_normalized"]["latitude"] == 37.5
    assert image.fields["gps_normalized"]["longitude"] == 127.0
    assert image.fields["media_timestamps"][0]["raw_value"] == "2024:01:02 03:04:05"
    assert image.fields["media_timestamps"][0]["normalized_utc"] == "2024-01-01T18:04:05.000000Z"
    assert image.fields["thumbnail_cache"]["kind"] == "THUMBNAIL"
    assert image.fields["thumbnail_cache"]["hash_verifiable"] is True

    video = next(
        artifact for artifact in page.items if artifact.artifact_type is ArtifactType.MEDIA_VIDEO
    )
    assert video.fields["codec"] == "avc1"
    assert video.fields["duration_seconds"] == 125.0

    audio = next(
        artifact for artifact in page.items if artifact.artifact_type is ArtifactType.MEDIA_AUDIO
    )
    assert audio.fields["media_kind"] == "AUDIO"
    assert audio.fields["classification"]["format"] == "MP3"
    assert {warning["code"] for warning in audio.warnings}.intersection(
        {"FFPROBE_CAPABILITY_UNAVAILABLE", "FFPROBE_CORRUPT_OR_UNSUPPORTED"}
    )

    browser_visit = services.artifacts.list_artifacts(
        ArtifactQuery(
            case_id=case.case_id,
            artifact_type=ArtifactType.BROWSER_VISIT,
            browser_profile="Default",
            browser_table="visits",
            browser_row_id=7,
            observed_from=datetime(2024, 1, 2, 0, 0, 0, tzinfo=UTC),
            observed_to=datetime(2024, 1, 2, 23, 59, 59, tzinfo=UTC),
        )
    )
    assert browser_visit.returned == 1
    assert browser_visit.items[0].fields["url"] == "https://example.com/?q=apex"
    assert browser_visit.items[0].raw_locator["details"]["table"] == "visits"
    assert browser_visit.items[0].raw_locator["details"]["row_id"] == 7

    browser_search = services.artifacts.list_artifacts(
        ArtifactQuery(case_id=case.case_id, artifact_type=ArtifactType.BROWSER_SEARCH)
    )
    assert browser_search.items[0].fields["search_term"] == "apex forensic"

    cache_rows = services.repository.connection.execute(
        "SELECT kind, key_sha256, content_sha256 FROM cache_entries WHERE kind = 'THUMBNAIL'"
    ).fetchall()
    assert len(cache_rows) >= 2
    assert all(len(row["key_sha256"]) == 64 for row in cache_rows)
    assert all(len(row["content_sha256"]) == 64 for row in cache_rows)

    for artifact in page.items:
        schema_validator.validate_artifact(artifact.to_schema_dict())


def test_phase5_browser_wal_reanalysis_reuse_and_reopen(tmp_path: Path) -> None:
    db_path = tmp_path / "wal-revisions.db"
    evidence_dir = tmp_path / "wal-evidence"
    browser_dir = evidence_dir / "Chrome" / "Default"
    browser_dir.mkdir(parents=True)
    history_path = browser_dir / "History"
    _create_chromium_history(history_path)
    setup = sqlite3.connect(history_path)
    try:
        setup.execute("PRAGMA journal_mode=WAL")
        setup.execute("PRAGMA wal_autocheckpoint=0")
        setup.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    finally:
        setup.close()

    services = build_services(db_path)
    writer: sqlite3.Connection | None = None
    try:
        case, evidence = _case_evidence_and_index(services, evidence_dir)
        first_job, _ = services.artifacts.analyze_evidence(
            case_id=case.case_id,
            evidence_id=evidence.evidence_id,
            profile_type=AnalysisProfileType.FULL_ANALYSIS,
            analyzers=["browser.history"],
        )
        assert first_job.status == "SUCCEEDED"
        assert _browser_revision_count(services) == 1

        services.search.index(case_id=case.case_id)
        before = services.search.query(case_id=case.case_id, query_text="wal-only")
        assert before.execution.result_count == 0

        writer = sqlite3.connect(history_path)
        writer.execute("PRAGMA journal_mode=WAL")
        writer.execute("PRAGMA wal_autocheckpoint=0")
        _append_chromium_visit(
            writer,
            url_id=2,
            visit_id=8,
            url="https://example.com/wal-only",
            title="wal-only visit",
        )
        assert history_path.with_name("History-wal").exists()

        second_job, _ = services.artifacts.analyze_evidence(
            case_id=case.case_id,
            evidence_id=evidence.evidence_id,
            profile_type=AnalysisProfileType.FULL_ANALYSIS,
            analyzers=["browser.history"],
        )
        assert second_job.status == "SUCCEEDED"
        assert _browser_revision_count(services) == 2
        wal_visit = services.artifacts.list_artifacts(
            ArtifactQuery(
                case_id=case.case_id,
                artifact_type=ArtifactType.BROWSER_VISIT,
                browser_table="visits",
                browser_row_id=8,
            )
        )
        assert wal_visit.returned == 1

        services.search.index(case_id=case.case_id)
        after = services.search.query(case_id=case.case_id, query_text="wal-only")
        assert after.execution.result_count >= 1
        services.timeline.build(case_id=case.case_id)
        timeline = services.timeline.list_events(
            case_id=case.case_id,
            event_types=[TimelineEventType.BROWSER_VISIT],
            keyword="wal-only",
        )
        assert timeline.page.returned >= 1

        services.artifacts.analyze_evidence(
            case_id=case.case_id,
            evidence_id=evidence.evidence_id,
            profile_type=AnalysisProfileType.FULL_ANALYSIS,
            analyzers=["browser.history"],
        )
        assert _browser_revision_count(services) == 2
        services.close()

        reopened = build_services(db_path)
        try:
            reopened.artifacts.analyze_evidence(
                case_id=case.case_id,
                evidence_id=evidence.evidence_id,
                profile_type=AnalysisProfileType.FULL_ANALYSIS,
                analyzers=["browser.history"],
            )
            assert _browser_revision_count(reopened) == 2
        finally:
            reopened.close()
    finally:
        if writer is not None:
            writer.close()
        with suppress(sqlite3.ProgrammingError):
            services.close()


def _browser_revision_count(services) -> int:
    row = services.repository.connection.execute(
        "SELECT COUNT(DISTINCT source_fingerprint) AS count FROM browser_source_revisions"
    ).fetchone()
    return int(row["count"])


def test_phase5_browser_budgeted_resume_completes_one_large_source(
    services,
    tmp_path: Path,
) -> None:
    evidence_dir = tmp_path / "budgeted-browser"
    browser_dir = evidence_dir / "Chrome" / "Default"
    browser_dir.mkdir(parents=True)
    _create_chromium_history_with_visits(browser_dir / "History", count=7)
    case, evidence = _case_evidence_and_index(services, evidence_dir)

    job, _ = services.artifacts.analyze_evidence(
        case_id=case.case_id,
        evidence_id=evidence.evidence_id,
        profile_type=AnalysisProfileType.FULL_ANALYSIS,
        item_budget=2,
        batch_size=2,
        analyzers=["browser.history"],
    )
    assert job.status == "PARTIAL"
    source = services.repository.connection.execute(
        "SELECT status, inspected_count, source_checkpoint_json FROM artifact_sources"
    ).fetchone()
    assert source["status"] == "QUEUED"
    assert source["inspected_count"] == 2
    assert source["source_checkpoint_json"] is not None

    for _ in range(10):
        if job.status == "SUCCEEDED":
            break
        job, _ = services.artifacts.resume_artifact_job(job.job_id, item_budget=2)
    assert job.status == "SUCCEEDED"
    completed_source = services.repository.connection.execute(
        "SELECT status, inspected_count, source_checkpoint_json FROM artifact_sources"
    ).fetchone()
    assert completed_source["status"] == "SUCCEEDED"
    assert completed_source["source_checkpoint_json"] is None
    assert completed_source["inspected_count"] >= 10
    visits = services.artifacts.list_artifacts(
        ArtifactQuery(case_id=case.case_id, artifact_type=ArtifactType.BROWSER_VISIT, limit=50)
    )
    assert visits.returned >= 7


def test_phase5_browser_pause_and_cancel_within_large_sqlite_source(
    services,
    tmp_path: Path,
) -> None:
    evidence_dir = tmp_path / "pause-cancel-browser"
    paused_browser_dir = evidence_dir / "Chrome" / "Default"
    cancelled_browser_dir = evidence_dir / "Chromium" / "Profile 1"
    paused_browser_dir.mkdir(parents=True)
    cancelled_browser_dir.mkdir(parents=True)
    _create_chromium_history_with_visits(paused_browser_dir / "History", count=8)
    _create_chromium_history_with_visits(cancelled_browser_dir / "History", count=8)
    case, evidence = _case_evidence_and_index(services, evidence_dir)

    pause_token = PauseToken.new()

    def request_pause(_job) -> None:
        pause_token.request_pause()

    paused, _ = services.artifacts.analyze_evidence(
        case_id=case.case_id,
        evidence_id=evidence.evidence_id,
        profile_type=AnalysisProfileType.FULL_ANALYSIS,
        batch_size=2,
        analyzers=["browser.history"],
        selected_paths=["Chrome/Default/History"],
        pause_token=pause_token,
        progress_callback=request_pause,
    )
    assert paused.status == "PAUSED"
    paused_source = services.repository.connection.execute(
        """
        SELECT status, source_checkpoint_json
        FROM artifact_sources
        WHERE job_id = ?
        """,
        (paused.job_id,),
    ).fetchone()
    assert paused_source["status"] == "QUEUED"
    assert paused_source["source_checkpoint_json"] is not None
    resumed, _ = services.artifacts.resume_artifact_job(paused.job_id)
    assert resumed.status == "SUCCEEDED"

    cancel_token = CancellationToken.new()

    def request_cancel(_job) -> None:
        cancel_token.cancel()

    cancelled, _ = services.artifacts.analyze_evidence(
        case_id=case.case_id,
        evidence_id=evidence.evidence_id,
        profile_type=AnalysisProfileType.FULL_ANALYSIS,
        batch_size=2,
        analyzers=["browser.history"],
        selected_paths=["Chromium/Profile 1/History"],
        cancellation_token=cancel_token,
        progress_callback=request_cancel,
    )
    assert cancelled.status == "CANCELLED"
    cancelled_source = services.repository.connection.execute(
        """
        SELECT status, source_checkpoint_json
        FROM artifact_sources
        WHERE job_id = ?
        """,
        (cancelled.job_id,),
    ).fetchone()
    assert cancelled_source["status"] == "QUEUED"
    assert cancelled_source["source_checkpoint_json"] is not None
    resumed_cancelled, _ = services.artifacts.resume_artifact_job(cancelled.job_id)
    assert resumed_cancelled.status == "SUCCEEDED"


def test_phase5_firefox_input_history_is_limited_candidate_not_search(
    services,
    tmp_path: Path,
) -> None:
    evidence_dir = tmp_path / "firefox"
    firefox_dir = evidence_dir / "Firefox" / "default-release"
    firefox_dir.mkdir(parents=True)
    _create_firefox_places(firefox_dir / "places.sqlite")
    case, evidence = _case_evidence_and_index(services, evidence_dir)

    job, _ = services.artifacts.analyze_evidence(
        case_id=case.case_id,
        evidence_id=evidence.evidence_id,
        profile_type=AnalysisProfileType.FULL_ANALYSIS,
        analyzers=["browser.history"],
    )
    assert job.status == "PARTIAL"
    visits = services.artifacts.list_artifacts(
        ArtifactQuery(case_id=case.case_id, artifact_type=ArtifactType.BROWSER_VISIT)
    )
    assert visits.returned == 1
    downloads = services.artifacts.list_artifacts(
        ArtifactQuery(case_id=case.case_id, artifact_type=ArtifactType.BROWSER_DOWNLOAD)
    )
    assert downloads.returned == 1
    searches = services.artifacts.list_artifacts(
        ArtifactQuery(case_id=case.case_id, artifact_type=ArtifactType.BROWSER_SEARCH)
    )
    assert searches.returned == 0
    candidates = services.artifacts.list_artifacts(
        ArtifactQuery(
            case_id=case.case_id,
            artifact_type=ArtifactType.BROWSER_PROFILE,
            artifact_subtype="FIREFOX_URLBAR_INPUT_HISTORY_CANDIDATE",
        )
    )
    assert candidates.returned == 1
    candidate = candidates.items[0]
    assert candidate.fields["input_text"] == "typed query"
    assert candidate.fields["search_term_confirmed"] is False
    assert candidate.observed_at_raw is None
    assert candidate.observed_at_utc is None

    services.timeline.build(case_id=case.case_id)
    timeline_searches = services.timeline.list_events(
        case_id=case.case_id,
        event_types=[TimelineEventType.BROWSER_SEARCH],
        keyword="typed query",
    )
    assert timeline_searches.page.returned == 0


def test_phase5_browser_projection_displayed_case_time_converts_timezone(
    services,
    tmp_path: Path,
) -> None:
    cases = [
        ("seoul", "Asia/Seoul", "2024-01-02T12:04:05.000000+09:00", "Asia/Seoul"),
        ("utc", "UTC", "2024-01-02T03:04:05.000000+00:00", "UTC"),
        ("new-york", "America/New_York", "2024-01-01T22:04:05.000000-05:00", "America/New_York"),
    ]
    for name, timezone, displayed, stored_timezone in cases:
        evidence_dir = tmp_path / name
        browser_dir = evidence_dir / "Chrome" / "Default"
        browser_dir.mkdir(parents=True)
        _create_chromium_history(browser_dir / "History")
        case = services.cases.create_case(name=name, timezone=timezone)
        evidence = services.evidence.register_evidence(
            case_id=case.case_id,
            source_path=evidence_dir,
        )
        services.fs.index_evidence(
            case_id=case.case_id,
            evidence_id=evidence.evidence_id,
            profile_type=AnalysisProfileType.FULL_ANALYSIS,
        )
        services.artifacts.analyze_evidence(
            case_id=case.case_id,
            evidence_id=evidence.evidence_id,
            profile_type=AnalysisProfileType.FULL_ANALYSIS,
            analyzers=["browser.history"],
        )
        row = _browser_projection_row(services, case.case_id)
        assert row["normalized_utc"] == "2024-01-02T03:04:05.000000Z"
        assert row["displayed_case_time"] == displayed
        assert row["case_timezone"] == stored_timezone

    invalid_dir = tmp_path / "invalid-zone"
    invalid_browser_dir = invalid_dir / "Chrome" / "Default"
    invalid_browser_dir.mkdir(parents=True)
    _create_chromium_history(invalid_browser_dir / "History")
    invalid_case = services.cases.create_case(name="invalid-zone", timezone="UTC")
    invalid_evidence = services.evidence.register_evidence(
        case_id=invalid_case.case_id,
        source_path=invalid_dir,
    )
    services.fs.index_evidence(
        case_id=invalid_case.case_id,
        evidence_id=invalid_evidence.evidence_id,
        profile_type=AnalysisProfileType.FULL_ANALYSIS,
    )
    services.repository.connection.execute(
        "UPDATE cases SET timezone = ? WHERE case_id = ?",
        ("Mars/Base", invalid_case.case_id),
    )
    services.artifacts.analyze_evidence(
        case_id=invalid_case.case_id,
        evidence_id=invalid_evidence.evidence_id,
        profile_type=AnalysisProfileType.FULL_ANALYSIS,
        analyzers=["browser.history"],
    )
    invalid_row = _browser_projection_row(services, invalid_case.case_id)
    fields = json.loads(str(invalid_row["fields_json"]))
    assert invalid_row["case_timezone"] == "UTC"
    assert invalid_row["displayed_case_time"] == "2024-01-02T03:04:05.000000Z"
    assert fields["projection_warnings"][0]["code"] == "INVALID_CASE_TIMEZONE_FALLBACK"


def _browser_projection_row(services, case_id: str):
    row = services.repository.connection.execute(
        """
        SELECT normalized_utc, displayed_case_time, case_timezone, fields_json
        FROM browser_artifacts
        WHERE case_id = ? AND artifact_type = 'HISTORY_VISIT'
        ORDER BY artifact_id
        LIMIT 1
        """,
        (case_id,),
    ).fetchone()
    assert row is not None
    return row


def test_phase5_timeline_small_batch_keeps_browser_sources(
    services,
    tmp_path: Path,
) -> None:
    evidence_dir = tmp_path / "timeline-browser-pagination"
    browser_dir = evidence_dir / "Chrome" / "Default"
    browser_dir.mkdir(parents=True)
    _create_chromium_history(browser_dir / "History")
    case, evidence = _case_evidence_and_index(services, evidence_dir)

    services.artifacts.analyze_evidence(
        case_id=case.case_id,
        evidence_id=evidence.evidence_id,
        profile_type=AnalysisProfileType.FULL_ANALYSIS,
        analyzers=["browser.history"],
    )
    job, _ = services.timeline.build(case_id=case.case_id, batch_size=1)
    assert job.status == "SUCCEEDED"

    timeline = services.timeline.list_events(
        case_id=case.case_id,
        event_types=[TimelineEventType.BROWSER_VISIT],
        keyword="Example",
    )
    assert timeline.page.returned >= 1


def test_phase5_media_revision_updates_search_and_timeline(
    services,
    tmp_path: Path,
) -> None:
    evidence_dir = tmp_path / "media-revision"
    media_dir = evidence_dir / "media"
    media_dir.mkdir(parents=True)
    photo = media_dir / "photo.jpg"
    photo.write_bytes(_jpeg_with_exif(width=2, height=3))
    case, evidence = _case_evidence_and_index(services, evidence_dir)

    services.artifacts.analyze_evidence(
        case_id=case.case_id,
        evidence_id=evidence.evidence_id,
        profile_type=AnalysisProfileType.FULL_ANALYSIS,
        analyzers=["media.metadata"],
    )
    services.search.index(case_id=case.case_id)
    before = services.search.query(case_id=case.case_id, query_text="640")
    assert before.execution.result_count == 0

    photo.write_bytes(
        _jpeg_with_exif(
            width=640,
            height=480,
            datetime_original="2024:03:04 05:06:07",
            offset_time_original="-05:00",
        )
    )
    services.artifacts.analyze_evidence(
        case_id=case.case_id,
        evidence_id=evidence.evidence_id,
        profile_type=AnalysisProfileType.FULL_ANALYSIS,
        analyzers=["media.metadata"],
    )
    services.search.index(case_id=case.case_id)
    after = services.search.query(case_id=case.case_id, query_text="640")
    assert after.execution.result_count >= 1

    services.timeline.build(case_id=case.case_id)
    timeline = services.timeline.list_events(
        case_id=case.case_id,
        artifact_type=ArtifactType.MEDIA_IMAGE.value,
        keyword="640",
    )
    assert timeline.page.returned >= 1
    assert any(event.fields.get("width") == 640 for event in timeline.items)


def test_phase5_media_decompression_bomb_and_corrupt_boundaries(
    services,
    tmp_path: Path,
) -> None:
    evidence_dir = tmp_path / "media-bounds"
    media_dir = evidence_dir / "media"
    media_dir.mkdir(parents=True)
    (media_dir / "huge.bmp").write_bytes(_bmp_header(width=200_000, height=1_000))
    (media_dir / "corrupt.jpg").write_bytes(b"not a jpeg")
    case, evidence = _case_evidence_and_index(services, evidence_dir)

    services.artifacts.analyze_evidence(
        case_id=case.case_id,
        evidence_id=evidence.evidence_id,
        profile_type=AnalysisProfileType.FULL_ANALYSIS,
        analyzers=["media.metadata"],
    )
    page = services.artifacts.list_artifacts(
        ArtifactQuery(case_id=case.case_id, artifact_type=ArtifactType.MEDIA_IMAGE, limit=20)
    )
    huge = next(item for item in page.items if item.source_path.endswith("huge.bmp"))
    corrupt = next(item for item in page.items if item.source_path.endswith("corrupt.jpg"))
    assert any(warning["code"] == "IMAGE_DECOMPRESSION_BOMB_LIMIT" for warning in huge.warnings)
    assert corrupt.parse_status is ArtifactParseStatus.CORRUPT


def test_phase5_ffprobe_timestamp_normalization_cases() -> None:
    cases = [
        ("2024-01-02T03:04:05Z", "2024-01-02T03:04:05.000000Z", None),
        ("2024-01-02T03:04:05+09:00", "2024-01-01T18:04:05.000000Z", None),
        ("2024-01-02T03:04:05.123456-05:00", "2024-01-02T08:04:05.123456Z", None),
        ("2024-01-02T03:04:05", None, "FFPROBE_TIMESTAMP_TIMEZONE_UNKNOWN"),
        ("not-a-time", None, "FFPROBE_TIMESTAMP_INVALID"),
    ]
    for raw_value, normalized, warning_code in cases:
        metadata, warnings = media_adapter._metadata_from_ffprobe(
            {"format": {"tags": {"creation_time": raw_value}}, "streams": []}
        )
        timestamp = metadata["media_timestamps"][0]
        assert timestamp["raw_value"] == raw_value
        assert timestamp["normalized_utc"] == normalized
        if warning_code is None:
            assert not warnings
            assert timestamp["timezone_confidence"] == "HIGH"
        else:
            assert warnings[0]["code"] == warning_code
            assert timestamp["timezone_confidence"] == "UNKNOWN"


def test_phase5_ffprobe_bounded_output_timeout_and_argv_safety(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stdout_limit = media_adapter._run_bounded_process(
        [sys.executable, "-c", "import sys; sys.stdout.write('x' * 2048)"],
        timeout=3,
        max_bytes=64,
    )
    assert stdout_limit.limit_stream == "stdout"
    stderr_limit = media_adapter._run_bounded_process(
        [sys.executable, "-c", "import sys; sys.stderr.write('x' * 2048)"],
        timeout=3,
        max_bytes=64,
    )
    assert stderr_limit.limit_stream == "stderr"
    timed_out = media_adapter._run_bounded_process(
        [sys.executable, "-c", "import time; time.sleep(2)"],
        timeout=1,
        max_bytes=64,
    )
    assert timed_out.timed_out is True

    monkeypatch.setattr(media_adapter.shutil, "which", lambda _name: None)
    unavailable = media_adapter._ffprobe_metadata(
        file_path=tmp_path / "missing.mp4",
        media_kind="VIDEO",
    )
    assert unavailable["warnings"][0]["code"] == "FFPROBE_CAPABILITY_UNAVAILABLE"

    fake = tmp_path / "ffprobe"
    fake.write_text(
        "#!/usr/bin/env python3\n"
        "import json\n"
        "print(json.dumps({'format': {'format_name': 'mov,mp4,m4a,3gp,3g2,mj2', "
        "'duration': '1.5', 'tags': {'creation_time': '2024-01-02T03:04:05+09:00'}}, "
        "'streams': [{'codec_type': 'video', 'codec_name': 'h264', 'width': 640, "
        "'height': 480}]}))\n",
        encoding="utf-8",
    )
    os.chmod(fake, 0o755)
    monkeypatch.setattr(media_adapter.shutil, "which", lambda _name: str(fake))
    injected_path = tmp_path / "clip.mp4;touch SHOULD_NOT_EXIST"
    injected_path.write_bytes(b"fake")
    normal = media_adapter._ffprobe_metadata(file_path=injected_path, media_kind="VIDEO")
    assert normal["parse_status"] is ArtifactParseStatus.SUCCESS
    assert normal["metadata"]["width"] == 640
    assert normal["metadata"]["media_timestamps"][0]["normalized_utc"] == (
        "2024-01-01T18:04:05.000000Z"
    )
    assert not (tmp_path / "SHOULD_NOT_EXIST").exists()


def test_phase5_candidate_review_workflow_preserves_original_text(services, tmp_path: Path) -> None:
    evidence_dir = tmp_path / "candidate-phase5"
    evidence_dir.mkdir()
    (evidence_dir / "note.txt").write_text("candidate source", encoding="utf-8")
    case, evidence = _case_evidence_and_index(services, evidence_dir)
    source_node = services.fs.list_nodes(
        evidence_id=evidence.evidence_id, all_nodes=True, files_only=True, limit=10
    ).items[0]
    created_at = datetime(2024, 1, 2, 3, 4, 5, tzinfo=UTC)
    candidate = MachineExtractedCandidate(
        candidate_id="candidate-1",
        case_id=case.case_id,
        evidence_id=evidence.evidence_id,
        source_node_id=source_node.node_id,
        source_type="AUDIO",
        extraction_type="STT",
        text="helo world",
        language="en",
        confidence=0.72,
        provider_id="synthetic.stt",
        provider_version="1.0.0",
        model_id="fixture",
        region=None,
        frame_number=None,
        media_timestamp_ms=None,
        audio_start_ms=0,
        audio_end_ms=1200,
        raw_locator={"locator_type": "SYNTHETIC", "source_node_id": source_node.node_id},
        citations=[{"evidence_id": evidence.evidence_id, "source_id": source_node.node_id}],
        review_status="UNREVIEWED",
        reviewed_by=None,
        reviewed_at=None,
        correction_text=None,
        source_revision=source_node.index_revision,
        is_partial=False,
        created_at=created_at,
    )
    services.repository.save_machine_candidate(candidate)

    capabilities = services.candidates.capabilities()
    assert {item.capability_type for item in capabilities} >= {"OCR", "STT"}
    assert all(not item.is_available for item in capabilities)

    page = services.candidates.list_candidates(case_id=case.case_id, limit=1)
    assert page.items[0].text == "helo world"

    corrected = services.candidates.review_candidate(
        candidate_id="candidate-1",
        review_status="CORRECTED",
        reviewed_by="analyst",
        correction_text="hello world",
        reason="fixture correction",
    )
    assert corrected.text == "helo world"
    assert corrected.review_status == "CORRECTED"
    assert corrected.correction_text == "hello world"

    history = services.candidates.get_candidate("candidate-1")
    assert history["candidate"]["candidate_semantics"] == (
        "MACHINE_EXTRACTED_CANDIDATE_NOT_OBSERVED_FACT"
    )
    assert history["review_events"][0]["previous_review_status"] == "UNREVIEWED"
    review_event_id = history["review_events"][0]["review_event_id"]
    with pytest.raises(sqlite3.DatabaseError):
        services.repository.connection.execute(
            "UPDATE candidate_review_events SET reason = ? WHERE review_event_id = ?",
            ("mutated", review_event_id),
        )
    with pytest.raises(sqlite3.DatabaseError):
        services.repository.connection.execute(
            "DELETE FROM candidate_review_events WHERE review_event_id = ?",
            (review_event_id,),
        )


def test_phase5_cli_browser_and_media_helpers(
    tmp_path: Path,
    cli_env: dict[str, str],
) -> None:
    import json
    import subprocess
    import sys

    db_path = tmp_path / "phase5-cli.db"
    evidence_dir = tmp_path / "cli-phase5"
    browser_dir = evidence_dir / "Chrome" / "Default"
    media_dir = evidence_dir / "media"
    browser_dir.mkdir(parents=True)
    media_dir.mkdir(parents=True)
    _create_chromium_history(browser_dir / "History")
    (media_dir / "photo.jpg").write_bytes(_jpeg_with_exif())

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
        run_cli(["--db", str(db_path), "case", "create", "--name", "CLI Phase 5", "--json"]).stdout
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
    browser_analyzed = run_cli(
        [
            "--db",
            str(db_path),
            "browser",
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
    assert browser_analyzed.returncode == 0, browser_analyzed.stderr
    media_analyzed = run_cli(
        [
            "--db",
            str(db_path),
            "media",
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
    assert media_analyzed.returncode == 0, media_analyzed.stderr
    media = run_cli(
        [
            "--db",
            str(db_path),
            "artifact",
            "media",
            "list",
            "--case-id",
            case["id"],
            "--media-kind",
            "IMAGE",
            "--json",
        ]
    )
    assert media.returncode == 0, media.stderr
    assert json.loads(media.stdout)["items"][0]["artifact_type"] == "MEDIA_IMAGE"
    visits = run_cli(
        [
            "--db",
            str(db_path),
            "artifact",
            "browser",
            "visits",
            "--case-id",
            case["id"],
            "--browser-profile",
            "Default",
            "--browser-table",
            "visits",
            "--browser-row-id",
            "7",
            "--json",
        ]
    )
    assert visits.returncode == 0, visits.stderr
    assert json.loads(visits.stdout)["items"][0]["fields"]["url"].startswith("https://example.com")

    top_level_media = run_cli(
        [
            "--db",
            str(db_path),
            "media",
            "list",
            "--case-id",
            case["id"],
            "--media-kind",
            "IMAGE",
            "--json",
        ]
    )
    assert top_level_media.returncode == 0, top_level_media.stderr
    media_artifact_id = json.loads(top_level_media.stdout)["items"][0]["artifact_id"]
    thumbnail = run_cli(
        [
            "--db",
            str(db_path),
            "media",
            "thumbnail",
            "--artifact-id",
            media_artifact_id,
            "--json",
        ]
    )
    assert thumbnail.returncode == 0, thumbnail.stderr
    assert json.loads(thumbnail.stdout)["thumbnail_status"] == "GENERATED"

    top_level_history = run_cli(
        [
            "--db",
            str(db_path),
            "browser",
            "history",
            "--case-id",
            case["id"],
            "--browser-profile",
            "Default",
            "--browser-table",
            "visits",
            "--browser-row-id",
            "7",
            "--json",
        ]
    )
    assert top_level_history.returncode == 0, top_level_history.stderr
    assert json.loads(top_level_history.stdout)["items"][0]["artifact_type"] == "BROWSER_VISIT"

    capabilities = run_cli(["--db", str(db_path), "candidate", "capabilities", "--json"])
    assert capabilities.returncode == 0, capabilities.stderr
    capability_payload = json.loads(capabilities.stdout)
    assert {item["capability_type"] for item in capability_payload} >= {"OCR", "STT"}
    assert all(not item["is_available"] for item in capability_payload)
