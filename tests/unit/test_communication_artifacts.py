from __future__ import annotations

import sqlite3
from datetime import UTC, datetime
from pathlib import Path

from apex_forensic.adapters.artifacts.communication import (
    CommunicationCorePluginAnalyzer,
    DiscordSQLiteFixtureAnalyzer,
    EmailMboxFixtureAnalyzer,
    KakaoTalkEncryptedStoreDiscoveryAnalyzer,
    TelegramSQLiteFixtureAnalyzer,
)
from apex_forensic.domain.enums import (
    AnalysisProfileType,
    ArtifactParseStatus,
    ArtifactType,
    EvidenceFormat,
    EvidenceStatus,
    FileSystemNodeType,
    TimelineEventType,
)
from apex_forensic.domain.models import ArtifactQuery, Evidence, FileSystemNode


def _case_evidence_and_index(services, root: Path):
    case = services.cases.create_case(name="Communication Case")
    evidence = services.evidence.register_evidence(case_id=case.case_id, source_path=root)
    services.fs.index_evidence(
        case_id=case.case_id,
        evidence_id=evidence.evidence_id,
        profile_type=AnalysisProfileType.FULL_ANALYSIS,
    )
    return case, evidence


def _standalone_evidence_and_node(
    path: Path,
    relative_path: str,
) -> tuple[Evidence, FileSystemNode]:
    now = datetime(2024, 4, 1, tzinfo=UTC)
    evidence = Evidence(
        evidence_id="evidence-communication-direct",
        case_id="case-communication-direct",
        display_name="direct communication fixture",
        source_path=path.parent,
        evidence_type=EvidenceFormat.DIRECTORY,
        size_bytes=path.stat().st_size,
        status=EvidenceStatus.REGISTERED,
        read_only=True,
        fingerprint=None,
        created_at=now,
        updated_at=now,
    )
    node = FileSystemNode(
        node_id=f"node-{relative_path.casefold().replace('/', '-')}",
        case_id=evidence.case_id,
        evidence_id=evidence.evidence_id,
        provider_id="test.logical",
        provider_version="test",
        parent_node_id=None,
        original_name=path.name,
        original_relative_path=relative_path,
        display_path=str(path),
        comparison_path=relative_path.casefold(),
        node_type=FileSystemNodeType.FILE,
        file_size=path.stat().st_size,
        extension=path.suffix,
        mime_candidate=None,
        mime_confidence="NONE",
        fs_metadata={},
        platform="test",
        timestamp_meanings={},
        raw_timestamps={},
        utc_timestamps={},
        timestamp_sources={},
        is_deleted=False,
        is_readable=True,
        is_link=False,
        is_traversed=False,
        raw_locator={"type": "path", "path": str(path)},
        provider_metadata={},
        is_partial=False,
        index_revision=1,
        created_at=now,
        updated_at=now,
    )
    return evidence, node


def _write_mbox(path: Path) -> None:
    path.write_bytes(
        (
            "From alice@example.com Fri Apr 05 06:07:08 2024\n"
            "From: Alice <alice@example.com>\n"
            "To: Bob <bob@example.com>\n"
            "Date: Fri, 05 Apr 2024 06:07:08 +0000\n"
            "Subject: Korean fixture\n"
            "Message-ID: <msg-1@example.com>\n"
            "Content-Type: text/plain; charset=utf-8\n"
            "\n"
            "안녕하세요. token=abc123 should be redacted.\n"
        ).encode()
    )


def _write_message_db(path: Path, *, app: str) -> None:
    connection = sqlite3.connect(path)
    try:
        connection.executescript(
            """
            CREATE TABLE messages (
                id TEXT,
                conversation_id TEXT,
                sender TEXT,
                recipients TEXT,
                timestamp TEXT,
                body TEXT,
                deleted INTEGER,
                recovered INTEGER,
                attachment_name TEXT,
                attachment_path TEXT,
                attachment_mime TEXT,
                attachment_size INTEGER
            );
            """
        )
        if app == "discord":
            connection.execute(
                "INSERT INTO messages VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    "discord-msg-1",
                    "discord-conv-1",
                    "alice#0001",
                    "bob#0002",
                    "2024-04-06T07:08:09+00:00",
                    "디스코드 메시지 password=hunter2",
                    1,
                    0,
                    "image.png",
                    "attachments/image.png",
                    "image/png",
                    123,
                ),
            )
        else:
            connection.execute(
                "INSERT INTO messages VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    "telegram-msg-1",
                    "telegram-conv-1",
                    "alice",
                    "bob",
                    "2024-04-07T08:09:10Z",
                    "텔레그램 메시지",
                    0,
                    1,
                    None,
                    None,
                    None,
                    None,
                ),
            )
        connection.commit()
    finally:
        connection.close()


def test_communication_mbox_resume_search_timeline_and_redaction(
    services,
    tmp_path: Path,
    schema_validator,
) -> None:
    evidence_dir = tmp_path / "communication-mbox"
    mail_dir = evidence_dir / "Mail"
    mail_dir.mkdir(parents=True)
    _write_mbox(mail_dir / "archive.mbox")
    case, evidence = _case_evidence_and_index(services, evidence_dir)

    discovery = services.artifacts.discover_sources(
        case_id=case.case_id,
        evidence_id=evidence.evidence_id,
        profile_type=AnalysisProfileType.FULL_ANALYSIS,
        analyzers=["communication.core"],
    )
    assert "EMAIL_MBOX" in {item["source_kind"] for item in discovery["sources"]}

    partial, _ = services.artifacts.analyze_evidence(
        case_id=case.case_id,
        evidence_id=evidence.evidence_id,
        profile_type=AnalysisProfileType.FULL_ANALYSIS,
        analyzers=["communication.core"],
        item_budget=2,
    )
    assert partial.status == "PARTIAL"
    services.artifacts.resume_artifact_job(partial.job_id)

    messages = services.artifacts.list_artifacts(
        ArtifactQuery(case_id=case.case_id, artifact_type=ArtifactType.COMMUNICATION_MESSAGE)
    )
    assert messages.returned == 1
    message = messages.items[0]
    assert "안녕하세요" in message.fields["message_body"]
    assert "abc123" not in message.fields["message_body"]
    assert message.fields["credential_token_redaction_applied"] is True
    assert message.raw_locator["source_reference"] == "mbox:message:1"
    schema_validator.validate_artifact(message.to_schema_dict())

    services.search.index(case_id=case.case_id)
    search = services.search.query(case_id=case.case_id, query_text="안녕하세요")
    assert search.execution.result_count >= 1

    services.timeline.build(case_id=case.case_id)
    timeline = services.timeline.list_events(
        case_id=case.case_id,
        event_types=[TimelineEventType.COMMUNICATION_MESSAGE],
    )
    assert timeline.page.returned >= 1


def test_communication_capability_matrix_lists_each_application() -> None:
    capability = CommunicationCorePluginAnalyzer().capabilities().to_schema_dict()
    matrix = {
        item["application"]: item
        for item in capability["metadata"]["application_capability_matrix"]
    }

    assert matrix["EMAIL"]["status"] == "IMPLEMENTED_RUNTIME"
    assert matrix["EMAIL"]["platform"] == "MBOX_RFC5322"
    assert matrix["DISCORD"]["status"] == "IMPLEMENTED_RUNTIME"
    assert matrix["DISCORD"]["tables"][0].startswith("messages(")
    assert matrix["TELEGRAM"]["status"] == "IMPLEMENTED_RUNTIME"
    assert matrix["KAKAOTALK"]["status"] == "UNSUPPORTED"
    assert matrix["KAKAOTALK"]["reason"] == "KEY_UNAVAILABLE"


def test_application_specific_communication_analyzers_runtime_contracts(tmp_path: Path) -> None:
    mbox_path = tmp_path / "Mail" / "archive.mbox"
    discord_path = tmp_path / "Discord" / "messages.sqlite"
    telegram_path = tmp_path / "Telegram" / "messages.sqlite"
    kakao_path = tmp_path / "KakaoTalk" / "kakaotalk.db"
    for path in (mbox_path, discord_path, telegram_path, kakao_path):
        path.parent.mkdir(parents=True, exist_ok=True)
    _write_mbox(mbox_path)
    _write_message_db(discord_path, app="discord")
    _write_message_db(telegram_path, app="telegram")
    kakao_path.write_bytes(b"encrypted-kakao-fixture")

    cases = [
        (EmailMboxFixtureAnalyzer(), mbox_path, "Mail/archive.mbox", "EMAIL_MESSAGE"),
        (
            DiscordSQLiteFixtureAnalyzer(),
            discord_path,
            "Discord/messages.sqlite",
            "DISCORD_MESSAGE",
        ),
        (
            TelegramSQLiteFixtureAnalyzer(),
            telegram_path,
            "Telegram/messages.sqlite",
            "TELEGRAM_MESSAGE",
        ),
        (
            KakaoTalkEncryptedStoreDiscoveryAnalyzer(),
            kakao_path,
            "KakaoTalk/kakaotalk.db",
            "KAKAOTALK_STRUCTURED_UNSUPPORTED",
        ),
    ]

    for analyzer, path, relative_path, expected_subtype in cases:
        evidence, node = _standalone_evidence_and_node(path, relative_path)
        source = analyzer.detect_source(node)
        assert source is not None
        assert source.analyzer_id == analyzer.analyzer_id
        result = analyzer.analyze(
            evidence=evidence,
            node=node,
            source=source,
            file_path=path,
        )
        assert result.artifacts
        assert any(artifact.artifact_subtype == expected_subtype for artifact in result.artifacts)
        capability = analyzer.capabilities().to_schema_dict()
        assert capability["metadata"]["application_capability"]["analyzer_id"] == (
            analyzer.analyzer_id
        )

    evidence, node = _standalone_evidence_and_node(kakao_path, "KakaoTalk/kakaotalk.db")
    source = KakaoTalkEncryptedStoreDiscoveryAnalyzer().detect_source(node)
    assert source is not None
    unsupported = KakaoTalkEncryptedStoreDiscoveryAnalyzer().analyze(
        evidence=evidence,
        node=node,
        source=source,
        file_path=kakao_path,
    )
    assert unsupported.artifacts[0].parse_status is ArtifactParseStatus.UNSUPPORTED
    assert unsupported.artifacts[0].fields["success_without_key"] is False


def test_communication_sqlite_discord_telegram_and_kakao_unsupported(
    services,
    tmp_path: Path,
    schema_validator,
) -> None:
    evidence_dir = tmp_path / "communication-sqlite"
    discord_dir = evidence_dir / "Discord"
    telegram_dir = evidence_dir / "Telegram"
    kakao_dir = evidence_dir / "KakaoTalk"
    discord_dir.mkdir(parents=True)
    telegram_dir.mkdir(parents=True)
    kakao_dir.mkdir(parents=True)
    _write_message_db(discord_dir / "messages.sqlite", app="discord")
    _write_message_db(telegram_dir / "messages.sqlite", app="telegram")
    (kakao_dir / "kakaotalk.db").write_bytes(b"encrypted-kakao-fixture")
    case, evidence = _case_evidence_and_index(services, evidence_dir)

    job, _ = services.artifacts.analyze_evidence(
        case_id=case.case_id,
        evidence_id=evidence.evidence_id,
        profile_type=AnalysisProfileType.FULL_ANALYSIS,
        analyzers=["communication.core"],
    )
    assert job.status == "PARTIAL"

    messages = services.artifacts.list_artifacts(
        ArtifactQuery(
            case_id=case.case_id,
            artifact_type=ArtifactType.COMMUNICATION_MESSAGE,
            limit=10,
        )
    )
    attachments = services.artifacts.list_artifacts(
        ArtifactQuery(case_id=case.case_id, artifact_type=ArtifactType.COMMUNICATION_ATTACHMENT)
    )
    unsupported = services.artifacts.list_artifacts(
        ArtifactQuery(
            case_id=case.case_id,
            artifact_type=ArtifactType.COMMUNICATION_UNSUPPORTED_STORE,
        )
    )
    assert messages.returned == 2
    assert attachments.returned == 1
    assert unsupported.returned == 1

    discord = next(
        item for item in messages.items if item.fields["communication_app"] == "DISCORD"
    )
    telegram = next(
        item for item in messages.items if item.fields["communication_app"] == "TELEGRAM"
    )
    assert "디스코드 메시지" in discord.fields["message_body"]
    assert "hunter2" not in discord.fields["message_body"]
    assert discord.fields["deleted_candidate"] is True
    assert telegram.fields["recovered_candidate"] is True
    assert "텔레그램 메시지" in telegram.fields["message_body"]
    assert unsupported.items[0].fields["unsupported_reason"] == "KEY_UNAVAILABLE"
    assert unsupported.items[0].parse_status.value == "UNSUPPORTED"

    for artifact in (discord, telegram, attachments.items[0], unsupported.items[0]):
        schema_validator.validate_artifact(artifact.to_schema_dict())

    services.timeline.build(case_id=case.case_id)
    timeline = services.timeline.list_events(
        case_id=case.case_id,
        event_types=[TimelineEventType.COMMUNICATION_MESSAGE],
        time_from=datetime(2024, 4, 6, tzinfo=UTC),
        time_to=datetime(2024, 4, 8, tzinfo=UTC),
    )
    assert timeline.page.returned >= 2
