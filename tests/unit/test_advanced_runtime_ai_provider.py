from __future__ import annotations

import json
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, ClassVar

import pytest

from apex_forensic._time import to_json_timestamp
from apex_forensic.adapters.ai import OpenAICompatibleConfig, OpenAICompatibleProvider
from apex_forensic.cli.commands import main
from apex_forensic.config import build_services
from apex_forensic.domain.enums import AnalysisContextPurpose, AnalysisProfileType
from apex_forensic.domain.errors import ApexError
from apex_forensic.domain.models import AiAssistanceRequest


class _FixtureHandler(BaseHTTPRequestHandler):
    response_payload: ClassVar[dict[str, Any]] = {}
    status_code = 200
    seen_authorization: str | None = None

    def log_message(self, format: str, *args: Any) -> None:
        del format, args

    def do_POST(self) -> None:
        _FixtureHandler.seen_authorization = self.headers.get("Authorization")
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        assert b"secret-token-value" not in body
        payload = json.dumps(_FixtureHandler.response_payload).encode("utf-8")
        self.send_response(_FixtureHandler.status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


@contextmanager
def _fixture_server(payload: dict[str, Any], *, status_code: int = 200) -> Iterator[str]:
    _FixtureHandler.response_payload = payload
    _FixtureHandler.status_code = status_code
    _FixtureHandler.seen_authorization = None
    server = ThreadingHTTPServer(("127.0.0.1", 0), _FixtureHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def _provider(base_url: str, monkeypatch: pytest.MonkeyPatch) -> OpenAICompatibleProvider:
    monkeypatch.setenv("APEX_TEST_AI_KEY", "secret-token-value")
    return OpenAICompatibleProvider(
        OpenAICompatibleConfig(
            provider_id="fixture-openai",
            base_url=base_url,
            model="fixture-model",
            api_key_env="APEX_TEST_AI_KEY",
            timeout=2.0,
        )
    )


def _request() -> AiAssistanceRequest:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    return AiAssistanceRequest(
        assistance_request_id="req-1",
        case_id="case-1",
        context_snapshot_id="snap-1",
        purpose="KEYWORD_RECOMMENDATION",
        requested_operations=["RECOMMEND_KEYWORDS"],
        requested_scopes=["filesystem"],
        scope_context_ids=["scope-1"],
        locale="ko-KR",
        timezone="Asia/Seoul",
        context_fingerprint="a" * 64,
        source_revision_fingerprint="b" * 64,
        is_partial=False,
        is_stale=False,
        coverage_summary={},
        warnings=[],
        citations=[],
        max_keyword_candidates=5,
        max_summary_length=4000,
        requested_at=now,
        expires_at=now + timedelta(hours=1),
        request_version="test",
        correlation_id=None,
        request_fingerprint="c" * 64,
        resource_count=1,
    )


def _report_request(citation: dict[str, Any] | None = None) -> AiAssistanceRequest:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    return AiAssistanceRequest(
        assistance_request_id="req-report-1",
        case_id="case-1",
        context_snapshot_id="snap-1",
        purpose="REPORT_INPUT",
        requested_operations=["GENERATE_REPORT_DRAFT"],
        requested_scopes=["filesystem"],
        scope_context_ids=["scope-1"],
        locale="ko-KR",
        timezone="Asia/Seoul",
        context_fingerprint="a" * 64,
        source_revision_fingerprint="b" * 64,
        is_partial=False,
        is_stale=False,
        coverage_summary={},
        warnings=[],
        citations=[] if citation is None else [citation],
        max_keyword_candidates=5,
        max_summary_length=4000,
        requested_at=now,
        expires_at=now + timedelta(hours=1),
        request_version="test",
        correlation_id="corr-report",
        request_fingerprint="d" * 64,
        resource_count=1,
    )


def _citation(
    case_id: str = "case-1",
    evidence_id: str = "ev-1",
    source_id: str = "node-1",
) -> dict[str, Any]:
    return {
        "id": "cit-1",
        "label": "CIT-1",
        "case_id": case_id,
        "evidence_id": evidence_id,
        "source_kind": "FILE",
        "source_id": source_id,
        "source_path": "note.txt",
        "source_offset": 0,
        "source_reference": "filesystem node",
        "excerpt": "alpha",
        "created_at": to_json_timestamp(datetime(2026, 1, 1, tzinfo=UTC)),
        "source_length": 5,
        "encoding": "utf-8",
        "raw_locator": {
            "evidence_id": evidence_id,
            "source_kind": "FILE",
            "source_id": source_id,
            "source_path": "note.txt",
            "locator_type": "LOGICAL_PATH",
            "offset": 0,
            "length": 5,
            "encoding": "utf-8",
            "view_types": ["TEXT"],
            "limitations": [],
            "details": {},
        },
    }


def _openai_response(content: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": "chatcmpl-fixture",
        "choices": [{"message": {"role": "assistant", "content": json.dumps(content)}}],
        "usage": {"prompt_tokens": 12, "completion_tokens": 8, "total_tokens": 20},
    }


def test_openai_compatible_provider_generates_keyword_payload(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    content = {
        "recommendations": [
            {
                "keyword_type": "DOCUMENT_TERM",
                "value": "alpha",
                "reason": "Cited term.",
                "confidence": "MEDIUM",
                "recommended_scope": "filesystem",
                "citations": [{"case_id": "case-1", "source_kind": "FILE", "source_id": "node-1"}],
            }
        ]
    }
    with _fixture_server(_openai_response(content)) as base_url:
        provider = _provider(base_url, monkeypatch)
        payload = provider.generate_keyword_recommendations(_request())

    assert payload["provider_id"] == "fixture-openai"
    assert payload["model_id"] == "fixture-model"
    assert payload["recommendations"][0]["value"] == "alpha"
    assert _FixtureHandler.seen_authorization == "Bearer secret-token-value"
    assert "secret-token-value" not in json.dumps(payload)


def test_openai_compatible_provider_generates_report_draft_payload(
    monkeypatch: pytest.MonkeyPatch,
    schema_validator: Any,
) -> None:
    citation = _citation()
    content = {
        "title": "AI Draft",
        "executive_summary": "External AI draft summary.",
        "sections": [
            {
                "title": "Key Findings",
                "content": "alpha was observed in the selected file.",
                "citations": [citation],
            }
        ],
        "citations": [citation],
    }
    with _fixture_server(_openai_response(content)) as base_url:
        provider = _provider(base_url, monkeypatch)
        capability = provider.capabilities().to_schema_dict()
        payload = provider.generate_report_draft(_report_request(citation))

    assert "GENERATE_REPORT_DRAFT" in capability["supported_operations"]
    assert payload["provider_id"] == "fixture-openai"
    assert payload["model_id"] == "fixture-model"
    assert payload["response_hash"]
    assert payload["sections"][0]["source_kind"] == "AI_DRAFT"
    assert "secret-token-value" not in json.dumps(payload)
    schema_validator.validate("ai-report-draft-input.schema.json", payload)


def test_openai_compatible_provider_structured_error_boundaries(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("APEX_TEST_AI_KEY", raising=False)
    provider = OpenAICompatibleProvider(
        OpenAICompatibleConfig(
            provider_id="fixture-openai",
            base_url="http://127.0.0.1:1",
            model="fixture-model",
            api_key_env="APEX_TEST_AI_KEY",
        )
    )
    assert provider.capabilities().unavailable_reason == "KEY_UNAVAILABLE"
    with pytest.raises(ApexError) as missing_key:
        provider.generate_scope_summary(_request())
    assert missing_key.value.code == "KEY_UNAVAILABLE"

    monkeypatch.setenv("APEX_TEST_AI_KEY", "secret-token-value")
    with pytest.raises(ApexError) as cancelled:
        _provider("http://127.0.0.1:1", monkeypatch).generate_scope_summary(
            _request(),
            cancellation_requested=True,
        )
    assert cancelled.value.code == "OPERATION_CANCELLED"

    with _fixture_server({"choices": [{"message": {"content": "not-json"}}]}) as base_url:
        provider = _provider(base_url, monkeypatch)
        with pytest.raises(ApexError) as invalid_json:
            provider.generate_scope_summary(_request())
    assert invalid_json.value.code == "AI_PROVIDER_INVALID_RESPONSE"

    with _fixture_server(_openai_response({}), status_code=429) as base_url:
        provider = _provider(base_url, monkeypatch)
        with pytest.raises(ApexError) as rate_limited:
            provider.generate_scope_summary(_request())
    assert rate_limited.value.code == "RATE_LIMITED"

    oversized = "x" * (600 * 1024)
    with _fixture_server(_openai_response({"summary": oversized})) as base_url:
        provider = _provider(base_url, monkeypatch)
        with pytest.raises(ApexError) as too_large:
            provider.generate_scope_summary(_request())
    assert too_large.value.code == "AI_PROVIDER_RESPONSE_TOO_LARGE"


def test_ai_service_ingests_provider_keyword_result(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    services = build_services(tmp_path / "apex.db")
    try:
        root = tmp_path / "evidence"
        root.mkdir()
        (root / "note.txt").write_text("alpha", encoding="utf-8")
        case = services.cases.create_case(name="AI Runtime Case")
        evidence = services.evidence.register_evidence(case_id=case.case_id, source_path=root)
        services.fs.index_evidence(
            case_id=case.case_id,
            evidence_id=evidence.evidence_id,
            profile_type=AnalysisProfileType.FULL_ANALYSIS,
        )
        node = next(
            item
            for item in services.repository.list_fs_nodes_for_evidence(evidence.evidence_id)
            if item.node_type.value == "FILE"
        )
        context = services.contexts.create(
            session_id="ai-runtime",
            case_id=case.case_id,
            selected_file_node_ids=[node.node_id],
        )
        snapshot = services.contexts.build_from_session(
            context.session_context_id,
            purpose=AnalysisContextPurpose.AI_REQUEST,
            scopes=["filesystem"],
        )
        request = services.ai.create_request_from_context_snapshot(
            case_id=case.case_id,
            context_snapshot_id=snapshot.context_snapshot_id,
            purpose="KEYWORD_RECOMMENDATION",
            requested_operations=["RECOMMEND_KEYWORDS"],
            requested_scopes=["filesystem"],
        )
        citation = {
            "id": "cit-1",
            "label": "CIT-1",
            "case_id": case.case_id,
            "evidence_id": evidence.evidence_id,
            "source_kind": "FILE",
            "source_id": node.node_id,
            "source_path": node.original_relative_path,
            "source_offset": 0,
            "source_reference": "filesystem node",
            "excerpt": "alpha",
            "created_at": to_json_timestamp(datetime(2026, 1, 1, tzinfo=UTC)),
            "source_length": 5,
            "encoding": "utf-8",
            "raw_locator": {
                "evidence_id": evidence.evidence_id,
                "source_kind": "FILE",
                "source_id": node.node_id,
                "source_path": node.original_relative_path,
                "locator_type": "LOGICAL_PATH",
                "offset": 0,
                "length": 5,
                "encoding": "utf-8",
                "view_types": ["TEXT"],
                "limitations": [],
                "details": {},
            },
        }
        content = {
            "recommendations": [
                {
                    "keyword_type": "DOCUMENT_TERM",
                    "value": "alpha",
                    "reason": "Term appears in cited selected file.",
                    "confidence": "MEDIUM",
                    "recommended_scope": "filesystem",
                    "evidence_ids": [evidence.evidence_id],
                    "source_resource_ids": [node.node_id],
                    "citations": [citation],
                }
            ]
        }
        with _fixture_server(_openai_response(content)) as base_url:
            result = services.ai.generate_keyword_recommendations(
                assistance_request_id=request.assistance_request_id,
                provider=_provider(base_url, monkeypatch),
            )

        assert result["batch"]["provider_id"] == "fixture-openai"
        assert result["recommendations"][0]["observed_fact_status"] == "NOT_OBSERVED_FACT"
    finally:
        services.close()


def test_ai_cli_generates_and_ingests_report_draft(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: Any,
) -> None:
    monkeypatch.setenv("APEX_TEST_AI_KEY", "secret-token-value")
    db_path = tmp_path / "apex.db"
    services = build_services(db_path)
    try:
        root = tmp_path / "evidence"
        root.mkdir()
        (root / "note.txt").write_text("alpha", encoding="utf-8")
        case = services.cases.create_case(name="AI Report Runtime Case")
        evidence = services.evidence.register_evidence(case_id=case.case_id, source_path=root)
        services.fs.index_evidence(
            case_id=case.case_id,
            evidence_id=evidence.evidence_id,
            profile_type=AnalysisProfileType.FULL_ANALYSIS,
        )
        node = next(
            item
            for item in services.repository.list_fs_nodes_for_evidence(evidence.evidence_id)
            if item.node_type.value == "FILE"
        )
        context = services.contexts.create(
            session_id="ai-report-runtime",
            case_id=case.case_id,
            selected_file_node_ids=[node.node_id],
        )
        snapshot = services.contexts.build_from_session(
            context.session_context_id,
            purpose=AnalysisContextPurpose.REPORT_DRAFT,
            scopes=["filesystem"],
        )
        request = services.ai.create_request_from_context_snapshot(
            case_id=case.case_id,
            context_snapshot_id=snapshot.context_snapshot_id,
            purpose="REPORT_INPUT",
            requested_operations=["GENERATE_REPORT_DRAFT"],
            requested_scopes=["filesystem"],
        )
        report = services.reports.create_report(
            case_id=case.case_id,
            title="AI Runtime Report",
            created_by="analyst",
        )
        citation = _citation(
            case_id=case.case_id,
            evidence_id=evidence.evidence_id,
            source_id=node.node_id,
        ) | {"source_path": node.original_relative_path}
    finally:
        services.close()

    content = {
        "title": "AI Runtime Report",
        "executive_summary": "Generated report draft summary.",
        "sections": [
            {
                "title": "Key Findings",
                "content": "alpha was observed in the cited selected file.",
                "source_resource_ids": [node.node_id],
                "citations": [citation],
            }
        ],
        "citations": [citation],
    }
    with _fixture_server(_openai_response(content)) as base_url:
        exit_code = main(
            [
                "--db",
                str(db_path),
                "ai",
                "generate-report-draft",
                "--assistance-request-id",
                request.assistance_request_id,
                "--report-id",
                report.report_id,
                "--base-url",
                base_url,
                "--model",
                "fixture-model",
                "--api-key-env",
                "APEX_TEST_AI_KEY",
                "--json",
            ]
        )
    output = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert output["source_kind"] == "AI_DRAFT"
    assert output["title"] == "AI Runtime Report"
    assert output["sections"][0]["source_kind"] == "AI_DRAFT"
    assert "secret-token-value" not in json.dumps(output)


def test_ai_provider_capability_cli_records_repository_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: Any,
) -> None:
    db_path = tmp_path / "ai-provider-capability.db"
    monkeypatch.delenv("APEX_TEST_AI_PROVIDER_CAPABILITY_KEY", raising=False)

    exit_code = main(
        [
            "--db",
            str(db_path),
            "ai",
            "provider-capability",
            "--base-url",
            "http://127.0.0.1:9",
            "--model",
            "fixture-model",
            "--api-key-env",
            "APEX_TEST_AI_PROVIDER_CAPABILITY_KEY",
            "--json",
        ]
    )
    output = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert output["unavailable_reason"] == "KEY_UNAVAILABLE"
    services = build_services(db_path)
    try:
        row = services.repository.connection.execute(
            """
            SELECT provider_id, supported_operations_json, unavailable_reason
            FROM ai_provider_capabilities
            WHERE provider_id = ?
            """,
            ("openai-compatible",),
        ).fetchone()
        assert row is not None
        assert row["unavailable_reason"] == "KEY_UNAVAILABLE"
        assert "GENERATE_REPORT_DRAFT" in json.loads(row["supported_operations_json"])
    finally:
        services.close()
