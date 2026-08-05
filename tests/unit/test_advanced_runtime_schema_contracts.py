from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from apex_forensic._time import to_json_timestamp
from apex_forensic.adapters.ai import OpenAICompatibleConfig
from apex_forensic.adapters.decryption import KakaoTalkEncryptedStoreProvider
from apex_forensic.adapters.report import RuntimeReportRenderer
from apex_forensic.domain.models import (
    MachineExtractedCandidate,
    RegistryDeletedCellCandidate,
    ReportRenderPackage,
)

CASE_ID = "11111111-1111-4111-8111-111111111111"
EVIDENCE_ID = "22222222-2222-4222-8222-222222222222"
NODE_ID = "33333333-3333-4333-8333-333333333333"
SOURCE_HASH = "a" * 64


def _raw_locator() -> dict[str, Any]:
    return {
        "evidence_id": EVIDENCE_ID,
        "source_kind": "FILE",
        "source_id": NODE_ID,
        "source_path": "note.txt",
        "source_reference": "filesystem node",
        "locator_type": "LOGICAL_PATH",
        "offset": 0,
        "length": 5,
        "encoding": "utf-8",
        "view_types": ["TEXT"],
        "content_sha256": SOURCE_HASH,
        "limitations": [],
        "details": {},
    }


def _citation() -> dict[str, Any]:
    return {
        "id": "44444444-4444-4444-8444-444444444444",
        "label": "CIT-001",
        "case_id": CASE_ID,
        "evidence_id": EVIDENCE_ID,
        "source_kind": "FILE",
        "source_id": NODE_ID,
        "file_id": NODE_ID,
        "artifact_id": None,
        "timeline_event_id": None,
        "search_result_id": None,
        "source_path": "note.txt",
        "source_offset": 0,
        "source_reference": "filesystem node",
        "excerpt": "alpha",
        "content_sha256": SOURCE_HASH,
        "created_at": "2026-01-01T00:00:00Z",
        "source_length": 5,
        "encoding": "utf-8",
        "raw_locator": _raw_locator(),
    }


def _render_package() -> ReportRenderPackage:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    return ReportRenderPackage(
        package_id="pkg-1",
        report_id="rpt-1",
        report_version_id="rv-1",
        case_id=CASE_ID,
        locale="ko-KR",
        timezone="Asia/Seoul",
        report_metadata={"title": "Schema Render", "executive_summary": "Summary."},
        sections=[
            {
                "section_id": "sec-1",
                "section_type": "KEY_FINDINGS",
                "title": "Finding",
                "order": 1,
                "content": "alpha observed",
                "citations": [_citation()],
            }
        ],
        evidence_manifest=[],
        hash_integrity_summary={},
        custody_snapshot_id=None,
        context_snapshot_ids=[],
        citations=[_citation()],
        partial_state={"is_partial": False},
        stale_state={"is_stale": False},
        coverage_summary={},
        limitations=[],
        renderer_requirements={"formats": ["HTML"]},
        package_fingerprint="b" * 64,
        created_at=now,
    )


def test_wp11_decryption_and_artifact_boundary_schemas(
    schema_validator: Any,
    tmp_path: Path,
) -> None:
    now = "2026-01-01T00:00:00Z"
    schema_validator.validate(
        "dpapi-key-source.schema.json",
        {
            "schema_version": "1.0.0",
            "case_id": CASE_ID,
            "evidence_id": EVIDENCE_ID,
            "provider_id": "apex.dpapi.offline",
            "source_kind": "WINDOWS_USER_PASSWORD",
            "scope": "USER",
            "sid": "S-1-5-21-1000",
            "masterkey_guid": None,
            "source_path": "Users/Alice/AppData/Roaming/Microsoft/Protect",
            "source_revision": 1,
            "fingerprint": SOURCE_HASH,
            "raw_locator": _raw_locator(),
            "status": "CAPABILITY_UNAVAILABLE",
            "warnings": [{"code": "CAPABILITY_UNAVAILABLE"}],
            "created_at": now,
        },
    )
    schema_validator.validate(
        "nss-profile.schema.json",
        {
            "schema_version": "1.0.0",
            "profile_id": "profile-1",
            "case_id": CASE_ID,
            "evidence_id": EVIDENCE_ID,
            "profile_path": "Firefox/Profiles/default",
            "key4_db_present": True,
            "logins_json_present": True,
            "primary_password_required": None,
            "schema_status": "UNKNOWN",
            "status": "CAPABILITY_UNAVAILABLE",
            "fingerprint": SOURCE_HASH,
            "raw_locator": _raw_locator(),
            "warnings": [{"code": "CAPABILITY_UNAVAILABLE"}],
            "discovered_at": now,
        },
    )

    store = tmp_path / "KakaoTalk" / "kakaotalk.db"
    store.parent.mkdir()
    store.write_bytes(b"encrypted-kakao-schema-fixture")
    schema_validator.validate(
        "kakaotalk-artifact.schema.json",
        KakaoTalkEncryptedStoreProvider().inspect_store(
            case_id=CASE_ID,
            evidence_id=EVIDENCE_ID,
            store_path=str(store),
        ),
    )


def test_wp11_registry_machine_ai_and_report_runtime_schemas(
    schema_validator: Any,
    tmp_path: Path,
) -> None:
    registry_candidate = RegistryDeletedCellCandidate(
        candidate_type="VK",
        source_region="FREE_CELL",
        absolute_offset=8192,
        length=64,
        hbin_offset=4096,
        confidence="HIGH",
        reasons=("free-cell candidate",),
        name="DeletedValue",
        value_type="REG_DWORD",
        value_data=7,
        raw_name_hex="44656c6574656456616c7565",
    )
    schema_validator.validate(
        "registry-deleted-candidate.schema.json",
        registry_candidate.to_schema_dict(),
    )

    candidate = MachineExtractedCandidate(
        candidate_id="cand-1",
        case_id=CASE_ID,
        evidence_id=EVIDENCE_ID,
        source_node_id=NODE_ID,
        source_type="IMAGE",
        extraction_type="OCR",
        text="alpha",
        language="eng",
        confidence=0.9,
        provider_id="tesseract-cli",
        provider_version="0.1.0",
        model_id=None,
        region={"x": 1, "y": 2, "width": 3, "height": 4, "unit": "PIXEL"},
        frame_number=None,
        media_timestamp_ms=None,
        audio_start_ms=None,
        audio_end_ms=None,
        raw_locator=_raw_locator(),
        citations=[_citation()],
        review_status="UNREVIEWED",
        reviewed_by=None,
        reviewed_at=None,
        correction_text=None,
        source_revision=1,
        is_partial=False,
        created_at=datetime(2026, 1, 1, tzinfo=UTC),
    )
    schema_validator.validate(
        "machine-extraction-request.schema.json",
        {
            "schema_version": "1.0.0",
            "case_id": CASE_ID,
            "evidence_id": EVIDENCE_ID,
            "source_node_id": NODE_ID,
            "path": "image.png",
            "source_revision": 1,
            "extraction_type": "OCR",
            "provider_id": "tesseract-cli",
            "languages": ["eng"],
            "model_path": None,
            "timeout_seconds": 30.0,
        },
    )
    schema_validator.validate(
        "machine-extraction-result.schema.json",
        {
            "schema_version": "1.0.0",
            "status": "COMPLETED",
            "provider_id": "tesseract-cli",
            "provider_version": "0.1.0",
            "extraction_type": "OCR",
            "candidates": [candidate.to_schema_dict()],
            "warnings": [],
            "candidate_semantics": "MACHINE_EXTRACTED_CANDIDATE_NOT_OBSERVED_FACT",
        },
    )

    config = OpenAICompatibleConfig(
        provider_id="openai-compatible",
        base_url="http://127.0.0.1:9/v1",
        model="synthetic-model",
        api_key_env="APEX_TEST_AI_KEY",
    )
    schema_validator.validate("ai-provider-config.schema.json", config.to_schema_dict())
    schema_validator.validate(
        "ai-provider-execution.schema.json",
        {
            "schema_version": "1.0.0",
            "provider_id": "openai-compatible",
            "provider_version": "0.1.0:openai-compatible-http",
            "model_id": "synthetic-model",
            "operation": "GENERATE_REPORT_DRAFT",
            "status": "KEY_UNAVAILABLE",
            "prompt_template_version": "apex-ai-openai-compatible-v1",
            "request_fingerprint": "c" * 64,
            "result_fingerprint": None,
            "latency_ms": None,
            "token_usage": {
                "prompt_tokens": None,
                "completion_tokens": None,
                "total_tokens": None,
            },
            "warnings": [{"code": "KEY_UNAVAILABLE"}],
            "generated_at": None,
        },
    )

    renderer = RuntimeReportRenderer(output_root=tmp_path)
    render_result = renderer.render(
        _render_package(),
        export_manifest_id="manifest-1",
        requested_filename="schema.html",
    )
    schema_validator.validate("report-render-result.schema.json", render_result)
    schema_validator.validate(
        "report-render-request.schema.json",
        {
            "schema_version": "1.0.0",
            "report_version_id": "rv-1",
            "format": "HTML",
            "requested_filename": "schema.html",
            "renderer_id": "apex.report.runtime",
            "derived_output_root_id": "apex-derived-default",
            "overwrite_policy": "DENY",
            "redaction_policy": "STANDARD",
            "include_citations": True,
            "include_custody": True,
            "include_technical_appendix": True,
        },
    )
    schema_validator.validate(
        "derived-output.schema.json",
        {
            "schema_version": "1.0.0",
            "derived_output_root_id": "apex-derived-default",
            "output_reference": render_result["output_reference"],
            "filename": render_result["filename"],
            "mime_type": render_result["mime_type"],
            "size_bytes": render_result["size_bytes"],
            "sha256": render_result["sha256"],
            "created_by": "schema-test",
            "created_at": to_json_timestamp(datetime(2026, 1, 1, tzinfo=UTC)),
        },
    )
