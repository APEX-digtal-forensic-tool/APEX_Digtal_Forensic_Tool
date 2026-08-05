"""Verify an OpenAI-compatible AI provider without printing API key values."""

from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime, timedelta
from typing import Any

from apex_forensic.adapters.ai import OpenAICompatibleConfig, OpenAICompatibleProvider
from apex_forensic.domain.models import AiAssistanceRequest


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify APEX OpenAI-compatible provider config.")
    parser.add_argument("--provider-id", default="openai-compatible")
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--model", required=True)
    parser.add_argument("--api-key-env", required=True)
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument(
        "--operation",
        default="capability",
        choices=["capability", "keywords", "summary", "report-draft"],
    )
    parser.add_argument("--require-available", action="store_true")
    args = parser.parse_args()
    provider = OpenAICompatibleProvider(
        OpenAICompatibleConfig(
            provider_id=args.provider_id,
            base_url=args.base_url,
            model=args.model,
            api_key_env=args.api_key_env,
            timeout=args.timeout,
        )
    )
    capability = provider.capabilities().to_schema_dict()
    result: dict[str, Any] = capability
    if args.operation != "capability":
        result = {"capability": capability}
    if args.operation == "keywords":
        result["keywords"] = provider.generate_keyword_recommendations(
            _synthetic_request("KEYWORD_RECOMMENDATION", ["RECOMMEND_KEYWORDS"])
        )
    elif args.operation == "summary":
        result["summary"] = provider.generate_scope_summary(
            _synthetic_request("SCOPE_SUMMARY", ["SUMMARIZE_SCOPE"])
        )
    elif args.operation == "report-draft":
        result["report_draft"] = provider.generate_report_draft(
            _synthetic_request("REPORT_INPUT", ["GENERATE_REPORT_DRAFT"])
        )
    print(json.dumps(result, ensure_ascii=False, indent=2))
    if args.require_available and not capability["is_available"]:
        return 1
    return 0


def _synthetic_request(purpose: str, operations: list[str]) -> AiAssistanceRequest:
    now = datetime.now(UTC)
    citation = {
        "case_id": "verification-case",
        "evidence_id": "verification-evidence",
        "source_kind": "SYNTHETIC_VERIFICATION",
        "source_id": "verification-source",
        "excerpt": "Synthetic verification excerpt.",
    }
    return AiAssistanceRequest(
        assistance_request_id="verification-request",
        case_id="verification-case",
        context_snapshot_id="verification-snapshot",
        purpose=purpose,
        requested_operations=operations,
        requested_scopes=["filesystem"],
        scope_context_ids=["verification-scope"],
        locale="ko-KR",
        timezone="Asia/Seoul",
        context_fingerprint="a" * 64,
        source_revision_fingerprint="b" * 64,
        is_partial=False,
        is_stale=False,
        coverage_summary={"verification-scope": {"result_count": 1}},
        warnings=[],
        citations=[citation],
        max_keyword_candidates=10,
        max_summary_length=4000,
        requested_at=now,
        expires_at=now + timedelta(hours=1),
        request_version="ai-assistance-request-v1",
        correlation_id="verification",
        request_fingerprint="c" * 64,
        resource_count=1,
    )


if __name__ == "__main__":
    raise SystemExit(main())
