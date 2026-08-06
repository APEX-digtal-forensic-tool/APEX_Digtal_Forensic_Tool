"""Verify an OpenAI-compatible AI provider without printing API key values."""

from __future__ import annotations

# ruff: noqa: E402, I001

import argparse
import json
import tempfile
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from verification_common import ensure_source_tree_importable

ensure_source_tree_importable(__file__)

from apex_forensic.adapters.ai import OpenAICompatibleConfig, OpenAICompatibleProvider
from apex_forensic.adapters.ai.openai_compatible import PROMPT_TEMPLATE_VERSION
from apex_forensic.config import build_services
from apex_forensic.constants import SCHEMA_VERSION
from apex_forensic.domain.errors import ApexError
from apex_forensic.domain.models import AiAssistanceRequest
from apex_forensic.domain.services.canonical import canonical_sha256


_EXECUTION_STATUSES = {
    "COMPLETED",
    "KEY_UNAVAILABLE",
    "CAPABILITY_UNAVAILABLE",
    "AUTHENTICATION_FAILED",
    "RATE_LIMITED",
    "AI_PROVIDER_TIMEOUT",
    "AI_PROVIDER_INVALID_RESPONSE",
    "AI_PROVIDER_FAILED",
    "CANCELLED",
}


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
    result: dict[str, Any] = {
        "capability": capability,
        "verification_status": _verification_status(capability),
        "repository_reopen": _repository_reopen_check(provider),
        "secret_values_emitted": False,
    }
    if args.operation == "capability":
        print(json.dumps(result, ensure_ascii=False, indent=2))
        if args.require_available and not capability["is_available"]:
            return 1
        return 0
    if not capability["is_available"]:
        request = _synthetic_request(
            _purpose_for_operation(args.operation),
            _operations(args.operation),
        )
        unavailable_status = str(capability.get("unavailable_reason") or "CAPABILITY_UNAVAILABLE")
        result["execution"] = _execution_record(
            provider,
            request,
            operation=_operation_name(args.operation),
            status=unavailable_status,
            result_payload=None,
            latency_ms=None,
            warnings=[{"code": _verification_status(capability), "status": unavailable_status}],
        )
        print(json.dumps(result, ensure_ascii=False, indent=2))
        if args.require_available:
            return 1
        return 0
    request = _synthetic_request(
        _purpose_for_operation(args.operation),
        _operations(args.operation),
    )
    operation = _operation_name(args.operation)
    started = time.monotonic()
    try:
        if args.operation == "keywords":
            payload = provider.generate_keyword_recommendations(request)
            result["keywords"] = payload
        elif args.operation == "summary":
            payload = provider.generate_scope_summary(request)
            result["summary"] = payload
        else:
            payload = provider.generate_report_draft(request)
            result["report_draft"] = payload
        result["execution"] = _execution_record(
            provider,
            request,
            operation=operation,
            status="COMPLETED",
            result_payload=payload,
            latency_ms=int((time.monotonic() - started) * 1000),
            warnings=_warnings_from_payload(payload),
        )
    except ApexError as error:
        result["execution"] = _execution_record(
            provider,
            request,
            operation=operation,
            status=_execution_status_from_error(error),
            result_payload=None,
            latency_ms=int((time.monotonic() - started) * 1000),
            warnings=[{"code": _execution_status_from_error(error)}],
        )
        result["error"] = error.to_api_error()
    print(json.dumps(result, ensure_ascii=False, indent=2))
    if args.require_available and not capability["is_available"]:
        return 1
    return 0


def _verification_status(capability: dict[str, Any]) -> str:
    if capability.get("is_available") is True:
        return "NETWORK_PROVIDER_CONFIGURED"
    if capability.get("unavailable_reason") == "KEY_UNAVAILABLE":
        return "EXTERNAL_PROVIDER_NOT_CONFIGURED"
    return str(capability.get("unavailable_reason") or "CAPABILITY_UNAVAILABLE")


def _purpose_for_operation(operation: str) -> str:
    if operation == "keywords":
        return "KEYWORD_RECOMMENDATION"
    if operation == "summary":
        return "SCOPE_SUMMARY"
    return "REPORT_INPUT"


def _operations(operation: str) -> list[str]:
    return [_operation_name(operation)]


def _operation_name(operation: str) -> str:
    if operation == "keywords":
        return "RECOMMEND_KEYWORDS"
    if operation == "summary":
        return "SUMMARIZE_SCOPE"
    return "GENERATE_REPORT_DRAFT"


def _execution_record(
    provider: OpenAICompatibleProvider,
    request: AiAssistanceRequest,
    *,
    operation: str,
    status: str,
    result_payload: dict[str, Any] | None,
    latency_ms: int | None,
    warnings: list[dict[str, Any]],
) -> dict[str, Any]:
    normalized_status = status if status in _EXECUTION_STATUSES else "AI_PROVIDER_FAILED"
    return {
        "schema_version": SCHEMA_VERSION,
        "provider_id": provider.provider_id,
        "provider_version": provider.provider_version,
        "model_id": provider.model_id,
        "operation": operation,
        "status": normalized_status,
        "prompt_template_version": PROMPT_TEMPLATE_VERSION,
        "request_fingerprint": request.request_fingerprint,
        "result_fingerprint": None
        if result_payload is None
        else canonical_sha256(_without_raw_provider_fields(result_payload)),
        "latency_ms": latency_ms,
        "token_usage": _token_usage_from_warnings(warnings),
        "warnings": warnings,
        "generated_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
    }


def _repository_reopen_check(provider: OpenAICompatibleProvider) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="apex-ai-provider-verify-") as temp_dir:
        db_path = Path(temp_dir) / "ai-provider.db"
        services = build_services(db_path)
        try:
            services.repository.save_ai_provider_capability(provider.capabilities())
        finally:
            services.close()
        reopened = build_services(db_path)
        try:
            row = reopened.repository.connection.execute(
                """
                SELECT provider_id, provider_version, unavailable_reason
                FROM ai_provider_capabilities
                WHERE provider_id = ?
                """,
                (provider.provider_id,),
            ).fetchone()
            return {
                "status": "VERIFIED" if row is not None else "MISSING",
                "provider_id": None if row is None else str(row["provider_id"]),
                "provider_version": None if row is None else str(row["provider_version"]),
                "unavailable_reason": None if row is None else row["unavailable_reason"],
                "api_key_value_stored": False,
                "secret_values_emitted": False,
            }
        finally:
            reopened.close()


def _execution_status_from_error(error: ApexError) -> str:
    if error.code == "OPERATION_CANCELLED":
        return "CANCELLED"
    return error.code if error.code in _EXECUTION_STATUSES else "AI_PROVIDER_FAILED"


def _warnings_from_payload(payload: dict[str, Any]) -> list[dict[str, Any]]:
    warnings = payload.get("warnings", [])
    if isinstance(warnings, list):
        return [item for item in warnings if isinstance(item, dict)]
    sections = payload.get("sections", [])
    if isinstance(sections, list):
        collected: list[dict[str, Any]] = []
        for section in sections:
            if isinstance(section, dict) and isinstance(section.get("warnings"), list):
                collected.extend(item for item in section["warnings"] if isinstance(item, dict))
        return collected
    return []


def _token_usage_from_warnings(warnings: list[dict[str, Any]]) -> dict[str, int | None]:
    for warning in warnings:
        token_usage = warning.get("token_usage")
        if isinstance(token_usage, dict):
            return {
                "prompt_tokens": _int_or_none(token_usage.get("prompt_tokens")),
                "completion_tokens": _int_or_none(token_usage.get("completion_tokens")),
                "total_tokens": _int_or_none(token_usage.get("total_tokens")),
            }
        usage_count = warning.get("usage_count")
        if isinstance(usage_count, int):
            return {
                "prompt_tokens": None,
                "completion_tokens": None,
                "total_tokens": usage_count,
            }
    return {"prompt_tokens": None, "completion_tokens": None, "total_tokens": None}


def _int_or_none(value: Any) -> int | None:
    return value if isinstance(value, int) else None


def _without_raw_provider_fields(payload: dict[str, Any]) -> dict[str, Any]:
    forbidden = {"raw_body", "raw_response", "chain_of_thought", "chain-of-thought"}
    return {key: value for key, value in payload.items() if key.casefold() not in forbidden}


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
