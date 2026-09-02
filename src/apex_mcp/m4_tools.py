"""M4 human verification and accepted-keyword promotion bindings."""

from __future__ import annotations

from typing import Any

from apex_mcp.m1_tools import _ID, _object_schema
from apex_mcp.m3_tools import M3_TOOL_NAMES, m3_bindings
from apex_mcp.tool_registry import ToolBinding

_SCHEMA_ROOT = "https://schemas.apex-forensics.dev/v1/"
_ACTIONS = ["ACCEPT", "REJECT", "CORRECT", "COMMENT"]
_TARGET_TYPES = ["KEYWORD_RECOMMENDATION", "SCOPE_SUMMARY"]


def _review_input_schema(*, target_field: str, max_corrected_length: int) -> dict[str, Any]:
    schema = _object_schema(
        {
            "case_id": _ID,
            target_field: _ID,
            "action": {"enum": _ACTIONS},
            "reason": {"type": "string", "minLength": 1, "maxLength": 4000},
            "expected_review_revision": {"type": "integer", "minimum": 0},
            "corrected_value": {
                "type": "string",
                "minLength": 1,
                "maxLength": max_corrected_length,
            },
            "corrected_reason": {
                "type": "string",
                "minLength": 1,
                "maxLength": 4000,
            },
        },
        ["case_id", target_field, "action", "reason", "expected_review_revision"],
        schema_id=f"{target_field}-review-input",
    )
    schema["allOf"] = [
        {
            "if": {
                "required": ["action"],
                "properties": {"action": {"const": "CORRECT"}},
            },
            "then": {"required": ["corrected_value"]},
            "else": {
                "properties": {
                    "corrected_value": {"not": {}},
                    "corrected_reason": {"not": {}},
                }
            },
        }
    ]
    return schema


AI_KEYWORD_REVIEW_INPUT = _review_input_schema(
    target_field="recommendation_id",
    max_corrected_length=4096,
)
AI_SCOPE_SUMMARY_REVIEW_INPUT = _review_input_schema(
    target_field="scope_summary_id",
    max_corrected_length=20_000,
)
AI_VERIFICATION_HISTORY_INPUT = _object_schema(
    {
        "case_id": _ID,
        "target_type": {"enum": _TARGET_TYPES},
        "target_id": _ID,
    },
    ["case_id", "target_type", "target_id"],
    schema_id="ai-verification-history-input",
)
AI_PROMOTION_PREVIEW_INPUT = _object_schema(
    {
        "case_id": _ID,
        "recommendation_id": _ID,
        "keyword_set_id": _ID,
        "regex_confirmed": {"type": "boolean", "default": False},
    },
    ["case_id", "recommendation_id", "keyword_set_id"],
    schema_id="ai-promotion-preview-input",
)
AI_KEYWORD_PROMOTE_INPUT = _object_schema(
    {
        "case_id": _ID,
        "recommendation_id": _ID,
        "keyword_set_id": _ID,
        "reason": {"type": "string", "minLength": 1, "maxLength": 4000},
        "expected_review_revision": {"type": "integer", "minimum": 1},
        "regex_confirmed": {"type": "boolean", "default": False},
    },
    [
        "case_id",
        "recommendation_id",
        "keyword_set_id",
        "reason",
        "expected_review_revision",
    ],
    schema_id="ai-keyword-promote-input",
)

AI_VERIFICATION_HISTORY_OUTPUT: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "urn:apex-mcp:m4:ai-verification-history-output",
    "type": "array",
    "maxItems": 1000,
    "items": {"$ref": f"{_SCHEMA_ROOT}ai-verification-event.schema.json"},
}
AI_PROMOTION_PREVIEW_OUTPUT: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "urn:apex-mcp:m4:ai-promotion-preview-output",
    "type": "object",
    "additionalProperties": False,
    "required": [
        "recommendation_id",
        "keyword_set_id",
        "case_id",
        "review_status",
        "review_revision",
        "effective_value",
        "keyword_type",
        "match_mode",
        "duplicate",
        "duplicate_keyword_id",
        "regex_requires_confirmation",
        "promotable",
        "will_run_search",
        "will_activate_keyword_set",
    ],
    "properties": {
        "recommendation_id": _ID,
        "keyword_set_id": _ID,
        "case_id": _ID,
        "review_status": {"enum": ["UNREVIEWED", "ACCEPTED", "REJECTED", "CORRECTED"]},
        "review_revision": {"type": "integer", "minimum": 0},
        "effective_value": {"type": "string", "minLength": 1, "maxLength": 4096},
        "keyword_type": {"type": "string", "minLength": 1},
        "match_mode": {"enum": ["TERM", "PHRASE", "PREFIX", "EXACT", "REGEX_METADATA"]},
        "duplicate": {"type": "boolean"},
        "duplicate_keyword_id": {"type": ["string", "null"], "minLength": 1},
        "regex_requires_confirmation": {"type": "boolean"},
        "promotable": {"type": "boolean"},
        "will_run_search": {"const": False},
        "will_activate_keyword_set": {"const": False},
    },
}

M4_REVIEW_TOOL_NAMES = frozenset(
    {
        "ai.keyword-recommendation.review",
        "ai.scope-summary.review",
        "ai.verification.history",
        "ai.promotion.preview",
        "ai.keyword-recommendation.promote",
    }
)
M4_TOOL_NAMES = M3_TOOL_NAMES | M4_REVIEW_TOOL_NAMES


def m4_bindings() -> tuple[ToolBinding, ...]:
    return (
        *m3_bindings(),
        ToolBinding(
            "ai.keyword-recommendation.review",
            "ai.keyword-recommendation.review",
            AI_KEYWORD_REVIEW_INPUT,
            output_schema_ref="ai-verification-event.schema.json",
            description=(
                "Append a human verification event using the server-authenticated actor."
            ),
        ),
        ToolBinding(
            "ai.scope-summary.review",
            "ai.scope-summary.review",
            AI_SCOPE_SUMMARY_REVIEW_INPUT,
            output_schema_ref="ai-verification-event.schema.json",
            description=(
                "Append a human scope-summary verification event using the trusted actor."
            ),
        ),
        ToolBinding(
            "ai.verification.history",
            "ai.verification.history",
            AI_VERIFICATION_HISTORY_INPUT,
            output_data_schema=AI_VERIFICATION_HISTORY_OUTPUT,
            description="Return append-only human verification history for one case target.",
        ),
        ToolBinding(
            "ai.promotion.preview",
            "ai.promotion.preview",
            AI_PROMOTION_PREVIEW_INPUT,
            output_data_schema=AI_PROMOTION_PREVIEW_OUTPUT,
            description=(
                "Preview accepted-keyword promotion without running search or activating a set."
            ),
            idempotent=True,
        ),
        ToolBinding(
            "ai.keyword-recommendation.promote",
            "ai.keyword-recommendation.promote",
            AI_KEYWORD_PROMOTE_INPUT,
            output_schema_ref="ai-keyword-promotion.schema.json",
            description=(
                "Promote one human-accepted recommendation into a draft keyword set without "
                "running search."
            ),
            destructive=True,
            idempotent=True,
        ),
    )


__all__ = [
    "AI_KEYWORD_PROMOTE_INPUT",
    "AI_KEYWORD_REVIEW_INPUT",
    "AI_SCOPE_SUMMARY_REVIEW_INPUT",
    "M4_REVIEW_TOOL_NAMES",
    "M4_TOOL_NAMES",
    "m4_bindings",
]
