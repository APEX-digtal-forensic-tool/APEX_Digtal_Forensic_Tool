"""M3 snapshot-first AI assistance bindings."""

from __future__ import annotations

from typing import Any

from apex_mcp.m1_tools import _ID, _SCOPES, _object_schema
from apex_mcp.m2_tools import M2_TOOL_NAMES, m2_bindings
from apex_mcp.tool_registry import ToolBinding

_SCHEMA_ROOT = "https://schemas.apex-forensics.dev/v1/"
_AI_OPERATIONS = ["RECOMMEND_KEYWORDS", "SUMMARIZE_SCOPE"]

AI_CAPABILITIES_INPUT = _object_schema({}, [], schema_id="ai-capabilities-input")
AI_REQUEST_CREATE_INPUT = _object_schema(
    {
        "case_id": _ID,
        "context_snapshot_id": _ID,
        "purpose": {
            "enum": [
                "KEYWORD_RECOMMENDATION",
                "SCOPE_SUMMARY",
                "INVESTIGATION_ASSISTANCE",
            ]
        },
        "requested_operations": {
            "type": "array",
            "minItems": 1,
            "maxItems": len(_AI_OPERATIONS),
            "uniqueItems": True,
            "items": {"enum": _AI_OPERATIONS},
        },
        "requested_scopes": {
            "type": "array",
            "minItems": 1,
            "maxItems": len(_SCOPES),
            "uniqueItems": True,
            "items": {"enum": _SCOPES},
        },
        "scope_context_ids": {
            "type": "array",
            "minItems": 1,
            "maxItems": 32,
            "uniqueItems": True,
            "items": _ID,
        },
        "locale": {"type": "string", "minLength": 1, "maxLength": 35},
        "timezone": {"type": "string", "minLength": 1, "maxLength": 128},
        "max_keyword_candidates": {
            "type": "integer",
            "minimum": 1,
            "maximum": 1000,
            "default": 100,
        },
        "max_summary_length": {
            "type": "integer",
            "minimum": 1,
            "maximum": 20000,
            "default": 4000,
        },
    },
    ["case_id", "context_snapshot_id", "requested_operations", "requested_scopes"],
    schema_id="ai-request-create-input",
)
AI_REQUEST_GET_INPUT = _object_schema(
    {"assistance_request_id": _ID},
    ["assistance_request_id"],
    schema_id="ai-request-get-input",
)
AI_REQUEST_LIST_INPUT = _object_schema(
    {
        "case_id": _ID,
        "limit": {"type": "integer", "minimum": 1, "maximum": 1000, "default": 100},
    },
    ["case_id"],
    schema_id="ai-request-list-input",
)
AI_REQUEST_EXECUTE_INPUT = _object_schema(
    {
        "assistance_request_id": _ID,
        "operation": {"enum": _AI_OPERATIONS},
    },
    ["assistance_request_id", "operation"],
    schema_id="ai-request-execute-input",
)
AI_KEYWORD_BATCH_GET_INPUT = _object_schema(
    {"recommendation_batch_id": _ID},
    ["recommendation_batch_id"],
    schema_id="ai-keyword-batch-get-input",
)
AI_KEYWORD_RECOMMENDATION_GET_INPUT = _object_schema(
    {"recommendation_id": _ID},
    ["recommendation_id"],
    schema_id="ai-keyword-recommendation-get-input",
)
AI_KEYWORD_RECOMMENDATION_LIST_INPUT = _object_schema(
    {
        "case_id": _ID,
        "recommendation_batch_id": _ID,
        "cursor": {"type": "string", "minLength": 1, "maxLength": 4096},
        "limit": {"type": "integer", "minimum": 1, "maximum": 1000, "default": 100},
    },
    ["case_id"],
    schema_id="ai-keyword-recommendation-list-input",
)
AI_SCOPE_SUMMARY_GET_INPUT = _object_schema(
    {"scope_summary_id": _ID},
    ["scope_summary_id"],
    schema_id="ai-scope-summary-get-input",
)
AI_SCOPE_SUMMARY_LIST_INPUT = _object_schema(
    {
        "case_id": _ID,
        "context_snapshot_id": _ID,
        "scope_context_id": _ID,
        "limit": {"type": "integer", "minimum": 1, "maximum": 1000, "default": 100},
    },
    ["case_id"],
    schema_id="ai-scope-summary-list-input",
)

AI_KEYWORD_BATCH_OUTPUT: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "urn:apex-mcp:m3:ai-keyword-batch-output",
    "type": "object",
    "additionalProperties": False,
    "required": ["batch", "recommendations"],
    "properties": {
        "batch": {
            "$ref": f"{_SCHEMA_ROOT}ai-keyword-recommendation-batch.schema.json"
        },
        "recommendations": {
            "type": "array",
            "maxItems": 1000,
            "items": {
                "$ref": f"{_SCHEMA_ROOT}ai-keyword-recommendation.schema.json"
            },
        },
    },
}
AI_KEYWORD_RECOMMENDATION_LIST_OUTPUT: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "urn:apex-mcp:m3:ai-keyword-recommendation-list-output",
    "type": "object",
    "additionalProperties": False,
    "required": ["items", "page"],
    "properties": {
        "items": {
            "type": "array",
            "maxItems": 1000,
            "items": {
                "$ref": f"{_SCHEMA_ROOT}ai-keyword-recommendation.schema.json"
            },
        },
        "page": {
            "type": "object",
            "additionalProperties": False,
            "required": ["next_cursor", "has_more", "returned"],
            "properties": {
                "next_cursor": {"type": ["string", "null"], "minLength": 1},
                "has_more": {"type": "boolean"},
                "returned": {"type": "integer", "minimum": 0, "maximum": 1000},
            },
        },
    },
}
AI_REQUEST_LIST_OUTPUT: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "urn:apex-mcp:m3:ai-request-list-output",
    "type": "array",
    "maxItems": 1000,
    "items": {"$ref": f"{_SCHEMA_ROOT}ai-assistance-request.schema.json"},
}
AI_SCOPE_SUMMARY_LIST_OUTPUT: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "urn:apex-mcp:m3:ai-scope-summary-list-output",
    "type": "array",
    "maxItems": 1000,
    "items": {"$ref": f"{_SCHEMA_ROOT}ai-scope-summary.schema.json"},
}

M3_AI_TOOL_NAMES = frozenset(
    {
        "ai.capabilities",
        "ai.request.create",
        "ai.request.get",
        "ai.request.list",
        "ai.request.execute",
        "ai.keyword-batch.get",
        "ai.keyword-recommendation.get",
        "ai.keyword-recommendation.list",
        "ai.scope-summary.get",
        "ai.scope-summary.list",
    }
)
M3_TOOL_NAMES = M2_TOOL_NAMES | M3_AI_TOOL_NAMES


def m3_bindings() -> tuple[ToolBinding, ...]:
    return (
        *m2_bindings(),
        ToolBinding(
            "ai.capabilities",
            "ai.capabilities",
            AI_CAPABILITIES_INPUT,
            output_schema_ref="ai-capabilities.schema.json",
            description="Report the configured AI provider's availability and bounded operations.",
        ),
        ToolBinding(
            "ai.request.create",
            "ai.request.create",
            AI_REQUEST_CREATE_INPUT,
            output_schema_ref="ai-assistance-request.schema.json",
            description="Create an immutable AI request from an existing context snapshot.",
            idempotent=True,
        ),
        ToolBinding(
            "ai.request.get",
            "ai.request.get",
            AI_REQUEST_GET_INPUT,
            output_schema_ref="ai-assistance-request.schema.json",
            description="Return one immutable AI assistance request.",
        ),
        ToolBinding(
            "ai.request.list",
            "ai.request.list",
            AI_REQUEST_LIST_INPUT,
            output_data_schema=AI_REQUEST_LIST_OUTPUT,
            description="List bounded AI assistance requests for one case.",
        ),
        ToolBinding(
            "ai.request.execute",
            "ai.request.execute",
            AI_REQUEST_EXECUTE_INPUT,
            output_schema_ref="ai-provider-execute-result.schema.json",
            description=(
                "Execute one request-authorized provider operation after source revision checks, "
                "then validate and ingest the result."
            ),
            idempotent=True,
        ),
        ToolBinding(
            "ai.keyword-batch.get",
            "ai.keyword-batch.get",
            AI_KEYWORD_BATCH_GET_INPUT,
            output_data_schema=AI_KEYWORD_BATCH_OUTPUT,
            description="Return an ingested keyword batch and current recommendation review state.",
        ),
        ToolBinding(
            "ai.keyword-recommendation.get",
            "ai.keyword-recommendation.get",
            AI_KEYWORD_RECOMMENDATION_GET_INPUT,
            output_schema_ref="ai-keyword-recommendation.schema.json",
            description="Return one AI recommendation with review and citation state.",
        ),
        ToolBinding(
            "ai.keyword-recommendation.list",
            "ai.keyword-recommendation.list",
            AI_KEYWORD_RECOMMENDATION_LIST_INPUT,
            output_data_schema=AI_KEYWORD_RECOMMENDATION_LIST_OUTPUT,
            description="Page AI recommendations using an opaque Core cursor.",
        ),
        ToolBinding(
            "ai.scope-summary.get",
            "ai.scope-summary.get",
            AI_SCOPE_SUMMARY_GET_INPUT,
            output_schema_ref="ai-scope-summary.schema.json",
            description="Return one AI scope summary marked as not observed fact.",
        ),
        ToolBinding(
            "ai.scope-summary.list",
            "ai.scope-summary.list",
            AI_SCOPE_SUMMARY_LIST_INPUT,
            output_data_schema=AI_SCOPE_SUMMARY_LIST_OUTPUT,
            description="List bounded AI scope summaries for one case or snapshot scope.",
        ),
    )


__all__ = [
    "AI_REQUEST_CREATE_INPUT",
    "AI_REQUEST_EXECUTE_INPUT",
    "M3_AI_TOOL_NAMES",
    "M3_TOOL_NAMES",
    "m3_bindings",
]
