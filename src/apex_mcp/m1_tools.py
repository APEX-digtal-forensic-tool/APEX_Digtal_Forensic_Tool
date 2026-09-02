"""Explicit M1 invocation schemas and Tool bindings."""

from __future__ import annotations

from typing import Any

from apex_mcp.tool_registry import ToolBinding

_DRAFT = "https://json-schema.org/draft/2020-12/schema"
_SCHEMA_ROOT = "https://schemas.apex-forensics.dev/v1/"
_SCOPES = [
    "case",
    "evidence",
    "filesystem",
    "registry",
    "eventlog",
    "prefetch",
    "browser",
    "media",
    "timeline",
    "keyword_search",
    "machine_candidate",
    "chain_of_custody",
    "report",
    "selection",
]
_RESOURCE_TYPES = [
    "EVIDENCE",
    "FILE_SYSTEM_NODE",
    "ARTIFACT",
    "REGISTRY",
    "EVENT_LOG",
    "PREFETCH",
    "BROWSER",
    "MEDIA",
    "TIMELINE_EVENT",
    "SEARCH_RESULT",
    "MACHINE_CANDIDATE",
    "CUSTODY_EVENT",
    "CONTEXT_SNAPSHOT",
    "OTHER",
]


def _object_schema(
    properties: dict[str, Any],
    required: list[str],
    *,
    schema_id: str,
) -> dict[str, Any]:
    return {
        "$schema": _DRAFT,
        "$id": f"urn:apex-mcp:m1:{schema_id}",
        "type": "object",
        "additionalProperties": False,
        "required": required,
        "properties": properties,
    }


_ID = {"type": "string", "minLength": 1, "maxLength": 256}

CONTEXT_GET_INPUT = _object_schema(
    {"session_context_id": _ID},
    ["session_context_id"],
    schema_id="context-get-input",
)
CONTEXT_SNAPSHOT_INPUT = _object_schema(
    {
        "session_context_id": _ID,
        "scopes": {
            "type": "array",
            "items": {"enum": _SCOPES},
            "maxItems": len(_SCOPES),
            "uniqueItems": True,
        },
        "previous_snapshot_id": _ID,
    },
    ["session_context_id"],
    schema_id="context-snapshot-input",
)
CONTEXT_SNAPSHOT_SHOW_INPUT = _object_schema(
    {"context_snapshot_id": _ID},
    ["context_snapshot_id"],
    schema_id="context-snapshot-show-input",
)
CONTEXT_SCOPE_PAGE_INPUT = _object_schema(
    {
        "context_snapshot_id": _ID,
        "scope": {"enum": _SCOPES},
        "cursor": {"type": "string", "minLength": 1, "maxLength": 4096},
        "limit": {"type": "integer", "minimum": 1, "maximum": 1000, "default": 100},
    },
    ["context_snapshot_id", "scope"],
    schema_id="context-scope-page-input",
)
VIEW_INPUT = _object_schema(
    {
        "case_id": _ID,
        "resource_type": {"enum": _RESOURCE_TYPES},
        "resource_id": _ID,
    },
    ["case_id", "resource_type", "resource_id"],
    schema_id="view-input",
)

SCOPE_PAGE_OUTPUT = _object_schema(
    {
        "context_snapshot_id": _ID,
        "scope_type": {"enum": _SCOPES},
        "items": {
            "type": "array",
            "maxItems": 1000,
            "items": {
                "type": "object",
                "required": ["resource_type", "resource_id"],
                "properties": {
                    "resource_type": {"enum": _RESOURCE_TYPES},
                    "resource_id": _ID,
                },
                "additionalProperties": True,
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
        "scope": {"$ref": f"{_SCHEMA_ROOT}analysis-scope-context.schema.json"},
    },
    ["context_snapshot_id", "scope_type", "items", "page", "scope"],
    schema_id="context-scope-page-output",
)

M1_TOOL_NAMES = frozenset(
    {
        "apex.context.get",
        "apex.context.snapshot",
        "apex.context.snapshot_show",
        "apex.context.scope_page",
        "apex.view.simple",
        "apex.view.detailed",
        "apex.view.raw",
    }
)


def m1_bindings() -> tuple[ToolBinding, ...]:
    view_descriptions = {
        "apex.view.simple": "Return a concise Core projection for one case resource.",
        "apex.view.detailed": "Return a detailed Core projection for one case resource.",
        "apex.view.raw": "Return structured raw fields and provenance; this does not read bytes.",
    }
    bindings = [
        ToolBinding(
            "apex.context.get",
            "apex.context.get",
            CONTEXT_GET_INPUT,
            output_schema_ref="gui-session-context.schema.json",
            description=(
                "Return one live GUI session context with TTL, revision, partial, and stale state."
            ),
        ),
        ToolBinding(
            "apex.context.snapshot",
            "apex.context.snapshot",
            CONTEXT_SNAPSHOT_INPUT,
            output_schema_ref="analysis-context-snapshot.schema.json",
            description="Create an immutable MCP_REQUEST snapshot from an existing GUI context.",
        ),
        ToolBinding(
            "apex.context.snapshot_show",
            "apex.context.snapshot_show",
            CONTEXT_SNAPSHOT_SHOW_INPUT,
            output_schema_ref="analysis-context-snapshot.schema.json",
            description="Return one immutable context snapshot without reconstructing selections.",
        ),
        ToolBinding(
            "apex.context.scope_page",
            "apex.context.scope_page",
            CONTEXT_SCOPE_PAGE_INPUT,
            output_data_schema=SCOPE_PAGE_OUTPUT,
            description="Page one snapshot scope using its opaque cursor and bounded item limit.",
        ),
    ]
    bindings.extend(
        ToolBinding(
            tool_name,
            tool_name,
            VIEW_INPUT,
            output_schema_ref="view-projection.schema.json",
            description=description,
        )
        for tool_name, description in view_descriptions.items()
    )
    return tuple(bindings)


__all__ = [
    "CONTEXT_GET_INPUT",
    "CONTEXT_SCOPE_PAGE_INPUT",
    "CONTEXT_SNAPSHOT_INPUT",
    "CONTEXT_SNAPSHOT_SHOW_INPUT",
    "M1_TOOL_NAMES",
    "SCOPE_PAGE_OUTPUT",
    "VIEW_INPUT",
    "m1_bindings",
]
