"""M2 Safe Raw Read binding guarded by server-side confirmation."""

from __future__ import annotations

import copy
from typing import Any

from apex_mcp.m1_tools import M1_TOOL_NAMES, VIEW_INPUT, m1_bindings
from apex_mcp.tool_registry import ToolBinding


def _raw_read_input_schema() -> dict[str, Any]:
    properties = VIEW_INPUT["properties"]
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "urn:apex-mcp:m2:raw-read-input",
        "type": "object",
        "additionalProperties": False,
        "required": ["case_id", "resource_type", "resource_id", "offset", "length"],
        "properties": {
            "case_id": copy.deepcopy(properties["case_id"]),
            "resource_type": copy.deepcopy(properties["resource_type"]),
            "resource_id": copy.deepcopy(properties["resource_id"]),
            "offset": {"type": "integer", "minimum": 0},
            "length": {"type": "integer", "minimum": 1, "maximum": 1024 * 1024},
        },
    }


RAW_READ_INPUT = _raw_read_input_schema()
M2_TOOL_NAMES = M1_TOOL_NAMES | {"apex.view.raw_read"}


def m2_bindings() -> tuple[ToolBinding, ...]:
    return (
        *m1_bindings(),
        ToolBinding(
            "apex.view.raw_read",
            "apex.view.raw_read",
            RAW_READ_INPUT,
            output_schema_ref="raw-read-response.schema.json",
            description=(
                "Read a bounded Core-validated byte range after exact server-side human approval."
            ),
        ),
    )


__all__ = ["M2_TOOL_NAMES", "RAW_READ_INPUT", "m2_bindings"]
