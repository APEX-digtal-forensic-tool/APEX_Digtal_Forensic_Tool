"""M7 domain exposure boundary.

M7 deliberately adds no Tool: the current public Engine Interface has no
Case/Evidence/Search/Timeline/Annotation/Tag/KakaoTalk Tool Descriptor with a
matching transport operation.  Keeping this phase as an explicit binding layer
prevents service methods or legacy schemas from being mistaken for MCP contracts.
"""

from __future__ import annotations

from apex_mcp.m5_tools import M5_TOOL_NAMES, m5_bindings
from apex_mcp.tool_registry import ToolBinding

M7_NEW_DOMAIN_TOOL_NAMES: frozenset[str] = frozenset()
M7_TOOL_NAMES = M5_TOOL_NAMES | M7_NEW_DOMAIN_TOOL_NAMES


def m7_bindings() -> tuple[ToolBinding, ...]:
    """Return the reviewed M7 surface; no domain binding currently qualifies."""

    return m5_bindings()


__all__ = ["M7_NEW_DOMAIN_TOOL_NAMES", "M7_TOOL_NAMES", "m7_bindings"]
