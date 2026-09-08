"""Startup compatibility checks for the public Core interface."""

from __future__ import annotations

from typing import Any

from apex_mcp.engine_adapter import EngineAdapter
from apex_mcp.errors import DescriptorValidationError, InterfaceCompatibilityError
from apex_mcp.schema_catalog import SchemaCatalog


class InterfaceGuard:
    EXPECTED_NAME = "apex.engine.public"
    EXPECTED_INTERFACE_VERSION = "1.0.0"
    EXPECTED_SCHEMA_VERSION = "1.0.0"
    REQUIRED_CAPABILITIES = frozenset({"MCP_ADAPTER_DESCRIPTOR"})

    def __init__(self, catalog: SchemaCatalog) -> None:
        self._catalog = catalog

    def validate(self, adapter: EngineAdapter) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        interface = adapter.get_interface()
        self._catalog.validate("engine-interface.schema.json", interface)
        mismatches: dict[str, Any] = {}
        if interface.get("interface_name") != self.EXPECTED_NAME:
            mismatches["interface_name"] = interface.get("interface_name")
        if interface.get("interface_version") != self.EXPECTED_INTERFACE_VERSION:
            mismatches["interface_version"] = interface.get("interface_version")
        if interface.get("schema_version") != self.EXPECTED_SCHEMA_VERSION:
            mismatches["schema_version"] = interface.get("schema_version")
        missing = sorted(self.REQUIRED_CAPABILITIES - set(interface.get("capabilities", [])))
        if missing:
            mismatches["missing_capabilities"] = missing
        if mismatches:
            raise InterfaceCompatibilityError(
                "The Core public interface is not compatible with this MCP adapter.",
                details=mismatches,
            )

        descriptors = adapter.list_tool_descriptors()
        seen: set[str] = set()
        for descriptor in descriptors:
            self._catalog.validate("engine-tool-descriptor.schema.json", descriptor)
            tool_name = str(descriptor["tool_name"])
            if tool_name in seen:
                raise DescriptorValidationError(
                    "Duplicate Engine Tool Descriptor.",
                    target=tool_name,
                )
            seen.add(tool_name)
            if descriptor["tool_version"] != interface["interface_version"]:
                raise DescriptorValidationError(
                    "Tool and interface versions do not match.",
                    target=tool_name,
                )
            self._catalog.schema(str(descriptor["input_schema_ref"]))
            self._catalog.schema(str(descriptor["output_schema_ref"]))
        return interface, descriptors


__all__ = ["InterfaceGuard"]
