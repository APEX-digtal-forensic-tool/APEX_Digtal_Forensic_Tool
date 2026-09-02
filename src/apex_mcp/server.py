"""MCP 2.x server composition and stdio runner."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

import anyio
import mcp_types as types
from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.context import ServerRequestContext
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server

from apex_mcp.capability_gate import CapabilityGate
from apex_mcp.config import McpConfig
from apex_mcp.confirmation import ConfirmationGate, ConfirmationProvider
from apex_mcp.engine_adapter import EngineAdapter
from apex_mcp.error_mapper import ErrorMapper
from apex_mcp.frontend_security import FrontendSecurityProvider
from apex_mcp.interface_guard import InterfaceGuard
from apex_mcp.redaction import Redactor
from apex_mcp.schema_catalog import SchemaCatalog
from apex_mcp.telemetry import TelemetrySink
from apex_mcp.tool_registry import ToolBinding, ToolRegistry


@dataclass(slots=True)
class ApexMcpRuntime:
    server: Server[Any]
    registry: ToolRegistry
    adapter: EngineAdapter

    async def run_stdio_async(self) -> None:
        try:
            async with stdio_server() as (read_stream, write_stream):
                await self.server.run(
                    read_stream,
                    write_stream,
                    self.server.create_initialization_options(),
                )
        finally:
            self.close()

    def run_stdio(self) -> None:
        anyio.run(self.run_stdio_async)

    def close(self) -> None:
        self.adapter.close()


def create_runtime(
    config: McpConfig,
    *,
    bindings: Iterable[ToolBinding] = (),
    adapter: EngineAdapter | None = None,
    confirmation_provider: ConfirmationProvider | None = None,
    frontend_security_provider: FrontendSecurityProvider | None = None,
    telemetry: TelemetrySink | None = None,
) -> ApexMcpRuntime:
    validated = config.validate()
    engine = adapter or EngineAdapter.from_config(validated)
    try:
        catalog = SchemaCatalog(validated.schema_dir)
        interface, _ = InterfaceGuard(catalog).validate(engine)
        redactor = Redactor()
        registry = ToolRegistry(
            adapter=engine,
            catalog=catalog,
            capability_gate=CapabilityGate(interface),
            confirmation_gate=ConfirmationGate(
                confirmation_provider or frontend_security_provider
            ),
            allowed_tools=validated.allowed_tools,
            error_mapper=ErrorMapper(redactor),
            redactor=redactor,
            telemetry=telemetry,
            frontend_security=frontend_security_provider,
        )
        for binding in bindings:
            registry.register(binding)

        async def list_tools(
            context: ServerRequestContext[Any],
            params: types.PaginatedRequestParams | None,
        ) -> types.ListToolsResult:
            return types.ListToolsResult(tools=registry.list_tools())

        async def call_tool(
            context: ServerRequestContext[Any],
            params: types.CallToolRequestParams,
        ) -> types.CallToolResult:
            return registry.call_tool(
                params.name,
                params.arguments or {},
                # Stdio remains one process/connection; HTTP overrides this from its session.
                budget_scope="mcp-stdio-connection",
                trusted_actor_id="UNAUTHENTICATED",
                trusted_session_id="stdio",
                access_token=get_access_token(),
            )

        server = Server(
            "apex-mcp",
            version="0.1.0",
            title="APEX Digital Forensic MCP",
            description="Descriptor-driven transport for the APEX forensic engine.",
            instructions=(
                "Use only registered tools. Capability, partial, stale, citation, and "
                "human-confirmation boundaries are authoritative. Domain services without "
                "an explicit Engine Tool Descriptor and transport binding are unavailable."
            ),
            on_list_tools=list_tools,
            on_call_tool=call_tool,
        )
        return ApexMcpRuntime(server=server, registry=registry, adapter=engine)
    except Exception:
        engine.close()
        raise


__all__ = ["ApexMcpRuntime", "create_runtime"]
