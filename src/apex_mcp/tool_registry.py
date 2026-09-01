"""Descriptor-driven, allowlisted MCP Tool registry."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Any
from uuid import uuid4

import mcp_types as types
from mcp.server.auth.provider import AccessToken

from apex_mcp.budget import ToolBudget
from apex_mcp.capability_gate import CapabilityGate
from apex_mcp.confirmation import ConfirmationGate, ConfirmationRequest
from apex_mcp.context_bridge import ContextBridge, is_authenticated_actor
from apex_mcp.engine_adapter import EngineAdapter
from apex_mcp.error_mapper import ErrorMapper
from apex_mcp.errors import (
    AuthenticatedActorRequiredError,
    McpAuthorizationDeniedError,
    ToolInputValidationError,
    ToolNotFoundError,
    ToolOutputValidationError,
    ToolRegistrationError,
)
from apex_mcp.frontend_security import (
    FrontendAuthorizationGate,
    FrontendSecurityProvider,
)
from apex_mcp.redaction import Redactor
from apex_mcp.schema_catalog import SchemaCatalog
from apex_mcp.telemetry import (
    NoopTelemetrySink,
    TelemetrySink,
    ToolTelemetryEvent,
    request_fingerprint,
)


@dataclass(frozen=True, slots=True)
class ToolBinding:
    """Explicit transport schema and Core operation for one Descriptor."""

    tool_name: str
    operation: str
    input_schema: dict[str, Any]
    output_schema_ref: str | None = None
    output_data_schema: dict[str, Any] | None = None
    description: str | None = None
    destructive: bool = False
    idempotent: bool = False


@dataclass(frozen=True, slots=True)
class RegisteredTool:
    descriptor: dict[str, Any]
    binding: ToolBinding


class ToolRegistry:
    """Registers only tools approved by Descriptor, binding, allowlist, and capability."""

    def __init__(
        self,
        *,
        adapter: EngineAdapter,
        catalog: SchemaCatalog,
        capability_gate: CapabilityGate,
        confirmation_gate: ConfirmationGate,
        allowed_tools: frozenset[str],
        error_mapper: ErrorMapper | None = None,
        redactor: Redactor | None = None,
        telemetry: TelemetrySink | None = None,
        context_bridge: ContextBridge | None = None,
        budget: ToolBudget | None = None,
        frontend_security: FrontendSecurityProvider | None = None,
        authorization_gate: FrontendAuthorizationGate | None = None,
    ) -> None:
        self._adapter = adapter
        self._catalog = catalog
        self._capability_gate = capability_gate
        self._confirmation_gate = confirmation_gate
        self._allowed_tools = allowed_tools
        self._error_mapper = error_mapper or ErrorMapper()
        self._redactor = redactor or Redactor()
        self._telemetry = telemetry or NoopTelemetrySink()
        self._context_bridge = context_bridge or ContextBridge()
        self._budget = budget or ToolBudget()
        self._frontend_security = frontend_security
        self._authorization_gate = authorization_gate or FrontendAuthorizationGate()
        self._descriptors = {
            str(item["tool_name"]): item for item in adapter.list_tool_descriptors()
        }
        self._registered: dict[str, RegisteredTool] = {}

    def register(self, binding: ToolBinding) -> None:
        if binding.tool_name not in self._allowed_tools:
            raise ToolRegistrationError(
                "The Tool is outside the active phase allowlist.",
                target=binding.tool_name,
            )
        descriptor = self._descriptors.get(binding.tool_name)
        if descriptor is None:
            raise ToolRegistrationError(
                "No Engine Tool Descriptor exists for the Tool.",
                target=binding.tool_name,
            )
        if binding.tool_name in self._registered:
            raise ToolRegistrationError("Duplicate Tool binding.", target=binding.tool_name)
        if binding.operation != binding.tool_name:
            raise ToolRegistrationError(
                "M0 bindings must invoke the canonical Descriptor Tool name.",
                target=binding.tool_name,
            )
        if binding.input_schema.get("type") != "object":
            raise ToolRegistrationError(
                "MCP input schemas must have an object root.",
                target=binding.tool_name,
            )
        self._catalog.check_inline(binding.input_schema)
        if binding.output_schema_ref is not None and binding.output_data_schema is not None:
            raise ToolRegistrationError(
                "A Tool binding cannot declare two invocation output schemas.",
                target=binding.tool_name,
            )
        if binding.output_schema_ref is not None:
            self._catalog.schema(binding.output_schema_ref)
        if binding.output_data_schema is not None:
            self._catalog.check_inline(binding.output_data_schema)
        self._capability_gate.require(descriptor)
        self._registered[binding.tool_name] = RegisteredTool(descriptor, binding)

    def list_tools(self) -> list[types.Tool]:
        return [self._to_mcp_tool(item) for _, item in sorted(self._registered.items())]

    def call_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        *,
        confirmation: ConfirmationRequest | None = None,
        budget_scope: str = "direct",
        trusted_actor_id: str | None = None,
        trusted_session_id: str | None = None,
        access_token: AccessToken | None = None,
    ) -> types.CallToolResult:
        request_id = str(uuid4())
        correlation_id = str(uuid4())
        fingerprint = request_fingerprint(arguments)
        started = time.monotonic()
        error_code: str | None = None
        confirmation_actor_id: str | None = None
        confirmation_session_id: str | None = None
        confirmation_decision: str | None = None
        try:
            registered = self._registered.get(tool_name)
            if registered is None:
                raise ToolNotFoundError(tool_name)
            self._catalog.validate_inline(registered.binding.input_schema, arguments)
            self._capability_gate.require(registered.descriptor)
            target_ids = self._target_ids(arguments)
            if access_token is not None:
                if self._frontend_security is None:
                    raise McpAuthorizationDeniedError(tool_name)
                session = self._frontend_security.resolve_session(access_token)
                self._authorization_gate.require(
                    session,
                    access_token,
                    registered.descriptor,
                    tool_name=tool_name,
                    target_case_ids=self._adapter.target_case_ids(tool_name, arguments),
                )
                self._adapter.require_frontend_context(
                    tool_name,
                    arguments,
                    actor_id=session.actor_id,
                    session_id=session.session_id,
                )
                trusted_actor_id = session.actor_id
                trusted_session_id = session.session_id
                budget_scope = session.budget_scope
                if bool(registered.descriptor["requires_confirmation"]):
                    confirmation = self._frontend_security.confirmation_for(
                        session,
                        case_id=str(arguments.get("case_id", "")),
                        tool_name=tool_name,
                        request_fingerprint=fingerprint,
                        target_ids=target_ids,
                    )
            self._budget.begin_call(budget_scope, tool_name, arguments)
            if bool(registered.descriptor["requires_confirmation"]):
                confirmation_actor_id = trusted_actor_id
                confirmation_session_id = trusted_session_id
                if (
                    confirmation is not None
                    and trusted_actor_id is not None
                    and not is_authenticated_actor(trusted_actor_id)
                ):
                    confirmation_decision = "DENIED"
                    raise AuthenticatedActorRequiredError(tool_name)
                try:
                    confirmation_granted = self._confirmation_gate.require(
                        registered.descriptor,
                        confirmation,
                        expected_actor_id=trusted_actor_id or "",
                        expected_session_id=trusted_session_id or "",
                        expected_fingerprint=fingerprint,
                        expected_case_id=str(arguments.get("case_id", "")),
                        expected_target_ids=target_ids,
                    )
                except Exception:
                    confirmation_decision = "DENIED"
                    raise
                confirmation_decision = "APPROVED"
            else:
                confirmation_granted = False
            invocation_payload = self._context_bridge.prepare(
                tool_name,
                arguments,
                trusted_actor_id=trusted_actor_id,
                trusted_session_id=trusted_session_id,
                confirmation_grant_id=(
                    confirmation.grant_id if confirmation_granted and confirmation else None
                ),
                confirmation_fingerprint=(fingerprint if confirmation_granted else None),
            )
            result = self._adapter.invoke(
                registered.binding.operation,
                invocation_payload,
                request_id=request_id,
                correlation_id=correlation_id,
                confirmation_granted=confirmation_granted,
            )
            result = self._redactor.redact(result)
            self._catalog.validate("api-response.schema.json", result)
            self._validate_output(registered, result)
            self._budget.accept_result(
                budget_scope,
                result,
                max_result_items=int(registered.descriptor["max_result_items"]),
            )
            is_error = result.get("status") == "ERROR"
            if is_error and result.get("errors"):
                error_code = str(result["errors"][0].get("code"))
        except Exception as error:
            result = self._error_mapper.map_exception(
                error,
                request_id=request_id,
                correlation_id=correlation_id,
            )
            self._catalog.validate("api-response.schema.json", result)
            is_error = True
            error_code = str(result["errors"][0]["code"])
        finally:
            duration_ms = max(0, int((time.monotonic() - started) * 1000))
            self._telemetry.emit(
                ToolTelemetryEvent(
                    tool_name=tool_name,
                    correlation_id=correlation_id,
                    request_fingerprint=fingerprint,
                    status="ERROR" if error_code else "OK",
                    duration_ms=duration_ms,
                    error_code=error_code,
                    confirmation_actor_id=confirmation_actor_id,
                    confirmation_session_id=confirmation_session_id,
                    confirmation_decision=confirmation_decision,
                )
            )
        return types.CallToolResult(
            content=[
                types.TextContent(text=json.dumps(result, ensure_ascii=False, sort_keys=True))
            ],
            structured_content=result,
            is_error=is_error,
        )

    @staticmethod
    def _to_mcp_tool(registered: RegisteredTool) -> types.Tool:
        descriptor = registered.descriptor
        binding = registered.binding
        return types.Tool(
            name=binding.tool_name,
            title=binding.tool_name,
            description=binding.description or str(descriptor["description_key"]),
            input_schema=binding.input_schema,
            annotations=types.ToolAnnotations(
                read_only_hint=not bool(descriptor["mutates_state"]),
                destructive_hint=binding.destructive,
                idempotent_hint=binding.idempotent,
                open_world_hint=False,
            ),
            _meta={
                "apex/toolVersion": descriptor["tool_version"],
                "apex/inputSchemaRef": descriptor["input_schema_ref"],
                "apex/outputSchemaRef": descriptor["output_schema_ref"],
                "apex/requiresConfirmation": descriptor["requires_confirmation"],
                "apex/supportsPagination": descriptor["supports_pagination"],
                "apex/supportsPartial": descriptor["supports_partial"],
                "apex/supportsCitation": descriptor["supports_citation"],
                "apex/maxResultItems": descriptor["max_result_items"],
                "apex/invocationOutputSchema": (
                    binding.output_schema_ref
                    if binding.output_schema_ref is not None
                    else "inline"
                    if binding.output_data_schema is not None
                    else None
                ),
            },
        )

    def _validate_output(self, registered: RegisteredTool, result: dict[str, Any]) -> None:
        if result.get("status") != "OK":
            return
        try:
            if registered.binding.output_schema_ref is not None:
                self._catalog.validate(registered.binding.output_schema_ref, result.get("data"))
            elif registered.binding.output_data_schema is not None:
                self._catalog.validate_inline(
                    registered.binding.output_data_schema,
                    result.get("data"),
                )
        except ToolInputValidationError as error:
            raise ToolOutputValidationError(
                "Core output does not match the MCP invocation output contract.",
                target=error.target,
            ) from error

    @staticmethod
    def _target_ids(arguments: dict[str, Any]) -> tuple[str, ...]:
        values: list[str] = []
        for field in (
            "resource_id",
            "context_snapshot_id",
            "report_id",
            "report_version_id",
            "left_report_version_id",
            "right_report_version_id",
            "section_id",
            "custody_snapshot_id",
            "expected_custody_snapshot_id",
            "expected_approval_id",
            "package_id",
            "export_manifest_id",
            "recommendation_id",
            "scope_summary_id",
            "keyword_set_id",
            "target_id",
        ):
            value = arguments.get(field)
            if isinstance(value, str) and value and value not in values:
                values.append(value)
        return tuple(values)


__all__ = ["RegisteredTool", "ToolBinding", "ToolRegistry"]
