"""Single transport-neutral entry point from MCP into the APEX Core."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any

from apex_forensic.config import ServiceBundle, build_ai_provider, build_services
from apex_forensic.domain.errors import ContextExpiredError
from apex_forensic.runtime.capabilities import capability_report
from apex_mcp.config import McpConfig
from apex_mcp.errors import (
    ConfirmationRequiredError,
    McpAuthorizationDeniedError,
    ToolNotFoundError,
)


class EngineAdapter:
    """Owns a Core service bundle and exposes only its public interface."""

    def __init__(self, services: ServiceBundle, *, owns_services: bool = False) -> None:
        self._services = services
        self._owns_services = owns_services
        self._closed = False

    @classmethod
    def from_config(cls, config: McpConfig) -> EngineAdapter:
        validated = config.validate()
        services = build_services(
            validated.database_path,
            initialize=validated.initialize_database,
            ai_provider=(
                build_ai_provider(validated.ai_provider)
                if validated.ai_provider is not None
                else None
            ),
        )
        return cls(services, owns_services=True)

    def get_interface(self) -> dict[str, Any]:
        self._ensure_open()
        return self._services.interface.version().to_schema_dict()

    def list_tool_descriptors(self) -> list[dict[str, Any]]:
        self._ensure_open()
        return [descriptor.to_schema_dict() for descriptor in self._services.interface.tools()]

    def get_runtime_capabilities(self) -> dict[str, Any]:
        self._ensure_open()
        return capability_report()

    def invoke(
        self,
        tool_name: str,
        payload: Mapping[str, Any],
        *,
        request_id: str | None = None,
        correlation_id: str | None = None,
        confirmation_granted: bool = False,
    ) -> dict[str, Any]:
        self._ensure_open()
        descriptor = self.descriptor(tool_name)
        if descriptor["requires_confirmation"] and not confirmation_granted:
            raise ConfirmationRequiredError(tool_name)
        if tool_name in {"apex.context.get", "apex.context.snapshot"}:
            context_result = self._services.interface.invoke_read(
                "apex.context.get",
                {"session_context_id": payload.get("session_context_id")},
                request_id=request_id,
                correlation_id=correlation_id,
            )
            if context_result.get("status") != "OK":
                return context_result
            self._require_live_context(context_result.get("data"))
            if tool_name == "apex.context.get":
                return context_result
        invoke = (
            self._services.interface.invoke_mutation
            if descriptor["mutates_state"]
            else self._services.interface.invoke_read
        )
        return invoke(
            tool_name,
            payload,
            request_id=request_id,
            correlation_id=correlation_id,
        )

    def descriptor(self, tool_name: str) -> dict[str, Any]:
        for descriptor in self.list_tool_descriptors():
            if descriptor["tool_name"] == tool_name:
                return descriptor
        raise ToolNotFoundError(tool_name)

    def target_case_ids(
        self,
        tool_name: str,
        payload: Mapping[str, Any],
    ) -> frozenset[str]:
        """Resolve the case boundary through public Core read operations.

        Most tools carry ``case_id`` directly. Identifier-only tools are resolved
        before execution so a cross-tenant mutation cannot run before authorization.
        An ordinary Core not-found response is left to the requested operation so the
        transport does not turn existence checks into a tenant enumeration oracle.
        """

        self._ensure_open()
        case_id = payload.get("case_id")
        if isinstance(case_id, str) and case_id:
            return frozenset({case_id})
        lookup = _CASE_LOOKUPS.get(tool_name)
        if lookup is None:
            return frozenset()
        lookup_tool, argument_names = lookup
        lookup_payload = {
            name: payload[name]
            for name in argument_names
            if name in payload
        }
        result = self._services.interface.invoke_read(lookup_tool, lookup_payload)
        if result.get("status") != "OK":
            return frozenset()
        return frozenset(self._case_ids(result.get("data")))

    def require_frontend_context(
        self,
        tool_name: str,
        payload: Mapping[str, Any],
        *,
        actor_id: str,
        session_id: str,
    ) -> None:
        """Bind live GUI-context reads/snapshots to the authenticated session."""

        if tool_name not in {"apex.context.get", "apex.context.snapshot"}:
            return
        result = self._services.interface.invoke_read(
            "apex.context.get",
            {"session_context_id": payload.get("session_context_id")},
        )
        if result.get("status") != "OK":
            return
        data = result.get("data")
        if not isinstance(data, Mapping):
            raise McpAuthorizationDeniedError(tool_name)
        if data.get("session_id") != session_id or data.get("actor_id") != actor_id:
            raise McpAuthorizationDeniedError(tool_name)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self._owns_services:
            self._services.close()

    def _ensure_open(self) -> None:
        if self._closed:
            raise RuntimeError("EngineAdapter is closed.")

    @staticmethod
    def _require_live_context(data: Any) -> None:
        if not isinstance(data, Mapping):
            return
        expires_at = data.get("expires_at")
        if not isinstance(expires_at, str):
            return
        try:
            expiration = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
        except ValueError:
            return
        if expiration.tzinfo is None:
            expiration = expiration.replace(tzinfo=UTC)
        if expiration <= datetime.now(UTC):
            raise ContextExpiredError(
                "Expired GUI session contexts cannot be used by MCP.",
                target="session_context_id",
            )

    @classmethod
    def _case_ids(cls, value: Any) -> set[str]:
        case_ids: set[str] = set()
        if isinstance(value, Mapping):
            case_id = value.get("case_id")
            if isinstance(case_id, str) and case_id:
                case_ids.add(case_id)
            for item in value.values():
                case_ids.update(cls._case_ids(item))
        elif isinstance(value, list):
            for item in value:
                case_ids.update(cls._case_ids(item))
        return case_ids


_CASE_LOOKUPS: dict[str, tuple[str, tuple[str, ...]]] = {
    "apex.context.get": ("apex.context.get", ("session_context_id",)),
    "apex.context.snapshot": ("apex.context.get", ("session_context_id",)),
    "apex.context.snapshot_show": (
        "apex.context.snapshot_show",
        ("context_snapshot_id",),
    ),
    "apex.context.scope_page": (
        "apex.context.snapshot_show",
        ("context_snapshot_id",),
    ),
    "ai.request.get": ("ai.request.get", ("assistance_request_id",)),
    "ai.request.execute": ("ai.request.get", ("assistance_request_id",)),
    "ai.keyword-batch.get": (
        "ai.keyword-batch.get",
        ("recommendation_batch_id",),
    ),
    "ai.keyword-recommendation.get": (
        "ai.keyword-recommendation.get",
        ("recommendation_id",),
    ),
    "ai.scope-summary.get": ("ai.scope-summary.get", ("scope_summary_id",)),
}


__all__ = ["EngineAdapter"]
