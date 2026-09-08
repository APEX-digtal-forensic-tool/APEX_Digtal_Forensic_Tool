"""Structured errors owned by the MCP product layer."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class McpFoundationError(Exception):
    """Base error safe to translate into an APEX response envelope."""

    code: str
    developer_message: str
    target: str | None = None
    retryable: bool = False
    details: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        Exception.__init__(self, self.developer_message)


class McpConfigurationError(McpFoundationError):
    def __init__(self, message: str, *, target: str | None = None) -> None:
        super().__init__("MCP_CONFIGURATION_ERROR", message, target=target)


class InterfaceCompatibilityError(McpFoundationError):
    def __init__(self, message: str, *, details: dict[str, Any] | None = None) -> None:
        super().__init__(
            "INTERFACE_VERSION_INCOMPATIBLE",
            message,
            target="engine_interface",
            details=details or {},
        )


class DescriptorValidationError(McpFoundationError):
    def __init__(self, message: str, *, target: str | None = None) -> None:
        super().__init__("DESCRIPTOR_VALIDATION_FAILED", message, target=target)


class ToolRegistrationError(McpFoundationError):
    def __init__(self, message: str, *, target: str | None = None) -> None:
        super().__init__("TOOL_REGISTRATION_DENIED", message, target=target)


class CapabilityGateError(McpFoundationError):
    def __init__(self, missing: list[str]) -> None:
        super().__init__(
            "CAPABILITY_UNAVAILABLE",
            "The tool requires unavailable capabilities.",
            target="required_capabilities",
            details={"missing_capabilities": sorted(missing)},
        )


class ConfirmationRequiredError(McpFoundationError):
    def __init__(self, tool_name: str) -> None:
        super().__init__(
            "HUMAN_CONFIRMATION_REQUIRED",
            "A server-verified human confirmation is required.",
            target="confirmation",
            details={"tool_name": tool_name},
        )


class AuthenticatedActorRequiredError(McpFoundationError):
    def __init__(self, tool_name: str) -> None:
        super().__init__(
            "MCP_AUTHENTICATED_ACTOR_REQUIRED",
            "A trusted authenticated actor is required for this human action.",
            target="actor_id",
            details={"tool_name": tool_name},
        )


class McpAuthorizationDeniedError(McpFoundationError):
    def __init__(self, tool_name: str, *, required: tuple[str, ...] = ()) -> None:
        super().__init__(
            "MCP_AUTHORIZATION_DENIED",
            "The authenticated frontend session is not authorized for this tool.",
            target="authorization",
            details={
                "tool_name": tool_name,
                "required": list(required),
            },
        )


class McpTenantScopeViolationError(McpFoundationError):
    def __init__(self, tool_name: str) -> None:
        super().__init__(
            "MCP_TENANT_SCOPE_VIOLATION",
            "The requested case is outside the authenticated frontend session scope.",
            target="case_id",
            details={"tool_name": tool_name},
        )


class ToolInputValidationError(McpFoundationError):
    def __init__(self, message: str, *, target: str | None = None) -> None:
        super().__init__("VALIDATION_ERROR", message, target=target)


class ToolOutputValidationError(McpFoundationError):
    def __init__(self, message: str, *, target: str | None = None) -> None:
        super().__init__("MCP_OUTPUT_VALIDATION_FAILED", message, target=target)


class ToolBudgetExceededError(McpFoundationError):
    def __init__(self, limit: str) -> None:
        super().__init__(
            "MCP_BUDGET_EXCEEDED",
            "The MCP safety budget was exceeded.",
            target=limit,
            details={"limit": limit},
        )


class PaginationLoopError(McpFoundationError):
    def __init__(self) -> None:
        super().__init__(
            "MCP_PAGINATION_LOOP",
            "The same opaque pagination cursor was reused in one budget window.",
            target="cursor",
        )


class ToolNotFoundError(McpFoundationError):
    def __init__(self, tool_name: str) -> None:
        super().__init__(
            "TOOL_NOT_FOUND",
            "The requested tool is not registered.",
            target="tool_name",
            details={"tool_name": tool_name},
        )
