"""Domain error model."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class ApexError(Exception):
    """Base class for structured APEX errors."""

    code: str
    message_key: str
    developer_message: str | None = None
    target: str | None = None
    retryable: bool = False
    details: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        Exception.__init__(self, self.developer_message or self.code)

    def to_api_error(self) -> dict[str, Any]:
        """Return the JSON Schema-compatible error object."""

        return {
            "code": self.code,
            "message_key": self.message_key,
            "developer_message": self.developer_message,
            "target": self.target,
            "retryable": self.retryable,
            "details": self.details,
        }


class ValidationError(ApexError):
    """Raised when command input or state violates a contract."""

    def __init__(
        self,
        developer_message: str,
        *,
        target: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(
            code="VALIDATION_ERROR",
            message_key="error.validation",
            developer_message=developer_message,
            target=target,
            details=details or {},
        )


class NotFoundError(ApexError):
    """Raised when a requested entity does not exist."""

    def __init__(self, code: str, developer_message: str, *, target: str | None = None) -> None:
        super().__init__(
            code=code,
            message_key=f"error.{code.lower()}",
            developer_message=developer_message,
            target=target,
            details={},
        )


class UnsupportedCapabilityError(ApexError):
    """Raised when a requested feature is outside the current capability set."""

    def __init__(
        self,
        developer_message: str,
        *,
        target: str | None = None,
        required_capability: str | None = None,
    ) -> None:
        details: dict[str, Any] = {}
        if required_capability is not None:
            details["required_capability"] = required_capability
        super().__init__(
            code="CAPABILITY_UNAVAILABLE",
            message_key="error.evidence.capability_unavailable",
            developer_message=developer_message,
            target=target,
            details=details,
        )


class OperationCancelledError(ApexError):
    """Raised when cooperative cancellation is requested."""

    def __init__(self, developer_message: str = "Operation was cancelled.") -> None:
        super().__init__(
            code="OPERATION_CANCELLED",
            message_key="error.operation_cancelled",
            developer_message=developer_message,
            retryable=True,
            details={},
        )


class EvidenceChangedError(ApexError):
    """Raised when evidence metadata changes while a streaming hash is running."""

    def __init__(self, developer_message: str) -> None:
        super().__init__(
            code="EVIDENCE_CHANGED",
            message_key="error.evidence.changed_during_hash",
            developer_message=developer_message,
            retryable=True,
            details={},
        )


class StateConflictError(ApexError):
    """Raised when an operation conflicts with current persisted state."""

    def __init__(self, developer_message: str, *, target: str | None = None) -> None:
        super().__init__(
            code="STATE_CONFLICT",
            message_key="error.state_conflict",
            developer_message=developer_message,
            target=target,
            details={},
        )
