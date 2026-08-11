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


class PersistenceError(ApexError):
    """Raised when the persistence adapter cannot safely complete an operation."""

    def __init__(
        self,
        code: str,
        developer_message: str,
        *,
        retryable: bool,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(
            code=code,
            message_key=f"error.{code.lower()}",
            developer_message=developer_message,
            target="database",
            retryable=retryable,
            details=details or {},
        )


class ContextError(ApexError):
    """Raised for structured Phase 6 context contract violations."""

    def __init__(
        self,
        code: str,
        developer_message: str,
        *,
        target: str | None = None,
        retryable: bool = False,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(
            code=code,
            message_key=f"error.{code.lower()}",
            developer_message=developer_message,
            target=target,
            retryable=retryable,
            details=details or {},
        )


class AiAssistanceError(ApexError):
    """Raised for structured Phase 7 AI assistance contract violations."""

    def __init__(
        self,
        code: str,
        developer_message: str,
        *,
        target: str | None = None,
        retryable: bool = False,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(
            code=code,
            message_key=f"error.{code.lower()}",
            developer_message=developer_message,
            target=target,
            retryable=retryable,
            details=details or {},
        )


class ReportError(ApexError):
    """Raised for structured Phase 8 report contract violations."""

    def __init__(
        self,
        code: str,
        developer_message: str,
        *,
        target: str | None = None,
        retryable: bool = False,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(
            code=code,
            message_key=f"error.{code.lower()}",
            developer_message=developer_message,
            target=target,
            retryable=retryable,
            details=details or {},
        )


class DecryptionError(ApexError):
    """Raised for structured advanced secret and decryption runtime failures."""

    def __init__(
        self,
        code: str,
        developer_message: str,
        *,
        target: str | None = None,
        retryable: bool = False,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(
            code=code,
            message_key=f"error.{code.lower()}",
            developer_message=developer_message,
            target=target,
            retryable=retryable,
            details=details or {},
        )


class ContextRevisionConflictError(ContextError):
    """Raised when an optimistic-lock context revision check fails."""

    def __init__(self, developer_message: str, *, target: str | None = None) -> None:
        super().__init__(
            "CONTEXT_REVISION_CONFLICT",
            developer_message,
            target=target,
            retryable=True,
        )


class ContextExpiredError(ContextError):
    """Raised when a live GUI context is modified after expiration."""

    def __init__(self, developer_message: str, *, target: str | None = None) -> None:
        super().__init__("CONTEXT_EXPIRED", developer_message, target=target)


class ContextScopeMismatchError(ContextError):
    """Raised when selected resources do not belong to the target case/context."""

    def __init__(
        self,
        developer_message: str,
        *,
        target: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(
            "CONTEXT_SCOPE_MISMATCH",
            developer_message,
            target=target,
            details=details,
        )


class ContextSelectionLimitExceededError(ContextError):
    """Raised when a context selection exceeds the configured item budget."""

    def __init__(self, developer_message: str, *, target: str | None = None) -> None:
        super().__init__("CONTEXT_SELECTION_LIMIT_EXCEEDED", developer_message, target=target)


class ContextFilterLimitExceededError(ContextError):
    """Raised when filter/preferences JSON is too large or too deeply nested."""

    def __init__(self, developer_message: str, *, target: str | None = None) -> None:
        super().__init__("CONTEXT_FILTER_LIMIT_EXCEEDED", developer_message, target=target)


class CursorInvalidError(ApexError):
    """Raised when an opaque cursor cannot be decoded for the requested page."""

    def __init__(self, developer_message: str, *, target: str | None = None) -> None:
        super().__init__(
            code="CURSOR_INVALID",
            message_key="error.cursor_invalid",
            developer_message=developer_message,
            target=target,
            details={},
        )


class RawReadError(ApexError):
    """Raised for safe raw range reader contract violations."""

    def __init__(
        self,
        code: str,
        developer_message: str,
        *,
        target: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(
            code=code,
            message_key=f"error.{code.lower()}",
            developer_message=developer_message,
            target=target,
            details=details or {},
        )
