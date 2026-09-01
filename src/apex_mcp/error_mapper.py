"""Translate exceptions into redacted Core-compatible response envelopes."""

from __future__ import annotations

from typing import Any, cast
from uuid import uuid4

from apex_forensic.domain.errors import ApexError
from apex_mcp.errors import McpFoundationError
from apex_mcp.redaction import Redactor


class ErrorMapper:
    def __init__(self, redactor: Redactor | None = None) -> None:
        self._redactor = redactor or Redactor()

    def map_exception(
        self,
        error: Exception,
        *,
        request_id: str | None = None,
        correlation_id: str | None = None,
    ) -> dict[str, Any]:
        if isinstance(error, ApexError):
            api_error = error.to_api_error()
        elif isinstance(error, McpFoundationError):
            api_error = {
                "code": error.code,
                "message_key": f"error.mcp.{error.code.lower()}",
                "developer_message": error.developer_message,
                "target": error.target,
                "retryable": error.retryable,
                "details": error.details,
            }
        else:
            api_error = {
                "code": "MCP_INTERNAL_ERROR",
                "message_key": "error.mcp.internal",
                "developer_message": "The MCP adapter failed unexpectedly.",
                "target": None,
                "retryable": False,
                "details": {"error_type": type(error).__name__},
            }
        return cast(
            dict[str, Any],
            self._redactor.redact(
                {
                    "schema_version": "1.0.0",
                    "interface_version": "1.0.0",
                    "request_id": request_id or str(uuid4()),
                    "correlation_id": correlation_id,
                    "status": "ERROR",
                    "data": None,
                    "warnings": [],
                    "errors": [api_error],
                }
            ),
        )


__all__ = ["ErrorMapper"]
