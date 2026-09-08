"""Payload-free telemetry records for MCP Tool execution."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Protocol


@dataclass(frozen=True, slots=True)
class ToolTelemetryEvent:
    tool_name: str
    correlation_id: str
    request_fingerprint: str
    status: str
    duration_ms: int
    error_code: str | None = None
    confirmation_actor_id: str | None = None
    confirmation_session_id: str | None = None
    confirmation_decision: str | None = None


class TelemetrySink(Protocol):
    def emit(self, event: ToolTelemetryEvent) -> None: ...


class NoopTelemetrySink:
    def emit(self, event: ToolTelemetryEvent) -> None:
        return None


def request_fingerprint(payload: dict[str, Any]) -> str:
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


__all__ = ["NoopTelemetrySink", "TelemetrySink", "ToolTelemetryEvent", "request_fingerprint"]
