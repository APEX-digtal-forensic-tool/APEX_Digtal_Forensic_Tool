"""Central redaction for MCP errors, logs, and telemetry."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any

_SENSITIVE_KEY = re.compile(
    r"(?:api[-_]?key|authorization|credential|password|secret|access[-_]?token|"
    r"refresh[-_]?token|prompt|chain[-_]?of[-_]?thought|reasoning[-_]?trace|"
    r"raw[-_]?(?:response|body|blob)|attachment[-_]?bytes|base64)",
    re.IGNORECASE,
)
_BEARER = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]+")
_OPENAI_KEY = re.compile(r"\bsk-[A-Za-z0-9_-]{8,}\b")


class Redactor:
    REDACTED = "<redacted>"

    def redact(self, value: Any) -> Any:
        if isinstance(value, Mapping):
            return {
                str(key): self.REDACTED if _SENSITIVE_KEY.search(str(key)) else self.redact(item)
                for key, item in value.items()
            }
        if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
            return [self.redact(item) for item in value]
        if isinstance(value, (bytes, bytearray)):
            return self.REDACTED
        if isinstance(value, str):
            return self.redact_text(value)
        return value

    def redact_text(self, value: str) -> str:
        return _OPENAI_KEY.sub(self.REDACTED, _BEARER.sub(self.REDACTED, value))


__all__ = ["Redactor"]
