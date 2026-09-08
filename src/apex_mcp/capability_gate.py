"""Capability-aware registration and invocation guard."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from apex_mcp.errors import CapabilityGateError


@dataclass(frozen=True, slots=True)
class CapabilityDecision:
    allowed: bool
    missing: tuple[str, ...]


class CapabilityGate:
    def __init__(self, interface: dict[str, Any]) -> None:
        self._available = frozenset(str(item) for item in interface.get("capabilities", []))
        self._unavailable = frozenset(
            str(item) for item in interface.get("unavailable_capabilities", [])
        )

    def evaluate(self, descriptor: dict[str, Any]) -> CapabilityDecision:
        required = {str(item) for item in descriptor.get("required_capabilities", [])}
        missing = tuple(sorted((required - self._available) | (required & self._unavailable)))
        return CapabilityDecision(allowed=not missing, missing=missing)

    def require(self, descriptor: dict[str, Any]) -> None:
        decision = self.evaluate(descriptor)
        if not decision.allowed:
            raise CapabilityGateError(list(decision.missing))


__all__ = ["CapabilityDecision", "CapabilityGate"]
