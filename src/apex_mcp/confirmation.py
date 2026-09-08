"""Server-side human confirmation boundary."""

from __future__ import annotations

import threading
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol

from apex_mcp.errors import ConfirmationRequiredError


@dataclass(frozen=True, slots=True)
class ConfirmationRequest:
    grant_id: str
    actor_id: str
    session_id: str
    case_id: str
    tool_name: str
    request_fingerprint: str
    target_ids: tuple[str, ...]


class ConfirmationProvider(Protocol):
    def authorize(self, request: ConfirmationRequest) -> bool: ...


class DenyAllConfirmationProvider:
    def authorize(self, request: ConfirmationRequest) -> bool:
        return False


@dataclass(frozen=True, slots=True)
class ConfirmationGrant:
    """Trusted, server-issued approval record; never accepted as MCP arguments."""

    grant_id: str
    actor_id: str
    session_id: str
    case_id: str
    tool_name: str
    request_fingerprint: str
    target_ids: tuple[str, ...]
    expires_at: datetime
    max_uses: int = 1


class InMemoryConfirmationProvider:
    """One-time grant store for an embedding trusted frontend/backend."""

    def __init__(self, grants: tuple[ConfirmationGrant, ...] = ()) -> None:
        self._grants = {grant.grant_id: grant for grant in grants}
        self._uses: dict[str, int] = {}
        self._lock = threading.Lock()

    def issue(self, grant: ConfirmationGrant) -> None:
        if grant.max_uses < 1:
            raise ValueError("Confirmation grant max_uses must be positive.")
        with self._lock:
            self._grants[grant.grant_id] = grant
            self._uses.pop(grant.grant_id, None)

    def authorize(self, request: ConfirmationRequest) -> bool:
        with self._lock:
            grant = self._grants.get(request.grant_id)
            if grant is None or not self._matches(grant, request):
                return False
            expires_at = grant.expires_at
            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=UTC)
            if expires_at <= datetime.now(UTC):
                return False
            uses = self._uses.get(grant.grant_id, 0)
            if uses >= grant.max_uses:
                return False
            self._uses[grant.grant_id] = uses + 1
            return True

    @staticmethod
    def _matches(grant: ConfirmationGrant, request: ConfirmationRequest) -> bool:
        return (
            grant.actor_id == request.actor_id
            and grant.session_id == request.session_id
            and grant.case_id == request.case_id
            and grant.tool_name == request.tool_name
            and grant.request_fingerprint == request.request_fingerprint
            and grant.target_ids == request.target_ids
        )


class ConfirmationGate:
    def __init__(self, provider: ConfirmationProvider | None = None) -> None:
        self._provider = provider or DenyAllConfirmationProvider()

    def require(
        self,
        descriptor: dict[str, object],
        request: ConfirmationRequest | None,
        *,
        expected_actor_id: str = "",
        expected_session_id: str = "",
        expected_fingerprint: str = "",
        expected_case_id: str = "",
        expected_target_ids: tuple[str, ...] = (),
    ) -> bool:
        if not descriptor.get("requires_confirmation"):
            return False
        tool_name = str(descriptor.get("tool_name", "unknown"))
        if (
            request is None
            or request.tool_name != tool_name
            or request.actor_id != expected_actor_id
            or request.session_id != expected_session_id
            or request.case_id != expected_case_id
            or request.request_fingerprint != expected_fingerprint
            or request.target_ids != expected_target_ids
            or not self._provider.authorize(request)
        ):
            raise ConfirmationRequiredError(tool_name)
        return True


__all__ = [
    "ConfirmationGate",
    "ConfirmationGrant",
    "ConfirmationProvider",
    "ConfirmationRequest",
    "DenyAllConfirmationProvider",
    "InMemoryConfirmationProvider",
]
