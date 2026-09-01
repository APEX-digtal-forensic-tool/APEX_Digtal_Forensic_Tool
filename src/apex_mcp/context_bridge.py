"""MCP-owned validation and normalization for Core context operations."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from typing import Any

from apex_mcp.errors import AuthenticatedActorRequiredError, ToolInputValidationError

MAX_ARGUMENT_BYTES = 64 * 1024
MAX_ARGUMENT_DEPTH = 8

_FORBIDDEN_KEY = re.compile(
    r"(?:api[-_]?key|authorization|credential|password|secret|access[-_]?token|"
    r"refresh[-_]?token|prompt|chain[-_]?of[-_]?thought|reasoning[-_]?trace|"
    r"raw[-_]?(?:response|body|blob)|attachment[-_]?bytes|base64)",
    re.IGNORECASE,
)
_TRUSTED_ACTOR_FIELDS = {
    "ai.keyword-recommendation.review": "actor_id",
    "ai.scope-summary.review": "actor_id",
    "ai.keyword-recommendation.promote": "actor_id",
    "report.create": "created_by",
    "report.version.create": "created_by",
    "report.review.submit": "actor_id",
    "report.review.comment": "actor_id",
    "report.review.request-changes": "actor_id",
    "report.review.accept-section": "actor_id",
    "report.review.reject-section": "actor_id",
    "report.review.complete": "actor_id",
    "report.review.reopen": "actor_id",
    "report.approve": "approver_id",
    "report.reject": "approver_id",
    "report.approval.revoke": "actor_id",
    "report.custody-snapshot.create": "captured_by",
    "report.render-package.create": "created_by",
    "report.export.prepare": "created_by",
    "report.archive": "actor_id",
}
_AUTHENTICATED_HUMAN_TOOLS = frozenset(_TRUSTED_ACTOR_FIELDS) | {
    "apex.view.raw_read",
    "ai.promotion.preview",
}
_UNAUTHENTICATED_ACTORS = frozenset({"", "anonymous", "unauthenticated"})
_MACHINE_ACTOR = re.compile(
    r"^(?:ai|llm|model|bot|system|mcp-ai|external-ai)(?:$|[-_:])",
    re.IGNORECASE,
)


def is_authenticated_actor(actor_id: str | None) -> bool:
    return bool(
        actor_id is not None
        and actor_id.casefold() not in _UNAUTHENTICATED_ACTORS
        and _MACHINE_ACTOR.search(actor_id) is None
    )


def _depth(value: Any, level: int = 0) -> int:
    if isinstance(value, Mapping):
        return max((_depth(item, level + 1) for item in value.values()), default=level + 1)
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return max((_depth(item, level + 1) for item in value), default=level + 1)
    return level + 1


class ContextBridge:
    """Preserves snapshot semantics and rejects unsafe MCP argument payloads."""

    def prepare(
        self,
        tool_name: str,
        arguments: Mapping[str, Any],
        *,
        trusted_actor_id: str | None = None,
        trusted_session_id: str | None = None,
        confirmation_grant_id: str | None = None,
        confirmation_fingerprint: str | None = None,
    ) -> dict[str, Any]:
        payload = dict(arguments)
        self._reject_forbidden_values(payload)
        if tool_name == "apex.context.snapshot":
            payload["purpose"] = "MCP_REQUEST"
        if tool_name in _AUTHENTICATED_HUMAN_TOOLS:
            actor_id = trusted_actor_id or ""
            if not is_authenticated_actor(actor_id):
                raise AuthenticatedActorRequiredError(tool_name)
        trusted_actor_field = _TRUSTED_ACTOR_FIELDS.get(tool_name)
        if trusted_actor_field is not None:
            payload[trusted_actor_field] = actor_id
        if tool_name == "report.ai-draft.ingest":
            payload["created_by"] = "mcp-ai-layer"
        if tool_name == "ai.keyword-recommendation.promote":
            payload["confirmation_metadata"] = {
                "grant_id": confirmation_grant_id,
                "actor_id": trusted_actor_id,
                "session_id": trusted_session_id,
                "request_fingerprint": confirmation_fingerprint,
            }
        self._validate_budget(payload)
        return payload

    @staticmethod
    def _validate_budget(payload: dict[str, Any]) -> None:
        if _depth(payload) > MAX_ARGUMENT_DEPTH:
            raise ToolInputValidationError(
                "MCP arguments exceed the maximum JSON depth.",
                target="arguments",
            )
        serialized = json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        if len(serialized) > MAX_ARGUMENT_BYTES:
            raise ToolInputValidationError(
                "MCP arguments exceed the maximum serialized size.",
                target="arguments",
            )

    @classmethod
    def _reject_forbidden_values(cls, value: Any) -> None:
        if isinstance(value, Mapping):
            for key, item in value.items():
                if _FORBIDDEN_KEY.search(str(key)):
                    raise ToolInputValidationError(
                        "MCP arguments cannot contain secrets, prompts, or raw blobs.",
                        target=str(key),
                    )
                cls._reject_forbidden_values(item)
            return
        if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
            for item in value:
                cls._reject_forbidden_values(item)
            return
        if isinstance(value, (bytes, bytearray)):
            raise ToolInputValidationError(
                "MCP arguments cannot contain binary payloads.",
                target="arguments",
            )


__all__ = [
    "MAX_ARGUMENT_BYTES",
    "MAX_ARGUMENT_DEPTH",
    "ContextBridge",
    "is_authenticated_actor",
]
