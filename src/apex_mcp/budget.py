"""Bounded MCP call, pagination, item, and serialized-result budgets."""

from __future__ import annotations

import json
import threading
import time
from dataclasses import dataclass, field
from typing import Any

from apex_mcp.errors import PaginationLoopError, ToolBudgetExceededError


@dataclass(slots=True)
class _BudgetWindow:
    started_at: float
    calls: int = 0
    items: int = 0
    serialized_bytes: int = 0
    cursors: set[tuple[str, str]] = field(default_factory=set)


class ToolBudget:
    """Applies a rolling safety window when MCP has no portable turn identifier."""

    def __init__(
        self,
        *,
        window_seconds: float = 60.0,
        max_calls: int = 64,
        max_total_items: int = 4000,
        max_total_bytes: int = 4 * 1024 * 1024,
        max_call_bytes: int = 1024 * 1024,
    ) -> None:
        self._window_seconds = window_seconds
        self._max_calls = max_calls
        self._max_total_items = max_total_items
        self._max_total_bytes = max_total_bytes
        self._max_call_bytes = max_call_bytes
        self._windows: dict[str, _BudgetWindow] = {}
        self._lock = threading.Lock()

    def begin_call(self, scope: str, tool_name: str, arguments: dict[str, Any]) -> None:
        with self._lock:
            window = self._window(scope)
            if window.calls >= self._max_calls:
                raise ToolBudgetExceededError("max_tool_calls_per_window")
            cursor = arguments.get("cursor")
            if tool_name == "apex.context.scope_page" and isinstance(cursor, str):
                cursor_key = (tool_name, cursor)
                if cursor_key in window.cursors:
                    raise PaginationLoopError()
                window.cursors.add(cursor_key)
            window.calls += 1

    def accept_result(
        self,
        scope: str,
        result: dict[str, Any],
        *,
        max_result_items: int,
    ) -> None:
        serialized_bytes = len(
            json.dumps(
                result,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        )
        items = self._item_count(result)
        if serialized_bytes > self._max_call_bytes:
            raise ToolBudgetExceededError("max_serialized_bytes_per_call")
        if items > max_result_items:
            raise ToolBudgetExceededError("descriptor.max_result_items")
        with self._lock:
            window = self._window(scope)
            if window.items + items > self._max_total_items:
                raise ToolBudgetExceededError("max_total_items_per_window")
            if window.serialized_bytes + serialized_bytes > self._max_total_bytes:
                raise ToolBudgetExceededError("max_serialized_bytes_per_window")
            window.items += items
            window.serialized_bytes += serialized_bytes

    def _window(self, scope: str) -> _BudgetWindow:
        now = time.monotonic()
        window = self._windows.get(scope)
        if window is None or now - window.started_at >= self._window_seconds:
            window = _BudgetWindow(started_at=now)
            self._windows[scope] = window
        return window

    @staticmethod
    def _item_count(result: dict[str, Any]) -> int:
        if result.get("status") != "OK":
            return 0
        data = result.get("data")
        if isinstance(data, dict) and isinstance(data.get("items"), list):
            return len(data["items"])
        if isinstance(data, list):
            return len(data)
        return 0 if data is None else 1


__all__ = ["ToolBudget"]
