"""Verify Windows Event Message rendering against host-registered providers.

Run this on a Windows host with the ``windows-artifacts`` extra installed:

    python tools/verify_windows_event_message_renderer.py --require-rendered
"""

from __future__ import annotations

import argparse
import json
import platform
import sys
from typing import Any

from apex_forensic.adapters.artifacts.windows.eventlog import WindowsEventMessageRenderer


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify APEX Windows Event Message rendering on a Windows host."
    )
    parser.add_argument("--channel", default="System")
    parser.add_argument("--provider", default="Microsoft-Windows-Kernel-General")
    parser.add_argument("--event-id", type=int, default=12)
    parser.add_argument("--locale", default="en-US")
    parser.add_argument("--max-events", type=int, default=20)
    parser.add_argument(
        "--require-rendered",
        action="store_true",
        help="Exit non-zero unless a host event handle is rendered successfully.",
    )
    args = parser.parse_args(argv)

    result = verify_latest_matching_event(
        channel=args.channel,
        provider_name=args.provider,
        event_id=args.event_id,
        locale=args.locale,
        max_events=args.max_events,
    )
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    if args.require_rendered and not result.get("message_rendered"):
        return 2
    return 0


def verify_latest_matching_event(
    *,
    channel: str,
    provider_name: str,
    event_id: int,
    locale: str | None,
    max_events: int,
) -> dict[str, Any]:
    if platform.system() != "Windows":
        return {
            "message_rendered": False,
            "rendered_message": None,
            "message_rendering": {
                "status": "WINDOWS_HOST_REQUIRED",
                "channel": channel,
                "provider_name": provider_name,
                "event_id": event_id,
                "locale": locale,
                "render_mode": "EVENT_HANDLE",
            },
        }
    if not WindowsEventMessageRenderer.is_available():
        return {
            "message_rendered": False,
            "rendered_message": None,
            "message_rendering": {
                "status": "PYWIN32_UNAVAILABLE",
                "channel": channel,
                "provider_name": provider_name,
                "event_id": event_id,
                "locale": locale,
                "render_mode": "EVENT_HANDLE",
            },
        }

    import win32evtlog  # type: ignore[import-not-found]

    query_handle = None
    event_handles: list[Any] = []
    handle_diagnostics: dict[str, Any] = {}
    try:
        query_text = (
            f"*[System[Provider[@Name={_xpath_literal(provider_name)}] "
            f"and EventID={event_id}]]"
        )
        query_flags = (
            win32evtlog.EvtQueryChannelPath
            | win32evtlog.EvtQueryReverseDirection
        )
        query_handle = win32evtlog.EvtQuery(
            channel,
            query_flags,
            query_text,
        )
        handle_diagnostics["query_handle"] = _safe_handle_diagnostics(query_handle)
        event_handles = list(win32evtlog.EvtNext(query_handle, max_events))
        handle_diagnostics["matching_event_count"] = len(event_handles)
        if not event_handles:
            return {
                "message_rendered": False,
                "rendered_message": None,
                "message_rendering": {
                    "status": "NO_MATCHING_EVENTS",
                    "channel": channel,
                    "provider_name": provider_name,
                    "event_id": event_id,
                    "locale": locale,
                    "render_mode": "EVENT_HANDLE",
                    "handle_diagnostics": handle_diagnostics,
                },
            }
        renderer = WindowsEventMessageRenderer()
        for event_handle in event_handles:
            handle_diagnostics["event_handle"] = _safe_handle_diagnostics(event_handle)
            rendered = renderer.render_event_handle(
                provider_name=provider_name,
                event_handle=event_handle,
                locale=locale,
            )
            rendered["message_rendering"]["channel"] = channel
            rendered["message_rendering"]["event_id"] = event_id
            rendered["message_rendering"]["handle_diagnostics"] = dict(handle_diagnostics)
            if rendered.get("message_rendered"):
                return rendered
            _attach_pywin32_format_diagnostics(rendered, win32evtlog)
        rendered["message_rendering"]["matching_event_count"] = len(event_handles)
        return rendered
    except Exception as error:
        return {
            "message_rendered": False,
            "rendered_message": None,
            "message_rendering": {
                "status": "WINDOWS_EVENT_QUERY_FAILED",
                "channel": channel,
                "provider_name": provider_name,
                "event_id": event_id,
                "locale": locale,
                "render_mode": "EVENT_HANDLE",
                "error_type": type(error).__name__,
                "error": str(error),
            },
        }
    finally:
        for handle in event_handles:
            _evt_close(win32evtlog, handle)
        if query_handle is not None:
            _evt_close(win32evtlog, query_handle)


def _attach_pywin32_format_diagnostics(result: dict[str, Any], win32evtlog: Any) -> None:
    message_rendering = result.setdefault("message_rendering", {})
    diagnostics = message_rendering.setdefault("diagnostics", {})
    evt_format_message = getattr(win32evtlog, "EvtFormatMessage", None)
    doc = getattr(evt_format_message, "__doc__", None)
    diagnostics.setdefault(
        "expected_pywin32_event_handle_call",
        (
            "EvtFormatMessage(publisher_metadata_handle, event_handle, "
            "EvtFormatMessageEvent)"
        ),
    )
    diagnostics.setdefault(
        "expected_pywin32_contract",
        "EvtFormatMessage(Metadata, Event, Flags, ResourceId=0)",
    )
    if doc is not None:
        text = str(doc)
        diagnostics.setdefault(
            "evt_format_message_doc",
            text if len(text) <= 1200 else text[:1200] + "...",
        )


def _safe_handle_diagnostics(handle: Any) -> dict[str, Any]:
    return {
        "type": type(handle).__name__,
        "has_close": hasattr(handle, "Close"),
    }


def _evt_close(win32evtlog: Any, handle: Any) -> None:
    close = getattr(win32evtlog, "EvtClose", None)
    if close is not None:
        close(handle)


def _xpath_literal(value: str) -> str:
    if "'" not in value:
        return f"'{value}'"
    if '"' not in value:
        return f'"{value}"'
    parts = value.split("'")
    return "concat(" + ', "\'", '.join(f"'{part}'" for part in parts) + ")"


if __name__ == "__main__":
    sys.exit(main())
