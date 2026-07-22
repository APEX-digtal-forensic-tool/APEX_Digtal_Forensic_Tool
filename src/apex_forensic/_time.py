"""Datetime helpers for UTC-aware storage and JSON serialization."""

from __future__ import annotations

from datetime import UTC, datetime


def utc_now() -> datetime:
    """Return the current timezone-aware UTC time."""

    return datetime.now(UTC)


def parse_timestamp(value: str) -> datetime:
    """Parse an ISO 8601 timestamp stored by APEX."""

    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def to_json_timestamp(value: datetime) -> str:
    """Serialize a timezone-aware datetime for JSON DTOs."""

    if value.tzinfo is None:
        raise ValueError("datetime must be timezone-aware")
    utc_value = value.astimezone(UTC)
    return utc_value.isoformat(timespec="microseconds").replace("+00:00", "Z")
