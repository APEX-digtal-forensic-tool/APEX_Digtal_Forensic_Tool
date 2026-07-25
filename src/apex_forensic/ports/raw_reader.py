"""Safe raw range reader port for Phase 6 public views."""

from __future__ import annotations

from typing import Any, Protocol

from apex_forensic.domain.models import RawViewProjection
from apex_forensic.jobs import CancellationToken


class SafeRawRangeReaderPort(Protocol):
    """Provider-neutral bounded raw and logical field reader."""

    def capability(self) -> dict[str, Any]: ...

    def validate_locator(self, *, case_id: str, raw_locator: dict[str, Any]) -> dict[str, Any]: ...

    def read_range(self, **kwargs: Any) -> RawViewProjection: ...

    def read_logical_field(
        self,
        *,
        case_id: str,
        resource_type: str,
        resource_id: str,
        raw_locator: dict[str, Any],
        source_revision: str | int | None,
        citations: list[dict[str, Any]],
        structured_fields: dict[str, Any],
        requested_offset: int = 0,
        requested_length: int | None = None,
    ) -> RawViewProjection: ...

    def preview(self, **kwargs: Any) -> RawViewProjection: ...

    def hash_range(self, **kwargs: Any) -> dict[str, Any]: ...

    def read_resource(
        self,
        *,
        case_id: str,
        resource_type: str,
        resource_id: str,
        offset: int = 0,
        length: int | None = None,
        correlation_id: str | None = None,
        cancellation_token: CancellationToken | None = None,
    ) -> RawViewProjection: ...
