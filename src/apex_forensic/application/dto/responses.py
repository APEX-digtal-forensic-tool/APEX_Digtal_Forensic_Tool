"""API-style response envelope helpers."""

from __future__ import annotations

from typing import Any

from apex_forensic.constants import SCHEMA_VERSION
from apex_forensic.domain.errors import ApexError


def success_response(
    request_id: str,
    data: Any,
    warnings: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Return a Schema-compatible success envelope."""

    return {
        "schema_version": SCHEMA_VERSION,
        "request_id": request_id,
        "data": data,
        "page": None,
        "warnings": warnings or [],
    }


def error_response(request_id: str, error: ApexError) -> dict[str, Any]:
    """Return a Schema-compatible error envelope."""

    return {
        "schema_version": SCHEMA_VERSION,
        "request_id": request_id,
        "errors": [error.to_api_error()],
    }
