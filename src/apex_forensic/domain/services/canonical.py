"""Canonical JSON helpers for hashes and custody ledger events."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from typing import Any


def without_keys(value: Any, keys: set[str]) -> Any:
    """Return a deep copy of ``value`` with matching object keys removed."""

    if isinstance(value, Mapping):
        return {key: without_keys(item, keys) for key, item in value.items() if key not in keys}
    if isinstance(value, list):
        return [without_keys(item, keys) for item in value]
    return value


def canonical_json_bytes(value: Any, *, exclude_keys: set[str] | None = None) -> bytes:
    """Serialize JSON data using the Phase 1 canonicalization profile."""

    normalized = without_keys(value, exclude_keys or set())
    return json.dumps(
        normalized,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def canonical_sha256(value: Any, *, exclude_keys: set[str] | None = None) -> str:
    """Return the SHA-256 digest of canonical JSON data."""

    return hashlib.sha256(canonical_json_bytes(value, exclude_keys=exclude_keys)).hexdigest()
