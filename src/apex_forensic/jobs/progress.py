"""Progress DTOs used by long-running Phase 1 operations."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from apex_forensic.domain.enums import HashAlgorithm


@dataclass(frozen=True, slots=True)
class HashProgress:
    """Streaming hash progress callback payload."""

    processed_bytes: int
    total_bytes: int
    progress_percent: float


@dataclass(frozen=True, slots=True)
class HashComputation:
    """Result from a streaming hash run."""

    digests: dict[HashAlgorithm, str]
    bytes_hashed: int
    file_size: int
    chunk_size: int
    started_at: datetime
    completed_at: datetime
