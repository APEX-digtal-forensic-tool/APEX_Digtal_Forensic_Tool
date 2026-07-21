"""Hash provider port."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Protocol

from apex_forensic.domain.enums import HashAlgorithm
from apex_forensic.jobs.cancellation import CancellationToken
from apex_forensic.jobs.progress import HashComputation, HashProgress


class HashProvider(Protocol):
    """Computes streaming hashes for read-only evidence sources."""

    def compute_file(
        self,
        path: Path,
        algorithms: Iterable[HashAlgorithm],
        *,
        chunk_size: int,
        progress_callback: Callable[[HashProgress], None] | None = None,
        cancellation_token: CancellationToken | None = None,
    ) -> HashComputation:
        """Compute hashes without loading the entire file in memory."""
        ...
