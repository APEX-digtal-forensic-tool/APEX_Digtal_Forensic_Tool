"""Streaming hash provider backed by Python's hashlib."""

from __future__ import annotations

import hashlib
import logging
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Any, ClassVar

from apex_forensic._time import utc_now
from apex_forensic.constants import DEFAULT_HASH_CHUNK_SIZE
from apex_forensic.domain.enums import HashAlgorithm
from apex_forensic.domain.errors import (
    EvidenceChangedError,
    OperationCancelledError,
    UnsupportedCapabilityError,
    ValidationError,
)
from apex_forensic.jobs.cancellation import CancellationToken
from apex_forensic.jobs.progress import HashComputation, HashProgress

LOGGER = logging.getLogger(__name__)


class HashlibStreamingHashProvider:
    """Computes MD5, SHA-1, and SHA-256 using bounded read chunks."""

    _HASHLIB_NAMES: ClassVar[dict[HashAlgorithm, str]] = {
        HashAlgorithm.MD5: "md5",
        HashAlgorithm.SHA1: "sha1",
        HashAlgorithm.SHA256: "sha256",
    }

    def compute_file(
        self,
        path: Path,
        algorithms: Iterable[HashAlgorithm],
        *,
        chunk_size: int = DEFAULT_HASH_CHUNK_SIZE,
        progress_callback: Callable[[HashProgress], None] | None = None,
        cancellation_token: CancellationToken | None = None,
    ) -> HashComputation:
        """Compute requested hashes without reading the whole file at once."""

        if chunk_size <= 0:
            raise ValidationError("chunk_size must be greater than zero.", target="chunk_size")
        requested = tuple(dict.fromkeys(algorithms))
        if not requested:
            raise ValidationError("At least one hash algorithm is required.", target="algorithm")
        unsupported = [item.value for item in requested if item not in self._HASHLIB_NAMES]
        if unsupported:
            raise UnsupportedCapabilityError(
                "Unsupported hash algorithm requested.",
                target="algorithm",
                required_capability=",".join(unsupported),
            )
        if path.is_symlink():
            raise UnsupportedCapabilityError(
                "Symbolic link evidence is not followed in Phase 1.",
                target="path",
                required_capability="SYMLINK_POLICY",
            )
        if path.is_dir():
            raise UnsupportedCapabilityError(
                "Directory content hash is not defined in Phase 1.",
                target="path",
                required_capability="DIRECTORY_MANIFEST_HASH",
            )
        if not path.is_file():
            raise ValidationError("Evidence path is not a regular file.", target="path")

        before = path.stat()
        identity_before = self._file_identity(before)
        digesters = {
            algorithm: hashlib.new(self._HASHLIB_NAMES[algorithm]) for algorithm in requested
        }
        processed = 0
        started_at = utc_now()
        LOGGER.info(
            "hash_start",
            extra={
                "path": str(path),
                "size_bytes": before.st_size,
                "algorithms": [item.value for item in requested],
            },
        )

        try:
            with path.open("rb") as stream:
                while True:
                    if cancellation_token is not None and cancellation_token.is_cancelled:
                        raise OperationCancelledError()
                    chunk = stream.read(chunk_size)
                    if not chunk:
                        break
                    processed += len(chunk)
                    for digester in digesters.values():
                        digester.update(chunk)
                    self._emit_progress(processed, before.st_size, progress_callback)
        except OSError as error:
            raise ValidationError(str(error), target="path") from error

        completed_at = utc_now()
        after = path.stat()
        if (
            after.st_size != before.st_size
            or after.st_mtime_ns != before.st_mtime_ns
            or self._file_identity(after) != identity_before
        ):
            raise EvidenceChangedError("Evidence file changed while hash calculation was running.")
        self._emit_progress(processed, before.st_size, progress_callback)
        LOGGER.info(
            "hash_complete",
            extra={
                "path": str(path),
                "bytes_hashed": processed,
                "algorithms": [item.value for item in requested],
            },
        )
        return HashComputation(
            digests={algorithm: digester.hexdigest() for algorithm, digester in digesters.items()},
            bytes_hashed=processed,
            file_size=before.st_size,
            chunk_size=chunk_size,
            started_at=started_at,
            completed_at=completed_at,
        )

    @staticmethod
    def _emit_progress(
        processed: int,
        total: int,
        progress_callback: Callable[[HashProgress], None] | None,
    ) -> None:
        if progress_callback is None:
            return
        percent = 100.0 if total == 0 else min(100.0, processed / total * 100.0)
        progress_callback(HashProgress(processed, total, percent))

    @staticmethod
    def _file_identity(stat_result: Any) -> tuple[int | None, int | None]:
        return (
            getattr(stat_result, "st_dev", None),
            getattr(stat_result, "st_ino", None),
        )
