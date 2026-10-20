"""Persisted physical-source identity for bounded disk-image reads.

This is a change detector, not a replacement for explicit full-source hashing.
Use Path.stat consistently: Windows stat/fstat can disagree on ctime semantics.
"""

import stat
from pathlib import Path
from typing import Any

from apex_forensic.adapters.evidence.ewf import EwfEvidenceReader
from apex_forensic.domain.enums import EvidenceFormat
from apex_forensic.domain.errors import ApexError, RawReadError

SOURCE_IDENTITY_KEY = "source_identity"


def capture_source_identity(path: Path, evidence_format: EvidenceFormat) -> dict[str, Any]:
    """Capture every physical segment, including identity and mutation timestamps."""
    try:
        paths = (
            EwfEvidenceReader._discover_segments(path)
            if evidence_format is EvidenceFormat.E01
            else (path,)
        )
        sources = []
        for source in paths:
            source = source.absolute()
            for component in (*reversed(source.parents), source):
                info = component.lstat()
                if stat.S_ISLNK(info.st_mode) or (
                    getattr(info, "st_file_attributes", 0)
                    & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
                ):
                    raise RawReadError("RAW_SOURCE_CHANGED", "Source links are not followed.")
            info = source.stat()
            if not stat.S_ISREG(info.st_mode):
                raise RawReadError("RAW_SOURCE_CHANGED", "Image source is not a regular file.")
            sources.append(
                {
                    "path": str(source),
                    "size": info.st_size,
                    "mtime_ns": info.st_mtime_ns,
                    "ctime_ns": info.st_ctime_ns,
                    "device": info.st_dev,
                    "inode": info.st_ino,
                }
            )
        return {"version": 1, "format": evidence_format.value, "sources": sources}
    except (OSError, ApexError) as error:
        raise RawReadError(
            "RAW_SOURCE_CHANGED", "Image source or segment chain is unavailable or changed."
        ) from error


def assert_source_identity(
    path: Path, evidence_format: EvidenceFormat, expected: object
) -> None:
    """Never adopt the current source silently when a persisted baseline is absent."""
    if not isinstance(expected, dict) or expected.get("version") != 1:
        raise RawReadError(
            "RAW_SOURCE_CHANGED",
            "Image identity is missing; validate legacy single-file evidence with SHA256 "
            "or register the source again before reading.",
            details={"reason": "SOURCE_IDENTITY_REQUIRED"},
        )
    if capture_source_identity(path, evidence_format) != expected:
        raise RawReadError(
            "RAW_SOURCE_CHANGED",
            "Image source differs from its registered identity; do not reuse its index.",
        )
