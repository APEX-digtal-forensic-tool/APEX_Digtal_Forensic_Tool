"""Registration-time identity of image files, checked before every image read.

A content hash of a multi-gigabyte image on each 4 KiB read is not affordable, so the
baseline is filesystem identity: size, modification time and file id of the image and,
for EWF, every segment. This rejects edits, truncation and replacement through normal
file APIs. A change that also restores the original mtime is only caught by
`custody.verify` (full SHA-256), which remains the integrity proof.
"""

from pathlib import Path
from typing import Any

from apex_forensic.domain.enums import EvidenceFormat
from apex_forensic.domain.errors import RawReadError
from apex_forensic.domain.models import Evidence

IDENTITY_KEY = "source_identity"


def _files(path: Path, evidence_type: EvidenceFormat) -> tuple[Path, ...]:
    if evidence_type is EvidenceFormat.E01:
        from apex_forensic.adapters.evidence.ewf import EwfEvidenceReader

        return EwfEvidenceReader._discover_segments(path)
    return (path,)


def source_identity(path: Path, evidence_type: EvidenceFormat) -> dict[str, Any]:
    files = []
    for item in _files(path, evidence_type):
        stat = item.stat()
        files.append(
            {
                "name": item.name,
                "size": stat.st_size,
                "mtime_ns": stat.st_mtime_ns,
                "file_id": stat.st_ino,
            }
        )
    return {"version": 1, "files": files}


def check_source_identity(evidence: Evidence) -> None:
    """Refuse to read an image whose files differ from the registered baseline."""
    expected = evidence.metadata.get(IDENTITY_KEY)
    if expected is None:
        # Evidence registered before baselines existed; per-read checks still apply.
        return
    try:
        current = source_identity(evidence.source_path, evidence.evidence_type)
    except OSError as error:
        raise RawReadError(
            "RAW_SOURCE_CHANGED", "Registered image files are no longer readable."
        ) from error
    if current != expected:
        raise RawReadError(
            "RAW_SOURCE_CHANGED",
            "Image files changed after registration; verify integrity and re-register.",
        )
