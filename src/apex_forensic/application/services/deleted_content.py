"""TSK logical recovery also covers resident/compressed/sparse default data streams."""

import hashlib
from pathlib import Path
from typing import Any

from apex_forensic.adapters.filesystem.content import regular_path
from apex_forensic.adapters.filesystem.pytsk import PyTskFileSystemProvider
from apex_forensic.domain.errors import OperationCancelledError, ValidationError
from apex_forensic.jobs import CancellationToken


def recover_logical(
    images: Any,
    node: Any,
    *,
    output_root: Path,
    filename: str | None,
    overwrite: bool,
    cancellation_token: CancellationToken | None,
) -> dict[str, Any]:
    evidence = images._get_evidence(node.evidence_id)
    regular_path(evidence.source_path)
    output = images._safe_output_path(
        output_root, filename or f"{node.original_name}.recovered", overwrite=overwrite
    )
    temp = images._temporary_output_path(output)
    digest, copied, cursor = hashlib.sha256(), 0, 0
    missing: list[dict[str, int]] = []

    def check_cancel() -> None:
        if cancellation_token and cancellation_token.is_cancelled:
            raise OperationCancelledError("Deleted file recovery cancelled.")

    try:
        with (
            PyTskFileSystemProvider().open_file(evidence, node, allow_deleted=True) as handle,
            temp.open("wb") as dest,
        ):
            while cursor < node.file_size:
                check_cancel()
                count = min(1024 * 1024, node.file_size - cursor)
                try:
                    data = bytes(handle.read_random(cursor, count))
                except OSError:
                    data = b""
                copied += len(data)
                if len(data) != count:
                    missing.append(
                        {"file_offset": cursor + len(data), "byte_length": count - len(data)}
                    )
                    data += bytes(count - len(data))
                dest.write(data)
                digest.update(data)
                cursor += count
        if copied == 0:
            raise ValidationError("Deleted file recovery produced no readable bytes.")
        check_cancel()
        images._publish_output(temp, output, overwrite=overwrite)
    finally:
        temp.unlink(missing_ok=True)
    sha256 = digest.hexdigest()
    images._audit_export(
        evidence_id=node.evidence_id,
        output_path=output,
        sha256=sha256,
        action="Deleted logical file recovered",
        notes=f"node_id={node.node_id}; recovered_bytes={copied}; missing_ranges={len(missing)}",
    )
    return {
        "node_id": node.node_id,
        "evidence_id": node.evidence_id,
        "output_path": str(output),
        "logical_size": node.file_size,
        "output_size": cursor,
        "recovered_bytes": copied,
        "missing_ranges": missing,
        "missing_range_policy": "ZERO_FILL",
        "sha256": sha256,
        "partial": bool(missing),
        "recovery_method": "TSK_LOGICAL_DATA_STREAM",
        "warnings": ["DELETED_CONTENT_MAY_HAVE_BEEN_OVERWRITTEN"],
        "source": {"provider_id": node.provider_id, "raw_locator": node.raw_locator},
    }
