"""Read and export named NTFS data streams without conflating them with file data."""

import hashlib
from pathlib import Path
from typing import Any

from apex_forensic.adapters.filesystem.content import regular_path
from apex_forensic.adapters.filesystem.pytsk import PyTskFileSystemProvider
from apex_forensic.application.services.context import SafeRawRangeReader
from apex_forensic.application.services.evidence_image import EvidenceImageService
from apex_forensic.domain.errors import OperationCancelledError, ValidationError
from apex_forensic.jobs import CancellationToken


class FileStreamService:
    def __init__(self, repository: Any, images: EvidenceImageService) -> None:
        self.repository = repository
        self.images = images

    def source(self, case_id: str, node_id: str) -> tuple[Any, Any]:
        node = self.repository.get_fs_node(node_id)
        if node is None or node.case_id != case_id:
            raise ValidationError("File is outside this case.", target="node_id")
        evidence = self.repository.get_evidence(node.evidence_id)
        if evidence is None or evidence.case_id != case_id:
            raise ValidationError("Evidence is outside this case.", target="node_id")
        regular_path(evidence.source_path)
        return evidence, node

    @staticmethod
    def _streams(handle: Any) -> list[dict[str, Any]]:
        result = []
        for attr in handle:
            info = attr.info
            if int(info.type) != 128:  # NTFS $DATA, not file-name/index/bitmap attributes.
                continue
            raw = info.name or b""
            name = raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else str(raw)
            result.append(
                {
                    "id": int(info.id),
                    "type": 128,
                    "name": name,
                    "size": int(info.size),
                    "is_default": not name,
                }
            )
        return result

    def list(self, *, case_id: str, node_id: str) -> dict[str, Any]:
        evidence, node = self.source(case_id, node_id)
        with PyTskFileSystemProvider().open_file(evidence, node) as handle:
            return {"node_id": node_id, "streams": self._streams(handle)}

    @staticmethod
    def _selected(handle: Any, stream_id: int) -> dict[str, Any]:
        for stream in FileStreamService._streams(handle):
            if stream["id"] == stream_id:
                return stream
        raise ValidationError("The requested data stream does not exist.", target="stream_id")

    def read(
        self, *, case_id: str, node_id: str, stream_id: int, offset: int = 0, length: int = 4096
    ) -> dict[str, Any]:
        if offset < 0 or not 1 <= length <= 1024 * 1024:
            raise ValidationError("Invalid stream range.")
        evidence, node = self.source(case_id, node_id)
        with PyTskFileSystemProvider().open_file(evidence, node) as handle:
            stream = self._selected(handle, stream_id)
            if offset > stream["size"]:
                raise ValidationError("Stream offset is beyond EOF.")
            count = min(length, stream["size"] - offset)
            data = (
                bytes(handle.read_random(offset, count, type=128, id=stream_id)) if count else b""
            )
        text, _ = SafeRawRangeReader._text_preview(data, None)
        return {
            "node_id": node_id,
            "stream": stream,
            "returned_offset": offset,
            "returned_length": len(data),
            "total_length": stream["size"],
            "hex_preview": data[:4096].hex(),
            "text_preview": text,
            "truncated": len(data) > 4096,
            "hash": {"range_sha256": hashlib.sha256(data).hexdigest()},
            "raw_locator": {
                **node.raw_locator,
                "attribute_type": 128,
                "attribute_id": stream_id,
                "stream_name": stream["name"],
            },
        }

    def export(
        self,
        *,
        case_id: str,
        node_id: str,
        stream_id: int,
        output_root: Path,
        cancellation_token: CancellationToken | None = None,
    ) -> dict[str, Any]:
        evidence, node = self.source(case_id, node_id)
        output = self.images._safe_output_path(
            output_root, f"{node.original_name}.stream-{stream_id}.bin", overwrite=False
        )
        temp = self.images._temporary_output_path(output)
        digest, count = hashlib.sha256(), 0
        try:
            with (
                PyTskFileSystemProvider().open_file(evidence, node) as handle,
                temp.open("wb") as dest,
            ):
                stream = self._selected(handle, stream_id)
                while count < stream["size"]:
                    if cancellation_token and cancellation_token.is_cancelled:
                        raise OperationCancelledError("Stream export cancelled.")
                    chunk = bytes(
                        handle.read_random(
                            count, min(1024 * 1024, stream["size"] - count), type=128, id=stream_id
                        )
                    )
                    if not chunk:
                        raise ValidationError("Stream changed during export.")
                    dest.write(chunk)
                    digest.update(chunk)
                    count += len(chunk)
            if cancellation_token and cancellation_token.is_cancelled:
                raise OperationCancelledError("Stream export cancelled.")
            self.images._publish_output(temp, output, overwrite=False)
        finally:
            temp.unlink(missing_ok=True)
        sha256 = digest.hexdigest()
        self.images._audit_export(
            evidence_id=evidence.evidence_id,
            output_path=output,
            sha256=sha256,
            action="NTFS data stream exported",
            notes=f"node_id={node_id}; attribute_id={stream_id}",
        )
        return {
            "node_id": node_id,
            "stream": stream,
            "output_path": str(output),
            "exported_bytes": count,
            "sha256": sha256,
        }
