"""A bounded frame preview from a private copy of registered video evidence."""

import base64
import hashlib
import math
from datetime import UTC, datetime
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import BoundedSemaphore
from typing import Any
from uuid import uuid4

from apex_forensic.adapters.artifacts.media import _ffmpeg_sample_frame, _ffprobe_metadata
from apex_forensic.adapters.filesystem.content import EvidenceFileContent
from apex_forensic.domain.errors import ApexError, ValidationError

_SLOTS = BoundedSemaphore(2)
MAX_VIDEO_BYTES = 512 * 1024 * 1024


class VideoInspectionService:
    def __init__(self, repository: Any) -> None:
        self.repository = repository

    def inspect(
        self,
        *,
        case_id: str,
        resource_type: str,
        resource_id: str,
        timestamp_seconds: float = 0,
        max_dimension: int = 1536,
    ) -> dict[str, Any]:
        if not math.isfinite(timestamp_seconds) or not 0 <= timestamp_seconds <= 604800:
            raise ValidationError("Invalid frame time.")
        if not 256 <= max_dimension <= 2048:
            raise ValidationError("Invalid frame dimension.")
        expected_hash = None
        source_id = resource_id
        if resource_type == "ARTIFACT":
            artifact = self.repository.get_artifact(resource_id)
            if artifact is None or artifact.case_id != case_id:
                raise ApexError("CONTEXT_SCOPE_MISMATCH", "error.context_scope_mismatch")
            if artifact.artifact_type.value != "MEDIA_VIDEO":
                raise ApexError("MEDIA_FORMAT_UNSUPPORTED", "error.media_format_unsupported")
            source_id = artifact.source_file_node_id
            expected_hash = artifact.fields.get("thumbnail_cache", {}).get("source_content_sha256")
        elif resource_type != "FILE_SYSTEM_NODE":
            raise ValidationError("Invalid video resource type.")
        node = self.repository.get_fs_node(source_id)
        if node is None or node.case_id != case_id:
            raise ApexError("CONTEXT_SCOPE_MISMATCH", "error.context_scope_mismatch")
        evidence = self.repository.get_evidence(node.evidence_id)
        if evidence is None or evidence.case_id != case_id:
            raise ApexError("CONTEXT_SCOPE_MISMATCH", "error.context_scope_mismatch")
        if not EvidenceFileContent.supports(evidence, node):
            raise ApexError("MEDIA_SOURCE_UNAVAILABLE", "error.media_source_unavailable")
        with _SLOTS, TemporaryDirectory(prefix="apex-video-") as temp:
            path = Path(temp) / "source"
            digest = hashlib.sha256()
            count = 0
            with path.open("xb") as output:
                for chunk in EvidenceFileContent.chunks(evidence, node, limit=MAX_VIDEO_BYTES):
                    output.write(chunk)
                    digest.update(chunk)
                    count += len(chunk)
            source_hash = digest.hexdigest()
            if expected_hash and expected_hash != source_hash:
                raise ApexError("MEDIA_SOURCE_CHANGED", "error.media_source_changed")
            metadata = _ffprobe_metadata(file_path=path, media_kind="VIDEO")
            width = metadata["metadata"].get("width")
            height = metadata["metadata"].get("height")
            if not isinstance(width, int) or not isinstance(height, int) or min(width, height) <= 0:
                raise ApexError("VIDEO_FRAME_FAILED", "error.video_frame_failed")
            if width * height > 33_177_600:  # 8K UHD; reject before decoding large frames.
                raise ApexError("VIDEO_LIMIT_EXCEEDED", "error.video_limit_exceeded")
            try:
                frame = _ffmpeg_sample_frame(
                    file_path=path,
                    timestamp_seconds=timestamp_seconds,
                    max_dimension=max_dimension,
                    include_content=True,
                )
            except OSError as exc:
                raise ApexError("VIDEO_FRAME_FAILED", "error.video_frame_failed") from exc
            if frame["status"] != "GENERATED":
                code = (
                    "CAPABILITY_UNAVAILABLE"
                    if frame["status"] == "CAPABILITY_UNAVAILABLE"
                    else "VIDEO_FRAME_FAILED"
                )
                raise ApexError(code, f"error.{code.lower()}")
            content = frame.pop("content_bytes")
            return {
                "result_id": str(uuid4()),
                "case_id": case_id,
                "evidence_id": node.evidence_id,
                "source_id": node.node_id,
                "source_revision": node.index_revision,
                "source_relative_path": node.original_relative_path,
                "source_sha256": source_hash,
                "source_size": count,
                "timestamp_seconds_requested": timestamp_seconds,
                "seek_semantics": "FIRST_DECODED_FRAME_AT_OR_AFTER_REQUESTED_TIME",
                "max_dimension": max_dimension,
                "frame_sha256": frame["sha256"],
                "metadata": metadata["metadata"],
                "warnings": metadata["warnings"],
                "image_url": "data:image/png;base64," + base64.b64encode(content).decode("ascii"),
                "semantic_category": "DERIVED_ANALYSIS",
                "created_at": datetime.now(UTC).isoformat(),
            }
