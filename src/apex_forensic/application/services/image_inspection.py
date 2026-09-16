"""Bounded, read-only pixel inspection of registered logical image evidence."""

from __future__ import annotations

import base64
import hashlib
import importlib
import stat
from datetime import UTC, datetime
from io import BytesIO
from pathlib import Path, PurePosixPath
from threading import BoundedSemaphore
from typing import Any
from uuid import uuid4

from apex_forensic.constants import ENGINE_VERSION
from apex_forensic.domain.errors import ApexError

MAX_IMAGE_BYTES = 64 * 1024 * 1024
MAX_IMAGE_PIXELS = 25_000_000
_DECODE_SLOTS = BoundedSemaphore(2)


def _error(code: str) -> ApexError:
    return ApexError(code, f"error.{code.lower()}")


class ImageInspectionService:
    """Resolve IDs inside the case, decode original pixels, and return derived results.

    No renderer-supplied path or existing thumbnail path is opened. Pixel order is
    the first stored frame, without EXIF rotation; previews never feed extraction.
    """

    def __init__(self, repository: Any) -> None:
        self._repository = repository

    def inspect(
        self,
        *,
        case_id: str,
        resource_type: str,
        resource_id: str,
        action: str = "PREVIEW",
        channel: str = "RGB",
        bit: int | None = None,
        channels: str = "RGB",
        bit_order: str = "MSB_FIRST",
        pixel_offset: int = 0,
        byte_limit: int = 512,
        max_dimension: int = 1536,
    ) -> dict[str, Any]:
        if (
            action not in {"PREVIEW", "EXTRACT"}
            or channel not in {"RGB", "R", "G", "B", "A"}
            or (bit is not None
            and not 0 <= bit <= 7)
            or not channels
            or len(set(channels)) != len(channels)
            or any(c not in "RGBA" for c in channels)
            or bit_order not in {"MSB_FIRST", "LSB_FIRST"}
            or not 0 <= pixel_offset < MAX_IMAGE_PIXELS
            or not 1 <= byte_limit <= 65536
            or not 256 <= max_dimension <= 4096
        ):
            raise _error("VALIDATION_ERROR")
        node, expected_hash = self._source(case_id, resource_type, resource_id)
        evidence = self._repository.get_evidence(node.evidence_id)
        if evidence is None or evidence.case_id != case_id:
            raise _error("CONTEXT_SCOPE_MISMATCH")
        try:
            path = self._path(evidence.source_path, node)
        except OSError as error:
            raise _error("MEDIA_SOURCE_UNAVAILABLE") from error
        with _DECODE_SLOTS:
            try:
                with path.open("rb") as handle:
                    content = handle.read(MAX_IMAGE_BYTES + 1)
                if len(content) > MAX_IMAGE_BYTES:
                    raise _error("MEDIA_LIMIT_EXCEEDED")
                source_hash = hashlib.sha256(content).hexdigest()
                if expected_hash and source_hash != expected_hash:
                    raise _error("MEDIA_SOURCE_CHANGED")
                try:
                    pillow = importlib.import_module("PIL.Image")
                except ImportError as error:
                    raise _error("CAPABILITY_UNAVAILABLE") from error
                with pillow.open(BytesIO(content)) as image:
                    if image.width * image.height > MAX_IMAGE_PIXELS:
                        raise _error("MEDIA_LIMIT_EXCEEDED")
                    if image.format not in {"PNG", "JPEG", "GIF", "TIFF", "BMP", "WEBP"}:
                        raise _error("MEDIA_FORMAT_UNSUPPORTED")
                    provenance = {
                        "result_id": str(uuid4()),
                        "case_id": case_id,
                        "evidence_id": node.evidence_id,
                        "source_id": node.node_id,
                        "resource_type": resource_type,
                        "resource_id": resource_id,
                        "source_relative_path": node.original_relative_path,
                        "source_revision": node.index_revision,
                        "source_sha256": source_hash,
                        "source_size": len(content),
                        "width": image.width,
                        "height": image.height,
                        "format": image.format,
                        "color_mode": image.mode,
                        "frame": 0,
                        "frame_count": getattr(image, "n_frames", 1),
                        "pixel_order": "ROW_MAJOR_LEFT_TO_RIGHT_TOP_TO_BOTTOM",
                        "orientation": "STORED_PIXELS_NO_EXIF_TRANSPOSE",
                        "pixel_conversion": "RGBA_8_BIT",
                        "analyzer_id": "apex.image_inspection",
                        "analyzer_version": ENGINE_VERSION,
                        "created_at": datetime.now(UTC).isoformat(),
                        "semantic_category": "DERIVED_ANALYSIS",
                    }
                    with image.convert("RGBA") as pixels:
                        if action == "EXTRACT":
                            return self._extract(
                                pixels,
                                provenance,
                                channels,
                                bit if bit is not None else 0,
                                bit_order,
                                pixel_offset,
                                byte_limit,
                            )
                        preview = (
                            pixels.convert("RGB")
                            if channel == "RGB"
                            else (pixels.getchannel(channel))
                        )
                        try:
                            if bit is not None:
                                transformed = preview.point(
                                    [255 if value & (1 << bit) else 0 for value in range(256)]
                                    * len(preview.getbands())
                                )
                                preview.close()
                                preview = transformed
                            preview.thumbnail(
                                (max_dimension, max_dimension), pillow.Resampling.NEAREST
                            )
                            output = BytesIO()
                            preview.save(output, format="PNG")
                            data = output.getvalue()
                            if len(data) > 16 * 1024 * 1024:
                                raise _error("MEDIA_LIMIT_EXCEEDED")
                            return {
                                **provenance,
                                "action": action,
                                "channel": channel,
                                "bit": bit,
                                "preview_width": preview.width,
                                "preview_height": preview.height,
                                "is_resized": preview.size != image.size,
                                "preview_sha256": hashlib.sha256(data).hexdigest(),
                                "image_url": "data:image/png;base64,"
                                + base64.b64encode(data).decode("ascii"),
                            }
                        finally:
                            preview.close()
            except ApexError:
                raise
            except (OSError, ValueError, SyntaxError) as error:
                raise _error("MEDIA_DECODE_FAILED") from error
            except Exception as error:
                # Pillow's decompression-bomb exception is optional with the decoder.
                if type(error).__name__ == "DecompressionBombError":
                    raise _error("MEDIA_LIMIT_EXCEEDED") from error
                raise

    def _source(self, case_id: str, resource_type: str, resource_id: str) -> tuple[Any, str | None]:
        expected = None
        if resource_type == "ARTIFACT":
            artifact = self._repository.get_artifact(resource_id)
            if artifact is None or artifact.case_id != case_id:
                raise _error("CONTEXT_SCOPE_MISMATCH")
            if artifact.artifact_type.value != "MEDIA_IMAGE":
                raise _error("MEDIA_FORMAT_UNSUPPORTED")
            resource_id = artifact.source_file_node_id
            expected = artifact.fields.get("thumbnail_cache", {}).get("source_content_sha256")
        elif resource_type != "FILE_SYSTEM_NODE":
            raise _error("MEDIA_FORMAT_UNSUPPORTED")
        node = self._repository.get_fs_node(resource_id)
        if node is None or node.case_id != case_id:
            raise _error("CONTEXT_SCOPE_MISMATCH")
        if node.node_type.value != "FILE" or node.is_link:
            raise _error("MEDIA_SOURCE_UNAVAILABLE")
        return node, expected

    @staticmethod
    def _path(source: Path, node: Any) -> Path:
        # Reject links in every component, including a replaced evidence root.
        source = Path(source).absolute()
        relative = PurePosixPath(node.original_relative_path.replace("\\", "/"))
        if relative.is_absolute() or ".." in relative.parts:
            raise _error("CONTEXT_SCOPE_MISMATCH")
        if not source.is_dir() and relative.as_posix() not in {"", "."}:
            raise _error("MEDIA_SOURCE_UNAVAILABLE")
        candidate = source.joinpath(*relative.parts) if source.is_dir() else source
        try:
            candidate.absolute().relative_to(source if source.is_dir() else source.parent)
        except ValueError as error:
            raise _error("CONTEXT_SCOPE_MISMATCH") from error
        for part in (*reversed(candidate.parents), candidate):
            info = part.lstat()
            if part.is_symlink() or (
                getattr(info, "st_file_attributes", 0)
                & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
            ):
                raise _error("MEDIA_SOURCE_UNAVAILABLE")
        if not candidate.is_file():
            raise _error("MEDIA_SOURCE_UNAVAILABLE")
        return candidate

    @staticmethod
    def _extract(
        pixels: Any,
        provenance: dict[str, Any],
        channels: str,
        bit: int,
        bit_order: str,
        pixel_offset: int,
        byte_limit: int,
    ) -> dict[str, Any]:
        total_pixels = pixels.width * pixels.height
        if pixel_offset >= total_pixels:
            raise _error("MEDIA_OFFSET_OUT_OF_RANGE")
        indices = ["RGBA".index(channel) for channel in channels]
        available_bits = (total_pixels - pixel_offset) * len(indices)
        wanted_bits = min(byte_limit * 8, available_bits // 8 * 8)
        values = bytearray()
        accumulator = count = consumed = 0
        for position in range(pixel_offset, total_pixels):
            if consumed >= wanted_bits:
                break
            pixel = pixels.getpixel((position % pixels.width, position // pixels.width))
            for index in indices:
                if consumed >= wanted_bits:
                    break
                value = (pixel[index] >> bit) & 1
                shift = 7 - count if bit_order == "MSB_FIRST" else count
                accumulator |= value << shift
                count += 1
                consumed += 1
                if count == 8:
                    values.append(accumulator)
                    accumulator = count = 0
        data = bytes(values)
        return {
            **provenance,
            "action": "EXTRACT",
            "channels": channels,
            "bit": bit,
            "bit_order": bit_order,
            "pixel_offset": pixel_offset,
            "byte_limit": byte_limit,
            "returned_bytes": len(data),
            "available_bytes": available_bits // 8,
            "has_more": available_bits // 8 > len(data),
            "unused_tail_bits": available_bits % 8,
            "output_sha256": hashlib.sha256(data).hexdigest(),
            "hex": data.hex(),
            "text": data.decode("utf-8", errors="replace"),
            "text_encoding": "UTF-8 (invalid sequences replaced; hex is lossless)",
        }
