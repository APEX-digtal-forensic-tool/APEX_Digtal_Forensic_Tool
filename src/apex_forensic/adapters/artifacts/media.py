"""Media metadata artifact analyzer for Phase 5."""

from __future__ import annotations

import hashlib
import json
import shutil
import struct
import subprocess
import threading
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from apex_forensic._time import to_json_timestamp
from apex_forensic.adapters.artifacts.windows.common import (
    issue,
    make_artifact,
    make_raw_locator,
    sha256_hex,
    source_shell,
)
from apex_forensic.constants import ENGINE_VERSION
from apex_forensic.domain.enums import (
    ArtifactParseStatus,
    ArtifactSourceKind,
    ArtifactType,
    FileSystemNodeType,
)
from apex_forensic.domain.models import (
    ArtifactAnalysisResult,
    ArtifactCapability,
    ArtifactRecord,
    ArtifactSource,
    Evidence,
    FileSystemNode,
)
from apex_forensic.domain.services.canonical import canonical_sha256

_IMAGE_EXTENSIONS = {"jpg", "jpeg", "png", "gif", "tif", "tiff", "bmp", "webp"}
_VIDEO_EXTENSIONS = {"mp4", "m4v", "mov", "3gp", "3g2", "avi", "mkv", "webm"}
_AUDIO_EXTENSIONS = {"wav", "mp3", "m4a", "ogg", "flac"}
_MAX_LOCATOR_LENGTH = 1_048_576
_MAX_MEDIA_READ_BYTES = 64 * 1024 * 1024
_MAX_IMAGE_PIXELS = 178_956_970
_FFPROBE_TIMEOUT_SECONDS = 10
_MAX_FFPROBE_JSON_BYTES = 1_048_576
_MAC_EPOCH = datetime(1904, 1, 1, tzinfo=UTC)


@dataclass(frozen=True, slots=True)
class _BoundedProcessResult:
    returncode: int | None
    stdout: bytes
    stderr: bytes
    timed_out: bool = False
    limit_stream: str | None = None

_TIFF_TYPE_SIZES = {
    1: 1,
    2: 1,
    3: 2,
    4: 4,
    5: 8,
    7: 1,
    9: 4,
    10: 8,
}

_IFD0_TAGS = {
    0x0100: "image_width",
    0x0101: "image_height",
    0x010F: "camera_make",
    0x0110: "camera_model",
    0x0112: "orientation",
    0x0132: "datetime",
}
_EXIF_TAGS = {
    0x9003: "datetime_original",
    0x9004: "datetime_digitized",
    0x9010: "offset_time",
    0x9011: "offset_time_original",
    0x9012: "offset_time_digitized",
    0x9290: "subsec_time",
    0xA002: "pixel_x_dimension",
    0xA003: "pixel_y_dimension",
}
_GPS_TAGS = {
    0x0001: "latitude_ref",
    0x0002: "latitude",
    0x0003: "longitude_ref",
    0x0004: "longitude",
    0x0005: "altitude_ref",
    0x0006: "altitude",
    0x0007: "timestamp",
    0x001D: "datestamp",
}


class MediaMetadataAnalyzer:
    """Read-only image/video metadata analyzer."""

    analyzer_id = "media.metadata"
    analyzer_version = ENGINE_VERSION

    @property
    def parser_backend(self) -> str:
        return "apex.media_metadata"

    @property
    def parser_backend_version(self) -> str:
        return ENGINE_VERSION

    def capabilities(self) -> ArtifactCapability:
        return ArtifactCapability(
            analyzer_id=self.analyzer_id,
            analyzer_version=self.analyzer_version,
            parser_backend=self.parser_backend,
            parser_backend_version=self.parser_backend_version,
            supported_source_kinds=(
                ArtifactSourceKind.IMAGE_FILE,
                ArtifactSourceKind.VIDEO_FILE,
                ArtifactSourceKind.AUDIO_FILE,
            ),
            supported_artifact_types=(
                ArtifactType.MEDIA_IMAGE,
                ArtifactType.MEDIA_VIDEO,
                ArtifactType.MEDIA_AUDIO,
            ),
            capabilities=(
                "MEDIA_CLASSIFICATION",
                "IMAGE_DIMENSIONS",
                "JPEG_EXIF",
                "JPEG_EXIF_GPS",
                "PNG_GIF_TIFF_DIMENSIONS",
                "MP4_DURATION_CODEC",
                "FFPROBE_VIDEO_AUDIO_METADATA_PORT",
                "THUMBNAIL_CACHE_DERIVATIVE_METADATA",
            ),
            unavailable_capabilities=(
                "RASTER_THUMBNAIL_RENDERING_WITHOUT_IMAGE_LIBRARY",
                "OCR",
                "STT",
                *_ffprobe_unavailable_capabilities(),
            ),
            warnings=(
                {
                    "code": "RASTER_THUMBNAIL_RENDERING_UNAVAILABLE",
                    "message_key": "warning.media.thumbnail_rendering_unavailable",
                    "developer_message": (
                        "Phase 5 stores hash-verifiable thumbnail cache derivative metadata; "
                        "pixel rendering is deferred until an image backend is available."
                    ),
                },
            ),
            metadata={
                "image_extensions": sorted(_IMAGE_EXTENSIONS),
                "video_extensions": sorted(_VIDEO_EXTENSIONS),
                "audio_extensions": sorted(_AUDIO_EXTENSIONS),
                "ffprobe": _ffprobe_capability(),
            },
        )

    def detect_source(self, node: FileSystemNode) -> ArtifactSource | None:
        if node.node_type is not FileSystemNodeType.FILE:
            return None
        extension = (node.extension or "").casefold()
        if extension in _IMAGE_EXTENSIONS:
            return source_shell(
                node=node,
                source_kind=ArtifactSourceKind.IMAGE_FILE,
                analyzer_id=self.analyzer_id,
                analyzer_version=self.analyzer_version,
                parser_backend=self.parser_backend,
                parser_backend_version=self.parser_backend_version,
                priority=60,
            )
        if extension in _VIDEO_EXTENSIONS:
            return source_shell(
                node=node,
                source_kind=ArtifactSourceKind.VIDEO_FILE,
                analyzer_id=self.analyzer_id,
                analyzer_version=self.analyzer_version,
                parser_backend=self.parser_backend,
                parser_backend_version=self.parser_backend_version,
                priority=65,
            )
        if extension in _AUDIO_EXTENSIONS:
            return source_shell(
                node=node,
                source_kind=ArtifactSourceKind.AUDIO_FILE,
                analyzer_id=self.analyzer_id,
                analyzer_version=self.analyzer_version,
                parser_backend=self.parser_backend,
                parser_backend_version=self.parser_backend_version,
                priority=66,
            )
        return None

    def supports_source(self, source: ArtifactSource) -> bool:
        return source.source_kind in {
            ArtifactSourceKind.IMAGE_FILE,
            ArtifactSourceKind.VIDEO_FILE,
            ArtifactSourceKind.AUDIO_FILE,
        }

    def analyze(
        self,
        *,
        evidence: Evidence,
        node: FileSystemNode,
        source: ArtifactSource,
        file_path: Path,
        item_budget: int | None = None,
    ) -> ArtifactAnalysisResult:
        del item_budget
        try:
            file_size = file_path.stat().st_size
            content_sha256 = _sha256_file(file_path)
            data = _read_prefix(file_path, _MAX_MEDIA_READ_BYTES)
        except OSError as error:
            return ArtifactAnalysisResult(
                errors=(
                    issue(
                        severity="ERROR",
                        code="MEDIA_READ_FAILED",
                        message_key="error.media.read_failed",
                        developer_message="Media file could not be read.",
                        node=node,
                        details={"error": str(error)},
                    ),
                ),
                parse_status=ArtifactParseStatus.FAILED,
            )

        parsed = _parse_media(
            data=data,
            node=node,
            source=source,
            file_path=file_path,
            content_sha256=content_sha256,
            file_size=file_size,
            read_truncated=file_size > len(data),
        )
        cache_entry = _thumbnail_cache_entry(
            evidence=evidence,
            node=node,
            source=source,
            parsed=parsed,
        )
        artifact = _build_media_artifact(
            evidence=evidence,
            node=node,
            source=source,
            data=data,
            parsed=parsed,
            thumbnail_cache=cache_entry["reference"],
        )
        warnings = tuple(
            issue(
                severity="WARNING",
                code=str(warning["code"]),
                message_key=str(warning["message_key"]),
                developer_message=str(warning["developer_message"]),
                node=node,
                details=dict(warning.get("details", {})),
                artifact_id=artifact.artifact_id,
            )
            for warning in artifact.warnings
        )
        return ArtifactAnalysisResult(
            artifacts=(artifact,),
            warnings=warnings,
            cache_entries=(cache_entry["entry"],),
            coverage={
                "media_kind": parsed["media_kind"],
                "format": parsed["format"],
                "file_size": file_size,
            },
            parse_status=artifact.parse_status,
        )


def _parse_media(
    *,
    data: bytes,
    node: FileSystemNode,
    source: ArtifactSource,
    file_path: Path,
    content_sha256: str,
    file_size: int,
    read_truncated: bool,
) -> dict[str, Any]:
    media_kind, media_format, mime, confidence = _classify(data, node, source)
    metadata: dict[str, Any] = {}
    warnings: list[dict[str, Any]] = []
    parse_status = ArtifactParseStatus.SUCCESS
    if read_truncated:
        warnings.append(
            {
                "code": "MEDIA_READ_LIMIT_EXCEEDED",
                "message_key": "warning.media.read_limit_exceeded",
                "developer_message": (
                    "Media metadata parsing used a bounded prefix read; metadata may be partial."
                ),
                "details": {"file_size": file_size, "read_limit": _MAX_MEDIA_READ_BYTES},
            }
        )
        parse_status = ArtifactParseStatus.PARTIAL

    if media_kind == "IMAGE":
        image = _parse_image(data, media_format)
        metadata.update(image["metadata"])
        warnings.extend(image["warnings"])
        parse_status = _combine_status(parse_status, image["parse_status"])
        bomb_warning = _decompression_bomb_warning(metadata)
        if bomb_warning is not None:
            warnings.append(bomb_warning)
            parse_status = ArtifactParseStatus.PARTIAL
    elif media_kind == "VIDEO":
        if media_format == "MP4":
            video = _parse_video(data, media_format)
        else:
            video = _ffprobe_metadata(file_path=file_path, media_kind=media_kind)
        metadata.update(video["metadata"])
        warnings.extend(video["warnings"])
        parse_status = _combine_status(parse_status, video["parse_status"])
    elif media_kind == "AUDIO":
        audio = _ffprobe_metadata(file_path=file_path, media_kind=media_kind)
        metadata.update(audio["metadata"])
        warnings.extend(audio["warnings"])
        parse_status = _combine_status(parse_status, audio["parse_status"])
    else:
        warnings.append(
            {
                "code": "MEDIA_FORMAT_UNRECOGNIZED",
                "message_key": "warning.media.format_unrecognized",
                "developer_message": (
                    "Media extension was selected but file magic was unrecognized."
                ),
                "details": {"extension": node.extension, "file_size": file_size},
            }
        )
        parse_status = ArtifactParseStatus.CORRUPT if data else ArtifactParseStatus.UNSUPPORTED

    return {
        "media_kind": media_kind,
        "format": media_format,
        "mime": mime,
        "classification_confidence": confidence,
        "content_sha256": content_sha256,
        "metadata": metadata,
        "warnings": warnings,
        "parse_status": parse_status,
        "file_size": file_size,
        "read_length": len(data),
    }


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_prefix(path: Path, limit: int) -> bytes:
    with path.open("rb") as handle:
        return handle.read(limit)


def _combine_status(left: ArtifactParseStatus, right: ArtifactParseStatus) -> ArtifactParseStatus:
    order = {
        ArtifactParseStatus.SUCCESS: 0,
        ArtifactParseStatus.PARTIAL: 1,
        ArtifactParseStatus.UNSUPPORTED: 2,
        ArtifactParseStatus.CORRUPT: 3,
        ArtifactParseStatus.FAILED: 4,
    }
    return left if order[left] >= order[right] else right


def _decompression_bomb_warning(metadata: dict[str, Any]) -> dict[str, Any] | None:
    width = metadata.get("width")
    height = metadata.get("height")
    if not isinstance(width, int) or not isinstance(height, int):
        return None
    if width <= 0 or height <= 0 or width * height <= _MAX_IMAGE_PIXELS:
        return None
    return {
        "code": "IMAGE_DECOMPRESSION_BOMB_LIMIT",
        "message_key": "warning.media.image_decompression_bomb_limit",
        "developer_message": "Image dimensions exceed the configured safe pixel limit.",
        "details": {"width": width, "height": height, "max_pixels": _MAX_IMAGE_PIXELS},
    }


def _ffprobe_unavailable_capabilities() -> tuple[str, ...]:
    return () if shutil.which("ffprobe") else ("FFPROBE",)


def _ffprobe_capability() -> dict[str, Any]:
    executable = shutil.which("ffprobe")
    if executable is None:
        return {
            "is_available": False,
            "backend_id": "ffprobe",
            "backend_version": None,
            "unavailable_reason": "ffprobe executable was not found on PATH.",
        }
    try:
        completed = _run_bounded_process(
            [executable, "-version"],
            timeout=3,
            max_bytes=_MAX_FFPROBE_JSON_BYTES,
        )
    except OSError as error:
        return {
            "is_available": False,
            "backend_id": "ffprobe",
            "backend_version": None,
            "unavailable_reason": str(error),
        }
    if completed.timed_out:
        return {
            "is_available": False,
            "backend_id": "ffprobe",
            "backend_version": None,
            "unavailable_reason": "ffprobe -version timed out.",
        }
    if completed.limit_stream is not None:
        return {
            "is_available": False,
            "backend_id": "ffprobe",
            "backend_version": None,
            "unavailable_reason": (
                f"ffprobe -version exceeded {_MAX_FFPROBE_JSON_BYTES} bytes on "
                f"{completed.limit_stream}."
            ),
        }
    stdout = completed.stdout.decode("utf-8", errors="replace")
    stderr = completed.stderr.decode("utf-8", errors="replace")
    version_line = (stdout or stderr).splitlines()[0:1]
    return {
        "is_available": completed.returncode == 0,
        "backend_id": "ffprobe",
        "backend_version": version_line[0] if version_line else "unknown",
        "unavailable_reason": None if completed.returncode == 0 else stderr[:300],
    }


def _run_bounded_process(
    args: list[str],
    *,
    timeout: int,
    max_bytes: int,
) -> _BoundedProcessResult:
    process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout = bytearray()
    stderr = bytearray()
    state: dict[str, bool | str | None] = {"timed_out": False, "limit_stream": None}
    lock = threading.Lock()

    def kill_process() -> None:
        with suppress(OSError):
            process.kill()

    def wait_after_kill() -> int | None:
        try:
            return process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            return process.poll()

    def read_stream(stream: Any, stream_name: str, buffer: bytearray) -> None:
        try:
            while True:
                chunk = stream.read(64 * 1024)
                if not chunk:
                    return
                should_kill = False
                with lock:
                    if state["timed_out"] or state["limit_stream"] is not None:
                        should_kill = True
                    else:
                        remaining = max(0, max_bytes - len(buffer))
                        if len(chunk) > remaining:
                            buffer.extend(chunk[:remaining])
                            state["limit_stream"] = stream_name
                            should_kill = True
                        else:
                            buffer.extend(chunk)
                if should_kill:
                    kill_process()
                    return
        finally:
            with suppress(OSError):
                stream.close()

    threads: list[threading.Thread] = []
    if process.stdout is not None:
        threads.append(
            threading.Thread(
                target=read_stream,
                args=(process.stdout, "stdout", stdout),
                daemon=True,
            )
        )
    if process.stderr is not None:
        threads.append(
            threading.Thread(
                target=read_stream,
                args=(process.stderr, "stderr", stderr),
                daemon=True,
            )
        )
    for thread in threads:
        thread.start()

    returncode: int | None
    try:
        returncode = process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        with lock:
            state["timed_out"] = True
        kill_process()
        returncode = wait_after_kill()
    finally:
        if process.poll() is None:
            kill_process()
            wait_after_kill()
        for thread in threads:
            thread.join(timeout=1)

    return _BoundedProcessResult(
        returncode,
        bytes(stdout),
        bytes(stderr),
        timed_out=bool(state["timed_out"]),
        limit_stream=None
        if state["limit_stream"] is None
        else str(state["limit_stream"]),
    )


def _ffprobe_metadata(*, file_path: Path, media_kind: str) -> dict[str, Any]:
    executable = shutil.which("ffprobe")
    if executable is None:
        return {
            "metadata": {},
            "warnings": [
                {
                    "code": "FFPROBE_CAPABILITY_UNAVAILABLE",
                    "message_key": "warning.media.ffprobe_capability_unavailable",
                    "developer_message": (
                        "ffprobe is unavailable; video/audio metadata was not faked."
                    ),
                    "details": {"media_kind": media_kind},
                }
            ],
            "parse_status": ArtifactParseStatus.UNSUPPORTED,
        }
    args = [
        executable,
        "-v",
        "error",
        "-show_format",
        "-show_streams",
        "-of",
        "json",
        str(file_path),
    ]
    try:
        completed = _run_bounded_process(
            args,
            timeout=_FFPROBE_TIMEOUT_SECONDS,
            max_bytes=_MAX_FFPROBE_JSON_BYTES,
        )
    except OSError as error:
        return {
            "metadata": {},
            "warnings": [
                {
                    "code": "FFPROBE_EXECUTION_FAILED",
                    "message_key": "warning.media.ffprobe_execution_failed",
                    "developer_message": "ffprobe could not be executed.",
                    "details": {"error": str(error)},
                }
            ],
            "parse_status": ArtifactParseStatus.FAILED,
        }
    if completed.timed_out:
        return {
            "metadata": {},
            "warnings": [
                {
                    "code": "FFPROBE_TIMEOUT",
                    "message_key": "warning.media.ffprobe_timeout",
                    "developer_message": "ffprobe timed out while reading container metadata.",
                    "details": {"timeout_seconds": _FFPROBE_TIMEOUT_SECONDS},
                }
            ],
            "parse_status": ArtifactParseStatus.FAILED,
        }
    if completed.limit_stream is not None:
        return {
            "metadata": {},
            "warnings": [
                {
                    "code": "FFPROBE_OUTPUT_LIMIT_EXCEEDED",
                    "message_key": "warning.media.ffprobe_output_limit_exceeded",
                    "developer_message": "ffprobe output exceeded the configured safe limit.",
                    "details": {
                        "stream": completed.limit_stream,
                        "max_bytes": _MAX_FFPROBE_JSON_BYTES,
                    },
                }
            ],
            "parse_status": ArtifactParseStatus.PARTIAL,
        }
    if completed.returncode != 0:
        return {
            "metadata": {},
            "warnings": [
                {
                    "code": "FFPROBE_CORRUPT_OR_UNSUPPORTED",
                    "message_key": "warning.media.ffprobe_corrupt_or_unsupported",
                    "developer_message": "ffprobe reported unsupported or corrupt media.",
                    "details": {"stderr": completed.stderr.decode("utf-8", errors="replace")[:500]},
                }
            ],
            "parse_status": ArtifactParseStatus.CORRUPT,
        }
    try:
        payload = json.loads(completed.stdout.decode("utf-8"))
    except json.JSONDecodeError as error:
        return {
            "metadata": {},
            "warnings": [
                {
                    "code": "FFPROBE_JSON_INVALID",
                    "message_key": "warning.media.ffprobe_json_invalid",
                    "developer_message": "ffprobe output was not valid JSON.",
                    "details": {"error": str(error)},
                }
            ],
            "parse_status": ArtifactParseStatus.CORRUPT,
        }
    metadata, warnings = _metadata_from_ffprobe(payload)
    return {
        "metadata": metadata,
        "warnings": warnings,
        "parse_status": ArtifactParseStatus.PARTIAL
        if warnings
        else ArtifactParseStatus.SUCCESS,
    }


def _metadata_from_ffprobe(payload: dict[str, Any]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    metadata: dict[str, Any] = {"stream_count": len(_list(payload.get("streams")))}
    warnings: list[dict[str, Any]] = []
    format_info = _dict(payload.get("format"))
    metadata["container"] = format_info.get("format_name")
    metadata["duration_seconds"] = _float(format_info.get("duration"))
    metadata["bit_rate"] = _int(format_info.get("bit_rate"))
    tags = _dict(format_info.get("tags"))
    creation_time = tags.get("creation_time")
    if isinstance(creation_time, str):
        timestamp, warning = _ffprobe_creation_timestamp(creation_time)
        metadata["media_timestamps"] = [timestamp]
        if warning is not None:
            warnings.append(warning)
    codec_candidates: list[dict[str, Any]] = []
    for stream in _list(payload.get("streams")):
        if not isinstance(stream, dict):
            continue
        codec_type = stream.get("codec_type")
        codec_name = stream.get("codec_name")
        if codec_name is not None:
            codec_candidates.append({"type": codec_type, "codec": codec_name})
        if codec_type == "video":
            metadata["codec"] = codec_name
            metadata["video_codec"] = codec_name
            metadata["width"] = _int(stream.get("width"))
            metadata["height"] = _int(stream.get("height"))
            metadata["frame_rate"] = stream.get("avg_frame_rate") or stream.get("r_frame_rate")
        elif codec_type == "audio":
            metadata["audio_codec"] = codec_name
            metadata["sample_rate"] = _int(stream.get("sample_rate"))
            metadata["channels"] = _int(stream.get("channels"))
    metadata["codec_candidates"] = codec_candidates
    return metadata, warnings


def _ffprobe_creation_timestamp(
    value: str,
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    raw_value = value.strip()
    candidate = {
        "source": "FFPROBE:format.creation_time",
        "raw_value": value,
        "normalized_utc": None,
        "timezone_source": "UNKNOWN",
        "timezone_confidence": "UNKNOWN",
    }
    parse_value = raw_value[:-1] + "+00:00" if raw_value.endswith("Z") else raw_value
    try:
        parsed = datetime.fromisoformat(parse_value)
    except ValueError:
        return candidate, {
            "code": "FFPROBE_TIMESTAMP_INVALID",
            "message_key": "warning.media.ffprobe_timestamp_invalid",
            "developer_message": "ffprobe creation_time was not a valid ISO-8601 timestamp.",
            "details": {"raw_value": value},
        }
    if parsed.tzinfo is None:
        return candidate, {
            "code": "FFPROBE_TIMESTAMP_TIMEZONE_UNKNOWN",
            "message_key": "warning.media.ffprobe_timestamp_timezone_unknown",
            "developer_message": (
                "ffprobe creation_time did not include an explicit timezone and was not "
                "assumed to be UTC."
            ),
            "details": {"raw_value": value},
        }
    candidate["normalized_utc"] = to_json_timestamp(parsed.astimezone(UTC))
    candidate["timezone_source"] = "EXPLICIT_OFFSET"
    candidate["timezone_confidence"] = "HIGH"
    return candidate, None


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _int(value: Any) -> int | None:
    try:
        return None if value is None else int(value)
    except (TypeError, ValueError):
        return None


def _float(value: Any) -> float | None:
    try:
        return None if value is None else float(value)
    except (TypeError, ValueError):
        return None


def _classify(
    data: bytes,
    node: FileSystemNode,
    source: ArtifactSource,
) -> tuple[str, str | None, str | None, str]:
    extension = (node.extension or "").casefold()
    if data.startswith(b"\xff\xd8\xff"):
        return "IMAGE", "JPEG", "image/jpeg", "HIGH"
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "IMAGE", "PNG", "image/png", "HIGH"
    if data.startswith((b"GIF87a", b"GIF89a")):
        return "IMAGE", "GIF", "image/gif", "HIGH"
    if data.startswith((b"II*\x00", b"MM\x00*")):
        return "IMAGE", "TIFF", "image/tiff", "HIGH"
    if data.startswith(b"BM"):
        return "IMAGE", "BMP", "image/bmp", "HIGH"
    if len(data) >= 12 and data[0:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "IMAGE", "WEBP", "image/webp", "HIGH"
    if len(data) >= 12 and data[4:8] == b"ftyp":
        brand = data[8:12].decode("ascii", errors="replace")
        if extension == "m4a":
            return "AUDIO", "M4A", "audio/mp4", "HIGH"
        mime = "video/quicktime" if brand in {"qt  "} or extension == "mov" else "video/mp4"
        return "VIDEO", "MP4", mime, "HIGH"
    if extension in _AUDIO_EXTENSIONS or source.source_kind is ArtifactSourceKind.AUDIO_FILE:
        return "AUDIO", extension.upper() if extension else None, node.mime_candidate, "LOW"
    if source.source_kind is ArtifactSourceKind.IMAGE_FILE or extension in _IMAGE_EXTENSIONS:
        return "IMAGE", None, node.mime_candidate, "LOW"
    if source.source_kind is ArtifactSourceKind.VIDEO_FILE or extension in _VIDEO_EXTENSIONS:
        return "VIDEO", extension.upper() if extension else None, node.mime_candidate, "LOW"
    return "UNKNOWN", None, node.mime_candidate, "UNKNOWN"


def _parse_image(data: bytes, media_format: str | None) -> dict[str, Any]:
    warnings: list[dict[str, Any]] = []
    metadata: dict[str, Any] = {}
    parse_status = ArtifactParseStatus.SUCCESS
    try:
        if media_format == "JPEG":
            metadata.update(_jpeg_metadata(data))
        elif media_format == "PNG":
            metadata.update(_png_metadata(data))
        elif media_format == "GIF":
            metadata.update(_gif_metadata(data))
        elif media_format == "TIFF":
            metadata.update(_tiff_metadata(data))
        elif media_format == "BMP":
            metadata.update(_bmp_metadata(data))
        elif media_format == "WEBP":
            metadata.update(_webp_metadata(data))
        else:
            warnings.append(
                {
                    "code": "IMAGE_MAGIC_UNRECOGNIZED",
                    "message_key": "warning.media.image_magic_unrecognized",
                    "developer_message": "Image extension was present but file magic was invalid.",
                }
            )
            parse_status = ArtifactParseStatus.CORRUPT
    except ValueError as error:
        warnings.append(
            {
                "code": "IMAGE_METADATA_CORRUPT",
                "message_key": "warning.media.image_metadata_corrupt",
                "developer_message": "Image metadata could not be parsed.",
                "details": {"error": str(error)},
            }
        )
        parse_status = ArtifactParseStatus.CORRUPT
    if metadata.get("width") is None or metadata.get("height") is None:
        warnings.append(
            {
                "code": "IMAGE_DIMENSIONS_UNAVAILABLE",
                "message_key": "warning.media.image_dimensions_unavailable",
                "developer_message": "Image dimensions were unavailable from safe header parsing.",
            }
        )
        if parse_status is ArtifactParseStatus.SUCCESS:
            parse_status = ArtifactParseStatus.PARTIAL
    return {"metadata": metadata, "warnings": warnings, "parse_status": parse_status}


def _parse_video(data: bytes, media_format: str | None) -> dict[str, Any]:
    warnings: list[dict[str, Any]] = []
    metadata: dict[str, Any] = {}
    parse_status = ArtifactParseStatus.SUCCESS
    try:
        if media_format == "MP4":
            metadata.update(_mp4_metadata(data))
        else:
            warnings.append(
                {
                    "code": "VIDEO_MAGIC_UNRECOGNIZED",
                    "message_key": "warning.media.video_magic_unrecognized",
                    "developer_message": "Video extension was present but file magic was invalid.",
                }
            )
            parse_status = ArtifactParseStatus.CORRUPT
    except ValueError as error:
        warnings.append(
            {
                "code": "VIDEO_METADATA_CORRUPT",
                "message_key": "warning.media.video_metadata_corrupt",
                "developer_message": "Video metadata could not be parsed.",
                "details": {"error": str(error)},
            }
        )
        parse_status = ArtifactParseStatus.CORRUPT
    if metadata.get("duration_seconds") is None:
        warnings.append(
            {
                "code": "VIDEO_DURATION_UNAVAILABLE",
                "message_key": "warning.media.video_duration_unavailable",
                "developer_message": "Video duration was unavailable from safe container parsing.",
            }
        )
        if parse_status is ArtifactParseStatus.SUCCESS:
            parse_status = ArtifactParseStatus.PARTIAL
    return {"metadata": metadata, "warnings": warnings, "parse_status": parse_status}


def _build_media_artifact(
    *,
    evidence: Evidence,
    node: FileSystemNode,
    source: ArtifactSource,
    data: bytes,
    parsed: dict[str, Any],
    thumbnail_cache: dict[str, Any],
) -> ArtifactRecord:
    metadata = parsed["metadata"]
    raw_locator = make_raw_locator(
        evidence_id=evidence.evidence_id,
        source_file_node_id=node.node_id,
        source_path=node.display_path,
        source_reference="media:metadata",
        locator_type="MEDIA_METADATA",
        offset=0,
        length=min(max(int(parsed.get("read_length", len(data))), 1), _MAX_LOCATOR_LENGTH),
        encoding=None,
        view_types=["HEX"],
        content_sha256=parsed["content_sha256"],
        limitations=[
            "Phase 5 uses safe standard-library metadata parsing and does not decode pixels."
        ],
        details={
            "media_format": parsed["format"],
            "file_size": parsed.get("file_size"),
            "read_length": parsed.get("read_length"),
        },
    )
    file_times = _file_timestamp_fields(node)
    media_times = metadata.get("media_timestamps", [])
    observed = _choose_observed_time(file_times, media_times)
    if parsed["media_kind"] == "VIDEO":
        artifact_type = ArtifactType.MEDIA_VIDEO
    elif parsed["media_kind"] == "AUDIO":
        artifact_type = ArtifactType.MEDIA_AUDIO
    else:
        artifact_type = ArtifactType.MEDIA_IMAGE
    subtype_format = parsed["format"] or "UNRECOGNIZED"
    fields = {
        "media_kind": parsed["media_kind"],
        "classification": {
            "format": parsed["format"],
            "mime": parsed["mime"],
            "mime_candidate": parsed["mime"],
            "extension": node.extension,
            "confidence": parsed["classification_confidence"],
        },
        "format": parsed["format"],
        "mime": parsed["mime"],
        "mime_candidate": parsed["mime"],
        "file_size": parsed.get("file_size", len(data)),
        "is_deleted": node.is_deleted,
        "file_timestamps": file_times,
        "media_timestamps": media_times,
        "width": metadata.get("width"),
        "height": metadata.get("height"),
        "exif": metadata.get("exif", {}),
        "gps_raw": metadata.get("gps_raw", {}),
        "gps_normalized": metadata.get("gps_normalized", {}),
        "codec": metadata.get("codec"),
        "codec_candidates": metadata.get("codec_candidates", []),
        "duration_seconds": metadata.get("duration_seconds"),
        "frame_rate": metadata.get("frame_rate"),
        "video_codec": metadata.get("video_codec"),
        "audio_codec": metadata.get("audio_codec"),
        "sample_rate": metadata.get("sample_rate"),
        "channels": metadata.get("channels"),
        "bit_rate": metadata.get("bit_rate"),
        "thumbnail_cache": thumbnail_cache,
    }
    return make_artifact(
        evidence=evidence,
        node=node,
        source=source,
        artifact_type=artifact_type,
        artifact_subtype=f"MEDIA_{parsed['media_kind']}_{subtype_format}",
        fields=fields,
        raw_locator=raw_locator,
        title=f"{parsed['media_kind'].title()} metadata: {node.original_name}",
        summary="Media metadata extracted without AI; original file bytes were not modified.",
        parse_status=parsed["parse_status"],
        confidence=0.9 if parsed["classification_confidence"] == "HIGH" else 0.45,
        observed_at_raw=observed["raw"],
        observed_at_utc=observed["utc"],
        timezone_source=observed["timezone_source"],
        timezone_confidence=observed["timezone_confidence"],
        warnings=parsed["warnings"],
    )


def _thumbnail_cache_entry(
    *,
    evidence: Evidence,
    node: FileSystemNode,
    source: ArtifactSource,
    parsed: dict[str, Any],
) -> dict[str, Any]:
    content_sha256 = str(parsed["content_sha256"])
    metadata = parsed["metadata"]
    producer = {
        "producer_id": source.analyzer_id,
        "producer_version": source.analyzer_version,
        "parser_backend": source.parser_backend,
        "parser_backend_version": source.parser_backend_version,
        "case_id": evidence.case_id,
        "evidence_id": evidence.evidence_id,
        "source_file_node_id": node.node_id,
        "source_path": node.display_path,
        "source_content_sha256": content_sha256,
        "derivative": "THUMBNAIL",
        "strategy": "metadata-thumbnail-reference-v1",
    }
    content_payload = {
        "source_content_sha256": content_sha256,
        "media_kind": parsed["media_kind"],
        "format": parsed["format"],
        "width": metadata.get("width"),
        "height": metadata.get("height"),
    }
    content_bytes = json.dumps(
        content_payload,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    derivative_hash = sha256_hex(content_bytes)
    key = canonical_sha256(producer | {"content_sha256": derivative_hash})
    relative_path = f"media/thumbnails/{key[:2]}/{key}.json"
    now = datetime.now(UTC)
    entry = {
        "key_sha256": key,
        "case_id": evidence.case_id,
        "kind": "THUMBNAIL",
        "relative_path": relative_path,
        "size_bytes": len(content_bytes),
        "content_sha256": derivative_hash,
        "created_at": to_json_timestamp(now),
        "last_accessed_at": to_json_timestamp(now),
        "expires_at": None,
        "producer": producer,
    }
    reference = {
        "cache_key": key,
        "kind": "THUMBNAIL",
        "relative_path": relative_path,
        "size_bytes": len(content_bytes),
        "content_sha256": derivative_hash,
        "source_content_sha256": content_sha256,
        "hash_verifiable": True,
        "producer": producer,
        "limitations": [
            "The current Phase 5 adapter stores deterministic thumbnail derivative metadata; "
            "pixel rendering is deferred."
        ],
    }
    return {"entry": entry, "reference": reference}


def _jpeg_metadata(data: bytes) -> dict[str, Any]:
    width: int | None = None
    height: int | None = None
    exif: dict[str, Any] = {}
    gps_raw: dict[str, Any] = {}
    gps_normalized: dict[str, Any] = {}
    media_timestamps: list[dict[str, Any]] = []
    offset = 2
    while offset + 4 <= len(data):
        if data[offset] != 0xFF:
            offset += 1
            continue
        while offset < len(data) and data[offset] == 0xFF:
            offset += 1
        if offset >= len(data):
            break
        marker = data[offset]
        offset += 1
        if marker in {0xD8, 0xD9} or 0xD0 <= marker <= 0xD7:
            continue
        if offset + 2 > len(data):
            raise ValueError("truncated JPEG segment length")
        segment_length = int.from_bytes(data[offset : offset + 2], "big")
        if segment_length < 2:
            raise ValueError("invalid JPEG segment length")
        segment_start = offset + 2
        segment_end = offset + segment_length
        if segment_end > len(data):
            raise ValueError("truncated JPEG segment")
        segment = data[segment_start:segment_end]
        if marker in {
            0xC0,
            0xC1,
            0xC2,
            0xC3,
            0xC5,
            0xC6,
            0xC7,
            0xC9,
            0xCA,
            0xCB,
            0xCD,
            0xCE,
            0xCF,
        }:
            if len(segment) < 5:
                raise ValueError("truncated JPEG SOF segment")
            height = int.from_bytes(segment[1:3], "big")
            width = int.from_bytes(segment[3:5], "big")
        elif marker == 0xE1 and segment.startswith(b"Exif\x00\x00"):
            parsed = _parse_tiff(segment[6:])
            exif = parsed["exif"]
            gps_raw = parsed["gps_raw"]
            gps_normalized = parsed["gps_normalized"]
            media_timestamps = parsed["media_timestamps"]
            width = width or parsed.get("width")
            height = height or parsed.get("height")
        offset = segment_end
    return {
        "width": width,
        "height": height,
        "exif": exif,
        "gps_raw": gps_raw,
        "gps_normalized": gps_normalized,
        "media_timestamps": media_timestamps,
    }


def _png_metadata(data: bytes) -> dict[str, Any]:
    if len(data) < 24 or not data.startswith(b"\x89PNG\r\n\x1a\n"):
        raise ValueError("truncated PNG header")
    if data[12:16] != b"IHDR":
        raise ValueError("PNG IHDR chunk is missing")
    return {
        "width": int.from_bytes(data[16:20], "big"),
        "height": int.from_bytes(data[20:24], "big"),
    }


def _gif_metadata(data: bytes) -> dict[str, Any]:
    if len(data) < 10 or not data.startswith((b"GIF87a", b"GIF89a")):
        raise ValueError("truncated GIF header")
    return {
        "width": int.from_bytes(data[6:8], "little"),
        "height": int.from_bytes(data[8:10], "little"),
    }


def _bmp_metadata(data: bytes) -> dict[str, Any]:
    if len(data) < 26 or not data.startswith(b"BM"):
        raise ValueError("truncated BMP header")
    return {
        "width": int.from_bytes(data[18:22], "little", signed=True),
        "height": abs(int.from_bytes(data[22:26], "little", signed=True)),
    }


def _webp_metadata(data: bytes) -> dict[str, Any]:
    if len(data) >= 30 and data[12:16] == b"VP8X":
        width = int.from_bytes(data[24:27] + b"\x00", "little") + 1
        height = int.from_bytes(data[27:30] + b"\x00", "little") + 1
        return {"width": width, "height": height}
    return {}


def _tiff_metadata(data: bytes) -> dict[str, Any]:
    parsed = _parse_tiff(data)
    return {
        "width": parsed.get("width"),
        "height": parsed.get("height"),
        "exif": parsed["exif"],
        "gps_raw": parsed["gps_raw"],
        "gps_normalized": parsed["gps_normalized"],
        "media_timestamps": parsed["media_timestamps"],
    }


def _parse_tiff(data: bytes) -> dict[str, Any]:
    if len(data) < 8:
        raise ValueError("truncated TIFF header")
    if data[0:2] == b"II":
        endian = "<"
    elif data[0:2] == b"MM":
        endian = ">"
    else:
        raise ValueError("invalid TIFF byte order")
    if _unpack_u16(data, 2, endian) != 42:
        raise ValueError("invalid TIFF magic")
    ifd0_offset = _unpack_u32(data, 4, endian)
    ifd0 = _read_ifd(data, ifd0_offset, endian)
    exif_ifd = _read_ifd(data, int(ifd0.get(0x8769, {}).get("value", 0)), endian)
    gps_ifd = _read_ifd(data, int(ifd0.get(0x8825, {}).get("value", 0)), endian)
    exif = _named_values(ifd0, _IFD0_TAGS) | _named_values(exif_ifd, _EXIF_TAGS)
    gps_raw = _named_values(gps_ifd, _GPS_TAGS)
    gps_normalized = _gps_normalized(gps_raw)
    media_timestamps = _exif_timestamp_fields(exif, gps_raw)
    width = _first_int(
        exif.get("pixel_x_dimension"),
        exif.get("image_width"),
    )
    height = _first_int(
        exif.get("pixel_y_dimension"),
        exif.get("image_height"),
    )
    return {
        "width": width,
        "height": height,
        "exif": exif,
        "gps_raw": gps_raw,
        "gps_normalized": gps_normalized,
        "media_timestamps": media_timestamps,
    }


def _read_ifd(data: bytes, offset: int, endian: str) -> dict[int, dict[str, Any]]:
    if offset <= 0:
        return {}
    if offset + 2 > len(data):
        raise ValueError("TIFF IFD offset outside data")
    count = _unpack_u16(data, offset, endian)
    entries: dict[int, dict[str, Any]] = {}
    cursor = offset + 2
    for _ in range(count):
        if cursor + 12 > len(data):
            raise ValueError("truncated TIFF IFD entry")
        tag = _unpack_u16(data, cursor, endian)
        value_type = _unpack_u16(data, cursor + 2, endian)
        value_count = _unpack_u32(data, cursor + 4, endian)
        size = _TIFF_TYPE_SIZES.get(value_type)
        if size is None:
            cursor += 12
            continue
        byte_count = size * value_count
        if byte_count <= 4:
            raw = data[cursor + 8 : cursor + 8 + byte_count]
        else:
            value_offset = _unpack_u32(data, cursor + 8, endian)
            if value_offset + byte_count > len(data):
                raise ValueError("TIFF value offset outside data")
            raw = data[value_offset : value_offset + byte_count]
        entries[tag] = {
            "type": value_type,
            "count": value_count,
            "value": _decode_tiff_value(raw, value_type, value_count, endian),
            "raw": _raw_tiff_value(raw, value_type, value_count, endian),
        }
        cursor += 12
    return entries


def _decode_tiff_value(raw: bytes, value_type: int, count: int, endian: str) -> Any:
    if value_type == 2:
        return raw.split(b"\x00", 1)[0].decode("utf-8", errors="replace")
    if value_type == 3:
        values = [_unpack_u16(raw, index * 2, endian) for index in range(min(count, len(raw) // 2))]
        return values[0] if count == 1 and values else values
    if value_type == 4:
        values = [_unpack_u32(raw, index * 4, endian) for index in range(min(count, len(raw) // 4))]
        return values[0] if count == 1 and values else values
    if value_type == 5:
        rational_values: list[Any] = []
        for index in range(min(count, len(raw) // 8)):
            numerator = _unpack_u32(raw, index * 8, endian)
            denominator = _unpack_u32(raw, index * 8 + 4, endian)
            rational_values.append(
                {
                    "numerator": numerator,
                    "denominator": denominator,
                    "value": None if denominator == 0 else numerator / denominator,
                }
            )
        return rational_values[0] if count == 1 and rational_values else rational_values
    if value_type == 9:
        values = [
            struct.unpack_from(f"{endian}i", raw, index * 4)[0]
            for index in range(min(count, len(raw) // 4))
        ]
        return values[0] if count == 1 and values else values
    if value_type == 10:
        signed_rational_values: list[Any] = []
        for index in range(min(count, len(raw) // 8)):
            numerator = struct.unpack_from(f"{endian}i", raw, index * 8)[0]
            denominator = struct.unpack_from(f"{endian}i", raw, index * 8 + 4)[0]
            signed_rational_values.append(
                {
                    "numerator": numerator,
                    "denominator": denominator,
                    "value": None if denominator == 0 else numerator / denominator,
                }
            )
        return (
            signed_rational_values[0]
            if count == 1 and signed_rational_values
            else signed_rational_values
        )
    if value_type in {1, 7}:
        values = list(raw[:count])
        return values[0] if count == 1 and values else values
    return raw.hex()


def _raw_tiff_value(raw: bytes, value_type: int, count: int, endian: str) -> Any:
    if value_type in {5, 10}:
        signed = value_type == 10
        result = []
        for index in range(min(count, len(raw) // 8)):
            if signed:
                numerator = struct.unpack_from(f"{endian}i", raw, index * 8)[0]
                denominator = struct.unpack_from(f"{endian}i", raw, index * 8 + 4)[0]
            else:
                numerator = _unpack_u32(raw, index * 8, endian)
                denominator = _unpack_u32(raw, index * 8 + 4, endian)
            result.append(f"{numerator}/{denominator}")
        return result[0] if count == 1 and result else result
    return _decode_tiff_value(raw, value_type, count, endian)


def _named_values(entries: dict[int, dict[str, Any]], names: dict[int, str]) -> dict[str, Any]:
    named: dict[str, Any] = {}
    for tag, name in names.items():
        if tag in entries:
            named[name] = entries[tag]["value"]
            named[f"{name}_raw"] = entries[tag]["raw"]
    return named


def _gps_normalized(gps_raw: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    latitude = _dms_to_decimal(gps_raw.get("latitude"), gps_raw.get("latitude_ref"))
    longitude = _dms_to_decimal(gps_raw.get("longitude"), gps_raw.get("longitude_ref"))
    if latitude is not None:
        result["latitude"] = latitude
    if longitude is not None:
        result["longitude"] = longitude
    altitude = _rational_value(gps_raw.get("altitude"))
    if altitude is not None:
        if int(gps_raw.get("altitude_ref") or 0) == 1:
            altitude = -altitude
        result["altitude_meters"] = altitude
    if "datestamp" in gps_raw or "timestamp" in gps_raw:
        result["timestamp_utc"] = _gps_timestamp(gps_raw)
    return result


def _dms_to_decimal(value: Any, ref: Any) -> float | None:
    if not isinstance(value, list) or len(value) < 3:
        return None
    components = [_rational_value(item) for item in value[:3]]
    if any(item is None for item in components):
        return None
    degrees, minutes, seconds = components
    if degrees is None or minutes is None or seconds is None:
        return None
    decimal = float(degrees) + (float(minutes) / 60.0) + (float(seconds) / 3600.0)
    if str(ref).upper() in {"S", "W"}:
        decimal = -decimal
    return round(decimal, 8)


def _rational_value(value: Any) -> float | None:
    if isinstance(value, dict):
        parsed = value.get("value")
        return None if parsed is None else float(parsed)
    if isinstance(value, int | float):
        return float(value)
    return None


def _gps_timestamp(gps_raw: dict[str, Any]) -> str | None:
    date_value = gps_raw.get("datestamp")
    time_value = gps_raw.get("timestamp")
    if not isinstance(date_value, str) or not isinstance(time_value, list) or len(time_value) < 3:
        return None
    parts = [_rational_value(item) for item in time_value[:3]]
    if any(item is None for item in parts):
        return None
    try:
        date = datetime.strptime(date_value, "%Y:%m:%d").date()
        timestamp = datetime(
            date.year,
            date.month,
            date.day,
            int(parts[0] or 0),
            int(parts[1] or 0),
            int(parts[2] or 0),
            tzinfo=UTC,
        )
    except ValueError:
        return None
    return to_json_timestamp(timestamp)


def _exif_timestamp_fields(
    exif: dict[str, Any],
    gps_raw: dict[str, Any],
) -> list[dict[str, Any]]:
    fields: list[dict[str, Any]] = []
    offset_by_key = {
        "datetime_original": exif.get("offset_time_original") or exif.get("offset_time"),
        "datetime_digitized": exif.get("offset_time_digitized") or exif.get("offset_time"),
        "datetime": exif.get("offset_time"),
    }
    for key in ("datetime_original", "datetime_digitized", "datetime"):
        raw = exif.get(key)
        if not isinstance(raw, str) or not raw:
            continue
        parsed = _parse_exif_datetime(raw, offset_by_key.get(key))
        fields.append(
            {
                "source": f"EXIF:{key}",
                "raw_value": raw,
                "normalized_utc": None
                if parsed["utc"] is None
                else to_json_timestamp(parsed["utc"]),
                "timezone_source": parsed["timezone_source"],
                "timezone_confidence": parsed["timezone_confidence"],
            }
        )
    gps_timestamp = _gps_timestamp(gps_raw)
    if gps_timestamp is not None:
        fields.append(
            {
                "source": "EXIF:GPS_TIMESTAMP",
                "raw_value": {
                    "datestamp": gps_raw.get("datestamp"),
                    "timestamp": gps_raw.get("timestamp_raw") or gps_raw.get("timestamp"),
                },
                "normalized_utc": gps_timestamp,
                "timezone_source": "GPS_UTC",
                "timezone_confidence": "HIGH",
            }
        )
    return fields


def _parse_exif_datetime(raw: str, offset_value: Any) -> dict[str, Any]:
    try:
        naive = datetime.strptime(raw, "%Y:%m:%d %H:%M:%S")
    except ValueError:
        return {"utc": None, "timezone_source": "UNKNOWN", "timezone_confidence": "UNKNOWN"}
    offset_text = str(offset_value) if offset_value is not None else ""
    if len(offset_text) == 6 and offset_text[0] in {"+", "-"} and offset_text[3] == ":":
        sign = 1 if offset_text[0] == "+" else -1
        hours = int(offset_text[1:3])
        minutes = int(offset_text[4:6])
        tz = timezone(sign * timedelta(hours=hours, minutes=minutes))
        return {
            "utc": naive.replace(tzinfo=tz).astimezone(UTC),
            "timezone_source": "EXIF_OFFSET",
            "timezone_confidence": "HIGH",
        }
    return {
        "utc": None,
        "timezone_source": "UNKNOWN",
        "timezone_confidence": "UNKNOWN",
    }


def _mp4_metadata(data: bytes) -> dict[str, Any]:
    if len(data) < 12 or data[4:8] != b"ftyp":
        raise ValueError("MP4 ftyp box is missing")
    metadata: dict[str, Any] = {
        "major_brand": data[8:12].decode("ascii", errors="replace"),
        "compatible_brands": _compatible_brands(data),
        "codec_candidates": [],
        "media_timestamps": [],
    }
    for box_type, start, end, _, _ in _walk_boxes(data, 0, len(data)):
        if box_type == b"mvhd":
            metadata.update(_parse_mvhd(data[start:end]))
        elif box_type == b"stsd":
            for codec in _parse_stsd(data[start:end]):
                if codec not in metadata["codec_candidates"]:
                    metadata["codec_candidates"].append(codec)
    metadata["codec"] = (
        metadata["codec_candidates"][0]["codec"] if metadata["codec_candidates"] else None
    )
    return metadata


def _compatible_brands(data: bytes) -> list[str]:
    if len(data) < 16:
        return []
    size = int.from_bytes(data[0:4], "big")
    if size < 16 or size > len(data):
        return []
    brands = []
    for offset in range(16, size, 4):
        brands.append(data[offset : offset + 4].decode("ascii", errors="replace"))
    return brands


def _walk_boxes(
    data: bytes,
    start: int,
    end: int,
) -> list[tuple[bytes, int, int, int, int]]:
    boxes: list[tuple[bytes, int, int, int, int]] = []
    containers = {b"moov", b"trak", b"mdia", b"minf", b"stbl", b"edts", b"udta"}
    for box_type, content_start, content_end, box_offset, size in _iter_boxes(data, start, end):
        boxes.append((box_type, content_start, content_end, box_offset, size))
        if box_type in containers:
            boxes.extend(_walk_boxes(data, content_start, content_end))
        elif box_type == b"meta" and content_start + 4 <= content_end:
            boxes.extend(_walk_boxes(data, content_start + 4, content_end))
    return boxes


def _iter_boxes(
    data: bytes,
    start: int,
    end: int,
) -> list[tuple[bytes, int, int, int, int]]:
    boxes: list[tuple[bytes, int, int, int, int]] = []
    offset = start
    while offset + 8 <= end:
        size = int.from_bytes(data[offset : offset + 4], "big")
        box_type = data[offset + 4 : offset + 8]
        header = 8
        if size == 1:
            if offset + 16 > end:
                raise ValueError("truncated extended MP4 box size")
            size = int.from_bytes(data[offset + 8 : offset + 16], "big")
            header = 16
        elif size == 0:
            size = end - offset
        if size < header or offset + size > end:
            raise ValueError("invalid MP4 box size")
        boxes.append((box_type, offset + header, offset + size, offset, size))
        offset += size
    return boxes


def _parse_mvhd(data: bytes) -> dict[str, Any]:
    if len(data) < 20:
        raise ValueError("truncated mvhd box")
    version = data[0]
    media_timestamps: list[dict[str, Any]] = []
    if version == 1:
        if len(data) < 32:
            raise ValueError("truncated mvhd v1 box")
        creation_raw = int.from_bytes(data[4:12], "big")
        modification_raw = int.from_bytes(data[12:20], "big")
        timescale = int.from_bytes(data[20:24], "big")
        duration = int.from_bytes(data[24:32], "big")
    else:
        creation_raw = int.from_bytes(data[4:8], "big")
        modification_raw = int.from_bytes(data[8:12], "big")
        timescale = int.from_bytes(data[12:16], "big")
        duration = int.from_bytes(data[16:20], "big")
    for source_name, raw in (
        ("MP4:creation_time", creation_raw),
        ("MP4:modification_time", modification_raw),
    ):
        timestamp = _mac_time(raw)
        media_timestamps.append(
            {
                "source": source_name,
                "raw_value": raw,
                "normalized_utc": None if timestamp is None else to_json_timestamp(timestamp),
                "timezone_source": "MP4_UTC",
                "timezone_confidence": "HIGH" if timestamp is not None else "UNKNOWN",
            }
        )
    return {
        "duration_seconds": None if timescale == 0 else duration / timescale,
        "timescale": timescale,
        "duration_raw": duration,
        "media_timestamps": media_timestamps,
    }


def _parse_stsd(data: bytes) -> list[dict[str, Any]]:
    if len(data) < 8:
        raise ValueError("truncated stsd box")
    entry_count = int.from_bytes(data[4:8], "big")
    codecs: list[dict[str, Any]] = []
    offset = 8
    for _ in range(entry_count):
        if offset + 8 > len(data):
            raise ValueError("truncated sample description entry")
        size = int.from_bytes(data[offset : offset + 4], "big")
        if size < 8 or offset + size > len(data):
            raise ValueError("invalid sample description entry size")
        codec = data[offset + 4 : offset + 8].decode("ascii", errors="replace")
        candidate: dict[str, Any] = {"codec": codec}
        if offset + 36 <= len(data):
            width = int.from_bytes(data[offset + 32 : offset + 34], "big")
            height = int.from_bytes(data[offset + 34 : offset + 36], "big")
            if width > 0 and height > 0:
                candidate["width"] = width
                candidate["height"] = height
        codecs.append(candidate)
        offset += size
    return codecs


def _mac_time(value: int) -> datetime | None:
    if value <= 0:
        return None
    return _MAC_EPOCH + timedelta(seconds=value)


def _file_timestamp_fields(node: FileSystemNode) -> list[dict[str, Any]]:
    fields: list[dict[str, Any]] = []
    for key in ("created", "modified", "accessed", "changed"):
        raw = node.raw_timestamps.get(key)
        normalized = node.utc_timestamps.get(key)
        fields.append(
            {
                "source": f"FILESYSTEM:{key}",
                "raw_value": raw,
                "normalized_utc": None if normalized is None else to_json_timestamp(normalized),
                "meaning": node.timestamp_meanings.get(key),
                "timezone_source": node.timestamp_sources.get(key, "os.stat"),
                "timezone_confidence": "HIGH" if normalized is not None else "UNKNOWN",
            }
        )
    return fields


def _choose_observed_time(
    file_times: list[dict[str, Any]],
    media_times: list[dict[str, Any]],
) -> dict[str, Any]:
    for candidate in media_times:
        normalized = candidate.get("normalized_utc")
        if isinstance(normalized, str):
            return {
                "raw": str(candidate.get("raw_value")),
                "utc": datetime.fromisoformat(normalized.replace("Z", "+00:00")).astimezone(UTC),
                "timezone_source": candidate.get("timezone_source"),
                "timezone_confidence": str(candidate.get("timezone_confidence", "UNKNOWN")),
            }
    for candidate in file_times:
        if candidate["source"] == "FILESYSTEM:modified" and candidate.get("normalized_utc"):
            normalized = str(candidate["normalized_utc"])
            return {
                "raw": str(candidate.get("raw_value")),
                "utc": datetime.fromisoformat(normalized.replace("Z", "+00:00")).astimezone(UTC),
                "timezone_source": "FILESYSTEM_METADATA",
                "timezone_confidence": "HIGH",
            }
    return {"raw": None, "utc": None, "timezone_source": None, "timezone_confidence": "UNKNOWN"}


def _first_int(*values: Any) -> int | None:
    for value in values:
        if isinstance(value, int):
            return value
        if isinstance(value, list) and value and isinstance(value[0], int):
            return int(value[0])
    return None


def _unpack_u16(data: bytes, offset: int, endian: str) -> int:
    return int(struct.unpack_from(f"{endian}H", data, offset)[0])


def _unpack_u32(data: bytes, offset: int, endian: str) -> int:
    return int(struct.unpack_from(f"{endian}I", data, offset)[0])
