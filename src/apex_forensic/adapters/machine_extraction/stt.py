"""whisper.cpp CLI STT runtime adapter."""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from apex_forensic._time import utc_now
from apex_forensic.constants import ENGINE_VERSION
from apex_forensic.domain.errors import OperationCancelledError, UnsupportedCapabilityError
from apex_forensic.domain.models import ProviderCapability

MAX_AUDIO_BYTES = 200 * 1024 * 1024
MAX_STT_OUTPUT_BYTES = 10 * 1024 * 1024


class WhisperCppCliSttProvider:
    """Local STT provider using whisper.cpp style command line JSON output."""

    provider_id = "whisper.cpp-cli"
    provider_version = ENGINE_VERSION

    def __init__(
        self,
        *,
        executable: str = "whisper-cli",
        model_path: Path | None = None,
        timeout: float = 120.0,
    ) -> None:
        self._executable = executable
        self._model_path = model_path
        self._timeout = timeout

    def capabilities(self) -> ProviderCapability:
        executable = shutil.which(self._executable)
        model_available = self._model_path is not None and self._model_path.is_file()
        available = executable is not None and model_available
        warnings: list[dict[str, Any]] = []
        if executable is None:
            warnings.append(
                {
                    "code": "CAPABILITY_UNAVAILABLE",
                    "developer_message": "whisper.cpp CLI is not installed or not on PATH.",
                    "binary": self._executable,
                }
            )
        if not model_available:
            warnings.append(
                {
                    "code": "CAPABILITY_UNAVAILABLE",
                    "developer_message": "STT model path is not configured or is unavailable.",
                    "model_path_configured": self._model_path is not None,
                }
            )
        return ProviderCapability(
            provider_id=self.provider_id,
            provider_version=self.provider_version,
            capability_type="STT",
            is_available=available,
            supported_inputs=["WAV", "MP3", "MP4_AUDIO_STREAM"] if available else [],
            supported_outputs=["MACHINE_EXTRACTED_CANDIDATE"],
            unavailable_reason=None if available else "CAPABILITY_UNAVAILABLE",
            warnings=warnings,
            metadata={
                "candidate_is_observed_fact": False,
                "binary": executable,
                "model_path_configured": self._model_path is not None,
                "model": self._model_metadata(),
            },
            updated_at=utc_now(),
        )

    def analyze_audio(
        self,
        path: Path,
        *,
        language: str | None = None,
        cancellation_requested: bool = False,
    ) -> list[dict[str, Any]]:
        if cancellation_requested:
            raise OperationCancelledError("STT analysis was cancelled before dispatch.")
        executable = shutil.which(self._executable)
        if executable is None or self._model_path is None or not self._model_path.is_file():
            raise UnsupportedCapabilityError(
                "STT binary or model is unavailable.",
                target="stt_provider",
                required_capability="STT_RUNTIME",
            )
        resolved = path.resolve()
        if not resolved.is_file():
            raise UnsupportedCapabilityError("STT source audio is unavailable.", target="path")
        if resolved.stat().st_size > MAX_AUDIO_BYTES:
            raise UnsupportedCapabilityError(
                "STT source audio exceeds the size limit.",
                target="path",
            )
        with tempfile.TemporaryDirectory(prefix="apex-stt-") as temp_dir:
            output_stem = Path(temp_dir) / "transcript"
            command = [
                executable,
                "-m",
                str(self._model_path.resolve()),
                "-f",
                str(resolved),
                "-oj",
                "-of",
                str(output_stem),
            ]
            if language:
                command.extend(["-l", language])
            try:
                completed = subprocess.run(
                    command,
                    check=False,
                    capture_output=True,
                    timeout=self._timeout,
                )
            except subprocess.TimeoutExpired as exc:
                raise UnsupportedCapabilityError(
                    "STT provider timed out while analyzing the audio.",
                    target="stt_provider",
                    required_capability="STT_RUNTIME",
                ) from exc
            if completed.returncode != 0:
                raise UnsupportedCapabilityError(
                    "STT provider failed to analyze the audio.",
                    target="stt_provider",
                    required_capability="STT_RUNTIME",
                )
            json_path = output_stem.with_suffix(".json")
            if not json_path.is_file() or json_path.stat().st_size > MAX_STT_OUTPUT_BYTES:
                raise UnsupportedCapabilityError("STT provider output is missing or too large.")
            try:
                payload = json.loads(json_path.read_text(encoding="utf-8"))
            except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise UnsupportedCapabilityError("STT provider output is corrupt.") from exc
        return _segments(payload, language)

    def _model_metadata(self) -> dict[str, Any]:
        if self._model_path is None:
            return {
                "path": None,
                "available": False,
                "sha256": None,
                "version": None,
            }
        resolved = self._model_path.resolve()
        if not resolved.is_file():
            return {
                "path": str(resolved),
                "available": False,
                "sha256": None,
                "version": None,
            }
        return {
            "path": str(resolved),
            "available": True,
            "sha256": _file_sha256(resolved),
            "version": resolved.name,
            "size": resolved.stat().st_size,
        }


def _segments(payload: Any, language: str | None) -> list[dict[str, Any]]:
    if not isinstance(payload, dict):
        return []
    raw_segments = payload.get("transcription") or payload.get("segments") or []
    if not isinstance(raw_segments, list):
        return []
    rows: list[dict[str, Any]] = []
    for segment in raw_segments:
        if not isinstance(segment, dict):
            continue
        text = str(segment.get("text") or "").strip()
        if not text:
            continue
        rows.append(
            {
                "text": text,
                "language": language or segment.get("language"),
                "confidence": _score(segment.get("confidence") or segment.get("probability")),
                "audio_start_ms": _milliseconds(_first_present(segment, "start", "t0")),
                "audio_end_ms": _milliseconds(_first_present(segment, "end", "t1")),
            }
        )
    return rows


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _first_present(row: dict[str, Any], primary: str, fallback: str) -> Any:
    if primary in row:
        return row[primary]
    return row.get(fallback)


def _milliseconds(value: Any) -> int | None:
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value * 1000)
    return None


def _score(value: Any) -> float:
    if isinstance(value, int | float):
        return max(0.0, min(1.0, float(value)))
    return 0.0
