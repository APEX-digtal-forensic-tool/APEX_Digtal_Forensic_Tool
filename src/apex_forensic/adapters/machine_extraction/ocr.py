"""Tesseract CLI OCR runtime adapter."""

from __future__ import annotations

import csv
import importlib
import importlib.util
import shutil
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any

from apex_forensic._time import utc_now
from apex_forensic.constants import ENGINE_VERSION
from apex_forensic.domain.errors import OperationCancelledError, UnsupportedCapabilityError
from apex_forensic.domain.models import ProviderCapability

MAX_IMAGE_BYTES = 50 * 1024 * 1024
MAX_TESSERACT_OUTPUT_BYTES = 5 * 1024 * 1024


class RapidOcrProvider:
    """Local OCR provider using RapidOCR with onnxruntime models."""

    provider_id = "rapidocr-onnxruntime"
    provider_version = ENGINE_VERSION

    def __init__(self, *, timeout: float = 30.0) -> None:
        self._timeout = timeout
        self._engine: Any | None = None

    def capabilities(self) -> ProviderCapability:
        rapidocr_available = _module_available("rapidocr")
        onnx_available = _module_available("onnxruntime")
        available = rapidocr_available and onnx_available
        warnings: list[dict[str, Any]] = []
        if not rapidocr_available:
            warnings.append(
                {
                    "code": "CAPABILITY_UNAVAILABLE",
                    "developer_message": "RapidOCR package is not installed.",
                    "python_module": "rapidocr",
                }
            )
        if not onnx_available:
            warnings.append(
                {
                    "code": "CAPABILITY_UNAVAILABLE",
                    "developer_message": "onnxruntime package is not installed.",
                    "python_module": "onnxruntime",
                }
            )
        return ProviderCapability(
            provider_id=self.provider_id,
            provider_version=self.provider_version,
            capability_type="OCR",
            is_available=available,
            supported_inputs=["IMAGE_FILE", "RASTER_THUMBNAIL"] if available else [],
            supported_outputs=["MACHINE_EXTRACTED_CANDIDATE"],
            unavailable_reason=None if available else "CAPABILITY_UNAVAILABLE",
            warnings=warnings,
            metadata={
                "candidate_is_observed_fact": False,
                "engine": "rapidocr",
                "inference_backend": "onnxruntime" if onnx_available else None,
                "languages": ["eng", "ch_sim"],
                "korean_fixture_status": "BLOCKED_FONT_OR_MODEL",
            },
            updated_at=utc_now(),
        )

    def analyze_image(
        self,
        path: Path,
        *,
        languages: list[str],
        cancellation_requested: bool = False,
    ) -> list[dict[str, Any]]:
        if cancellation_requested:
            raise OperationCancelledError("OCR analysis was cancelled before dispatch.")
        capability = self.capabilities()
        if not capability.is_available:
            raise UnsupportedCapabilityError(
                "RapidOCR or onnxruntime is unavailable.",
                target="ocr_provider",
                required_capability="OCR_RUNTIME",
            )
        resolved = path.resolve()
        if not resolved.is_file():
            raise UnsupportedCapabilityError("OCR source image is unavailable.", target="path")
        if resolved.stat().st_size > MAX_IMAGE_BYTES:
            raise UnsupportedCapabilityError(
                "OCR source image exceeds the size limit.",
                target="path",
            )
        engine = self._rapidocr_engine()
        started = datetime.now().astimezone()
        output = engine(str(resolved))
        rows = _rapidocr_rows(output, "+".join(languages or ["auto"]), started)
        return rows

    def _rapidocr_engine(self) -> Any:
        if self._engine is None:
            rapidocr = importlib.import_module("rapidocr")
            self._engine = rapidocr.RapidOCR()
        return self._engine


class TesseractCliOcrProvider:
    """Local OCR provider using the Tesseract command line interface."""

    provider_id = "tesseract-cli"
    provider_version = ENGINE_VERSION

    def __init__(self, *, executable: str = "tesseract", timeout: float = 30.0) -> None:
        self._executable = executable
        self._timeout = timeout

    def capabilities(self) -> ProviderCapability:
        executable = shutil.which(self._executable)
        available = executable is not None
        return ProviderCapability(
            provider_id=self.provider_id,
            provider_version=self.provider_version,
            capability_type="OCR",
            is_available=available,
            supported_inputs=["IMAGE_FILE", "RASTER_THUMBNAIL"] if available else [],
            supported_outputs=["MACHINE_EXTRACTED_CANDIDATE"],
            unavailable_reason=None if available else "CAPABILITY_UNAVAILABLE",
            warnings=[]
            if available
            else [
                {
                    "code": "CAPABILITY_UNAVAILABLE",
                    "developer_message": "Tesseract CLI is not installed or not on PATH.",
                    "binary": self._executable,
                }
            ],
            metadata={
                "candidate_is_observed_fact": False,
                "binary": executable,
                "languages": self._languages(executable),
            },
            updated_at=utc_now(),
        )

    def analyze_image(
        self,
        path: Path,
        *,
        languages: list[str],
        cancellation_requested: bool = False,
    ) -> list[dict[str, Any]]:
        if cancellation_requested:
            raise OperationCancelledError("OCR analysis was cancelled before dispatch.")
        executable = shutil.which(self._executable)
        if executable is None:
            raise UnsupportedCapabilityError(
                "Tesseract CLI is not installed or not on PATH.",
                target="ocr_provider",
                required_capability="OCR_RUNTIME",
            )
        resolved = path.resolve()
        if not resolved.is_file():
            raise UnsupportedCapabilityError("OCR source image is unavailable.", target="path")
        if resolved.stat().st_size > MAX_IMAGE_BYTES:
            raise UnsupportedCapabilityError(
                "OCR source image exceeds the size limit.",
                target="path",
            )
        lang_arg = "+".join(languages or ["eng"])
        completed = subprocess.run(
            [executable, str(resolved), "stdout", "-l", lang_arg, "--psm", "6", "tsv"],
            check=False,
            capture_output=True,
            timeout=self._timeout,
        )
        if len(completed.stdout) > MAX_TESSERACT_OUTPUT_BYTES:
            raise UnsupportedCapabilityError("OCR provider output exceeds the size limit.")
        if completed.returncode != 0:
            raise UnsupportedCapabilityError(
                "OCR provider failed to analyze the image.",
                target="ocr_provider",
                required_capability="OCR_RUNTIME",
            )
        return _parse_tsv(completed.stdout.decode("utf-8", errors="replace"), lang_arg)

    def _languages(self, executable: str | None) -> list[str]:
        if executable is None:
            return []
        try:
            completed = subprocess.run(
                [executable, "--list-langs"],
                check=False,
                capture_output=True,
                timeout=5,
            )
        except (OSError, subprocess.TimeoutExpired):
            return []
        lines = completed.stdout.decode("utf-8", errors="replace").splitlines()
        return sorted(line.strip() for line in lines[1:] if line.strip())


def _parse_tsv(text: str, language: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    reader = csv.DictReader(text.splitlines(), delimiter="\t")
    created_at = datetime.now().astimezone()
    for row in reader:
        value = str(row.get("text") or "").strip()
        if not value:
            continue
        confidence = _confidence(row.get("conf"))
        if confidence < 0:
            continue
        rows.append(
            {
                "text": value,
                "language": language,
                "confidence": confidence,
                "region": {
                    "x": _int(row.get("left")),
                    "y": _int(row.get("top")),
                    "width": _int(row.get("width")),
                    "height": _int(row.get("height")),
                    "unit": "PIXEL",
                },
                "created_at": created_at,
            }
        )
    return rows


def _rapidocr_rows(output: Any, language: str, created_at: datetime) -> list[dict[str, Any]]:
    texts = _sequence_attr(output, "txts")
    scores = _sequence_attr(output, "scores")
    boxes = _sequence_attr(output, "boxes")
    rows: list[dict[str, Any]] = []
    for index, text in enumerate(texts):
        value = str(text or "").strip()
        if not value:
            continue
        score = scores[index] if index < len(scores) else None
        box = boxes[index] if index < len(boxes) else None
        rows.append(
            {
                "text": value,
                "language": language,
                "confidence": _confidence_score(score),
                "region": _polygon_region(box),
                "created_at": created_at,
                "model_id": "rapidocr-default-onnxruntime",
            }
        )
    return rows


def _confidence(value: str | None) -> float:
    try:
        raw = float(value or "-1")
    except ValueError:
        return -1.0
    return max(0.0, min(1.0, raw / 100.0))


def _confidence_score(value: Any) -> float:
    try:
        return max(0.0, min(1.0, float(value)))
    except (TypeError, ValueError):
        return 0.0


def _polygon_region(value: Any) -> dict[str, Any] | None:
    if value is None:
        return None
    points: list[dict[str, float]] = []
    try:
        iterator = list(value)
    except TypeError:
        return None
    for point in iterator:
        try:
            x, y = point
        except (TypeError, ValueError):
            return None
        points.append({"x": float(x), "y": float(y)})
    if not points:
        return None
    xs = [point["x"] for point in points]
    ys = [point["y"] for point in points]
    return {
        "x": min(xs),
        "y": min(ys),
        "width": max(xs) - min(xs),
        "height": max(ys) - min(ys),
        "unit": "PIXEL",
        "polygon": points,
    }


def _int(value: str | None) -> int | None:
    try:
        return int(value or "")
    except ValueError:
        return None


def _sequence_attr(output: Any, name: str) -> tuple[Any, ...]:
    value = getattr(output, name, None)
    if value is None:
        return ()
    try:
        return tuple(value)
    except TypeError:
        return ()


def _module_available(module_name: str) -> bool:
    try:
        return importlib.util.find_spec(module_name) is not None
    except (ImportError, ModuleNotFoundError, ValueError):
        return False
