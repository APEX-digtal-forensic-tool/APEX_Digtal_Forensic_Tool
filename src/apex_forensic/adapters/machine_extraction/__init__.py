"""Runtime machine-extraction provider adapters."""

from apex_forensic.adapters.machine_extraction.ocr import RapidOcrProvider, TesseractCliOcrProvider
from apex_forensic.adapters.machine_extraction.stt import (
    FasterWhisperSttProvider,
    WhisperCppCliSttProvider,
)

__all__ = [
    "FasterWhisperSttProvider",
    "RapidOcrProvider",
    "TesseractCliOcrProvider",
    "WhisperCppCliSttProvider",
]
