"""Resolve shipped local tools without changing the user's PATH or downloading data."""

import shutil
import sys
from pathlib import Path


def assets_root() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent / "assets"
    return Path(__file__).resolve().parents[3] / "desktop-assets"


def media_executable(name: str) -> str | None:
    if name not in {"ffmpeg", "ffprobe"}:
        raise ValueError("Unknown media tool")
    filename = name + (".exe" if sys.platform == "win32" else "")
    bundled = assets_root() / "media" / "bin" / filename
    if bundled.is_file():
        return str(bundled)
    return shutil.which(name)


def bundled_stt_model() -> Path | None:
    from apex_forensic.adapters.machine_extraction.stt import local_model_available

    model = assets_root() / "models" / "whisper-base"
    return model if local_model_available(model) else None
