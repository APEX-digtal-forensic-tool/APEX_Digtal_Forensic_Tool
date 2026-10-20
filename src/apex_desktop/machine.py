"""Local OCR/STT selection, bounded source extraction and candidate persistence."""

import json
import os
import tempfile
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from apex_forensic.adapters.filesystem.content import EvidenceFileContent
from apex_forensic.adapters.machine_extraction import (
    FasterWhisperSttProvider,
    RapidOcrProvider,
    TesseractCliOcrProvider,
    WhisperCppCliSttProvider,
)
from apex_forensic.adapters.machine_extraction.stt import local_model_available
from apex_forensic.config import ServiceBundle
from apex_forensic.domain.errors import ApexError, OperationCancelledError, ValidationError
from apex_forensic.jobs import CancellationToken
from apex_forensic.runtime.assets import bundled_stt_model

SETTINGS_FILE = "machine-settings.json"
# Sync operations run in a threadpool; serialise read-backup-replace of the settings file.
_SETTINGS_LOCK = threading.Lock()


def _managed() -> bool:
    return os.environ.get("APEX_DESKTOP_MACHINE_CONFIG") is not None


def load_settings(root: Path) -> tuple[dict[str, Any], dict[str, Any] | None]:
    """Return validated settings, or defaults plus a diagnosis when the stored copy is unusable."""
    from pydantic import ValidationError as ModelError

    from .models import MachineSettings

    path = root / SETTINGS_FILE
    source = "ENVIRONMENT" if _managed() else "FILE"
    fields: list[str] = []
    try:
        raw = os.environ.get("APEX_DESKTOP_MACHINE_CONFIG")
        if raw is None and path.exists():
            raw = path.read_bytes().decode("utf-8-sig")
            if not raw.strip():
                # A missing file means "never configured"; an existing empty one was truncated.
                raise EOFError
        value = json.loads(raw) if raw else {}
        if not isinstance(value, dict):
            raise TypeError
        return MachineSettings.model_validate(value).model_dump(), None
    except EOFError:
        reason = "EMPTY"
    except UnicodeDecodeError:
        reason = "ENCODING"
    except json.JSONDecodeError:
        reason = "JSON_SYNTAX"
    except TypeError:
        reason = "NOT_OBJECT"
    except ModelError as error:
        reason = "INVALID_FIELDS"
        fields = sorted({".".join(map(str, e["loc"])) for e in error.errors() if e["loc"]})
    except OSError:
        reason = "UNREADABLE"
    return MachineSettings().model_dump(), {
        "code": "MACHINE_SETTINGS_INVALID",
        "reason": reason,
        "source": source,
        "fields": fields,
        "resettable": source == "FILE",
    }


def config(root: Path) -> dict[str, Any]:
    settings, error = load_settings(root)
    if error is not None:
        # Running with silent defaults would hide which analyser actually produced candidates.
        raise ApexError(
            "MACHINE_SETTINGS_INVALID",
            "error.machine_settings_invalid",
            target=error["reason"],
            details=error,
        )
    return settings


def _preserve(root: Path, *, only_invalid: bool) -> str | None:
    """Move the stored settings aside so recovery never discards what was there."""
    path = root / SETTINGS_FILE
    if not path.exists():
        return None
    invalid = load_settings(root)[1] is not None
    if only_invalid and not invalid:
        return None
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
    backup = path.with_name(f"machine-settings.{'invalid' if invalid else 'previous'}-{stamp}.json")
    path.replace(backup)
    return backup.name


def reset_config(root: Path) -> dict[str, Any]:
    if _managed():
        raise ApexError("MACHINE_SETTINGS_MANAGED", "error.machine_settings_managed")
    with _SETTINGS_LOCK:
        preserved = _preserve(root, only_invalid=False)
    return {**capabilities(root), "preserved_settings_file": preserved}


def save_config(root: Path, values: dict[str, Any]) -> dict[str, Any]:
    if _managed():
        raise ApexError("MACHINE_SETTINGS_MANAGED", "error.machine_settings_managed")
    model = Path(values["stt_model_path"]) if values.get("stt_model_path") else None
    if model is not None:
        valid = (
            model.is_file() and model.stat().st_size > 0
            if values.get("stt_provider") == "whisper.cpp"
            else local_model_available(model)
        )
        if not valid:
            raise ApexError("STT_MODEL_INVALID", "error.stt_model_invalid", target="stt_model_path")
    tessdata = values.get("tessdata_path")
    if tessdata and not Path(tessdata).is_dir():
        raise ValidationError("OCR language models require a directory.", target="tessdata_path")
    path = root / SETTINGS_FILE
    # A per-request temporary name: concurrent saves must never consume each other's file.
    handle, name = tempfile.mkstemp(prefix=".machine-settings.", suffix=".tmp", dir=root)
    temp = Path(name)
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as output:
            json.dump(values, output)
        with _SETTINGS_LOCK:  # last completed save wins
            preserved = _preserve(root, only_invalid=True)
            temp.replace(path)
    finally:
        temp.unlink(missing_ok=True)
    return {**capabilities(root), "preserved_settings_file": preserved}


def providers(root: Path) -> tuple[Any, Any]:
    settings = config(root)
    ocr = settings["ocr_provider"]
    model = (
        Path(settings["stt_model_path"])
        if settings["stt_model_path"]
        else (bundled_stt_model() if settings["stt_provider"] == "faster-whisper" else None)
    )
    tessdata = Path(settings["tessdata_path"]) if settings["tessdata_path"] else None
    tesseract = TesseractCliOcrProvider(tessdata_prefix=tessdata)
    ocr_provider = (
        tesseract
        if ocr == "tesseract" or (ocr == "auto" and tesseract.capabilities().is_available)
        else RapidOcrProvider()
    )
    stt_provider = (
        WhisperCppCliSttProvider(model_path=model)
        if settings["stt_provider"] == "whisper.cpp"
        else FasterWhisperSttProvider(model_path=model)
    )
    return ocr_provider, stt_provider


def capabilities(root: Path) -> dict[str, Any]:
    from apex_forensic.adapters.artifacts.media import _ffmpeg_capability, _ffprobe_capability
    from apex_forensic.adapters.decryption.dpapi import DpapiOfflineProvider

    settings, settings_error = load_settings(root)
    ocr, stt = providers(root) if settings_error is None else (None, None)
    return {
        "settings": settings,
        "settings_error": settings_error,
        "managed": _managed(),
        # Not evaluated against defaults: the stored choice is unknown until it is repaired.
        "ocr": ocr.capabilities().to_schema_dict() if ocr else None,
        "stt": stt.capabilities().to_schema_dict() if stt else None,
        "bundled_stt": {
            "available": bundled_stt_model() is not None,
            "name": "Whisper base · 다국어 (한국어·영어 포함)",
        },
        "media": {"ffmpeg": _ffmpeg_capability(), "ffprobe": _ffprobe_capability()},
        "dpapi": DpapiOfflineProvider().capabilities().to_schema_dict(),
    }


def run(
    services: ServiceBundle,
    *,
    root: Path,
    case_id: str,
    node_id: str,
    kind: str,
    language: str,
    token: CancellationToken,
) -> dict[str, Any]:
    node = services.repository.get_fs_node(node_id)
    if node is None or node.case_id != case_id:
        raise ValidationError("Selected source is outside this case.", target="node_id")
    evidence = services.evidence.get_evidence(node.evidence_id)
    if evidence.case_id != case_id or not EvidenceFileContent.supports(evidence, node):
        raise ValidationError("Selected source does not support extraction.")

    def check_cancel() -> None:
        if token.is_cancelled:
            raise OperationCancelledError("Machine extraction cancelled.")

    check_cancel()
    language = (
        {"eng": "en", "kor": "ko", "kor+eng": "ko"}.get(language, language)
        if kind == "STT"
        else {"en": "eng", "ko": "kor"}.get(language, language)
    )
    ocr, stt = providers(root)
    if kind == "OCR" and config(root)["ocr_provider"] == "auto":
        supported = set(ocr.capabilities().metadata.get("languages", []))
        if not set(language.split("+")).issubset(supported):
            fallback = RapidOcrProvider()
            if fallback.capabilities().is_available:
                ocr = fallback
    with EvidenceFileContent.materialize(evidence, node, cancellation_token=token) as source:
        if kind == "OCR":
            provider = ocr
            rows = provider.analyze_image(source, languages=language.split("+"))
        else:
            provider = stt
            rows = provider.analyze_audio(source, language=None if language == "auto" else language)
        check_cancel()
        # Keep the indexed source identity, never the disposable extraction path.
        candidates = services.candidates.store_runtime_candidates(
            case_id=case_id,
            evidence_id=evidence.evidence_id,
            source_node_id=node_id,
            source_type="IMAGE_FILE" if kind == "OCR" else "AUDIO_FILE",
            extraction_type=kind,
            provider_id=provider.provider_id,
            provider_version=provider.provider_version,
            rows=rows,
            source_revision=node.index_revision,
            source_path=node.display_path,
        )
    return {
        "node_id": node_id,
        "candidate_count": len(candidates),
        "candidate_ids": [row.candidate_id for row in candidates],
        "semantics": "MACHINE_EXTRACTED_CANDIDATE_NOT_OBSERVED_FACT",
    }
