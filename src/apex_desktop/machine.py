"""Local OCR/STT selection, bounded source extraction and candidate persistence."""

import json
import os
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


def config(root: Path) -> dict[str, Any]:
    path = root / "machine-settings.json"
    raw = os.environ.get("APEX_DESKTOP_MACHINE_CONFIG")
    if raw is None and path.exists():
        raw = path.read_text(encoding="utf-8")
    from .models import MachineSettings

    return MachineSettings.model_validate(json.loads(raw) if raw else {}).model_dump()


def save_config(root: Path, values: dict[str, Any]) -> dict[str, Any]:
    if os.environ.get("APEX_DESKTOP_MACHINE_CONFIG") is not None:
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
    path = root / "machine-settings.json"
    temp = path.with_suffix(".tmp")
    temp.write_text(json.dumps(values), encoding="utf-8")
    temp.replace(path)
    return capabilities(root)


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

    ocr, stt = providers(root)
    return {
        "settings": config(root),
        "managed": os.environ.get("APEX_DESKTOP_MACHINE_CONFIG") is not None,
        "ocr": ocr.capabilities().to_schema_dict(),
        "stt": stt.capabilities().to_schema_dict(),
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
