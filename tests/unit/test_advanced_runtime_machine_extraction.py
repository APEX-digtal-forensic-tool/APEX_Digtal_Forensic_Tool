from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

from apex_forensic.adapters.machine_extraction import (
    RapidOcrProvider,
    TesseractCliOcrProvider,
    WhisperCppCliSttProvider,
)
from apex_forensic.config import build_services
from apex_forensic.domain.enums import AnalysisProfileType
from apex_forensic.domain.errors import ApexError


def _write_ocr_fixture(path: Path, text: str = "HELLO 123") -> None:
    image_module = pytest.importorskip("PIL.Image")
    image_draw_module = pytest.importorskip("PIL.ImageDraw")
    image_font_module = pytest.importorskip("PIL.ImageFont")
    image = image_module.new("RGB", (640, 180), "white")
    draw = image_draw_module.Draw(image)
    font = image_font_module.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 54)
    draw.text((30, 55), text, fill="black", font=font)
    image.save(path)


def _write_fake_whisper_cli(path: Path) -> None:
    path.write_text(
        """#!/usr/bin/env python3
import json
import os
import sys
import time
from pathlib import Path

if os.environ.get("APEX_STT_SLEEP"):
    time.sleep(float(os.environ["APEX_STT_SLEEP"]))
if os.environ.get("APEX_STT_EXIT"):
    raise SystemExit(int(os.environ["APEX_STT_EXIT"]))
output = Path(sys.argv[sys.argv.index("-of") + 1])
if os.environ.get("APEX_STT_TEMP_RECORD"):
    Path(os.environ["APEX_STT_TEMP_RECORD"]).write_text(str(output.parent), encoding="utf-8")
output.with_suffix(".json").write_text(
    json.dumps(
        {
            "transcription": [
                {
                    "text": "hello world",
                    "language": "en",
                    "start": 0,
                    "end": 1.25,
                    "confidence": 0.87,
                }
            ]
        }
    ),
    encoding="utf-8",
)
""",
        encoding="utf-8",
    )
    path.chmod(0o755)


def _write_fake_tesseract_cli(path: Path) -> None:
    path.write_text(
        """#!/usr/bin/env python3
import sys

if "--list-langs" in sys.argv:
    print("List of available languages (2):")
    print("eng")
    print("kor")
    raise SystemExit(0)

print("level\tpage_num\tblock_num\tpar_num\tline_num\tword_num\tleft\ttop\twidth\theight\tconf\ttext")
print("5\t1\t1\t1\t1\t1\t10\t20\t100\t30\t95.0\tHELLO")
print("5\t1\t1\t1\t1\t2\t120\t20\t100\t30\t93.0\t한글")
""",
        encoding="utf-8",
    )
    path.chmod(0o755)


def test_tesseract_ocr_capability_unavailable_is_structured(tmp_path: Path) -> None:
    provider = TesseractCliOcrProvider(executable="apex-missing-tesseract")
    capability = provider.capabilities()

    assert capability.is_available is False
    assert capability.unavailable_reason == "CAPABILITY_UNAVAILABLE"
    with pytest.raises(ApexError) as unavailable:
        provider.analyze_image(tmp_path / "missing.png", languages=["eng"])
    assert unavailable.value.code == "CAPABILITY_UNAVAILABLE"


def test_whisper_stt_capability_unavailable_is_structured(tmp_path: Path) -> None:
    provider = WhisperCppCliSttProvider(
        executable="apex-missing-whisper",
        model_path=tmp_path / "missing.bin",
    )
    capability = provider.capabilities()

    assert capability.is_available is False
    assert capability.unavailable_reason == "CAPABILITY_UNAVAILABLE"
    assert {warning["code"] for warning in capability.warnings} == {"CAPABILITY_UNAVAILABLE"}
    with pytest.raises(ApexError) as unavailable:
        provider.analyze_audio(tmp_path / "missing.wav")
    assert unavailable.value.code == "CAPABILITY_UNAVAILABLE"


def test_whisper_adapter_records_model_metadata_and_cleans_temp(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable = tmp_path / "whisper-cli"
    model = tmp_path / "ggml-synthetic.bin"
    audio = tmp_path / "synthetic.wav"
    temp_record = tmp_path / "stt-temp.txt"
    _write_fake_whisper_cli(executable)
    model.write_bytes(b"synthetic model metadata only")
    audio.write_bytes(b"RIFFsynthetic")
    monkeypatch.setenv("APEX_STT_TEMP_RECORD", str(temp_record))
    provider = WhisperCppCliSttProvider(
        executable=str(executable),
        model_path=model,
        timeout=5.0,
    )

    capability = provider.capabilities()
    rows = provider.analyze_audio(audio, language="en")

    assert capability.is_available is True
    assert capability.metadata["model"]["sha256"] == hashlib.sha256(model.read_bytes()).hexdigest()
    assert rows == [
        {
            "text": "hello world",
            "language": "en",
            "confidence": 0.87,
            "audio_start_ms": 0,
            "audio_end_ms": 1250,
        }
    ]
    assert temp_record.is_file()
    assert not Path(temp_record.read_text(encoding="utf-8")).exists()


def test_whisper_adapter_timeout_and_cancellation_are_structured(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable = tmp_path / "whisper-cli"
    model = tmp_path / "ggml-synthetic.bin"
    audio = tmp_path / "synthetic.wav"
    _write_fake_whisper_cli(executable)
    model.write_bytes(b"synthetic model metadata only")
    audio.write_bytes(b"RIFFsynthetic")
    provider = WhisperCppCliSttProvider(
        executable=str(executable),
        model_path=model,
        timeout=0.01,
    )

    with pytest.raises(ApexError) as cancelled:
        provider.analyze_audio(audio, cancellation_requested=True)

    monkeypatch.setenv("APEX_STT_SLEEP", "1")
    with pytest.raises(ApexError) as timed_out:
        provider.analyze_audio(audio)

    assert cancelled.value.code == "OPERATION_CANCELLED"
    assert timed_out.value.code == "CAPABILITY_UNAVAILABLE"


def test_stt_verifier_runs_configured_audio_path_with_segments(
    tmp_path: Path,
    project_root: Path,
    cli_env: dict[str, str],
) -> None:
    executable = tmp_path / "whisper-cli"
    model = tmp_path / "ggml-synthetic.bin"
    audio = tmp_path / "synthetic.wav"
    _write_fake_whisper_cli(executable)
    model.write_bytes(b"synthetic model metadata only")
    audio.write_bytes(b"RIFFsynthetic")

    completed = subprocess.run(
        [
            sys.executable,
            str(project_root / "tools" / "verify_stt_runtime.py"),
            "--whisper",
            str(executable),
            "--model-path",
            str(model),
            "--audio-path",
            str(audio),
            "--language",
            "en",
            "--expect-text",
            "hello",
            "--require-segment",
            "--require-available",
        ],
        check=False,
        capture_output=True,
        env=cli_env,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
    payload = json.loads(completed.stdout)
    assert payload["capability"]["is_available"] is True
    assert payload["verification"]["segment_count"] == 1
    assert payload["verification"]["expected_text_present"] is True
    assert payload["segments"][0]["text"] == "hello world"


def test_ocr_verifier_enforces_candidate_and_expected_text(
    tmp_path: Path,
    project_root: Path,
    cli_env: dict[str, str],
) -> None:
    executable = tmp_path / "tesseract"
    image = tmp_path / "mixed.png"
    _write_fake_tesseract_cli(executable)
    image.write_bytes(b"synthetic image placeholder")

    completed = subprocess.run(
        [
            sys.executable,
            str(project_root / "tools" / "verify_ocr_runtime.py"),
            "--provider",
            "tesseract",
            "--tesseract",
            str(executable),
            "--image",
            str(image),
            "--language",
            "eng",
            "--language",
            "kor",
            "--expect-text",
            "한글",
            "--require-candidate",
            "--require-available",
        ],
        check=False,
        capture_output=True,
        env=cli_env,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
    payload = json.loads(completed.stdout)
    assert payload["is_available"] is True
    assert payload["analysis"]["candidate_count"] == 2
    assert payload["analysis"]["expected_text_present"] is True
    assert payload["analysis"]["required_candidate_present"] is True


def test_rapidocr_provider_runs_actual_english_ocr(tmp_path: Path) -> None:
    pytest.importorskip("rapidocr")
    pytest.importorskip("onnxruntime")
    image = tmp_path / "english.png"
    _write_ocr_fixture(image)
    provider = RapidOcrProvider(timeout=30.0)

    capability = provider.capabilities()
    rows = provider.analyze_image(image, languages=["eng"])

    assert capability.is_available is True
    assert capability.metadata["inference_backend"] == "onnxruntime"
    assert rows
    assert any("HELLO" in row["text"].replace(" ", "") for row in rows)
    assert all(0.0 <= row["confidence"] <= 1.0 for row in rows)
    assert any(row.get("region") for row in rows)


def test_rapidocr_cli_service_persists_candidate_and_review(tmp_path: Path) -> None:
    pytest.importorskip("rapidocr")
    pytest.importorskip("onnxruntime")
    db_path = tmp_path / "rapidocr.db"
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    image = evidence_root / "ocr.png"
    _write_ocr_fixture(image)
    services = build_services(db_path)
    try:
        case = services.cases.create_case(name="RapidOCR Runtime", locale="ko-KR")
        evidence = services.evidence.register_evidence(
            case_id=case.case_id,
            source_path=evidence_root,
        )
        services.fs.index_evidence(
            case_id=case.case_id,
            evidence_id=evidence.evidence_id,
            profile_type=AnalysisProfileType.FULL_ANALYSIS,
        )
        node = next(
            item
            for item in services.repository.list_fs_nodes_for_evidence(evidence.evidence_id)
            if item.original_name == "ocr.png"
        )

        candidates = services.candidates.analyze_image_file(
            case_id=case.case_id,
            evidence_id=evidence.evidence_id,
            source_node_id=node.node_id,
            path=str(image),
            provider=RapidOcrProvider(timeout=30.0),
            languages=["eng"],
            source_revision=node.index_revision,
        )

        assert candidates
        candidate = candidates[0]
        assert candidate.provider_id == "rapidocr-onnxruntime"
        assert candidate.review_status == "UNREVIEWED"
        reviewed = services.candidates.review_candidate(
            candidate_id=candidate.candidate_id,
            review_status="ACCEPTED",
            reviewed_by="analyst",
            reason="Synthetic OCR fixture was reviewed.",
        )
        assert reviewed.review_status == "ACCEPTED"
    finally:
        services.close()

    reopened = build_services(db_path)
    try:
        page = reopened.candidates.list_candidates(case_id=case.case_id, limit=10)
        assert len(page.items) == len(candidates)
        assert any(item.review_status == "ACCEPTED" for item in page.items)
        assert any("HELLO" in item.text.replace(" ", "") for item in page.items)
        stored_capabilities = reopened.candidates.capabilities(capability_type="OCR")
        assert any(item.provider_id == "rapidocr-onnxruntime" for item in stored_capabilities)
    finally:
        reopened.close()
