"""Regression fixtures reflect whisper.cpp JSON and faster-whisper second units."""

import hashlib
from pathlib import Path
from types import SimpleNamespace

import pytest

from apex_forensic.adapters.machine_extraction import stt
from apex_forensic.domain.errors import ApexError


def test_whisper_cpp_real_json_offsets_detected_language_and_zero_confidence():
    rows = stt._segments(
        {
            "result": {"language": "ko"},
            "transcription": [
                {
                    "offsets": {"from": 0, "to": 1250},
                    "timestamps": {"from": "00:00:00,000", "to": "00:00:01,250"},
                    "text": "음성 분석",
                    "confidence": 0,
                    "probability": 0.9,
                },
                {"text": "두 번째", "offsets": {"from": 1250, "to": 3000}},
            ],
        },
        None,
    )
    assert [(row["audio_start_ms"], row["audio_end_ms"]) for row in rows] == [
        (0, 1250),
        (1250, 3000),
    ]
    assert rows[0]["language"] == "ko"
    assert rows[0]["confidence"] == 0


def test_stt_seconds_and_cpp_ticks_have_explicit_units():
    rows = stt._segments(
        {
            "segments": [
                {"text": "seconds", "start": 2, "end": 3.5},
                {"text": "ticks", "t0": 200, "t1": 350},
            ]
        },
        "en",
    )
    assert [(row["audio_start_ms"], row["audio_end_ms"]) for row in rows] == [
        (2000, 3500),
        (2000, 3500),
    ]


def test_faster_whisper_hashes_audio_once_and_rejects_wrong_model_language(tmp_path, monkeypatch):
    source = tmp_path / "recording.wav"
    source.write_bytes(b"synthetic audio")
    calls = []
    hashes = []

    def transcribe(*args, **kwargs):
        calls.append(kwargs)
        return iter(
            [
                SimpleNamespace(text="first", start=0, end=2, avg_logprob=-0.1),
                SimpleNamespace(text="second", start=2, end=3.5, avg_logprob=-0.2),
            ]
        ), SimpleNamespace(language="en")

    def hash_source(path):
        hashes.append(path)
        return hashlib.sha256(path.read_bytes()).hexdigest()

    monkeypatch.setattr(stt, "_file_sha256", hash_source)
    provider = stt.FasterWhisperSttProvider(model_path=Path("tiny.en"))
    provider._engine = SimpleNamespace(
        model=SimpleNamespace(is_multilingual=False), transcribe=transcribe
    )
    with pytest.raises(ApexError, match="STT_LANGUAGE_UNSUPPORTED"):
        provider._transcribe(source, "ko")
    assert calls == []
    rows = provider._transcribe(source, "en")
    assert rows[1]["audio_start_ms"] == 2000
    assert rows[1]["audio_end_ms"] == 3500
    assert hashes == [source]
    assert rows[0]["source_sha256"] == rows[1]["source_sha256"]


def test_whisper_cpp_auto_language_is_sent_and_source_provenance_attached(tmp_path, monkeypatch):
    source, model = tmp_path / "recording.wav", tmp_path / "model.bin"
    source.write_bytes(b"synthetic audio")
    model.write_bytes(b"synthetic model")
    monkeypatch.setattr(stt.shutil, "which", lambda _: "whisper-cli")

    def run(command, **kwargs):
        assert command[command.index("-l") + 1] == "auto"
        output = Path(command[command.index("-of") + 1]).with_suffix(".json")
        output.write_text(
            '{"result":{"language":"ko"},"transcription":'
            '[{"text":"known","offsets":{"from":0,"to":1000}}]}'
        )
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(stt.subprocess, "run", run)
    rows = stt.WhisperCppCliSttProvider(model_path=model).analyze_audio(source)
    assert rows[0]["language"] == "ko"
    assert rows[0]["audio_end_ms"] == 1000
    assert rows[0]["source_sha256"] == hashlib.sha256(source.read_bytes()).hexdigest()
    assert rows[0]["model_id"] == "whisper.cpp:model.bin"
