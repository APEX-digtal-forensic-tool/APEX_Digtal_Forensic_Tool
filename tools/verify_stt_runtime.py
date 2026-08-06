"""Verify local STT provider capability and optional real audio transcription."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from apex_forensic.adapters.machine_extraction import (
    FasterWhisperSttProvider,
    WhisperCppCliSttProvider,
)
from apex_forensic.domain.errors import ApexError


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify local whisper.cpp STT capability.")
    parser.add_argument(
        "--provider",
        default="whisper-cpp",
        choices=["whisper-cpp", "faster-whisper"],
    )
    parser.add_argument("--whisper", default="whisper-cli")
    parser.add_argument("--model-path", type=Path)
    parser.add_argument("--device", default="cpu")
    parser.add_argument("--compute-type", default="int8")
    parser.add_argument("--audio-path", type=Path)
    parser.add_argument("--language")
    parser.add_argument("--timeout", type=float, default=120.0)
    parser.add_argument("--expect-text")
    parser.add_argument("--require-segment", action="store_true")
    parser.add_argument("--require-available", action="store_true")
    args = parser.parse_args()
    provider = (
        FasterWhisperSttProvider(
            model_path=args.model_path,
            device=args.device,
            compute_type=args.compute_type,
            timeout=args.timeout,
        )
        if args.provider == "faster-whisper"
        else WhisperCppCliSttProvider(
            executable=args.whisper,
            model_path=args.model_path,
            timeout=args.timeout,
        )
    )
    capability = provider.capabilities()
    result: dict[str, object] = {
        "capability": capability.to_schema_dict(),
        "segments": None,
        "verification": {
            "audio_path_supplied": args.audio_path is not None,
            "expected_text_supplied": args.expect_text is not None,
            "model_bytes_emitted": False,
            "audio_bytes_emitted": False,
        },
    }
    exit_code = 0
    if args.audio_path is not None:
        try:
            segments = provider.analyze_audio(args.audio_path, language=args.language)
            result["segments"] = segments
            flattened = " ".join(str(item.get("text", "")) for item in segments).casefold()
            checks = {
                "segment_count": len(segments),
                "required_segment_present": (not args.require_segment) or bool(segments),
                "expected_text_present": (
                    args.expect_text is None or args.expect_text.casefold() in flattened
                ),
            }
            result["verification"] = result["verification"] | checks  # type: ignore[operator]
            if not checks["required_segment_present"] or not checks["expected_text_present"]:
                exit_code = 1
        except ApexError as error:
            result["analysis_error"] = error.to_api_error()
            exit_code = 1 if args.require_available or args.require_segment else 0
    print(json.dumps(result, ensure_ascii=False, indent=2))
    if args.require_available and not capability.is_available:
        return 1
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
