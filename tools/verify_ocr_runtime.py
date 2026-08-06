"""Verify OCR provider capability without using private evidence."""

from __future__ import annotations

import argparse
import json
from datetime import datetime
from pathlib import Path
from typing import Any

from apex_forensic.adapters.machine_extraction import RapidOcrProvider, TesseractCliOcrProvider


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify local OCR provider capability.")
    parser.add_argument("--provider", default="tesseract", choices=["tesseract", "rapidocr"])
    parser.add_argument("--tesseract", default="tesseract")
    parser.add_argument("--tessdata-prefix", type=Path)
    parser.add_argument("--image", type=Path)
    parser.add_argument("--language", action="append", default=[])
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument("--expect-text")
    parser.add_argument("--require-candidate", action="store_true")
    parser.add_argument("--require-available", action="store_true")
    args = parser.parse_args()
    provider = (
        RapidOcrProvider(timeout=args.timeout)
        if args.provider == "rapidocr"
        else TesseractCliOcrProvider(
            executable=args.tesseract,
            tessdata_prefix=args.tessdata_prefix,
            timeout=args.timeout,
        )
    )
    capability = provider.capabilities()
    result: dict[str, object] = capability.to_schema_dict()
    exit_code = 0
    if args.image is not None:
        if not capability.is_available:
            result["analysis"] = {"status": "CAPABILITY_UNAVAILABLE"}
            if args.require_candidate:
                exit_code = 1
        else:
            rows = provider.analyze_image(args.image, languages=args.language or ["eng"])
            flattened = " ".join(str(item.get("text", "")) for item in rows).casefold()
            expected_present = args.expect_text is None or _contains_expected(
                flattened,
                args.expect_text,
            )
            result["analysis"] = {
                "status": "COMPLETED",
                "candidate_count": len(rows),
                "candidates": _json_safe(rows),
                "required_candidate_present": (not args.require_candidate) or bool(rows),
                "expected_text_present": expected_present,
            }
            if (args.require_candidate and not rows) or not expected_present:
                exit_code = 1
    print(json.dumps(result, ensure_ascii=False, indent=2))
    if args.require_available and not capability.is_available:
        return 1
    return exit_code


def _json_safe(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, list | tuple):
        return [_json_safe(item) for item in value]
    return value


def _contains_expected(flattened: str, expected_text: str) -> bool:
    expected = expected_text.casefold()
    compact_flattened = "".join(flattened.split())
    compact_expected = "".join(expected.split())
    return expected in flattened or compact_expected in compact_flattened


if __name__ == "__main__":
    raise SystemExit(main())
