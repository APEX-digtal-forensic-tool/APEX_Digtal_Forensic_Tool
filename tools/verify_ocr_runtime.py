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
    parser.add_argument("--image", type=Path)
    parser.add_argument("--language", action="append", default=[])
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument("--require-available", action="store_true")
    args = parser.parse_args()
    provider = (
        RapidOcrProvider(timeout=args.timeout)
        if args.provider == "rapidocr"
        else TesseractCliOcrProvider(executable=args.tesseract, timeout=args.timeout)
    )
    capability = provider.capabilities()
    result: dict[str, object] = capability.to_schema_dict()
    if args.image is not None:
        if not capability.is_available:
            result["analysis"] = {"status": "CAPABILITY_UNAVAILABLE"}
        else:
            rows = provider.analyze_image(args.image, languages=args.language or ["eng"])
            result["analysis"] = {
                "status": "COMPLETED",
                "candidate_count": len(rows),
                "candidates": _json_safe(rows),
            }
    print(json.dumps(result, ensure_ascii=False, indent=2))
    if args.require_available and not capability.is_available:
        return 1
    return 0


def _json_safe(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, list | tuple):
        return [_json_safe(item) for item in value]
    return value


if __name__ == "__main__":
    raise SystemExit(main())
