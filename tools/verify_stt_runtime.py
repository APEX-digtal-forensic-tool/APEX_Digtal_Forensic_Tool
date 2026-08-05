"""Verify STT provider capability without using private evidence."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from apex_forensic.adapters.machine_extraction import WhisperCppCliSttProvider


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify local whisper.cpp STT capability.")
    parser.add_argument("--whisper", default="whisper-cli")
    parser.add_argument("--model-path", type=Path)
    parser.add_argument("--require-available", action="store_true")
    args = parser.parse_args()
    capability = WhisperCppCliSttProvider(
        executable=args.whisper,
        model_path=args.model_path,
    ).capabilities()
    result = capability.to_schema_dict()
    print(json.dumps(result, ensure_ascii=False, indent=2))
    if args.require_available and not capability.is_available:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
