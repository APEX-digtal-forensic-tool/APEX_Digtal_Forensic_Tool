"""Bounded signature carving with provenance, cancellation and protected derived output."""

import hashlib
import importlib
import importlib.util
import json
import struct
import zlib
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from uuid import uuid4

from apex_forensic.adapters.evidence.factory import evidence_reader
from apex_forensic.adapters.filesystem.pytsk import PyTskFileSystemProvider
from apex_forensic.adapters.filesystem.unallocated import free_ranges
from apex_forensic.application.services.evidence_image import EvidenceImageService
from apex_forensic.domain.errors import (
    OperationCancelledError,
    UnsupportedCapabilityError,
    ValidationError,
)
from apex_forensic.jobs import CancellationToken

SIGNATURES = {
    "PNG": b"\x89PNG\r\n\x1a\n",
    "JPEG": b"\xff\xd8\xff",
    "PDF": b"%PDF-",
    "ZIP": b"PK\x03\x04",
    "GIF": b"GIF8",
}
CHUNK = 1024 * 1024


def candidate_length(kind: str, data: bytes) -> int | None:
    """Recognize a bounded end; candidates still require an examiner's review."""
    if kind == "PNG":
        offset = 8
        while offset + 12 <= len(data):
            size = int.from_bytes(data[offset : offset + 4], "big")
            end = offset + size + 12
            if end > len(data):
                return None
            block = data[offset + 4 : end - 4]
            if zlib.crc32(block) & 0xFFFFFFFF != int.from_bytes(data[end - 4 : end], "big"):
                return None
            if offset == 8 and (block[:4] != b"IHDR" or size != 13):
                return None
            if block[:4] == b"IEND":
                return end if size == 0 else None
            offset = end
        return None
    if kind == "ZIP":
        offset = data.find(b"PK\x05\x06")
        while offset >= 0:
            if offset + 22 > len(data):
                return None
            disk, central_disk, on_disk, total, size, central, comment = struct.unpack_from(
                "<4H2IH", data, offset + 4
            )
            end = offset + 22 + comment
            if (
                disk == central_disk == 0
                and on_disk == total
                and total > 0
                and central + size == offset
                and end <= len(data)
                and data[central : central + 4] == b"PK\x01\x02"
            ):
                return int(end)
            offset = data.find(b"PK\x05\x06", offset + 4)
        return None
    marker = {"PDF": b"%%EOF", "JPEG": b"\xff\xd9", "GIF": b";"}[kind]
    offset = data.find(marker, len(SIGNATURES[kind]))
    while offset >= 0:
        end = offset + len(marker)
        if kind == "PDF":
            return end if b"obj" in data[:offset] else None
        try:
            from io import BytesIO

            image_module = importlib.import_module("PIL.Image")
            with image_module.open(BytesIO(data[:end])) as image:
                image.verify()
            return end
        except (ImportError, OSError, ValueError, SyntaxError):
            offset = data.find(marker, end)
    return None


class CarvingService:
    def __init__(self, images: EvidenceImageService) -> None:
        self.images = images

    def _ranges(
        self, evidence: Any, reader: Any, scope: str, warnings: list[str]
    ) -> Iterator[tuple[int, int]]:
        if scope == "IMAGE":
            yield 0, reader.size
            return
        provider = PyTskFileSystemProvider()
        for volume in reader.volumes(case_id=evidence.case_id, evidence_id=evidence.evidence_id):
            if not volume.is_allocated:
                yield volume.byte_offset, volume.byte_length
                continue
            filesystem = provider._open_fs(evidence, volume)
            try:
                yield from free_ranges(reader, filesystem, volume, warnings)
            finally:
                filesystem.close()

    def carve(
        self,
        *,
        evidence_id: str,
        output_root: Path,
        scope: str = "UNALLOCATED",
        formats: tuple[str, ...] = ("PNG", "JPEG", "PDF", "ZIP", "GIF"),
        start_offset: int = 0,
        max_scan_bytes: int = 256 * CHUNK,
        max_file_bytes: int = 64 * CHUNK,
        max_results: int = 1000,
        cancellation_token: CancellationToken | None = None,
    ) -> dict[str, Any]:
        if (
            scope not in {"IMAGE", "UNALLOCATED"}
            or not formats
            or set(formats) - SIGNATURES.keys()
            or start_offset < 0
            or not 1 <= max_scan_bytes <= 1024**4
            or not 1024 <= max_file_bytes <= 256 * CHUNK
            or not 1 <= max_results <= 10000
        ):
            raise ValidationError("Invalid carving limits or formats.")
        if set(formats) & {"JPEG", "GIF"} and importlib.util.find_spec("PIL") is None:
            raise UnsupportedCapabilityError(
                "JPEG/GIF carving requires Pillow.", required_capability="PILLOW_IMAGE_VALIDATION"
            )
        evidence = self.images._get_evidence(evidence_id)
        run_id = str(uuid4())
        root = output_root / run_id
        manifest_path = self.images._safe_output_path(root, "manifest.json", overwrite=False)
        result: dict[str, Any] = {
            "run_id": run_id,
            "evidence_id": evidence_id,
            "scope": scope,
            "semantics": "CARVED_CANDIDATES_NOT_OBSERVED_FILES",
            "candidates": [],
            "scanned_bytes": 0,
            "candidate_read_bytes": 0,
            "coverage_complete": True,
            "partial": False,
            "next_offset": None,
            "max_file_bytes": max_file_bytes,
            "skipped_signatures": 0,
            "warnings": ["CONTIGUOUS_SIGNATURE_CARVING; fragmented files may be incomplete"],
            "manifest_path": str(manifest_path),
        }

        def check_cancel() -> None:
            if cancellation_token and cancellation_token.is_cancelled:
                raise OperationCancelledError("Carving cancelled.")

        try:
            with evidence_reader(evidence) as reader:
                for begin, length in self._ranges(evidence, reader, scope, result["warnings"]):
                    cursor, end = max(begin, start_offset), min(begin + length, reader.size)
                    if cursor >= end:
                        continue
                    tail = b""
                    while cursor < end:
                        check_cancel()
                        remaining = max_scan_bytes - result["scanned_bytes"]
                        if remaining <= 0:
                            result.update(partial=True, next_offset=max(begin, cursor - 16))
                            break
                        data = reader.read_at(cursor, min(CHUNK, remaining, end - cursor))
                        if not data:
                            raise ValidationError("Image changed during carving.")
                        window, origin = tail + data, cursor - len(tail)
                        hits: set[tuple[int, str]] = set()
                        for kind in formats:
                            marker = SIGNATURES[kind]
                            position = window.find(marker)
                            while position >= 0:
                                absolute = origin + position
                                if absolute + len(marker) > cursor:
                                    hits.add((absolute, kind))
                                position = window.find(marker, position + 1)
                        for absolute, kind in sorted(hits):
                            check_cancel()
                            candidate = bytearray()
                            probe_budget = max(max_file_bytes, max_scan_bytes * 4)
                            if result["candidate_read_bytes"] >= probe_budget:
                                result.update(partial=True, next_offset=absolute)
                                result["warnings"].append("CANDIDATE_READ_BUDGET_REACHED")
                                break
                            available = min(max_file_bytes, end - absolute)
                            size = None
                            while len(candidate) < available:
                                check_cancel()
                                block = reader.read_at(
                                    absolute + len(candidate),
                                    min(CHUNK, available - len(candidate)),
                                )
                                if not block:
                                    break
                                result["candidate_read_bytes"] += len(block)
                                candidate.extend(block)
                                size = candidate_length(kind, bytes(candidate))
                                if size is not None:
                                    break
                            if size is None:
                                result["skipped_signatures"] += 1
                                continue
                            payload = bytes(candidate[:size])
                            digest = hashlib.sha256(payload).hexdigest()
                            path = self.images._safe_output_path(
                                root,
                                f"{absolute:016x}-{kind.lower()}.{kind.lower()}",
                                overwrite=False,
                            )
                            self.images._write_output(path, payload, overwrite=False)
                            self.images._audit_export(
                                evidence_id=evidence_id,
                                output_path=path,
                                sha256=digest,
                                action="Signature-carved candidate exported",
                                notes=f"scope={scope}; offset={absolute}; size={size}; kind={kind}",
                            )
                            result["candidates"].append(
                                {
                                    "format": kind,
                                    "offset": absolute,
                                    "length": size,
                                    "sha256": digest,
                                    "output_path": str(path),
                                    "review_status": "UNREVIEWED",
                                }
                            )
                            if len(result["candidates"]) >= max_results:
                                result.update(partial=True, next_offset=absolute + 1)
                                break
                        result["scanned_bytes"] += len(data)
                        cursor += len(data)
                        tail = window[-16:]
                        if result["partial"]:
                            break
                    if result["partial"]:
                        break
        except BaseException as error:
            result.update(partial=True, error=type(error).__name__)
            self.images._write_output(manifest_path, json.dumps(result).encode(), overwrite=False)
            raise
        result["coverage_complete"] = not result["partial"] and len(result["warnings"]) == 1
        if result["skipped_signatures"]:
            result["warnings"].append(
                "INVALID_OR_INCOMPLETE_SIGNATURES_SKIPPED; max_file_bytes applies"
            )
        self.images._write_output(manifest_path, json.dumps(result).encode(), overwrite=False)
        return result
