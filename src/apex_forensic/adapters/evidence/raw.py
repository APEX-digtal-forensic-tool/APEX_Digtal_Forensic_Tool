"""Read-only RAW/DD/IMG evidence reader."""

from __future__ import annotations

import hashlib
import os
import threading
from pathlib import Path
from types import TracebackType
from typing import BinaryIO, Self

from apex_forensic._time import to_json_timestamp, utc_now
from apex_forensic.constants import ENGINE_VERSION
from apex_forensic.domain.enums import (
    EvidenceFormat,
    EvidenceReaderCapability,
    EvidenceReaderCapabilityStatus,
)
from apex_forensic.domain.errors import UnsupportedCapabilityError, ValidationError
from apex_forensic.domain.models import EvidenceVolume
from apex_forensic.ports.evidence_reader import (
    MAX_EVIDENCE_READ_SIZE,
    EvidenceProbeResult,
    EvidenceReaderCapabilityStatement,
)

_RAW_SUFFIX_FORMATS = {
    ".dd": EvidenceFormat.DD,
    ".img": EvidenceFormat.IMG,
    ".raw": EvidenceFormat.RAW,
}
_DEFAULT_SECTOR_SIZE = 512
_FINGERPRINT_CHUNK_SIZE = 1024 * 1024


class RawImageReader:
    """Bounded random-access reader for uncompressed raw disk image streams."""

    reader_id = "apex.raw_image_reader"
    reader_version = ENGINE_VERSION

    def __init__(
        self,
        path: Path,
        *,
        evidence_format: EvidenceFormat | None = None,
        sector_size: int = _DEFAULT_SECTOR_SIZE,
        max_read_size: int = MAX_EVIDENCE_READ_SIZE,
    ) -> None:
        if sector_size <= 0:
            raise ValidationError("sector_size must be greater than zero.", target="sector_size")
        if max_read_size <= 0:
            raise ValidationError(
                "max_read_size must be greater than zero.",
                target="max_read_size",
            )
        self.path = path
        self.evidence_format = evidence_format or self._format_for_path(path)
        self._sector_size = sector_size
        self._max_read_size = max_read_size
        self._fd: int | None = None
        self._stream: BinaryIO | None = None
        self._size: int | None = None
        self._fingerprint: dict[str, object] | None = None
        self._lock = threading.RLock()
        self._closed = True

    @classmethod
    def probe(cls, path: Path) -> EvidenceProbeResult:
        """Probe raw-image readability without opening the file for writing."""

        warnings: list[dict[str, object]] = []
        supported = True
        unavailable_reason = None
        sector_size: int | None = _DEFAULT_SECTOR_SIZE
        if path.is_symlink():
            supported = False
            unavailable_reason = "SYMLINK_POLICY"
            warnings.append(
                {
                    "code": "SYMLINK_REJECTED",
                    "developer_message": "Symbolic links are not followed for evidence readers.",
                }
            )
        elif not path.exists() or not path.is_file():
            supported = False
            unavailable_reason = "NOT_REGULAR_FILE"
            sector_size = None
        return EvidenceProbeResult(
            reader_id=cls.reader_id,
            reader_version=cls.reader_version,
            evidence_format=cls._format_for_path(path),
            supported=supported,
            sector_size=sector_size,
            capabilities=cls._capability_tuple(),
            warnings=tuple(warnings),
            unavailable_reason=unavailable_reason,
        )

    def open_readonly(self) -> Self:
        """Open the image using an OS read-only handle."""

        normalized = self._normalize_path(self.path)
        try:
            fd = os.open(normalized, os.O_RDONLY)
        except OSError as error:
            raise ValidationError(
                "Evidence source cannot be opened read-only.",
                target="path",
                details={"path": normalized, "error": str(error)},
            ) from error
        try:
            stat_result = os.fstat(fd)
            if not os.path.isfile(normalized):
                raise ValidationError("Evidence path is not a regular file.", target="path")
            self._fd = fd
            self._stream = os.fdopen(fd, "rb", buffering=0)
            self._size = int(stat_result.st_size)
            self._fingerprint = self._compute_source_fingerprint()
            self._closed = False
        except Exception:
            os.close(fd)
            self._fd = None
            self._stream = None
            raise
        return self

    @property
    def size(self) -> int:
        self._ensure_open()
        assert self._size is not None
        return self._size

    @property
    def sector_size(self) -> int:
        return self._sector_size

    @property
    def source_fingerprint(self) -> dict[str, object]:
        self._ensure_open()
        assert self._fingerprint is not None
        return dict(self._fingerprint)

    def capabilities(self) -> tuple[EvidenceReaderCapabilityStatement, ...]:
        return self._capability_tuple()

    def volumes(self, *, case_id: str, evidence_id: str) -> list[EvidenceVolume]:
        from apex_forensic.adapters.evidence.partitions import PartitionParser

        return PartitionParser().parse(self, case_id=case_id, evidence_id=evidence_id)

    def read_at(self, offset: int, length: int) -> bytes:
        """Read a bounded byte range. Reads at or past EOF return an empty byte string."""

        self._ensure_open()
        if offset < 0:
            raise ValidationError("offset must be non-negative.", target="offset")
        if length < 0:
            raise ValidationError("length must be non-negative.", target="length")
        if length > self._max_read_size:
            raise ValidationError(
                "Requested read length exceeds the evidence reader limit.",
                target="length",
                details={"max_read_size": self._max_read_size},
            )
        if length == 0 or offset >= self.size:
            return b""
        bounded_length = min(length, self.size - offset)
        fd = self._fd
        if fd is None:
            raise ValidationError("Evidence reader is closed.", target="reader")
        if hasattr(os, "pread"):
            try:
                return bytes(os.pread(fd, bounded_length, offset))
            except OSError as error:
                raise ValidationError(
                    "Evidence range read failed.",
                    target="offset",
                    details={"offset": offset, "length": bounded_length, "error": str(error)},
                ) from error
        stream = self._stream
        if stream is None:
            raise ValidationError("Evidence reader is closed.", target="reader")
        with self._lock:
            try:
                stream.seek(offset)
                return stream.read(bounded_length)
            except OSError as error:
                raise ValidationError(
                    "Evidence range read failed.",
                    target="offset",
                    details={"offset": offset, "length": bounded_length, "error": str(error)},
                ) from error

    def close(self) -> None:
        """Close the read-only stream; this method is idempotent."""

        if self._closed:
            return
        stream = self._stream
        self._stream = None
        self._fd = None
        self._closed = True
        if stream is not None:
            stream.close()

    def __enter__(self) -> Self:
        return self.open_readonly()

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()

    @classmethod
    def _capability_tuple(cls) -> tuple[EvidenceReaderCapabilityStatement, ...]:
        return (
            EvidenceReaderCapabilityStatement(
                EvidenceReaderCapability.READ_STREAM.value,
                EvidenceReaderCapabilityStatus.SUPPORTED.value,
            ),
            EvidenceReaderCapabilityStatement(
                EvidenceReaderCapability.RANDOM_ACCESS.value,
                EvidenceReaderCapabilityStatus.SUPPORTED.value,
                details={
                    "max_read_size": MAX_EVIDENCE_READ_SIZE,
                    "eof_policy": "SHORT_READ_OR_EMPTY",
                    "concurrent_read_policy": "PREAD_OR_LOCKED_SEEK",
                    "sparse_file_policy": "OPERATING_SYSTEM_ZERO_FILLED_HOLES",
                },
            ),
            EvidenceReaderCapabilityStatement(
                EvidenceReaderCapability.PARTITION_ENUMERATION.value,
                EvidenceReaderCapabilityStatus.SUPPORTED.value,
                details={"schemes": ["MBR", "GPT", "SUPERFLOPPY"]},
            ),
        )

    @staticmethod
    def _format_for_path(path: Path) -> EvidenceFormat:
        return _RAW_SUFFIX_FORMATS.get(path.suffix.lower(), EvidenceFormat.RAW)

    @staticmethod
    def _normalize_path(path: Path) -> str:
        expanded = path.expanduser()
        absolute = expanded if expanded.is_absolute() else Path.cwd() / expanded
        if absolute.is_symlink():
            raise UnsupportedCapabilityError(
                "Symbolic links and reparse points are not followed by evidence readers.",
                target="path",
                required_capability="SYMLINK_POLICY",
            )
        if not absolute.exists():
            raise ValidationError("Evidence path does not exist.", target="path")
        if not absolute.is_file():
            raise ValidationError("Evidence path is not a regular file.", target="path")
        return str(absolute.resolve(strict=True))

    def _compute_source_fingerprint(self) -> dict[str, object]:
        stream = self._stream
        if stream is None:
            raise ValidationError("Evidence reader is closed.", target="reader")
        digest = hashlib.sha256()
        processed = 0
        with self._lock:
            stream.seek(0)
            while True:
                chunk = stream.read(_FINGERPRINT_CHUNK_SIZE)
                if not chunk:
                    break
                processed += len(chunk)
                digest.update(chunk)
            stream.seek(0)
        return {
            "algorithm": "SHA256",
            "sha256": digest.hexdigest(),
            "size_bytes": processed,
            "reader_id": self.reader_id,
            "reader_version": self.reader_version,
            "created_at": to_json_timestamp(utc_now()),
        }

    def _ensure_open(self) -> None:
        if self._closed or self._fd is None:
            raise ValidationError("Evidence reader is closed.", target="reader")
