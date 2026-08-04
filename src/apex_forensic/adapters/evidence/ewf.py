"""Optional Expert Witness Format evidence reader adapter."""

from __future__ import annotations

import importlib
import importlib.metadata
import re
from collections.abc import Callable
from pathlib import Path
from types import ModuleType, TracebackType
from typing import Any, Self

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


class EwfEvidenceReader:
    """Adapter boundary for E01/EWF images backed by an optional pyewf module."""

    reader_id = "apex.ewf_reader"
    reader_version = ENGINE_VERSION

    def __init__(
        self,
        path: Path,
        *,
        module_loader: Callable[[], ModuleType] | None = None,
        max_read_size: int = MAX_EVIDENCE_READ_SIZE,
    ) -> None:
        self.path = path
        self._module_loader = module_loader or self._load_pyewf
        self._max_read_size = max_read_size
        self._handle: Any | None = None
        self._size: int | None = None
        self._sector_size = 512
        self._segments: tuple[Path, ...] = ()
        self._closed = True

    @classmethod
    def probe(cls, path: Path) -> EvidenceProbeResult:
        unavailable_reason = None
        dependency_available = cls._dependency_available()
        supported = False
        capabilities = cls._capability_tuple(dependency_available=dependency_available)
        if path.suffix.lower() != ".e01":
            unavailable_reason = "EWF_FIRST_SEGMENT_EXTENSION_NOT_RECOGNIZED"
        elif not dependency_available:
            unavailable_reason = "PYEWF_NOT_INSTALLED"
        elif path.is_symlink():
            unavailable_reason = "SYMLINK_POLICY"
        elif not path.exists() or not path.is_file():
            unavailable_reason = "NOT_REGULAR_FILE"
        elif cls._has_ewf_signature(path):
            supported = True
        else:
            supported = False
            unavailable_reason = "EWF_SIGNATURE_NOT_RECOGNIZED"
        return EvidenceProbeResult(
            reader_id=cls.reader_id,
            reader_version=cls.reader_version,
            evidence_format=EvidenceFormat.E01,
            supported=supported,
            sector_size=512 if supported else None,
            capabilities=capabilities,
            unavailable_reason=unavailable_reason,
        )

    def open_readonly(self) -> Self:
        self._segments = self._discover_segments(self.path)
        try:
            pyewf = self._module_loader()
        except ModuleNotFoundError as error:
            raise UnsupportedCapabilityError(
                "E01 analysis requires the optional pyewf dependency.",
                target="path",
                required_capability="EWF_READER_PYEWF",
            ) from error
        handle_factory = getattr(pyewf, "handle", None)
        signature_check = getattr(pyewf, "check_file_signature", None)
        if handle_factory is None:
            raise UnsupportedCapabilityError(
                "The installed EWF module does not expose the expected read adapter.",
                target="path",
                required_capability="EWF_READER_PYEWF",
            )
        if callable(signature_check):
            try:
                signature_supported = bool(signature_check(str(self._segments[0])))
            except Exception as error:
                raise ValidationError(
                    "EWF signature could not be checked by the native adapter.",
                    target="path",
                    details={"segment": str(self._segments[0]), "error": str(error)},
                ) from error
            if not signature_supported:
                raise ValidationError(
                    "EWF signature was not recognized by the native adapter.",
                    target="path",
                    details={"segment": str(self._segments[0])},
                )
        handle = handle_factory()
        try:
            handle.open([str(item) for item in self._segments])
            self._size = int(handle.get_media_size())
            sector_size = getattr(handle, "get_bytes_per_sector", None)
            if callable(sector_size):
                self._sector_size = int(sector_size())
        except Exception as error:
            close = getattr(handle, "close", None)
            if callable(close):
                close()
            raise ValidationError(
                "E01 image could not be opened read-only.",
                target="path",
                details={"error": str(error), "segments": [str(item) for item in self._segments]},
            ) from error
        self._handle = handle
        self._closed = False
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
    def source_fingerprint(self) -> dict[str, Any]:
        self._ensure_open()
        embedded_hashes = self._embedded_hashes()
        return {
            "algorithm": "EWF_EMBEDDED_OR_SEGMENT_METADATA",
            "size_bytes": self.size,
            "segments": [str(item) for item in self._segments],
            "reader_id": self.reader_id,
            "reader_version": self.reader_version,
            "adapter": "pyewf",
            "adapter_version": self._dependency_version(),
            "embedded_hashes": embedded_hashes,
            "embedded_hash_status": "EXTRACTED" if embedded_hashes else "NOT_EXPOSED_BY_PYEWF",
        }

    def capabilities(self) -> tuple[EvidenceReaderCapabilityStatement, ...]:
        return self._capability_tuple(dependency_available=True)

    def volumes(self, *, case_id: str, evidence_id: str) -> list[EvidenceVolume]:
        from apex_forensic.adapters.evidence.partitions import PartitionParser

        return PartitionParser().parse(self, case_id=case_id, evidence_id=evidence_id)

    def read_at(self, offset: int, length: int) -> bytes:
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
        handle = self._handle
        if handle is None:
            raise ValidationError("Evidence reader is closed.", target="reader")
        try:
            handle.seek(offset)
            return bytes(handle.read(bounded_length))
        except Exception as error:
            raise ValidationError(
                "E01 range read failed.",
                target="offset",
                details={"offset": offset, "length": bounded_length, "error": str(error)},
            ) from error

    def close(self) -> None:
        if self._closed:
            return
        handle = self._handle
        self._handle = None
        self._closed = True
        if handle is not None:
            close = getattr(handle, "close", None)
            if callable(close):
                close()

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
    def _capability_tuple(
        cls, *, dependency_available: bool
    ) -> tuple[EvidenceReaderCapabilityStatement, ...]:
        status = (
            EvidenceReaderCapabilityStatus.SUPPORTED
            if dependency_available
            else EvidenceReaderCapabilityStatus.CAPABILITY_UNAVAILABLE
        )
        reason = None if dependency_available else "PYEWF_NOT_INSTALLED"
        return (
            EvidenceReaderCapabilityStatement(
                EvidenceReaderCapability.READ_STREAM.value,
                status.value,
                reason=reason,
            ),
            EvidenceReaderCapabilityStatement(
                EvidenceReaderCapability.RANDOM_ACCESS.value,
                status.value,
                reason=reason,
                details={"max_read_size": MAX_EVIDENCE_READ_SIZE},
            ),
            EvidenceReaderCapabilityStatement(
                EvidenceReaderCapability.SEGMENTED_IMAGE.value,
                status.value,
                reason=reason,
            ),
            EvidenceReaderCapabilityStatement(
                EvidenceReaderCapability.EMBEDDED_HASH.value,
                status.value,
                reason=reason,
            ),
        )

    @staticmethod
    def _load_pyewf() -> ModuleType:
        return importlib.import_module("pyewf")

    @staticmethod
    def _dependency_available() -> bool:
        try:
            importlib.import_module("pyewf")
        except ModuleNotFoundError:
            return False
        return True

    @staticmethod
    def _dependency_version() -> str | None:
        try:
            return importlib.metadata.version("libewf-python")
        except importlib.metadata.PackageNotFoundError:
            try:
                pyewf = importlib.import_module("pyewf")
            except ModuleNotFoundError:
                return None
            version = getattr(pyewf, "get_version", None)
            return str(version()) if callable(version) else None

    @staticmethod
    def _has_ewf_signature(path: Path) -> bool:
        try:
            pyewf = importlib.import_module("pyewf")
            return bool(pyewf.check_file_signature(str(path)))
        except Exception:
            return False

    def _embedded_hashes(self) -> dict[str, str]:
        handle = self._handle
        if handle is None:
            return {}
        hashes: dict[str, str] = {}
        getter = getattr(handle, "get_hash_values", None)
        if callable(getter):
            try:
                values = getter()
            except Exception:
                values = None
            if isinstance(values, dict):
                hashes.update({str(key).upper(): str(value) for key, value in values.items()})
        single_getter = getattr(handle, "get_hash_value", None)
        if callable(single_getter):
            for algorithm in ("MD5", "SHA1", "SHA256"):
                if algorithm in hashes:
                    continue
                try:
                    value = single_getter(algorithm)
                except Exception:
                    continue
                if value:
                    hashes[algorithm] = str(value)
        return hashes

    @staticmethod
    def _discover_segments(path: Path) -> tuple[Path, ...]:
        if path.is_symlink():
            raise UnsupportedCapabilityError(
                "Symbolic links and reparse points are not followed by evidence readers.",
                target="path",
                required_capability="SYMLINK_POLICY",
            )
        if not path.exists():
            raise ValidationError("Evidence path does not exist.", target="path")
        match = re.match(r"^(?P<base>.+)\.[Ee](?P<num>\d{2})$", path.name)
        if match is None:
            raise ValidationError("EWF segment names must use an .E01 style suffix.", target="path")
        base_name = match.group("base")
        segment_pattern = re.compile(rf"^{re.escape(base_name)}\.[Ee](?P<num>\d{{2}})$")
        discovered: dict[int, Path] = {}
        for candidate in path.parent.iterdir():
            candidate_match = segment_pattern.match(candidate.name)
            if candidate_match is None:
                continue
            discovered[int(candidate_match.group("num"))] = candidate
        if 1 not in discovered:
            raise ValidationError("EWF first segment is missing.", target="path")
        max_segment = max(discovered)
        missing = [index for index in range(1, max_segment + 1) if index not in discovered]
        if missing:
            raise ValidationError(
                "EWF segment chain is incomplete.",
                target="path",
                details={"missing_segments": missing},
            )
        return tuple(discovered[index].resolve(strict=True) for index in range(1, max_segment + 1))

    def _ensure_open(self) -> None:
        if self._closed or self._handle is None:
            raise ValidationError("Evidence reader is closed.", target="reader")
