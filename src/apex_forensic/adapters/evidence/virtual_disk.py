"""Optional VHD/VHDX evidence reader adapter boundary."""

from __future__ import annotations

import hashlib
import importlib
import importlib.metadata
import json
import shutil
import subprocess
import tempfile
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


class VirtualDiskEvidenceReader:
    """Read-only VHD adapter backed by optional libvhdi/pyvhdi."""

    reader_id = "apex.virtual_disk_reader"
    reader_version = ENGINE_VERSION

    def __init__(
        self,
        path: Path,
        *,
        evidence_format: EvidenceFormat | None = None,
        module: ModuleType | None = None,
        max_read_size: int = MAX_EVIDENCE_READ_SIZE,
    ) -> None:
        self.path = path
        self.evidence_format = evidence_format or self._format_for_path(path)
        self._module = module
        self._max_read_size = max_read_size
        self._handle: Any | None = None
        self._raw_cache_dir: tempfile.TemporaryDirectory[str] | None = None
        self._raw_cache_stream: Any | None = None
        self._size: int | None = None
        self._sector_size = 512
        self._fingerprint: dict[str, Any] | None = None
        self._closed = True

    @classmethod
    def probe(cls, path: Path) -> EvidenceProbeResult:
        evidence_format = cls._format_for_path(path)
        dependency_available = cls._dependency_available()
        supported = False
        unavailable_reason = None
        sector_size: int | None = None
        if evidence_format is EvidenceFormat.VHDX:
            if not cls._qemu_img_available():
                unavailable_reason = "QEMU_IMG_NOT_INSTALLED"
            elif path.is_symlink():
                unavailable_reason = "SYMLINK_POLICY"
            elif not path.exists() or not path.is_file():
                unavailable_reason = "NOT_REGULAR_FILE"
            elif cls._has_vhdx_signature(path):
                supported = True
                sector_size = 512
            else:
                unavailable_reason = "VHDX_SIGNATURE_NOT_RECOGNIZED"
        elif not dependency_available:
            unavailable_reason = "PYVHDI_NOT_INSTALLED"
        elif path.is_symlink():
            unavailable_reason = "SYMLINK_POLICY"
        elif not path.exists() or not path.is_file():
            unavailable_reason = "NOT_REGULAR_FILE"
        elif cls._has_vhd_signature(path):
            supported = True
            sector_size = 512
        else:
            unavailable_reason = "VHD_SIGNATURE_NOT_RECOGNIZED"
        return EvidenceProbeResult(
            reader_id=cls.reader_id,
            reader_version=cls.reader_version,
            evidence_format=evidence_format,
            supported=supported,
            sector_size=sector_size,
            capabilities=cls._capability_tuple(
                evidence_format,
                dependency_available=(
                    cls._qemu_img_available()
                    if evidence_format is EvidenceFormat.VHDX
                    else dependency_available
                ),
            ),
            unavailable_reason=unavailable_reason,
        )

    def open_readonly(self) -> Self:
        if self.evidence_format is EvidenceFormat.VHDX:
            return self._open_vhdx_readonly()
        normalized = self._normalize_path(self.path)
        try:
            pyvhdi = self._module or importlib.import_module("pyvhdi")
        except ModuleNotFoundError as error:
            raise UnsupportedCapabilityError(
                "VHD analysis requires the optional pyvhdi dependency.",
                target="path",
                required_capability="VHD_READER_PYVHDI",
            ) from error
        try:
            if not self._has_vhd_signature(Path(normalized), module=pyvhdi):
                raise ValidationError(
                    "VHD signature was not recognized by the native adapter.",
                    target="path",
                )
            handle = pyvhdi.file()
            handle.open(normalized)
            self._handle = handle
            self._size = int(handle.get_media_size())
            self._sector_size = int(handle.get_bytes_per_sector())
            self._fingerprint = self._compute_source_fingerprint(handle)
            self._closed = False
        except ValidationError:
            raise
        except Exception as error:
            raise ValidationError(
                "VHD image could not be opened read-only.",
                target="path",
                details={"error": str(error)},
            ) from error
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
        assert self._fingerprint is not None
        return dict(self._fingerprint)

    def capabilities(self) -> tuple[EvidenceReaderCapabilityStatement, ...]:
        return self._capability_tuple(
            self.evidence_format,
            dependency_available=self._module is not None or self._dependency_available(),
        )

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
        if handle is not None:
            try:
                return bytes(handle.read_buffer_at_offset(bounded_length, offset))
            except Exception as error:
                raise ValidationError(
                    "VHD range read failed.",
                    target="offset",
                    details={"offset": offset, "length": bounded_length, "error": str(error)},
                ) from error
        stream = self._raw_cache_stream
        if stream is None:
            raise ValidationError("Virtual disk reader is closed.", target="reader")
        try:
            stream.seek(offset)
            return bytes(stream.read(bounded_length))
        except Exception as error:
            raise ValidationError(
                "VHDX range read failed.",
                target="offset",
                details={"offset": offset, "length": bounded_length, "error": str(error)},
            ) from error

    def close(self) -> None:
        if self._closed:
            return
        handle = self._handle
        stream = self._raw_cache_stream
        raw_cache_dir = self._raw_cache_dir
        self._handle = None
        self._raw_cache_stream = None
        self._raw_cache_dir = None
        self._closed = True
        if stream is not None:
            stream.close()
        if raw_cache_dir is not None:
            raw_cache_dir.cleanup()
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
        cls,
        evidence_format: EvidenceFormat,
        *,
        dependency_available: bool,
    ) -> tuple[EvidenceReaderCapabilityStatement, ...]:
        if evidence_format is EvidenceFormat.VHDX:
            status = (
                EvidenceReaderCapabilityStatus.SUPPORTED
                if dependency_available
                else EvidenceReaderCapabilityStatus.CAPABILITY_UNAVAILABLE
            )
            reason = None if dependency_available else "QEMU_IMG_NOT_INSTALLED"
        elif dependency_available:
            status = EvidenceReaderCapabilityStatus.SUPPORTED
            reason = None
        else:
            status = EvidenceReaderCapabilityStatus.CAPABILITY_UNAVAILABLE
            reason = "PYVHDI_NOT_INSTALLED"
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
                details={"format": evidence_format.value, "max_read_size": MAX_EVIDENCE_READ_SIZE},
            ),
            EvidenceReaderCapabilityStatement(
                EvidenceReaderCapability.SPARSE_RANGE.value,
                EvidenceReaderCapabilityStatus.PLANNED.value
                if evidence_format in {EvidenceFormat.VHD, EvidenceFormat.VHDX}
                else EvidenceReaderCapabilityStatus.CAPABILITY_UNAVAILABLE.value,
                reason=(
                    f"{evidence_format.value} sparse-range metadata is not exposed yet."
                    if evidence_format in {EvidenceFormat.VHD, EvidenceFormat.VHDX}
                    else reason
                ),
            ),
            EvidenceReaderCapabilityStatement(
                EvidenceReaderCapability.DIFFERENCING_DISK.value,
                EvidenceReaderCapabilityStatus.CAPABILITY_UNAVAILABLE.value,
                reason="Differencing disk parent resolution is not enabled.",
            ),
            EvidenceReaderCapabilityStatement(
                EvidenceReaderCapability.ENCRYPTION_DETECTION.value,
                EvidenceReaderCapabilityStatus.CAPABILITY_UNAVAILABLE.value,
                reason="Virtual disk encryption detection is not exposed by this adapter.",
            ),
        )

    @staticmethod
    def _format_for_path(path: Path) -> EvidenceFormat:
        return EvidenceFormat.VHDX if path.suffix.lower() == ".vhdx" else EvidenceFormat.VHD

    @staticmethod
    def _dependency_available() -> bool:
        try:
            importlib.import_module("pyvhdi")
        except ModuleNotFoundError:
            return False
        return True

    @staticmethod
    def _dependency_version() -> str | None:
        try:
            return importlib.metadata.version("libvhdi-python")
        except importlib.metadata.PackageNotFoundError:
            return None

    @classmethod
    def _has_vhd_signature(cls, path: Path, *, module: ModuleType | None = None) -> bool:
        try:
            pyvhdi = module or importlib.import_module("pyvhdi")
            return bool(pyvhdi.check_file_signature(str(path)))
        except Exception:
            return False

    @staticmethod
    def _qemu_img_available() -> bool:
        return shutil.which("qemu-img") is not None

    @classmethod
    def _has_vhdx_signature(cls, path: Path) -> bool:
        try:
            info = cls._qemu_image_info(path, source_format="vhdx")
        except ValidationError:
            return False
        return info.get("format") == "vhdx"

    @staticmethod
    def _qemu_img_version() -> str | None:
        executable = shutil.which("qemu-img")
        if executable is None:
            return None
        try:
            result = subprocess.run(
                [executable, "--version"],
                capture_output=True,
                check=False,
                text=True,
                timeout=10,
            )
        except Exception:
            return None
        if result.returncode != 0:
            return None
        return result.stdout.splitlines()[0] if result.stdout else None

    @staticmethod
    def _qemu_image_info(path: Path, *, source_format: str) -> dict[str, Any]:
        executable = shutil.which("qemu-img")
        if executable is None:
            raise UnsupportedCapabilityError(
                "VHDX analysis requires qemu-img.",
                target="path",
                required_capability="VHDX_READER_QEMU_IMG",
            )
        try:
            result = subprocess.run(
                [
                    executable,
                    "info",
                    "-f",
                    source_format,
                    "--output=json",
                    str(path),
                ],
                capture_output=True,
                check=False,
                text=True,
                timeout=30,
            )
        except subprocess.TimeoutExpired as error:
            raise ValidationError(
                "qemu-img info timed out while probing virtual disk.",
                target="path",
                details={"format": source_format},
            ) from error
        if result.returncode != 0:
            raise ValidationError(
                "qemu-img could not identify the virtual disk.",
                target="path",
                details={"format": source_format, "stderr": result.stderr.strip()},
            )
        try:
            info = json.loads(result.stdout)
        except json.JSONDecodeError as error:
            raise ValidationError(
                "qemu-img returned invalid JSON while probing virtual disk.",
                target="path",
                details={"format": source_format},
            ) from error
        if not isinstance(info, dict):
            raise ValidationError(
                "qemu-img returned an unexpected info payload.",
                target="path",
                details={"format": source_format},
            )
        return info

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

    def _compute_source_fingerprint(self, handle: Any) -> dict[str, Any]:
        digest = hashlib.sha256()
        with self.path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        identifier = getattr(handle, "get_identifier", lambda: None)()
        return {
            "algorithm": "SHA256",
            "value": digest.hexdigest(),
            "container_size_bytes": self.path.stat().st_size,
            "logical_size_bytes": self._size,
            "bytes_per_sector": self._sector_size,
            "disk_type": getattr(handle, "get_disk_type", lambda: None)(),
            "format_version": getattr(handle, "get_format_version", lambda: None)(),
            "identifier": None if identifier is None else str(identifier),
            "reader_id": self.reader_id,
            "reader_version": self.reader_version,
            "adapter": "pyvhdi",
            "adapter_version": self._dependency_version(),
        }

    def _open_vhdx_readonly(self) -> Self:
        normalized = self._normalize_path(self.path)
        executable = shutil.which("qemu-img")
        if executable is None:
            raise UnsupportedCapabilityError(
                "VHDX analysis requires qemu-img.",
                target="path",
                required_capability="VHDX_READER_QEMU_IMG",
            )
        source_path = Path(normalized)
        info = self._qemu_image_info(source_path, source_format="vhdx")
        if info.get("format") != "vhdx":
            raise ValidationError(
                "VHDX signature was not recognized by qemu-img.",
                target="path",
                details={"format": info.get("format")},
            )
        if info.get("backing-filename"):
            raise UnsupportedCapabilityError(
                "VHDX differencing disk parent resolution is not enabled.",
                target="path",
                required_capability="VHDX_DIFFERENCING_DISK",
            )
        raw_cache_dir = tempfile.TemporaryDirectory(prefix="apex-vhdx-")
        raw_cache_path = Path(raw_cache_dir.name) / "disk.raw"
        try:
            result = subprocess.run(
                [
                    executable,
                    "convert",
                    "-q",
                    "-f",
                    "vhdx",
                    "-O",
                    "raw",
                    normalized,
                    str(raw_cache_path),
                ],
                capture_output=True,
                check=False,
                text=True,
                timeout=120,
            )
            if result.returncode != 0:
                raise ValidationError(
                    "qemu-img could not convert VHDX to a read-only raw cache.",
                    target="path",
                    details={"stderr": result.stderr.strip()},
                )
            self._raw_cache_stream = raw_cache_path.open("rb")
            self._raw_cache_dir = raw_cache_dir
            self._size = int(info.get("virtual-size") or raw_cache_path.stat().st_size)
            self._sector_size = 512
            self._fingerprint = self._compute_vhdx_source_fingerprint(info)
            self._closed = False
        except Exception:
            raw_cache_dir.cleanup()
            raise
        return self

    def _compute_vhdx_source_fingerprint(self, info: dict[str, Any]) -> dict[str, Any]:
        digest = hashlib.sha256()
        with self.path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        return {
            "algorithm": "SHA256",
            "value": digest.hexdigest(),
            "container_size_bytes": self.path.stat().st_size,
            "logical_size_bytes": self._size,
            "bytes_per_sector": self._sector_size,
            "format": info.get("format"),
            "cluster_size": info.get("cluster-size"),
            "reader_id": self.reader_id,
            "reader_version": self.reader_version,
            "adapter": "qemu-img",
            "adapter_version": self._qemu_img_version(),
            "temporary_raw_cache": True,
        }

    def _ensure_open(self) -> None:
        if self._closed or (self._handle is None and self._raw_cache_stream is None):
            raise ValidationError("Virtual disk reader is not open.", target="reader")
