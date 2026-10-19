"""Portable read-only EWF/VHD/VHDX streams, without mounts or whole-image conversion."""

import importlib
from pathlib import Path
from types import TracebackType
from typing import Any, Self

from apex_forensic.adapters.evidence.ewf import EwfEvidenceReader
from apex_forensic.adapters.evidence.partitions import PartitionParser
from apex_forensic.constants import ENGINE_VERSION
from apex_forensic.domain.enums import EvidenceFormat
from apex_forensic.domain.errors import UnsupportedCapabilityError, ValidationError
from apex_forensic.domain.models import EvidenceVolume
from apex_forensic.ports.evidence_reader import (
    MAX_EVIDENCE_READ_SIZE,
    EvidenceProbeResult,
    EvidenceReaderCapabilityStatement,
)


class ContainerImageReader:
    reader_id = "apex.portable_container_reader"
    reader_version = ENGINE_VERSION

    def __init__(self, path: Path) -> None:
        self.path = path
        self._stream: Any = None
        self._container: Any = None
        self._source: Any = None
        self._sector_size = 512
        self._size = 0
        self._segments: tuple[Path, ...] = (path,)

    @classmethod
    def probe(cls, path: Path) -> EvidenceProbeResult:
        fmt = EvidenceFormat(path.suffix[1:].upper())
        supported, reason, sector = False, None, None
        try:
            with cls(path) as reader:
                sector = reader.sector_size
                supported = True
        except (OSError, ValueError, ValidationError, UnsupportedCapabilityError) as error:
            reason = getattr(error, "code", "CONTAINER_INVALID")
        return EvidenceProbeResult(
            reader_id=cls.reader_id,
            reader_version=cls.reader_version,
            evidence_format=fmt,
            supported=supported,
            sector_size=sector,
            capabilities=cls._capabilities(supported),
            unavailable_reason=reason,
        )

    def open_readonly(self) -> Self:
        # Import here to avoid the filesystem provider/content module dependency cycle.
        from apex_forensic.adapters.filesystem.content import regular_path

        regular_path(self.path)
        try:
            suffix = self.path.suffix.lower()
            if suffix == ".e01":
                module = importlib.import_module("dissect.evidence.ewf")
                self._segments = EwfEvidenceReader._discover_segments(self.path)
                for segment in self._segments:
                    regular_path(segment)
                self._container = module.EWF(list(self._segments))
                chunks = sum(
                    self._container.segment(i).chunk_count for i in range(len(self._segments))
                )
                if chunks != self._container.volume.chunk_count:
                    raise ValidationError("EWF segment chain is incomplete or inconsistent.")
                self._stream = self._container.open()
                self._size = int(self._container.size)
                self._sector_size = int(self._container.volume.sector_size)
            else:
                self._source = self.path.open("rb")
                if suffix == ".vhd":
                    module = importlib.import_module("dissect.hypervisor.disk.vhd")
                    footer = module.read_footer(self._source)
                    if int(footer.disk_type) == 4:
                        raise UnsupportedCapabilityError(
                            "Differencing disks require a verified parent.",
                            required_capability="VERIFIED_PARENT_DISK",
                        )
                    self._source.seek(0)
                    self._stream = module.VHD(self._source)
                elif suffix == ".vhdx":
                    module = importlib.import_module("dissect.hypervisor.disk.vhdx")
                    regions = module.RegionTable(self._source, 3 * 65536)
                    region = regions.get(module.METADATA_REGION_GUID)
                    metadata = module.MetadataTable(self._source, region.file_offset, region.length)
                    if metadata.get(module.FILE_PARAMETERS_GUID).has_parent:
                        raise UnsupportedCapabilityError(
                            "Differencing disks require a verified parent.",
                            required_capability="VERIFIED_PARENT_DISK",
                        )
                    self._source.seek(0)
                    self._stream = module.VHDX(self._source)
                    self._sector_size = int(self._stream.sector_size)
                else:
                    raise ValidationError("Unsupported image container.")
                self._size = int(self._stream.size)
            return self
        except Exception as error:
            self.close()
            if isinstance(error, (UnsupportedCapabilityError, ValidationError)):
                raise
            raise ValidationError("Container image could not be opened read-only.") from error

    @property
    def size(self) -> int:
        if self._stream is None:
            raise ValidationError("Container image is closed.")
        return self._size

    @property
    def sector_size(self) -> int:
        return self._sector_size

    @property
    def source_fingerprint(self) -> dict[str, Any]:
        return {
            "algorithm": "CONTAINER_SEGMENT_METADATA",
            "size_bytes": self.size,
            "segments": [
                {"path": str(p), "size": p.stat().st_size, "mtime_ns": p.stat().st_mtime_ns}
                for p in self._segments
            ],
            "reader_id": self.reader_id,
            "reader_version": self.reader_version,
        }

    @staticmethod
    def _capabilities(available: bool) -> tuple[EvidenceReaderCapabilityStatement, ...]:
        return tuple(
            EvidenceReaderCapabilityStatement(
                name, "SUPPORTED" if available else "CAPABILITY_UNAVAILABLE"
            )
            for name in ("READ_STREAM", "RANDOM_ACCESS", "PARTITION_ENUMERATION")
        )

    def capabilities(self) -> tuple[EvidenceReaderCapabilityStatement, ...]:
        return self._capabilities(self._stream is not None)

    def volumes(self, *, case_id: str, evidence_id: str) -> list[EvidenceVolume]:
        return PartitionParser().parse(self, case_id=case_id, evidence_id=evidence_id)

    def read_at(self, offset: int, length: int) -> bytes:
        if offset < 0 or not 0 <= length <= MAX_EVIDENCE_READ_SIZE:
            raise ValidationError("Invalid image byte range.")
        size = self.size
        if offset >= size or length == 0:
            return b""
        self._stream.seek(offset)
        return bytes(self._stream.read(min(length, size - offset)))

    def close(self) -> None:
        if self._stream is not None:
            self._stream.close()
            self._stream = None
        if self._source is not None:
            self._source.close()
            self._source = None
        if self._container is not None:
            for segment in self._container._segments.values():
                segment.fh.close()
            self._container = None

    def __enter__(self) -> Self:
        return self.open_readonly()

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()
