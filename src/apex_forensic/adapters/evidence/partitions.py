"""MBR/GPT partition parsing for read-only evidence readers."""

from __future__ import annotations

import math
import struct
import uuid
import zlib
from dataclasses import replace
from typing import Protocol
from uuid import NAMESPACE_URL, uuid5

from apex_forensic._time import utc_now
from apex_forensic.domain.enums import VolumeScheme
from apex_forensic.domain.models import EvidenceVolume

_MBR_SIGNATURE = b"\x55\xaa"
_GPT_SIGNATURE = b"EFI PART"
_EXTENDED_TYPES = {0x05, 0x0F, 0x85}
_PROTECTIVE_MBR_TYPE = 0xEE
_MAX_GPT_ENTRY_BYTES = 16 * 1024 * 1024
_MAX_EXTENDED_CHAIN = 128


class _Reader(Protocol):
    reader_id: str
    reader_version: str

    @property
    def size(self) -> int: ...

    @property
    def sector_size(self) -> int: ...

    def read_at(self, offset: int, length: int) -> bytes: ...


class PartitionParser:
    """Parse disk-image partition metadata without mounting or modifying evidence."""

    parser_id = "apex.partition_parser"
    parser_version = "0.1.0"

    def parse(self, reader: _Reader, *, case_id: str, evidence_id: str) -> list[EvidenceVolume]:
        """Return allocated and unallocated ranges for the reader's logical image."""

        if reader.size <= 0:
            return []
        sector_size = reader.sector_size
        boot = reader.read_at(0, min(sector_size, reader.size))
        if len(boot) < 512:
            return [
                self._superfloppy(
                    reader,
                    case_id=case_id,
                    evidence_id=evidence_id,
                    warning=self._warning(
                        "SHORT_BOOT_SECTOR",
                        "Image is smaller than a standard 512-byte boot sector.",
                    ),
                )
            ]
        if boot[510:512] != _MBR_SIGNATURE:
            return [self._superfloppy(reader, case_id=case_id, evidence_id=evidence_id)]
        entries = self._mbr_entries(boot)
        protective = [
            item
            for item in entries
            if item["partition_type"] == _PROTECTIVE_MBR_TYPE and item["sector_count"] > 0
        ]
        if protective:
            volumes = self._parse_gpt(reader, case_id=case_id, evidence_id=evidence_id)
            if volumes:
                return volumes
            protective_volume = self._volume(
                reader,
                case_id=case_id,
                evidence_id=evidence_id,
                volume_index=0,
                scheme=VolumeScheme.PROTECTIVE_MBR.value,
                partition_type="0xEE",
                start_lba=int(protective[0]["start_lba"]),
                sector_count=int(protective[0]["sector_count"]),
                is_allocated=True,
                name="Protective MBR",
                warnings=[
                    self._warning(
                        "GPT_HEADER_UNAVAILABLE",
                        "Protective MBR was found but the GPT header could not be parsed.",
                    )
                ],
            )
            return self._with_unallocated_gaps(reader, [protective_volume], case_id, evidence_id)
        allocated: list[EvidenceVolume] = []
        index = 0
        for entry in entries:
            partition_type = int(entry["partition_type"])
            sector_count = int(entry["sector_count"])
            start_lba = int(entry["start_lba"])
            if partition_type == 0 or sector_count == 0:
                continue
            if partition_type in _EXTENDED_TYPES:
                logical = self._parse_extended_chain(
                    reader,
                    case_id=case_id,
                    evidence_id=evidence_id,
                    base_lba=start_lba,
                    first_volume_index=index,
                )
                allocated.extend(logical)
                index += len(logical)
                continue
            allocated.append(
                self._volume(
                    reader,
                    case_id=case_id,
                    evidence_id=evidence_id,
                    volume_index=index,
                    scheme=VolumeScheme.MBR.value,
                    partition_type=f"0x{partition_type:02X}",
                    start_lba=start_lba,
                    sector_count=sector_count,
                    is_allocated=True,
                    name=f"MBR Partition {index + 1}",
                )
            )
            index += 1
        if not allocated:
            return [self._superfloppy(reader, case_id=case_id, evidence_id=evidence_id)]
        allocated = self._mark_overlaps(allocated)
        return self._with_unallocated_gaps(reader, allocated, case_id, evidence_id)

    def _parse_extended_chain(
        self,
        reader: _Reader,
        *,
        case_id: str,
        evidence_id: str,
        base_lba: int,
        first_volume_index: int,
    ) -> list[EvidenceVolume]:
        volumes: list[EvidenceVolume] = []
        visited: set[int] = set()
        next_ebr_lba = base_lba
        ended_normally = False
        chain_limited = False
        while next_ebr_lba not in visited:
            if len(visited) >= _MAX_EXTENDED_CHAIN:
                chain_limited = True
                break
            visited.add(next_ebr_lba)
            ebr = reader.read_at(next_ebr_lba * reader.sector_size, min(reader.sector_size, 512))
            if len(ebr) < 512 or ebr[510:512] != _MBR_SIGNATURE:
                volumes.append(
                    self._warning_volume(
                        reader,
                        case_id=case_id,
                        evidence_id=evidence_id,
                        volume_index=first_volume_index + len(volumes),
                        scheme=VolumeScheme.MBR_EXTENDED.value,
                        byte_offset=next_ebr_lba * reader.sector_size,
                        warning=self._warning(
                            "CORRUPT_EXTENDED_BOOT_RECORD",
                            "Extended boot record is truncated or lacks the MBR signature.",
                        ),
                    )
                )
                break
            entries = self._mbr_entries(ebr)
            logical = entries[0]
            logical_type = int(logical["partition_type"])
            if logical_type != 0 and int(logical["sector_count"]) > 0:
                volumes.append(
                    self._volume(
                        reader,
                        case_id=case_id,
                        evidence_id=evidence_id,
                        volume_index=first_volume_index + len(volumes),
                        scheme=VolumeScheme.MBR_EXTENDED.value,
                        partition_type=f"0x{logical_type:02X}",
                        start_lba=next_ebr_lba + int(logical["start_lba"]),
                        sector_count=int(logical["sector_count"]),
                        is_allocated=True,
                        name=f"Logical Partition {len(volumes) + 1}",
                    )
                )
            link = entries[1]
            link_type = int(link["partition_type"])
            if link_type not in _EXTENDED_TYPES or int(link["sector_count"]) <= 0:
                ended_normally = True
                break
            next_ebr_lba = base_lba + int(link["start_lba"])
        if chain_limited:
            volumes.append(
                self._warning_volume(
                    reader,
                    case_id=case_id,
                    evidence_id=evidence_id,
                    volume_index=first_volume_index + len(volumes),
                    scheme=VolumeScheme.MBR_EXTENDED.value,
                    byte_offset=next_ebr_lba * reader.sector_size,
                    warning=self._warning(
                        "EXTENDED_CHAIN_LIMIT_REACHED",
                        "Extended partition chain exceeded the parser safety limit.",
                    ),
                )
            )
        elif not ended_normally and next_ebr_lba in visited:
            volumes.append(
                self._warning_volume(
                    reader,
                    case_id=case_id,
                    evidence_id=evidence_id,
                    volume_index=first_volume_index + len(volumes),
                    scheme=VolumeScheme.MBR_EXTENDED.value,
                    byte_offset=next_ebr_lba * reader.sector_size,
                    warning=self._warning(
                        "EXTENDED_CHAIN_CYCLE",
                        "Extended partition chain references an already visited EBR.",
                    ),
                )
            )
        return volumes

    def _parse_gpt(
        self, reader: _Reader, *, case_id: str, evidence_id: str
    ) -> list[EvidenceVolume]:
        sector_size = reader.sector_size
        header = reader.read_at(sector_size, sector_size)
        if len(header) < 92 or header[:8] != _GPT_SIGNATURE:
            return []
        warnings: list[dict[str, object]] = []
        header_size = struct.unpack_from("<I", header, 12)[0]
        if header_size < 92 or header_size > len(header):
            return []
        observed_crc = struct.unpack_from("<I", header, 16)[0]
        crc_bytes = bytearray(header[:header_size])
        struct.pack_into("<I", crc_bytes, 16, 0)
        calculated_crc = zlib.crc32(crc_bytes) & 0xFFFFFFFF
        if calculated_crc != observed_crc:
            warnings.append(
                self._warning(
                    "GPT_HEADER_CRC_MISMATCH",
                    "GPT header CRC does not match; entries are parsed with reduced confidence.",
                    {"expected": observed_crc, "observed": calculated_crc},
                )
            )
        first_usable = struct.unpack_from("<Q", header, 40)[0]
        last_usable = struct.unpack_from("<Q", header, 48)[0]
        entry_lba = struct.unpack_from("<Q", header, 72)[0]
        entry_count = struct.unpack_from("<I", header, 80)[0]
        entry_size = struct.unpack_from("<I", header, 84)[0]
        entries_crc = struct.unpack_from("<I", header, 88)[0]
        if entry_size < 128 or entry_count == 0:
            return []
        entry_bytes = entry_count * entry_size
        if entry_bytes > _MAX_GPT_ENTRY_BYTES:
            warnings.append(
                self._warning(
                    "GPT_ENTRY_ARRAY_TOO_LARGE",
                    "GPT entry array exceeds the parser safety bound.",
                    {"entry_count": entry_count, "entry_size": entry_size},
                )
            )
            return [
                self._warning_volume(
                    reader,
                    case_id=case_id,
                    evidence_id=evidence_id,
                    volume_index=0,
                    scheme=VolumeScheme.GPT.value,
                    byte_offset=entry_lba * sector_size,
                    warning=warnings[-1],
                )
            ]
        entries_offset = entry_lba * sector_size
        if entries_offset >= reader.size:
            return []
        entries_data = reader.read_at(
            entries_offset,
            min(entry_bytes, reader.size - entries_offset),
        )
        if len(entries_data) < entry_bytes:
            warnings.append(
                self._warning(
                    "GPT_ENTRY_ARRAY_TRUNCATED",
                    "GPT entry array extends beyond the image boundary.",
                    {"declared_bytes": entry_bytes, "available_bytes": len(entries_data)},
                )
            )
        if len(entries_data) >= entry_bytes:
            observed_entries_crc = zlib.crc32(entries_data[:entry_bytes]) & 0xFFFFFFFF
            if observed_entries_crc != entries_crc:
                warnings.append(
                    self._warning(
                        "GPT_ENTRY_CRC_MISMATCH",
                        "GPT partition entry CRC does not match.",
                        {"expected": entries_crc, "observed": observed_entries_crc},
                    )
                )
        volumes: list[EvidenceVolume] = []
        count = min(entry_count, len(entries_data) // entry_size)
        for index in range(count):
            entry = entries_data[index * entry_size : (index + 1) * entry_size]
            type_guid = entry[:16]
            if type_guid == b"\x00" * 16:
                continue
            unique_guid = entry[16:32]
            start_lba = struct.unpack_from("<Q", entry, 32)[0]
            end_lba = struct.unpack_from("<Q", entry, 40)[0]
            if end_lba < start_lba:
                entry_warning = self._warning(
                    "GPT_ENTRY_INVALID_RANGE",
                    "GPT entry end LBA is before its start LBA.",
                    {"entry_index": index, "start_lba": start_lba, "end_lba": end_lba},
                )
                volumes.append(
                    self._warning_volume(
                        reader,
                        case_id=case_id,
                        evidence_id=evidence_id,
                        volume_index=len(volumes),
                        scheme=VolumeScheme.GPT.value,
                        byte_offset=start_lba * sector_size,
                        warning=entry_warning,
                    )
                )
                continue
            name = entry[56:128].decode("utf-16-le", errors="replace").rstrip("\x00") or None
            volume = self._volume(
                reader,
                case_id=case_id,
                evidence_id=evidence_id,
                volume_index=len(volumes),
                scheme=VolumeScheme.GPT.value,
                partition_type=str(uuid.UUID(bytes_le=type_guid)),
                start_lba=start_lba,
                sector_count=end_lba - start_lba + 1,
                is_allocated=True,
                name=name,
                guid=str(uuid.UUID(bytes_le=unique_guid)),
                warnings=warnings.copy(),
            )
            if start_lba < first_usable or end_lba > last_usable:
                volume.warnings.append(
                    self._warning(
                        "GPT_ENTRY_OUTSIDE_USABLE_RANGE",
                        "GPT entry is outside the usable LBA range.",
                        {
                            "entry_index": index,
                            "first_usable_lba": first_usable,
                            "last_usable_lba": last_usable,
                        },
                    )
                )
            volumes.append(volume)
        if not volumes:
            return []
        volumes = self._mark_overlaps(volumes)
        return self._with_unallocated_gaps(
            reader,
            volumes,
            case_id,
            evidence_id,
            gap_start_lba=first_usable,
            gap_end_lba=last_usable,
            scheme=VolumeScheme.GPT.value,
        )

    @staticmethod
    def _mbr_entries(sector: bytes) -> list[dict[str, int]]:
        entries: list[dict[str, int]] = []
        for index in range(4):
            offset = 446 + index * 16
            entry = sector[offset : offset + 16]
            entries.append(
                {
                    "status": entry[0],
                    "partition_type": entry[4],
                    "start_lba": struct.unpack_from("<I", entry, 8)[0],
                    "sector_count": struct.unpack_from("<I", entry, 12)[0],
                }
            )
        return entries

    def _volume(
        self,
        reader: _Reader,
        *,
        case_id: str,
        evidence_id: str,
        volume_index: int,
        scheme: str,
        partition_type: str,
        start_lba: int,
        sector_count: int,
        is_allocated: bool,
        name: str | None,
        guid: str | None = None,
        warnings: list[dict[str, object]] | None = None,
    ) -> EvidenceVolume:
        warnings = [] if warnings is None else warnings
        if start_lba < 0 or sector_count < 0:
            warnings.append(
                self._warning(
                    "NEGATIVE_PARTITION_RANGE",
                    "Partition range contains a negative start or length.",
                )
            )
            start_lba = max(0, start_lba)
            sector_count = max(0, sector_count)
        declared_offset = start_lba * reader.sector_size
        declared_length = sector_count * reader.sector_size
        byte_offset = declared_offset
        byte_length = declared_length
        if byte_offset > reader.size:
            warnings.append(
                self._warning(
                    "PARTITION_OFFSET_BEYOND_IMAGE",
                    "Partition starts beyond the image boundary.",
                    {"declared_offset": declared_offset, "image_size": reader.size},
                )
            )
            byte_length = 0
        elif byte_offset + byte_length > reader.size:
            warnings.append(
                self._warning(
                    "PARTITION_RANGE_TRUNCATED",
                    "Partition range extends beyond the image boundary.",
                    {
                        "declared_offset": declared_offset,
                        "declared_length": declared_length,
                        "image_size": reader.size,
                    },
                )
            )
            byte_length = max(0, reader.size - byte_offset)
        effective_sectors = math.ceil(byte_length / reader.sector_size) if byte_length else 0
        end_lba = start_lba + effective_sectors - 1 if effective_sectors else start_lba - 1
        volume_id = self._volume_id(
            case_id,
            evidence_id,
            scheme,
            partition_type,
            str(start_lba),
            str(declared_length),
            guid or "",
            str(is_allocated),
        )
        raw_locator = {
            "locator_type": "DISK_IMAGE_BYTE_RANGE",
            "evidence_id": evidence_id,
            "volume_id": volume_id,
            "byte_offset": byte_offset,
            "byte_length": byte_length,
            "declared_byte_offset": declared_offset,
            "declared_byte_length": declared_length,
            "sector_size": reader.sector_size,
            "partition_scheme": scheme,
            "reader_id": reader.reader_id,
            "reader_version": reader.reader_version,
            "parser_id": self.parser_id,
            "parser_version": self.parser_version,
        }
        return EvidenceVolume(
            volume_id=volume_id,
            case_id=case_id,
            evidence_id=evidence_id,
            volume_index=volume_index,
            scheme=scheme,
            partition_type=partition_type,
            start_lba=start_lba,
            end_lba=end_lba,
            byte_offset=byte_offset,
            byte_length=byte_length,
            sector_size=reader.sector_size,
            is_allocated=is_allocated,
            raw_locator=raw_locator,
            reader_id=reader.reader_id,
            reader_version=reader.reader_version,
            created_at=utc_now(),
            name=name,
            guid=guid,
            warnings=warnings,
        )

    def _superfloppy(
        self,
        reader: _Reader,
        *,
        case_id: str,
        evidence_id: str,
        warning: dict[str, object] | None = None,
    ) -> EvidenceVolume:
        warnings = [] if warning is None else [warning]
        return self._volume(
            reader,
            case_id=case_id,
            evidence_id=evidence_id,
            volume_index=0,
            scheme=VolumeScheme.SUPERFLOPPY.value,
            partition_type="UNPARTITIONED",
            start_lba=0,
            sector_count=math.ceil(reader.size / reader.sector_size),
            is_allocated=True,
            name="Unpartitioned Image",
            warnings=warnings,
        )

    def _warning_volume(
        self,
        reader: _Reader,
        *,
        case_id: str,
        evidence_id: str,
        volume_index: int,
        scheme: str,
        byte_offset: int,
        warning: dict[str, object],
    ) -> EvidenceVolume:
        start_lba = max(0, byte_offset // reader.sector_size)
        return self._volume(
            reader,
            case_id=case_id,
            evidence_id=evidence_id,
            volume_index=volume_index,
            scheme=scheme,
            partition_type="PARSER_WARNING",
            start_lba=start_lba,
            sector_count=0,
            is_allocated=False,
            name="Partition Parser Warning",
            warnings=[warning],
        )

    def _with_unallocated_gaps(
        self,
        reader: _Reader,
        allocated: list[EvidenceVolume],
        case_id: str,
        evidence_id: str,
        *,
        gap_start_lba: int = 0,
        gap_end_lba: int | None = None,
        scheme: str = VolumeScheme.UNPARTITIONED.value,
    ) -> list[EvidenceVolume]:
        if not allocated:
            return []
        end_limit = reader.size
        if gap_end_lba is not None:
            end_limit = min(end_limit, (gap_end_lba + 1) * reader.sector_size)
        cursor = min(end_limit, max(0, gap_start_lba * reader.sector_size))
        combined: list[EvidenceVolume] = []
        unallocated_index = 0
        for volume in sorted(allocated, key=lambda item: (item.byte_offset, item.volume_id)):
            if volume.byte_offset > cursor:
                combined.append(
                    self._unallocated_gap(
                        reader,
                        case_id=case_id,
                        evidence_id=evidence_id,
                        volume_index=10_000 + unallocated_index,
                        byte_offset=cursor,
                        byte_length=volume.byte_offset - cursor,
                        scheme=scheme,
                    )
                )
                unallocated_index += 1
            combined.append(volume)
            cursor = max(cursor, volume.byte_offset + volume.byte_length)
        if cursor < end_limit:
            combined.append(
                self._unallocated_gap(
                    reader,
                    case_id=case_id,
                    evidence_id=evidence_id,
                    volume_index=10_000 + unallocated_index,
                    byte_offset=cursor,
                    byte_length=end_limit - cursor,
                    scheme=scheme,
                )
            )
        return [replace(volume, volume_index=index) for index, volume in enumerate(combined)]

    def _unallocated_gap(
        self,
        reader: _Reader,
        *,
        case_id: str,
        evidence_id: str,
        volume_index: int,
        byte_offset: int,
        byte_length: int,
        scheme: str,
    ) -> EvidenceVolume:
        start_lba = byte_offset // reader.sector_size
        sectors = math.ceil(byte_length / reader.sector_size)
        return self._volume(
            reader,
            case_id=case_id,
            evidence_id=evidence_id,
            volume_index=volume_index,
            scheme=scheme,
            partition_type="UNALLOCATED",
            start_lba=start_lba,
            sector_count=sectors,
            is_allocated=False,
            name="Unallocated Range",
        )

    def _mark_overlaps(self, volumes: list[EvidenceVolume]) -> list[EvidenceVolume]:
        sorted_volumes = sorted(volumes, key=lambda item: (item.byte_offset, item.byte_length))
        previous_end = -1
        for volume in sorted_volumes:
            if volume.byte_offset < previous_end:
                volume.warnings.append(
                    self._warning(
                        "PARTITION_OVERLAP",
                        "Partition overlaps a previously parsed partition.",
                    )
                )
            previous_end = max(previous_end, volume.byte_offset + volume.byte_length)
        return volumes

    @staticmethod
    def _warning(
        code: str, developer_message: str, details: dict[str, object] | None = None
    ) -> dict[str, object]:
        return {
            "code": code,
            "message_key": f"warning.partition.{code.lower()}",
            "developer_message": developer_message,
            "details": details or {},
        }

    @staticmethod
    def _volume_id(*parts: str) -> str:
        return str(uuid5(NAMESPACE_URL, ":".join(["apex-volume-v1", *parts])))
