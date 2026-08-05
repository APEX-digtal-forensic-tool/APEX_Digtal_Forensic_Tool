"""Conservative Windows Registry binary deleted-cell carver."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from apex_forensic.constants import ENGINE_VERSION
from apex_forensic.domain.models import (
    RegistryCarvingReport,
    RegistryDeletedCellCandidate,
)

_HIVE_HEADER_SIZE = 4096
_HBIN_HEADER_SIZE = 32
_MAX_HBIN_SIZE = 64 * 1024 * 1024
_MAX_CELL_SIZE = 16 * 1024 * 1024
_MAX_NAME_BYTES = 1024
_REG_TYPES = {
    0: "REG_NONE",
    1: "REG_SZ",
    2: "REG_EXPAND_SZ",
    3: "REG_BINARY",
    4: "REG_DWORD",
    7: "REG_MULTI_SZ",
    11: "REG_QWORD",
}


class RegistryDeletedCellCarver:
    """Parse HBIN free cells and slack without promoting candidates to facts."""

    provider_id = "apex.registry.deleted-cell-carver"
    provider_version = ENGINE_VERSION

    def carve(
        self,
        hive_path: Path,
        *,
        max_candidates: int | None = None,
    ) -> RegistryCarvingReport:
        try:
            data = hive_path.read_bytes()
        except OSError as error:
            return RegistryCarvingReport(
                provider_id=self.provider_id,
                provider_version=self.provider_version,
                status="FAILED",
                warnings=(
                    {
                        "code": "REGISTRY_HIVE_READ_FAILED",
                        "developer_message": "Registry hive could not be read for carving.",
                        "error_type": type(error).__name__,
                    },
                ),
            )
        if len(data) < _HIVE_HEADER_SIZE or data[:4] != b"regf":
            return RegistryCarvingReport(
                provider_id=self.provider_id,
                provider_version=self.provider_version,
                status="UNSUPPORTED_VERSION",
                warnings=(
                    {
                        "code": "REGISTRY_HIVE_HEADER_UNSUPPORTED",
                        "developer_message": "Registry hive header is missing or unsupported.",
                    },
                ),
                coverage={"hive_size": len(data), "hbin_count": 0},
            )
        candidates: list[RegistryDeletedCellCandidate] = []
        warnings: list[dict[str, Any]] = []
        hbin_count = 0
        free_cell_count = 0
        slack_bytes = 0
        offset = _HIVE_HEADER_SIZE
        while offset + _HBIN_HEADER_SIZE <= len(data):
            if data[offset : offset + 4] != b"hbin":
                next_hbin = data.find(b"hbin", offset + 8)
                if next_hbin < 0:
                    break
                warnings.append(
                    {
                        "code": "REGISTRY_HBIN_ALIGNMENT_RECOVERED",
                        "developer_message": "Skipped bytes before the next HBIN signature.",
                        "offset": offset,
                        "next_hbin_offset": next_hbin,
                    }
                )
                offset = next_hbin
                continue
            hbin_size = _u32(data, offset + 8)
            if (
                hbin_size is None
                or hbin_size < _HBIN_HEADER_SIZE
                or hbin_size > _MAX_HBIN_SIZE
                or offset + hbin_size > len(data)
            ):
                warnings.append(
                    {
                        "code": "REGISTRY_HBIN_SIZE_INVALID",
                        "developer_message": "HBIN size is outside safe bounds.",
                        "offset": offset,
                        "declared_size": hbin_size,
                    }
                )
                break
            hbin_count += 1
            hbin_candidates, free_cells, slack = self._carve_hbin(
                data,
                hbin_offset=offset,
                hbin_size=hbin_size,
                max_candidates=None
                if max_candidates is None
                else max(0, max_candidates - len(candidates)),
            )
            candidates.extend(hbin_candidates)
            free_cell_count += free_cells
            slack_bytes += slack
            if max_candidates is not None and len(candidates) >= max_candidates:
                break
            offset += hbin_size
        status = "SUCCESS" if candidates else "PARTIAL"
        return RegistryCarvingReport(
            provider_id=self.provider_id,
            provider_version=self.provider_version,
            status=status,
            candidates=tuple(candidates),
            warnings=tuple(warnings),
            coverage={
                "hive_size": len(data),
                "hbin_count": hbin_count,
                "free_cell_count": free_cell_count,
                "hbin_slack_bytes": slack_bytes,
                "candidate_count": len(candidates),
                "candidate_semantics": "DELETED_CELL_CANDIDATE_NOT_OBSERVED_FACT",
            },
        )

    def _carve_hbin(
        self,
        data: bytes,
        *,
        hbin_offset: int,
        hbin_size: int,
        max_candidates: int | None,
    ) -> tuple[list[RegistryDeletedCellCandidate], int, int]:
        hbin_end = hbin_offset + hbin_size
        cell_offset = hbin_offset + _HBIN_HEADER_SIZE
        candidates: list[RegistryDeletedCellCandidate] = []
        covered = bytearray(hbin_size)
        covered[:_HBIN_HEADER_SIZE] = b"\x01" * _HBIN_HEADER_SIZE
        free_cells = 0
        while cell_offset + 4 <= hbin_end:
            raw_size = _i32(data, cell_offset)
            if raw_size is None or raw_size == 0:
                break
            cell_size = abs(raw_size)
            if cell_size < 8 or cell_size > _MAX_CELL_SIZE or cell_offset + cell_size > hbin_end:
                break
            start = cell_offset - hbin_offset
            covered[start : start + cell_size] = b"\x01" * cell_size
            if raw_size > 0:
                free_cells += 1
                candidate = _candidate_from_cell(
                    data,
                    absolute_offset=cell_offset,
                    cell_size=cell_size,
                    hbin_offset=hbin_offset,
                    source_region="FREE_CELL",
                )
                if candidate is not None:
                    candidates.append(candidate)
                    if max_candidates is not None and len(candidates) >= max_candidates:
                        return candidates, free_cells, _slack_count(covered)
            cell_offset += cell_size
        for relative in range(_HBIN_HEADER_SIZE, hbin_size - 2, 8):
            if covered[relative]:
                continue
            absolute = hbin_offset + relative
            signature = data[absolute : absolute + 2]
            if signature not in {b"nk", b"vk", b"sk"}:
                continue
            candidate = _candidate_from_body(
                data,
                absolute_offset=absolute,
                available=min(512, hbin_offset + hbin_size - absolute),
                hbin_offset=hbin_offset,
                source_region="HBIN_SLACK",
            )
            if candidate is not None:
                candidates.append(candidate)
                if max_candidates is not None and len(candidates) >= max_candidates:
                    break
        return candidates, free_cells, _slack_count(covered)


def _candidate_from_cell(
    data: bytes,
    *,
    absolute_offset: int,
    cell_size: int,
    hbin_offset: int,
    source_region: str,
) -> RegistryDeletedCellCandidate | None:
    body_offset = absolute_offset + 4
    return _candidate_from_body(
        data,
        absolute_offset=body_offset,
        available=cell_size - 4,
        hbin_offset=hbin_offset,
        source_region=source_region,
        cell_offset=absolute_offset,
        cell_size=cell_size,
    )


def _candidate_from_body(
    data: bytes,
    *,
    absolute_offset: int,
    available: int,
    hbin_offset: int,
    source_region: str,
    cell_offset: int | None = None,
    cell_size: int | None = None,
) -> RegistryDeletedCellCandidate | None:
    signature = data[absolute_offset : absolute_offset + 2]
    if signature == b"nk":
        return _parse_nk(
            data,
            absolute_offset=absolute_offset,
            available=available,
            hbin_offset=hbin_offset,
            source_region=source_region,
            cell_offset=cell_offset,
            cell_size=cell_size,
        )
    if signature == b"vk":
        return _parse_vk(
            data,
            absolute_offset=absolute_offset,
            available=available,
            hbin_offset=hbin_offset,
            source_region=source_region,
            cell_offset=cell_offset,
            cell_size=cell_size,
        )
    if signature == b"sk":
        return RegistryDeletedCellCandidate(
            candidate_type="SK",
            source_region=source_region,
            absolute_offset=cell_offset if cell_offset is not None else absolute_offset,
            length=cell_size or available,
            hbin_offset=hbin_offset,
            confidence="MEDIUM",
            reasons=("signature", "bounds", "hbin_containment", "alignment"),
            partial=True,
        )
    return None


def _parse_nk(
    data: bytes,
    *,
    absolute_offset: int,
    available: int,
    hbin_offset: int,
    source_region: str,
    cell_offset: int | None,
    cell_size: int | None,
) -> RegistryDeletedCellCandidate | None:
    if available < 76:
        return None
    name_length = _u16(data, absolute_offset + 72)
    if name_length is None or name_length < 1 or name_length > _MAX_NAME_BYTES:
        return None
    if 76 + name_length > available:
        return None
    flags = _u16(data, absolute_offset + 2) or 0
    raw_name = data[absolute_offset + 76 : absolute_offset + 76 + name_length]
    name = _decode_name(raw_name, compressed=bool(flags & 0x20))
    if not _plausible_name(name):
        return None
    parent = _u32(data, absolute_offset + 16)
    return RegistryDeletedCellCandidate(
        candidate_type="NK",
        source_region=source_region,
        absolute_offset=cell_offset if cell_offset is not None else absolute_offset,
        length=cell_size or available,
        hbin_offset=hbin_offset,
        confidence="HIGH" if source_region == "FREE_CELL" else "MEDIUM",
        reasons=(
            "signature",
            "bounds",
            "cell_length",
            "name_length",
            "hbin_containment",
            "alignment",
        ),
        name=name,
        parent_cell_offset=parent,
        partial=True,
        raw_name_hex=raw_name.hex(),
    )


def _parse_vk(
    data: bytes,
    *,
    absolute_offset: int,
    available: int,
    hbin_offset: int,
    source_region: str,
    cell_offset: int | None,
    cell_size: int | None,
) -> RegistryDeletedCellCandidate | None:
    if available < 20:
        return None
    name_length = _u16(data, absolute_offset + 2)
    if name_length is None or name_length > _MAX_NAME_BYTES or 20 + name_length > available:
        return None
    raw_size = _u32(data, absolute_offset + 4)
    data_reference = _u32(data, absolute_offset + 8)
    type_id = _u32(data, absolute_offset + 12)
    flags = _u16(data, absolute_offset + 16) or 0
    if raw_size is None or type_id is None:
        return None
    value_length = raw_size & 0x7FFF_FFFF
    if value_length > _MAX_CELL_SIZE:
        return None
    raw_name = data[absolute_offset + 20 : absolute_offset + 20 + name_length]
    name = "@" if name_length == 0 else _decode_name(raw_name, compressed=bool(flags & 0x1))
    if not _plausible_name(name):
        return None
    inline = bool(raw_size & 0x8000_0000)
    value_data = None
    if inline:
        inline_bytes = int(data_reference or 0).to_bytes(4, "little")[:value_length]
        value_data = _decode_value(inline_bytes, type_id)
    return RegistryDeletedCellCandidate(
        candidate_type="VK",
        source_region=source_region,
        absolute_offset=cell_offset if cell_offset is not None else absolute_offset,
        length=cell_size or available,
        hbin_offset=hbin_offset,
        confidence="HIGH" if source_region == "FREE_CELL" else "MEDIUM",
        reasons=(
            "signature",
            "bounds",
            "cell_length",
            "name_length",
            "data_length",
            "hbin_containment",
            "alignment",
        ),
        name=name,
        value_type=_REG_TYPES.get(type_id, f"REG_TYPE_{type_id}"),
        value_data=value_data,
        data_reference_offset=None if inline else data_reference,
        partial=not inline,
        raw_name_hex=raw_name.hex(),
    )


def _decode_value(raw: bytes, type_id: int) -> Any:
    if type_id == 4:
        return int.from_bytes(raw[:4].ljust(4, b"\x00"), "little", signed=False)
    if type_id in {1, 2}:
        return raw.rstrip(b"\x00").decode("utf-16le", errors="replace")
    if type_id == 3:
        return {"encoding": "hex", "value_hex": raw.hex()}
    return {"encoding": "hex", "value_hex": raw.hex()}


def _decode_name(raw: bytes, *, compressed: bool) -> str:
    if compressed:
        return raw.decode("latin-1", errors="replace")
    return raw.decode("utf-16le", errors="replace")


def _plausible_name(name: str) -> bool:
    if not name:
        return False
    if len(name) > 512 or "\x00" in name:
        return False
    return sum(1 for char in name if char.isprintable()) >= max(1, len(name) - 1)


def _u16(data: bytes, offset: int) -> int | None:
    if offset + 2 > len(data):
        return None
    return int.from_bytes(data[offset : offset + 2], "little", signed=False)


def _u32(data: bytes, offset: int) -> int | None:
    if offset + 4 > len(data):
        return None
    return int.from_bytes(data[offset : offset + 4], "little", signed=False)


def _i32(data: bytes, offset: int) -> int | None:
    if offset + 4 > len(data):
        return None
    return int.from_bytes(data[offset : offset + 4], "little", signed=True)


def _slack_count(covered: bytearray) -> int:
    return sum(1 for item in covered if not item)
