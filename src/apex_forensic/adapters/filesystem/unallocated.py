"""Enumerate verified free allocation units; never infer free space from file extents."""

from collections.abc import Callable, Iterator
from typing import Any

from apex_forensic.domain.errors import UnsupportedCapabilityError, ValidationError


def bitmap_runs(
    read: Callable[[int, int], bytes], count: int, unit: int, base: int
) -> Iterator[tuple[int, int]]:
    start: int | None = None
    index = 0
    while index < count:
        data = read(index // 8, min(65536, (count - index + 7) // 8))
        if not data:
            raise ValidationError("Allocation bitmap ended before the volume boundary.")
        for byte in data:
            for bit in range(8):
                if index >= count:
                    break
                if not byte & (1 << bit):
                    if start is None:
                        start = index
                elif start is not None:
                    yield base + start * unit, (index - start) * unit
                    start = None
                index += 1
    if start is not None:
        yield base + start * unit, (count - start) * unit


def free_ranges(
    reader: Any, filesystem: Any, volume: Any, warnings: list[str] | None = None
) -> Iterator[tuple[int, int]]:
    base, size = volume.byte_offset, volume.byte_length
    boot = reader.read_at(base, 4096)
    if boot[3:11] == b"NTFS    ":
        bitmap = filesystem.open_meta(inode=6)  # $Bitmap, allocated cluster bits.
        unit = int(filesystem.info.block_size)
        count = min(int(filesystem.info.block_count), size // unit)
        yield from bitmap_runs(lambda o, n: bytes(bitmap.read_random(o, n)), count, unit, base)
        return
    if boot[3:11] == b"EXFAT   ":
        yield from _exfat(reader, boot, base, size)
        return
    if boot[1080:1082] == b"\x53\xef":
        yield from _ext(reader, boot[1024:], base, size, warnings)
        return
    sector = int.from_bytes(boot[11:13], "little")
    if sector in {512, 1024, 2048, 4096} and boot[13] in {1, 2, 4, 8, 16, 32, 64, 128}:
        yield from _fat(reader, boot, base, size)
        return
    raise UnsupportedCapabilityError(
        "Allocation map is not supported for this filesystem.",
        required_capability="FILESYSTEM_FREE_SPACE",
    )


def _fat(reader: Any, boot: bytes, base: int, size: int) -> Iterator[tuple[int, int]]:
    def u(start: int, length: int) -> int:
        return int.from_bytes(boot[start : start + length], "little")

    sector, cluster = u(11, 2), boot[13]
    reserved, fats = u(14, 2), boot[16]
    fat_sectors = u(22, 2) or u(36, 4)
    total = u(19, 2) or u(32, 4)
    data_sector = reserved + fats * fat_sectors + (u(17, 2) * 32 + sector - 1) // sector
    count = (min(total, size // sector) - data_sector) // cluster
    if count <= 0 or not fat_sectors or not fats:
        raise ValidationError("Invalid FAT allocation geometry.")
    bits = 12 if count < 4085 else (16 if count < 65525 else 32)
    fat_start = base + reserved * sector
    if bits == 32 and u(40, 2) & 0x80:
        active = u(40, 2) & 15
        if active >= fats:
            raise ValidationError("Invalid active FAT.")
        fat_start += active * fat_sectors * sector
    cache_offset, cache = -1, b""
    start: int | None = None
    unit = cluster * sector
    for cluster_id in range(2, count + 2):
        offset = cluster_id * bits // 8
        width = 2 if bits == 12 else bits // 8
        if offset + width > fat_sectors * sector:
            raise ValidationError("FAT is smaller than its declared cluster count.")
        if not cache_offset <= offset <= cache_offset + len(cache) - width:
            cache_offset = offset
            cache = reader.read_at(fat_start + offset, min(65536, fat_sectors * sector - offset))
        entry = cache[offset - cache_offset : offset - cache_offset + width]
        if len(entry) != width:
            raise ValidationError("Truncated FAT allocation table.")
        value = int.from_bytes(entry, "little")
        value = (value >> (4 if cluster_id & 1 else 0)) & 0xFFF if bits == 12 else value
        if bits == 32:
            value &= 0x0FFFFFFF
        if value == 0:
            if start is None:
                start = cluster_id
        elif start is not None:
            yield base + data_sector * sector + (start - 2) * unit, (cluster_id - start) * unit
            start = None
    if start is not None:
        yield base + data_sector * sector + (start - 2) * unit, (count + 2 - start) * unit


def _ext(
    reader: Any, sb: bytes, base: int, size: int, warnings: list[str] | None = None
) -> Iterator[tuple[int, int]]:
    def u(start: int, length: int = 4) -> int:
        return int.from_bytes(sb[start : start + length], "little")

    if u(24) > 6:
        raise ValidationError("Invalid EXT block size.")
    unit = 1024 << u(24)
    per_group, first, blocks = u(32), u(20), u(4)
    incompat, ro_compat = u(96), u(100)
    if ro_compat & 0x200:  # BIGALLOC needs cluster accounting, never guess block bits.
        raise UnsupportedCapabilityError(
            "EXT bigalloc requires cluster bitmap support.", required_capability="EXT_BIGALLOC"
        )
    if incompat & 0x10:  # META_BG changes descriptor placement.
        raise UnsupportedCapabilityError(
            "EXT meta_bg descriptor layout is unsupported.", required_capability="EXT_META_BG"
        )
    if incompat & 0x80:
        blocks |= u(336) << 32
    desc_size = max(32, u(254, 2)) if incompat & 0x80 else 32
    if (
        not 0 < per_group <= unit * 8
        or not first < blocks
        or blocks * unit > size
        or not 32 <= desc_size <= unit
    ):
        raise ValidationError("Invalid EXT allocation geometry.")
    table = base + (2 if unit == 1024 else 1) * unit
    for group in range((blocks - first + per_group - 1) // per_group):
        if table + (group + 1) * desc_size > base + size:
            raise ValidationError("EXT descriptor exceeds volume.")
        descriptor = reader.read_at(table + group * desc_size, desc_size)
        if len(descriptor) != desc_size:
            raise ValidationError("Truncated EXT descriptor.")
        bitmap_block = int.from_bytes(descriptor[:4], "little")
        if desc_size >= 64:
            bitmap_block |= int.from_bytes(descriptor[32:36], "little") << 32
        if int.from_bytes(descriptor[18:20], "little") & 2:
            # BLOCK_UNINIT bitmaps are not authoritative; report omitted coverage.
            if warnings is not None:
                warning = "EXT_UNINITIALIZED_GROUPS_SKIPPED: allocation map coverage is incomplete"
                if warning not in warnings:
                    warnings.append(warning)
            continue
        if not 0 < bitmap_block < blocks:
            raise ValidationError("Invalid EXT block bitmap location.")
        group_start = first + group * per_group
        count = min(per_group, blocks - group_start)
        def read_group(offset: int, amount: int, *, block: int = bitmap_block) -> bytes:
            return bytes(reader.read_at(base + block * unit + offset, amount))

        yield from bitmap_runs(
            read_group,
            count,
            unit,
            base + group_start * unit,
        )


def _exfat(reader: Any, boot: bytes, base: int, size: int) -> Iterator[tuple[int, int]]:
    def u(start: int, length: int = 4) -> int:
        return int.from_bytes(boot[start : start + length], "little")

    if not 9 <= boot[108] <= 12 or boot[108] + boot[109] > 24:
        raise ValidationError("Invalid exFAT cluster size.")
    sector = 1 << boot[108]
    unit = sector << boot[109]
    heap, count, root = u(88), u(92), u(96)
    fat = base + u(80) * sector + (u(106, 2) & 1) * u(84) * sector
    if (
        not count
        or (heap * sector + count * unit) > size
        or (count + 2) * 4 > u(84) * sector
        or not base <= fat < fat + u(84) * sector <= base + heap * sector
    ):
        raise ValidationError("Invalid exFAT allocation geometry.")

    def cluster_offset(cluster: int) -> int:
        if not 2 <= cluster < count + 2:
            raise ValidationError("Invalid exFAT cluster chain.")
        return base + heap * sector + (cluster - 2) * unit

    seen: set[int] = set()
    while root < 0xFFFFFFF8 and root not in seen:
        seen.add(root)
        if len(seen) > 65536:
            raise ValidationError("exFAT root directory exceeds scan limit.")
        data = reader.read_at(cluster_offset(root), unit)
        for offset in range(0, len(data), 32):
            entry = data[offset : offset + 32]
            if not entry or entry[0] == 0:
                break
            if entry[0] != 0x81 or (entry[1] & 1) != (u(106, 2) & 1):
                continue
            location = int.from_bytes(entry[20:24], "little")
            length = int.from_bytes(entry[24:32], "little")
            required = (count + 7) // 8
            if not required <= length <= required + unit:
                raise ValidationError("exFAT bitmap is truncated.")
            # The bitmap itself follows its FAT cluster chain (Microsoft exFAT §7.1.3).
            chain: list[int] = []
            visited: set[int] = set()
            current = location
            for _ in range((required + unit - 1) // unit):
                if current in visited:
                    raise ValidationError("Cyclic exFAT bitmap chain.")
                visited.add(current)
                chain.append(cluster_offset(current))
                current = int.from_bytes(reader.read_at(fat + current * 4, 4), "little")

            def read_bitmap(
                offset: int, amount: int, *, length: int = length, chain: list[int] = chain
            ) -> bytes:
                result = bytearray()
                while amount and offset < length:
                    idx, within = divmod(offset, unit)
                    take = min(amount, unit - within, length - offset)
                    block = reader.read_at(chain[idx] + within, take)
                    if len(block) != take:
                        raise ValidationError("Truncated exFAT bitmap cluster.")
                    result.extend(block)
                    offset += take
                    amount -= take
                return bytes(result)

            yield from bitmap_runs(read_bitmap, count, unit, base + heap * sector)
            return
        root = int.from_bytes(reader.read_at(fat + root * 4, 4), "little")
    raise ValidationError("exFAT allocation bitmap was not found.")
