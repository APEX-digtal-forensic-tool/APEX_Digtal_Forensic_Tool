from __future__ import annotations

import base64
import shutil
import struct
import subprocess
import zlib
from pathlib import Path
from types import SimpleNamespace
from uuid import UUID

import pytest

from apex_forensic.adapters.evidence import (
    EwfEvidenceReader,
    PartitionParser,
    RawImageReader,
    VirtualDiskEvidenceReader,
)
from apex_forensic.domain.enums import EvidenceFormat, VolumeScheme
from apex_forensic.domain.errors import UnsupportedCapabilityError, ValidationError


def _mbr_entry(partition_type: int, start_lba: int, sector_count: int) -> bytes:
    return bytes([0, 0, 0, 0, partition_type, 0, 0, 0]) + struct.pack(
        "<II", start_lba, sector_count
    )


def _write_mbr_entry(image: bytearray, index: int, entry: bytes) -> None:
    offset = 446 + index * 16
    image[offset : offset + 16] = entry
    image[510:512] = b"\x55\xaa"


def _fixed_vhd_footer(logical_size: int) -> bytes:
    footer = bytearray(512)
    footer[0:8] = b"conectix"
    struct.pack_into(">I", footer, 8, 0x00000002)
    struct.pack_into(">I", footer, 12, 0x00010000)
    struct.pack_into(">Q", footer, 16, 0xFFFFFFFFFFFFFFFF)
    struct.pack_into(">I", footer, 24, 0)
    footer[28:32] = b"apex"
    struct.pack_into(">I", footer, 32, 0x00010000)
    footer[36:40] = b"Wi2k"
    struct.pack_into(">Q", footer, 40, logical_size)
    struct.pack_into(">Q", footer, 48, logical_size)
    cylinders = max(1, min(65535, logical_size // (16 * 63 * 512)))
    geometry = (cylinders << 16) | (16 << 8) | 63
    struct.pack_into(">I", footer, 56, geometry)
    struct.pack_into(">I", footer, 60, 2)
    struct.pack_into(">I", footer, 64, 0)
    footer[68:84] = UUID("12345678-1234-5678-1234-567812345678").bytes
    checksum = ~sum(footer) & 0xFFFFFFFF
    struct.pack_into(">I", footer, 64, checksum)
    return bytes(footer)


def _fixed_vhd_bytes(payload: bytes) -> bytes:
    return payload + _fixed_vhd_footer(len(payload))


def _write_ewf_fixture(tmp_path: Path, payload: bytes) -> Path:
    executable = shutil.which("ewfacquirestream")
    if executable is None:
        pytest.skip("ewfacquirestream is not installed")
    target = tmp_path / "native-case"
    result = subprocess.run(
        [
            executable,
            "-q",
            "-B",
            str(len(payload)),
            "-P",
            "512",
            "-c",
            "none",
            "-d",
            "sha1",
            "-t",
            str(target),
        ],
        input=payload,
        capture_output=True,
        check=False,
        timeout=30,
    )
    if result.returncode != 0:
        pytest.fail(result.stderr.decode("utf-8", errors="replace"))
    e01 = target.with_suffix(".E01")
    assert e01.exists()
    return e01


def _write_vhdx_fixture(tmp_path: Path, payload: bytes) -> Path:
    executable = shutil.which("qemu-img")
    if executable is None:
        pytest.skip("qemu-img is not installed")
    raw = tmp_path / "source.raw"
    raw.write_bytes(payload)
    vhdx = tmp_path / "source.vhdx"
    result = subprocess.run(
        [executable, "convert", "-q", "-f", "raw", "-O", "vhdx", str(raw), str(vhdx)],
        capture_output=True,
        check=False,
        text=True,
        timeout=30,
    )
    if result.returncode != 0:
        pytest.fail(result.stderr)
    assert vhdx.exists()
    return vhdx


def test_raw_reader_contract_bounds_and_idempotent_close(tmp_path: Path) -> None:
    image = tmp_path / "sample.dd"
    image.write_bytes(b"0123456789")

    probe = RawImageReader.probe(image)
    assert probe.supported is True
    assert probe.evidence_format is EvidenceFormat.DD

    reader = RawImageReader(image, max_read_size=4).open_readonly()
    try:
        assert reader.size == 10
        assert reader.sector_size == 512
        assert reader.read_at(2, 4) == b"2345"
        assert reader.read_at(9, 4) == b"9"
        assert reader.read_at(10, 4) == b""
        with pytest.raises(ValidationError):
            reader.read_at(-1, 1)
        with pytest.raises(ValidationError):
            reader.read_at(0, -1)
        with pytest.raises(ValidationError):
            reader.read_at(0, 5)
        assert reader.source_fingerprint["sha256"]
    finally:
        reader.close()
        reader.close()
    with pytest.raises(ValidationError):
        reader.read_at(0, 1)


def test_partition_parser_mbr_extended_and_unallocated_ranges(tmp_path: Path) -> None:
    image_bytes = bytearray(64 * 512)
    _write_mbr_entry(image_bytes, 0, _mbr_entry(0x07, 1, 5))
    _write_mbr_entry(image_bytes, 1, _mbr_entry(0x0F, 10, 30))
    ebr1 = 10 * 512
    image_bytes[ebr1 + 510 : ebr1 + 512] = b"\x55\xaa"
    image_bytes[ebr1 + 446 : ebr1 + 462] = _mbr_entry(0x07, 1, 4)
    image_bytes[ebr1 + 462 : ebr1 + 478] = _mbr_entry(0x0F, 10, 10)
    ebr2 = 20 * 512
    image_bytes[ebr2 + 510 : ebr2 + 512] = b"\x55\xaa"
    image_bytes[ebr2 + 446 : ebr2 + 462] = _mbr_entry(0x0B, 1, 3)
    image = tmp_path / "mbr.dd"
    image.write_bytes(image_bytes)

    with RawImageReader(image) as reader:
        volumes = PartitionParser().parse(reader, case_id="case", evidence_id="evidence")

    allocated = [volume for volume in volumes if volume.is_allocated]
    unallocated = [volume for volume in volumes if not volume.is_allocated]
    assert [(item.scheme, item.start_lba, item.end_lba) for item in allocated] == [
        (VolumeScheme.MBR.value, 1, 5),
        (VolumeScheme.MBR_EXTENDED.value, 11, 14),
        (VolumeScheme.MBR_EXTENDED.value, 21, 23),
    ]
    assert unallocated
    assert all(volume.byte_offset + volume.byte_length <= len(image_bytes) for volume in volumes)


def test_partition_parser_gpt_crc_name_and_bounds(tmp_path: Path) -> None:
    image_bytes = bytearray(100 * 512)
    _write_mbr_entry(image_bytes, 0, _mbr_entry(0xEE, 1, 99))
    entries = bytearray(128 * 128)
    type_guid = UUID("EBD0A0A2-B9E5-4433-87C0-68B6B72699C7")
    unique_guid = UUID("11111111-2222-3333-4444-555555555555")
    entries[0:16] = type_guid.bytes_le
    entries[16:32] = unique_guid.bytes_le
    struct.pack_into("<QQQ", entries, 32, 40, 45, 0)
    entries[56:56 + 12] = "증거".encode("utf-16-le")
    image_bytes[2 * 512 : 2 * 512 + len(entries)] = entries
    entries_crc = zlib.crc32(entries) & 0xFFFFFFFF
    header = bytearray(512)
    header[0:8] = b"EFI PART"
    struct.pack_into("<I", header, 8, 0x00010000)
    struct.pack_into("<I", header, 12, 92)
    struct.pack_into("<QQQQ", header, 24, 1, 99, 34, 90)
    header[56:72] = UUID("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").bytes_le
    struct.pack_into("<QII", header, 72, 2, 128, 128)
    struct.pack_into("<I", header, 88, entries_crc)
    header_crc_bytes = bytearray(header[:92])
    struct.pack_into("<I", header_crc_bytes, 16, 0)
    struct.pack_into("<I", header, 16, zlib.crc32(header_crc_bytes) & 0xFFFFFFFF)
    image_bytes[512:1024] = header
    image = tmp_path / "gpt.img"
    image.write_bytes(image_bytes)

    with RawImageReader(image) as reader:
        volumes = PartitionParser().parse(reader, case_id="case", evidence_id="evidence")

    allocated = next(volume for volume in volumes if volume.is_allocated)
    assert allocated.scheme == VolumeScheme.GPT.value
    assert allocated.partition_type == str(type_guid)
    assert allocated.guid == str(unique_guid)
    assert allocated.name == "증거"
    assert allocated.byte_offset == 40 * 512
    assert allocated.byte_length == 6 * 512


def test_partition_parser_superfloppy_and_truncated_image(tmp_path: Path) -> None:
    image = tmp_path / "tiny.raw"
    image.write_bytes(b"abc")

    with RawImageReader(image) as reader:
        volumes = PartitionParser().parse(reader, case_id="case", evidence_id="evidence")

    assert len(volumes) == 1
    assert volumes[0].scheme == VolumeScheme.SUPERFLOPPY.value
    assert volumes[0].warnings[0]["code"] == "SHORT_BOOT_SECTOR"


def test_optional_readers_are_capability_honest(tmp_path: Path) -> None:
    e01 = tmp_path / "case.E01"
    e03 = tmp_path / "case.E03"
    e01.write_bytes(b"segment")
    e03.write_bytes(b"segment")

    with pytest.raises(ValidationError) as missing_segment:
        EwfEvidenceReader(e01).open_readonly()
    assert missing_segment.value.details["missing_segments"] == [2]

    e03.unlink()
    with pytest.raises((UnsupportedCapabilityError, ValidationError)):
        EwfEvidenceReader(e01).open_readonly()

    vhd_probe = VirtualDiskEvidenceReader.probe(tmp_path / "disk.vhd")
    vhdx_probe = VirtualDiskEvidenceReader.probe(tmp_path / "disk.vhdx")
    assert vhd_probe.supported is False
    assert vhdx_probe.supported is False
    assert vhd_probe.evidence_format is EvidenceFormat.VHD
    assert vhdx_probe.evidence_format is EvidenceFormat.VHDX
    assert vhdx_probe.unavailable_reason in {"NOT_REGULAR_FILE", "QEMU_IMG_NOT_INSTALLED"}


def test_virtual_disk_vhd_reader_runtime_and_vhdx_boundary(tmp_path: Path) -> None:
    pytest.importorskip("pyvhdi")
    payload = bytearray(16 * 512)
    _write_mbr_entry(payload, 0, _mbr_entry(0x07, 1, 2))
    payload[512:516] = b"VHD!"
    vhd = tmp_path / "fixed.vhd"
    vhd.write_bytes(_fixed_vhd_bytes(bytes(payload)))

    probe = VirtualDiskEvidenceReader.probe(vhd)
    assert probe.supported is True
    assert probe.evidence_format is EvidenceFormat.VHD
    with VirtualDiskEvidenceReader(vhd) as reader:
        assert reader.size == len(payload)
        assert reader.sector_size == 512
        assert reader.read_at(512, 4) == b"VHD!"
        volumes = reader.volumes(case_id="case", evidence_id="evidence")
        allocated = [item for item in volumes if item.is_allocated]
        assert allocated[0].scheme == VolumeScheme.MBR.value
        assert allocated[0].byte_offset == 512
        assert reader.source_fingerprint["adapter"] == "pyvhdi"


def test_virtual_disk_vhdx_reader_runtime_with_qemu_img(tmp_path: Path) -> None:
    payload = bytearray(4096 * 512)
    _write_mbr_entry(payload, 0, _mbr_entry(0x07, 1, 2))
    payload[512:520] = b"VHDXDATA"
    vhdx = _write_vhdx_fixture(tmp_path, bytes(payload))

    probe = VirtualDiskEvidenceReader.probe(vhdx)
    assert probe.supported is True
    assert probe.evidence_format is EvidenceFormat.VHDX
    with VirtualDiskEvidenceReader(vhdx) as reader:
        assert reader.size == len(payload)
        assert reader.sector_size == 512
        assert reader.read_at(512, 8) == b"VHDXDATA"
        volumes = reader.volumes(case_id="case", evidence_id="evidence")
        allocated = [item for item in volumes if item.is_allocated]
        assert allocated[0].scheme == VolumeScheme.MBR.value
        assert allocated[0].byte_offset == 512
        assert reader.source_fingerprint["adapter"] == "qemu-img"
        assert reader.source_fingerprint["temporary_raw_cache"] is True
    with pytest.raises(ValidationError):
        reader.read_at(0, 1)


def test_ewf_reader_native_runtime_fixture(tmp_path: Path) -> None:
    pytest.importorskip("pyewf")
    payload = bytearray(4096 * 512)
    _write_mbr_entry(payload, 0, _mbr_entry(0x07, 1, 2))
    payload[512:520] = b"EWFTEST!"
    e01 = _write_ewf_fixture(tmp_path, bytes(payload))

    probe = EwfEvidenceReader.probe(e01)
    assert probe.supported is True
    assert probe.evidence_format is EvidenceFormat.E01
    with EwfEvidenceReader(e01) as reader:
        assert reader.size == len(payload)
        assert reader.sector_size == 512
        assert reader.read_at(512, 8) == b"EWFTEST!"
        volumes = reader.volumes(case_id="case", evidence_id="evidence")
        allocated = [item for item in volumes if item.is_allocated]
        assert allocated[0].scheme == VolumeScheme.MBR.value
        assert allocated[0].byte_offset == 512
        fingerprint = reader.source_fingerprint
        assert fingerprint["adapter"] == "pyewf"
        assert fingerprint["adapter_version"]
        assert isinstance(fingerprint["embedded_hashes"], dict)
        assert fingerprint["embedded_hash_status"] in {
            "EXTRACTED",
            "NOT_EXPOSED_BY_PYEWF",
        }


def test_evidence_image_service_persists_volumes_and_reads_ranges(services, tmp_path: Path) -> None:
    image_bytes = bytearray(16 * 512)
    _write_mbr_entry(image_bytes, 0, _mbr_entry(0x07, 1, 2))
    image_bytes[512:516] = b"DATA"
    image = tmp_path / "service.dd"
    image.write_bytes(image_bytes)
    case = services.cases.create_case(name="Image Case")
    evidence = services.evidence.register_evidence(case_id=case.case_id, source_path=image)

    volumes = services.images.enumerate_volumes(evidence.evidence_id)
    persisted = services.repository.list_evidence_volumes(evidence.evidence_id)
    read = services.images.read_range(evidence_id=evidence.evidence_id, offset=512, length=4)

    assert [volume.to_schema_dict() for volume in persisted] == [
        volume.to_schema_dict() for volume in volumes
    ]
    assert base64.b64decode(read["data"]) == b"DATA"
    assert read["returned_length"] == 4


def test_ewf_fake_adapter_contract_reads_without_domain_leak(tmp_path: Path) -> None:
    e01 = tmp_path / "fake.E01"
    e01.write_bytes(b"fake")

    class _FakeHandle:
        def __init__(self) -> None:
            self.data = b"abcdef"
            self.offset = 0
            self.closed = False

        def open(self, paths: list[str]) -> None:
            assert paths == [str(e01.resolve())]

        def get_media_size(self) -> int:
            return len(self.data)

        def get_bytes_per_sector(self) -> int:
            return 512

        def seek(self, offset: int) -> None:
            self.offset = offset

        def read(self, length: int) -> bytes:
            return self.data[self.offset : self.offset + length]

        def close(self) -> None:
            self.closed = True

    fake_module = SimpleNamespace(handle=_FakeHandle)
    with EwfEvidenceReader(e01, module_loader=lambda: fake_module) as reader:
        assert reader.size == 6
        assert reader.read_at(2, 3) == b"cde"
        assert reader.source_fingerprint["segments"] == [str(e01.resolve())]
