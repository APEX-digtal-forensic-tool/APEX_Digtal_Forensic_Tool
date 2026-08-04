"""Evidence image reader orchestration service."""

from __future__ import annotations

import base64
import hashlib
import os
import re
import tempfile
from pathlib import Path
from typing import Any, Protocol

from apex_forensic._time import to_json_timestamp, utc_now
from apex_forensic.adapters.evidence import (
    EwfEvidenceReader,
    RawImageReader,
    VirtualDiskEvidenceReader,
)
from apex_forensic.domain.enums import CustodyEventType, EvidenceFormat
from apex_forensic.domain.errors import (
    NotFoundError,
    StateConflictError,
    UnsupportedCapabilityError,
    ValidationError,
)
from apex_forensic.domain.models import Evidence, EvidenceVolume, FileSystemNode
from apex_forensic.ports.evidence_reader import EvidenceProbeResult, EvidenceReader
from apex_forensic.ports.evidence_repository import EvidenceRepository


class EvidenceImageRepository(EvidenceRepository, Protocol):
    """Repository methods needed by image reader orchestration."""

    def replace_evidence_volumes(
        self, evidence_id: str, volumes: list[EvidenceVolume]
    ) -> None: ...

    def list_evidence_volumes(self, evidence_id: str) -> list[EvidenceVolume]: ...

    def get_fs_node(self, node_id: str) -> FileSystemNode | None: ...


class EvidenceImageService:
    """Coordinates read-only image access and partition enumeration."""

    def __init__(
        self,
        repository: EvidenceImageRepository,
        custody_ledger: Any | None = None,
    ) -> None:
        self._repository = repository
        self._custody_ledger = custody_ledger

    def probe_path(self, path: Path) -> EvidenceProbeResult:
        """Return the reader probe result for a path based on extension."""

        evidence_format = self._format_for_path(path)
        if evidence_format is EvidenceFormat.E01:
            return EwfEvidenceReader.probe(path)
        if evidence_format in {EvidenceFormat.VHD, EvidenceFormat.VHDX}:
            return VirtualDiskEvidenceReader.probe(path)
        return RawImageReader.probe(path)

    def enumerate_volumes(self, evidence_id: str) -> list[EvidenceVolume]:
        """Parse and persist image partition metadata for an evidence source."""

        evidence = self._get_evidence(evidence_id)
        with self._reader_for_evidence(evidence) as reader:
            volumes = reader.volumes(case_id=evidence.case_id, evidence_id=evidence_id)
        self._repository.replace_evidence_volumes(evidence_id, volumes)
        evidence.metadata["partition_parser"] = {
            "id": "apex.partition_parser",
            "version": "0.1.0",
            "volume_count": len(volumes),
        }
        self._repository.update_evidence(evidence)
        return volumes

    def list_volumes(self, evidence_id: str) -> list[EvidenceVolume]:
        """Return stored volumes, parsing them on demand if none have been stored."""

        self._get_evidence(evidence_id)
        volumes = self._repository.list_evidence_volumes(evidence_id)
        return volumes if volumes else self.enumerate_volumes(evidence_id)

    def read_range(self, *, evidence_id: str, offset: int, length: int) -> dict[str, Any]:
        """Return a bounded raw range without mutating evidence."""

        evidence = self._get_evidence(evidence_id)
        with self._reader_for_evidence(evidence) as reader:
            data = reader.read_at(offset, length)
            digest = hashlib.sha256(data).hexdigest()
            return {
                "evidence_id": evidence_id,
                "offset": offset,
                "requested_length": length,
                "returned_length": len(data),
                "sha256": digest,
                "encoding": "base64",
                "data": base64.b64encode(data).decode("ascii"),
                "reader": {"id": reader.reader_id, "version": reader.reader_version},
            }

    def list_unallocated_ranges(self, evidence_id: str) -> list[dict[str, Any]]:
        """Return partition-level unallocated ranges with stable locators."""

        evidence = self._get_evidence(evidence_id)
        ranges: list[dict[str, Any]] = []
        for volume in self.list_volumes(evidence_id):
            if volume.is_allocated:
                continue
            ranges.append(
                {
                    "extent_id": volume.volume_id,
                    "case_id": evidence.case_id,
                    "evidence_id": evidence_id,
                    "byte_offset": volume.byte_offset,
                    "byte_length": volume.byte_length,
                    "volume_id": volume.volume_id,
                    "volume_relation": "PARTITION_GAP",
                    "raw_locator": volume.raw_locator,
                    "capability": {
                        "range_read": "SUPPORTED",
                        "range_export": "SUPPORTED",
                        "file_carving": "PLANNED",
                    },
                    "warnings": volume.warnings,
                }
            )
        return ranges

    def export_range(
        self,
        *,
        evidence_id: str,
        offset: int,
        length: int,
        output_root: Path,
        filename: str | None = None,
        overwrite: bool = False,
    ) -> dict[str, Any]:
        """Export one bounded raw image range as derived output."""

        evidence = self._get_evidence(evidence_id)
        if offset < 0:
            raise ValidationError("offset must be non-negative.", target="offset")
        if length <= 0:
            raise ValidationError("length must be positive.", target="length")
        output_path = self._safe_output_path(
            output_root,
            filename or f"range-{offset}-{length}.bin",
            overwrite=overwrite,
        )
        with self._reader_for_evidence(evidence) as reader:
            data = reader.read_at(offset, length)
            reader_info = {"id": reader.reader_id, "version": reader.reader_version}
        if not data:
            raise ValidationError(
                "Requested range produced no bytes and was not exported.",
                target="offset",
                details={"offset": offset, "length": length},
            )
        sha256 = hashlib.sha256(data).hexdigest()
        self._write_output(output_path, data, overwrite=overwrite)
        self._audit_export(
            evidence_id=evidence_id,
            output_path=output_path,
            sha256=sha256,
            action="Raw range exported",
            notes=f"offset={offset}; requested_length={length}; exported_bytes={len(data)}",
        )
        return {
            "evidence_id": evidence_id,
            "output_path": str(output_path),
            "byte_offset": offset,
            "requested_length": length,
            "exported_bytes": len(data),
            "sha256": sha256,
            "partial": len(data) != length,
            "exported_at": to_json_timestamp(utc_now()),
            "reader": reader_info,
            "raw_locator": {
                "locator_type": "DISK_IMAGE_BYTE_RANGE",
                "evidence_id": evidence_id,
                "byte_offset": offset,
                "byte_length": len(data),
            },
        }

    def recover_deleted_file(
        self,
        *,
        node_id: str,
        output_root: Path,
        filename: str | None = None,
        overwrite: bool = False,
    ) -> dict[str, Any]:
        """Recover a selected deleted file node from recorded image extents."""

        node = self._repository.get_fs_node(node_id)
        if node is None:
            raise NotFoundError("FS_NODE_NOT_FOUND", f"Filesystem node not found: {node_id}")
        if not node.is_deleted:
            raise ValidationError("Only deleted file nodes can be recovered.", target="node_id")
        if node.file_size is None or node.file_size <= 0:
            raise ValidationError("Deleted file has no recoverable logical size.", target="node_id")
        extents = node.provider_metadata.get("extents")
        if not isinstance(extents, list) or not extents:
            raise ValidationError(
                "Deleted file has no recorded data runs for recovery.",
                target="node_id",
            )
        evidence = self._get_evidence(node.evidence_id)
        output_path = self._safe_output_path(
            output_root,
            filename or f"{node.original_name}.recovered",
            overwrite=overwrite,
        )
        written = 0
        missing_ranges: list[dict[str, int]] = []
        hasher = hashlib.sha256()
        reader_info: dict[str, str] | None = None
        temp_path: Path | None = None
        try:
            temp_path = self._temporary_output_path(output_path)
            with self._reader_for_evidence(evidence) as reader, temp_path.open("wb") as output:
                reader_info = {"id": reader.reader_id, "version": reader.reader_version}
                for extent in sorted(extents, key=lambda item: int(item.get("file_offset", 0))):
                    file_offset = int(extent.get("file_offset", written))
                    if file_offset > written:
                        missing_ranges.append(
                            {
                                "file_offset": written,
                                "byte_length": file_offset - written,
                            }
                        )
                        written = file_offset
                    remaining = node.file_size - written
                    if remaining <= 0:
                        break
                    byte_offset = int(extent["byte_offset"])
                    byte_length = min(int(extent["byte_length"]), remaining)
                    data = reader.read_at(byte_offset, byte_length)
                    if len(data) < byte_length:
                        missing_ranges.append(
                            {
                                "file_offset": written + len(data),
                                "byte_length": byte_length - len(data),
                            }
                        )
                    if data:
                        output.write(data)
                        hasher.update(data)
                        written += len(data)
            if written == 0:
                raise ValidationError(
                    "Deleted file recovery produced no bytes.",
                    target="node_id",
                )
            self._publish_output(temp_path, output_path, overwrite=overwrite)
            temp_path = None
        except FileExistsError as error:
            raise StateConflictError(
                "Derived output already exists; overwrite is disabled.",
                target="output_root",
            ) from error
        finally:
            if temp_path is not None:
                temp_path.unlink(missing_ok=True)
        if written < node.file_size:
            missing_ranges.append(
                {"file_offset": written, "byte_length": node.file_size - written}
            )
        sha256 = hasher.hexdigest()
        self._audit_export(
            evidence_id=node.evidence_id,
            output_path=output_path,
            sha256=sha256,
            action="Deleted file recovered",
            notes=(
                f"node_id={node.node_id}; recovered_bytes={written}; "
                f"missing_ranges={len(missing_ranges)}"
            ),
        )
        return {
            "node_id": node.node_id,
            "evidence_id": node.evidence_id,
            "output_path": str(output_path),
            "recovered_bytes": written,
            "logical_size": node.file_size,
            "missing_ranges": missing_ranges,
            "sha256": sha256,
            "partial": bool(missing_ranges),
            "recovered_at": to_json_timestamp(utc_now()),
            "reader": reader_info,
            "source": {
                "provider_id": node.provider_id,
                "provider_version": node.provider_version,
                "raw_locator": node.raw_locator,
            },
        }

    def export_file_slack(
        self,
        *,
        node_id: str,
        output_root: Path,
        filename: str | None = None,
        overwrite: bool = False,
    ) -> dict[str, Any]:
        """Export selected file slack as derived output when a provider exposes it."""

        node = self._repository.get_fs_node(node_id)
        if node is None:
            raise NotFoundError("FS_NODE_NOT_FOUND", f"Filesystem node not found: {node_id}")
        slack = node.provider_metadata.get("slack")
        if not isinstance(slack, dict) or not slack.get("available"):
            raise UnsupportedCapabilityError(
                "File slack is not available for this node.",
                target="node_id",
                required_capability="FILE_SLACK_EXPORT",
            )
        byte_offset = int(slack["byte_offset"])
        byte_length = int(slack["byte_length"])
        if byte_length <= 0:
            raise ValidationError("Slack range has no bytes to export.", target="node_id")
        evidence = self._get_evidence(node.evidence_id)
        output_path = self._safe_output_path(
            output_root,
            filename or f"{node.original_name}.slack.bin",
            overwrite=overwrite,
        )
        with self._reader_for_evidence(evidence) as reader:
            data = reader.read_at(byte_offset, byte_length)
            reader_info = {"id": reader.reader_id, "version": reader.reader_version}
        if not data:
            raise ValidationError(
                "Slack range produced no bytes and was not exported.",
                target="node_id",
            )
        sha256 = hashlib.sha256(data).hexdigest()
        self._write_output(output_path, data, overwrite=overwrite)
        self._audit_export(
            evidence_id=node.evidence_id,
            output_path=output_path,
            sha256=sha256,
            action="File slack exported",
            notes=(
                f"node_id={node.node_id}; slack_offset={byte_offset}; "
                f"requested_length={byte_length}; exported_bytes={len(data)}"
            ),
        )
        return {
            "node_id": node.node_id,
            "evidence_id": node.evidence_id,
            "output_path": str(output_path),
            "byte_offset": byte_offset,
            "requested_length": byte_length,
            "exported_bytes": len(data),
            "sha256": sha256,
            "partial": len(data) != byte_length,
            "zero_filled": all(byte == 0 for byte in data),
            "exported_at": to_json_timestamp(utc_now()),
            "reader": reader_info,
            "source": {
                "provider_id": node.provider_id,
                "provider_version": node.provider_version,
                "raw_locator": node.raw_locator,
            },
        }

    def _get_evidence(self, evidence_id: str) -> Evidence:
        evidence = self._repository.get_evidence(evidence_id)
        if evidence is None:
            raise NotFoundError(
                "EVIDENCE_NOT_FOUND",
                f"Evidence not found: {evidence_id}",
                target="evidence_id",
            )
        return evidence

    @staticmethod
    def _reader_for_evidence(evidence: Evidence) -> EvidenceReader:
        if evidence.evidence_type in {EvidenceFormat.RAW, EvidenceFormat.DD, EvidenceFormat.IMG}:
            return RawImageReader(evidence.source_path, evidence_format=evidence.evidence_type)
        if evidence.evidence_type is EvidenceFormat.E01:
            return EwfEvidenceReader(evidence.source_path)
        if evidence.evidence_type in {EvidenceFormat.VHD, EvidenceFormat.VHDX}:
            return VirtualDiskEvidenceReader(
                evidence.source_path, evidence_format=evidence.evidence_type
            )
        raise UnsupportedCapabilityError(
            "Directory evidence does not expose a disk-image byte reader.",
            target="evidence_id",
            required_capability="DISK_IMAGE_READER",
        )

    @staticmethod
    def _format_for_path(path: Path) -> EvidenceFormat:
        suffix = path.suffix.lower()
        if suffix == ".e01":
            return EvidenceFormat.E01
        if suffix == ".dd":
            return EvidenceFormat.DD
        if suffix == ".img":
            return EvidenceFormat.IMG
        if suffix == ".vhdx":
            return EvidenceFormat.VHDX
        if suffix == ".vhd":
            return EvidenceFormat.VHD
        return EvidenceFormat.RAW

    @staticmethod
    def _safe_output_path(output_root: Path, filename: str, *, overwrite: bool) -> Path:
        root = output_root.expanduser()
        root.mkdir(parents=True, exist_ok=True)
        root_resolved = root.resolve(strict=True)
        safe_name = _safe_filename(filename)
        output_path = (root_resolved / safe_name).resolve(strict=False)
        try:
            output_path.relative_to(root_resolved)
        except ValueError as error:
            raise ValidationError(
                "Derived output path escapes output root.",
                target="output_root",
            ) from error
        if output_path.exists() and not overwrite:
            raise StateConflictError(
                "Derived output already exists; overwrite is disabled.",
                target="output_root",
            )
        return output_path

    @staticmethod
    def _write_output(output_path: Path, data: bytes, *, overwrite: bool) -> None:
        temp_path: Path | None = None
        try:
            temp_path = EvidenceImageService._temporary_output_path(output_path)
            with temp_path.open("wb") as stream:
                stream.write(data)
            EvidenceImageService._publish_output(temp_path, output_path, overwrite=overwrite)
            temp_path = None
        except FileExistsError as error:
            raise StateConflictError(
                "Derived output already exists; overwrite is disabled.",
                target="output_root",
            ) from error
        finally:
            if temp_path is not None:
                temp_path.unlink(missing_ok=True)

    @staticmethod
    def _temporary_output_path(output_path: Path) -> Path:
        with tempfile.NamedTemporaryFile(
            prefix=f".{output_path.name}.",
            suffix=".tmp",
            dir=output_path.parent,
            delete=False,
        ) as stream:
            return Path(stream.name)

    @staticmethod
    def _publish_output(temp_path: Path, output_path: Path, *, overwrite: bool) -> None:
        if overwrite:
            temp_path.replace(output_path)
            return
        os.link(temp_path, output_path)
        temp_path.unlink()

    def _audit_export(
        self,
        *,
        evidence_id: str,
        output_path: Path,
        sha256: str,
        action: str,
        notes: str,
    ) -> None:
        if self._custody_ledger is None:
            return
        self._custody_ledger.add_event(
            evidence_id=evidence_id,
            event_type=CustodyEventType.EXPORTED,
            actor_name="SYSTEM",
            action=action,
            destination_location=str(output_path),
            current_hash={"algorithm": "SHA256", "digest_hex": sha256},
            notes=notes,
        )


def _safe_filename(value: str) -> str:
    name = Path(value).name
    name = re.sub(r"[^A-Za-z0-9._-]+", "_", name).strip("._")
    return name[:120] or "derived-output.bin"
