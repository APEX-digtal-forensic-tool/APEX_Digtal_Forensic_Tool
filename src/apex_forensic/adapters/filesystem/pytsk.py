"""Sleuth Kit filesystem provider backed by pytsk3."""

from __future__ import annotations

import importlib
import mimetypes
import unicodedata
from datetime import UTC, datetime
from pathlib import PurePosixPath
from types import ModuleType
from typing import Any
from uuid import NAMESPACE_URL, uuid5

from apex_forensic._time import utc_now
from apex_forensic.adapters.evidence import RawImageReader
from apex_forensic.constants import ENGINE_VERSION
from apex_forensic.domain.enums import (
    EvidenceFormat,
    FileSystemNodeType,
    FileSystemProviderCapability,
)
from apex_forensic.domain.errors import UnsupportedCapabilityError, ValidationError
from apex_forensic.domain.models import Evidence, EvidenceVolume, FileSystemNode
from apex_forensic.ports.filesystem_provider import (
    FileSystemProviderCapabilities,
    ProviderEntry,
    ProviderScanIssue,
)

_DISK_IMAGE_FORMATS = {EvidenceFormat.RAW, EvidenceFormat.DD, EvidenceFormat.IMG}
_SUPPORTED_FS_FAMILIES = ("NTFS", "FAT12", "FAT16", "FAT32", "EXFAT", "EXT2", "EXT3", "EXT4")


class PyTskFileSystemProvider:
    """Read-only image filesystem provider using The Sleuth Kit bindings."""

    provider_id = "apex.pytsk_filesystem_provider"
    provider_version = ENGINE_VERSION

    def __init__(self, *, module: ModuleType | None = None) -> None:
        self._module = module

    def capabilities(self) -> FileSystemProviderCapabilities:
        available = self._dependency_available()
        capabilities = (
            FileSystemProviderCapability.IMAGE_FILE_SYSTEM,
            FileSystemProviderCapability.METADATA_ONLY,
            FileSystemProviderCapability.STABLE_RAW_LOCATOR,
            FileSystemProviderCapability.FILE_EXTENTS,
            FileSystemProviderCapability.DELETED_ENTRIES,
            FileSystemProviderCapability.SLACK_METADATA,
        )
        return FileSystemProviderCapabilities(
            provider_id=self.provider_id,
            provider_version=self.provider_version,
            capabilities=capabilities if available else (),
            unsupported_formats=("E01", "VHD", "VHDX"),
            metadata={
                "backend": "pytsk3",
                "backend_available": available,
                "unavailable_reason": None if available else "PYTSK3_NOT_INSTALLED",
                "supported_filesystem_families": list(_SUPPORTED_FS_FAMILIES),
                "reads_file_body": False,
                "follows_symlinks_by_default": False,
                "deleted_entries": "CANDIDATE_METADATA",
                "unallocated_file_carving": "PLANNED",
            },
        )

    def supports_evidence(self, evidence: Evidence) -> bool:
        return evidence.evidence_type in _DISK_IMAGE_FORMATS

    def get_root_node(self, evidence: Evidence, *, index_revision: int) -> FileSystemNode:
        self._ensure_supported(evidence)
        volumes = self._candidate_volumes(evidence)
        if not volumes:
            raise UnsupportedCapabilityError(
                "No allocated image volume is available for filesystem probing.",
                target="evidence_id",
                required_capability="IMAGE_FILE_SYSTEM_VOLUME",
            )
        now = utc_now()
        return FileSystemNode(
            node_id=self._node_id(evidence, ""),
            case_id=evidence.case_id,
            evidence_id=evidence.evidence_id,
            provider_id=self.provider_id,
            provider_version=self.provider_version,
            parent_node_id=None,
            original_name=evidence.display_name,
            original_relative_path="",
            display_path="/",
            comparison_path="/",
            node_type=FileSystemNodeType.ROOT,
            file_size=evidence.size_bytes,
            extension=None,
            mime_candidate=None,
            mime_confidence="NONE",
            fs_metadata={
                "volume_count": len(volumes),
                "image_format": evidence.evidence_type.value,
            },
            platform="DISK_IMAGE",
            timestamp_meanings={},
            raw_timestamps={},
            utc_timestamps={},
            timestamp_sources={},
            is_deleted=False,
            is_readable=True,
            is_link=False,
            is_traversed=True,
            raw_locator={
                "locator_type": "DISK_IMAGE",
                "evidence_id": evidence.evidence_id,
                "reader_id": evidence.metadata.get("reader_id", "apex.raw_image_reader"),
                "provider_id": self.provider_id,
                "provider_version": self.provider_version,
            },
            provider_metadata={
                "backend": "pytsk3",
                "source_kind": "DISK_IMAGE_ROOT",
                "volume_count": len(volumes),
                "reads_file_body": False,
            },
            is_partial=False,
            index_revision=index_revision,
            created_at=now,
            updated_at=now,
        )

    def iter_directory_entries(
        self,
        evidence: Evidence,
        parent: FileSystemNode,
        *,
        index_revision: int,
        after_cursor: str | None = None,
    ) -> list[ProviderEntry]:
        self._ensure_supported(evidence)
        if parent.original_relative_path == "":
            return self._volume_root_entries(evidence, index_revision, after_cursor=after_cursor)
        volume_index = self._volume_index(parent)
        if volume_index is None:
            return []
        volume = self._volume_by_index(evidence, volume_index)
        if volume is None:
            return [
                ProviderScanIssue(
                    severity="ERROR",
                    code="IMAGE_VOLUME_NOT_FOUND",
                    message_key="error.fs.image_volume_not_found",
                    developer_message="The filesystem node references an unknown image volume.",
                    path=parent.display_path,
                    node_id=parent.node_id,
                    details={"volume_index": volume_index},
                )
            ]
        try:
            fs_info = self._open_fs(evidence, volume)
            tsk_path = str(parent.provider_metadata.get("tsk_path", "/"))
            directory = fs_info.open_dir(path=tsk_path)
        except Exception as error:
            return [
                ProviderScanIssue(
                    severity="ERROR",
                    code="TSK_DIRECTORY_OPEN_FAILED",
                    message_key="error.fs.tsk_directory_open_failed",
                    developer_message="Sleuth Kit could not open the image directory.",
                    path=parent.display_path,
                    node_id=parent.node_id,
                    details={"error": str(error)},
                )
            ]
        results: list[ProviderEntry] = []
        for entry in directory:
            node = self._node_from_entry(
                evidence=evidence,
                volume=volume,
                parent=parent,
                entry=entry,
                fs_info=fs_info,
                index_revision=index_revision,
            )
            if node is None:
                continue
            sort_key = str(node.provider_metadata.get("entry_sort_key", ""))
            if after_cursor is not None and sort_key <= after_cursor:
                continue
            results.append(node)
        return sorted(results, key=lambda item: self._provider_sort_key(item))

    def get_metadata(
        self,
        evidence: Evidence,
        relative_path: str,
        *,
        index_revision: int,
    ) -> FileSystemNode:
        self._ensure_supported(evidence)
        clean = self._clean_relative_path(relative_path)
        if clean == "":
            return self.get_root_node(evidence, index_revision=index_revision)
        volume_index, tsk_path = self._split_volume_path(clean)
        volume = self._volume_by_index(evidence, volume_index)
        if volume is None:
            raise ValidationError("Selected image volume does not exist.", target="relative_path")
        parent_path = str(PurePosixPath(tsk_path).parent)
        if parent_path == ".":
            parent_path = "/"
        parent = self._synthetic_parent(evidence, volume, parent_path, index_revision)
        for entry in self.iter_directory_entries(
            evidence, parent, index_revision=index_revision
        ):
            if isinstance(entry, ProviderScanIssue):
                continue
            if entry.original_relative_path == clean:
                return entry
        raise ValidationError("Selected image path does not exist.", target="relative_path")

    def get_child_entry(
        self,
        evidence: Evidence,
        parent: FileSystemNode,
        original_name: str,
        *,
        index_revision: int,
    ) -> FileSystemNode | None:
        for entry in self.iter_directory_entries(evidence, parent, index_revision=index_revision):
            if isinstance(entry, ProviderScanIssue):
                continue
            if entry.original_name == original_name:
                return entry
        return None

    def make_raw_locator(self, evidence: Evidence, relative_path: str) -> dict[str, Any]:
        volume_index, tsk_path = self._split_volume_path(self._clean_relative_path(relative_path))
        volume = self._volume_by_index(evidence, volume_index)
        return {
            "provider_id": self.provider_id,
            "provider_version": self.provider_version,
            "evidence_id": evidence.evidence_id,
            "relative_path": relative_path,
            "volume_id": None if volume is None else volume.volume_id,
            "volume_index": volume_index,
            "tsk_path": tsk_path,
            "locator_type": "IMAGE_FILE_SYSTEM_PATH",
            "reads_file_body": False,
        }

    def _volume_root_entries(
        self,
        evidence: Evidence,
        index_revision: int,
        *,
        after_cursor: str | None,
    ) -> list[ProviderEntry]:
        results: list[ProviderEntry] = []
        for volume in self._candidate_volumes(evidence):
            sort_key = f"{volume.volume_index:08d}"
            if after_cursor is not None and sort_key <= after_cursor:
                continue
            try:
                fs_info = self._open_fs(evidence, volume)
            except Exception as error:
                results.append(
                    ProviderScanIssue(
                        severity="WARNING",
                        code="TSK_FILESYSTEM_OPEN_FAILED",
                        message_key="warning.fs.tsk_filesystem_open_failed",
                        developer_message=(
                            "Sleuth Kit could not open this image volume as a supported filesystem."
                        ),
                        path=f"/volume-{volume.volume_index}",
                        details={
                            "volume_id": volume.volume_id,
                            "byte_offset": volume.byte_offset,
                            "error": str(error),
                        },
                    )
                )
                continue
            now = utc_now()
            fs_type = self._fs_type_name(fs_info)
            results.append(
                FileSystemNode(
                    node_id=self._node_id(evidence, f"volume-{volume.volume_index}"),
                    case_id=evidence.case_id,
                    evidence_id=evidence.evidence_id,
                    provider_id=self.provider_id,
                    provider_version=self.provider_version,
                    parent_node_id=self._node_id(evidence, ""),
                    original_name=f"volume-{volume.volume_index}",
                    original_relative_path=f"volume-{volume.volume_index}",
                    display_path=f"/volume-{volume.volume_index}",
                    comparison_path=f"/volume-{volume.volume_index}",
                    node_type=FileSystemNodeType.DIRECTORY,
                    file_size=volume.byte_length,
                    extension=None,
                    mime_candidate=None,
                    mime_confidence="NONE",
                    fs_metadata={
                        "filesystem_type": fs_type,
                        "block_size": int(fs_info.info.block_size),
                        "block_count": int(fs_info.info.block_count),
                        "first_block": int(fs_info.info.first_block),
                        "last_block": int(fs_info.info.last_block),
                        "volume_id": volume.volume_id,
                    },
                    platform="DISK_IMAGE",
                    timestamp_meanings={},
                    raw_timestamps={},
                    utc_timestamps={},
                    timestamp_sources={},
                    is_deleted=False,
                    is_readable=True,
                    is_link=False,
                    is_traversed=True,
                    raw_locator=volume.raw_locator,
                    provider_metadata={
                        "backend": "pytsk3",
                        "source_kind": "IMAGE_VOLUME_ROOT",
                        "volume_index": volume.volume_index,
                        "volume_id": volume.volume_id,
                        "volume_byte_offset": volume.byte_offset,
                        "tsk_path": "/",
                        "entry_sort_key": sort_key,
                        "reads_file_body": False,
                    },
                    is_partial=False,
                    index_revision=index_revision,
                    created_at=now,
                    updated_at=now,
                )
            )
        return results

    def _node_from_entry(
        self,
        *,
        evidence: Evidence,
        volume: EvidenceVolume,
        parent: FileSystemNode,
        entry: Any,
        fs_info: Any,
        index_revision: int,
    ) -> FileSystemNode | None:
        name_info = getattr(entry.info, "name", None)
        meta = getattr(entry.info, "meta", None)
        raw_name = getattr(name_info, "name", None)
        if raw_name is None or meta is None:
            return None
        name = self._decode_name(raw_name)
        if name in {"", ".", ".."}:
            return None
        pytsk3 = self._pytsk3()
        meta_type = int(getattr(meta, "type", 0))
        if name.startswith("$") or meta_type in {
            int(pytsk3.TSK_FS_META_TYPE_VIRT),
            int(pytsk3.TSK_FS_META_TYPE_VIRT_DIR),
        }:
            return None
        parent_tsk = str(parent.provider_metadata.get("tsk_path", "/"))
        tsk_path = self._join_tsk_path(parent_tsk, name)
        relative_path = self._join_relative(parent.original_relative_path, name)
        is_deleted = bool(
            int(getattr(name_info, "flags", 0)) & int(pytsk3.TSK_FS_NAME_FLAG_UNALLOC)
            or int(getattr(meta, "flags", 0)) & int(pytsk3.TSK_FS_META_FLAG_UNALLOC)
        )
        node_type = self._node_type(meta_type)
        extents = self._extents(entry, fs_info, volume)
        file_size = int(getattr(meta, "size", 0)) if node_type is FileSystemNodeType.FILE else None
        slack = self._slack(file_size, extents)
        now = utc_now()
        extension = self._extension(name) if node_type is FileSystemNodeType.FILE else None
        mime = mimetypes.guess_type(name)[0] if node_type is FileSystemNodeType.FILE else None
        timestamps = {
            "created": self._timestamp(getattr(meta, "crtime", 0)),
            "modified": self._timestamp(getattr(meta, "mtime", 0)),
            "accessed": self._timestamp(getattr(meta, "atime", 0)),
            "changed": self._timestamp(getattr(meta, "ctime", 0)),
        }
        raw_timestamps = {
            "crtime": int(getattr(meta, "crtime", 0)),
            "mtime": int(getattr(meta, "mtime", 0)),
            "atime": int(getattr(meta, "atime", 0)),
            "ctime": int(getattr(meta, "ctime", 0)),
        }
        inode = str(getattr(meta, "addr", ""))
        return FileSystemNode(
            node_id=self._node_id(evidence, relative_path, inode),
            case_id=evidence.case_id,
            evidence_id=evidence.evidence_id,
            provider_id=self.provider_id,
            provider_version=self.provider_version,
            parent_node_id=parent.node_id,
            original_name=name,
            original_relative_path=relative_path,
            display_path="/" + relative_path,
            comparison_path="/" + unicodedata.normalize("NFC", relative_path).casefold(),
            node_type=node_type,
            file_size=file_size,
            extension=extension,
            mime_candidate=mime,
            mime_confidence="EXTENSION" if mime is not None else "NONE",
            fs_metadata={
                "inode": inode,
                "mode": int(getattr(meta, "mode", 0)),
                "uid": int(getattr(meta, "uid", 0)),
                "gid": int(getattr(meta, "gid", 0)),
                "nlink": int(getattr(meta, "nlink", 0)),
                "file_attributes": int(getattr(meta, "flags", 0)),
                "name_flags": int(getattr(name_info, "flags", 0)),
                "metadata_confidence": "CANDIDATE" if is_deleted else "OBSERVED",
            },
            platform="DISK_IMAGE",
            timestamp_meanings={
                "created": "filesystem_created",
                "modified": "filesystem_modified",
                "accessed": "filesystem_accessed",
                "changed": "filesystem_metadata_changed",
            },
            raw_timestamps=raw_timestamps,
            utc_timestamps=timestamps,
            timestamp_sources=dict.fromkeys(timestamps, "PYTSK_FS_META"),
            is_deleted=is_deleted,
            is_readable=not is_deleted and node_type is not FileSystemNodeType.OTHER,
            is_link=node_type is FileSystemNodeType.SYMLINK,
            is_traversed=node_type is FileSystemNodeType.DIRECTORY and not is_deleted,
            raw_locator={
                "locator_type": "IMAGE_FILE_SYSTEM_OBJECT",
                "evidence_id": evidence.evidence_id,
                "volume_id": volume.volume_id,
                "volume_index": volume.volume_index,
                "volume_byte_offset": volume.byte_offset,
                "tsk_path": tsk_path,
                "inode": inode,
                "extents": extents,
                "reader_id": evidence.metadata.get("reader_id", "apex.raw_image_reader"),
                "provider_id": self.provider_id,
                "provider_version": self.provider_version,
            },
            provider_metadata={
                "backend": "pytsk3",
                "source_kind": "IMAGE_FILE_SYSTEM_OBJECT",
                "volume_index": volume.volume_index,
                "volume_id": volume.volume_id,
                "volume_byte_offset": volume.byte_offset,
                "tsk_path": tsk_path,
                "inode": inode,
                "file_reference": inode,
                "allocated": not is_deleted,
                "deleted": is_deleted,
                "deleted_metadata_confidence": "CANDIDATE" if is_deleted else "NOT_DELETED",
                "extents": extents,
                "allocated_size": sum(int(item["byte_length"]) for item in extents),
                "slack": slack,
                "entry_sort_key": self._entry_sort_key(name, inode),
                "reads_file_body": False,
            },
            is_partial=False,
            index_revision=index_revision,
            created_at=now,
            updated_at=now,
        )

    def _open_fs(self, evidence: Evidence, volume: EvidenceVolume) -> Any:
        pytsk3 = self._pytsk3()
        img = pytsk3.Img_Info(str(evidence.source_path))
        return pytsk3.FS_Info(img, offset=volume.byte_offset)

    def _candidate_volumes(self, evidence: Evidence) -> list[EvidenceVolume]:
        try:
            with RawImageReader(
                evidence.source_path,
                evidence_format=evidence.evidence_type,
            ) as reader:
                volumes = reader.volumes(case_id=evidence.case_id, evidence_id=evidence.evidence_id)
        except Exception as error:
            raise ValidationError(
                "Image volumes could not be enumerated for filesystem probing.",
                target="evidence_id",
                details={"error": str(error)},
            ) from error
        return [volume for volume in volumes if volume.is_allocated and volume.byte_length > 0]

    def _volume_by_index(self, evidence: Evidence, volume_index: int) -> EvidenceVolume | None:
        for volume in self._candidate_volumes(evidence):
            if volume.volume_index == volume_index:
                return volume
        return None

    def _synthetic_parent(
        self,
        evidence: Evidence,
        volume: EvidenceVolume,
        tsk_path: str,
        index_revision: int,
    ) -> FileSystemNode:
        relative = f"volume-{volume.volume_index}" if tsk_path == "/" else (
            f"volume-{volume.volume_index}/" + tsk_path.strip("/")
        )
        now = utc_now()
        return FileSystemNode(
            node_id=self._node_id(evidence, relative),
            case_id=evidence.case_id,
            evidence_id=evidence.evidence_id,
            provider_id=self.provider_id,
            provider_version=self.provider_version,
            parent_node_id=None,
            original_name=PurePosixPath(relative).name,
            original_relative_path=relative,
            display_path="/" + relative,
            comparison_path="/" + relative.casefold(),
            node_type=FileSystemNodeType.DIRECTORY,
            file_size=None,
            extension=None,
            mime_candidate=None,
            mime_confidence="NONE",
            fs_metadata={},
            platform="DISK_IMAGE",
            timestamp_meanings={},
            raw_timestamps={},
            utc_timestamps={},
            timestamp_sources={},
            is_deleted=False,
            is_readable=True,
            is_link=False,
            is_traversed=True,
            raw_locator=self.make_raw_locator(evidence, relative),
            provider_metadata={
                "volume_index": volume.volume_index,
                "volume_id": volume.volume_id,
                "tsk_path": tsk_path,
                "reads_file_body": False,
            },
            is_partial=False,
            index_revision=index_revision,
            created_at=now,
            updated_at=now,
        )

    def _pytsk3(self) -> ModuleType:
        if self._module is not None:
            return self._module
        try:
            self._module = importlib.import_module("pytsk3")
        except ModuleNotFoundError as error:
            raise UnsupportedCapabilityError(
                "Image filesystem indexing requires the optional pytsk3 dependency.",
                target="evidence_id",
                required_capability="PYTSK3",
            ) from error
        return self._module

    def _ensure_supported(self, evidence: Evidence) -> None:
        if not self.supports_evidence(evidence):
            raise UnsupportedCapabilityError(
                "This evidence format is not supported by the pytsk filesystem provider.",
                target="evidence_id",
                required_capability="PYTSK3_RAW_IMAGE",
            )
        self._pytsk3()

    def _dependency_available(self) -> bool:
        if self._module is not None:
            return True
        try:
            importlib.import_module("pytsk3")
        except ModuleNotFoundError:
            return False
        return True

    @staticmethod
    def _fs_type_name(fs_info: Any) -> str:
        ftype = int(fs_info.info.ftype)
        names = {
            1: "NTFS",
            2: "FAT12",
            4: "FAT16",
            8: "FAT32",
            16: "EXT2",
            32: "EXT3",
            64: "EXFAT",
        }
        return names.get(ftype, f"TSK_FS_TYPE_{ftype}")

    def _node_type(self, meta_type: int) -> FileSystemNodeType:
        pytsk3 = self._pytsk3()
        if meta_type == int(pytsk3.TSK_FS_META_TYPE_DIR):
            return FileSystemNodeType.DIRECTORY
        if meta_type == int(pytsk3.TSK_FS_META_TYPE_REG):
            return FileSystemNodeType.FILE
        if meta_type == int(pytsk3.TSK_FS_META_TYPE_LNK):
            return FileSystemNodeType.SYMLINK
        return FileSystemNodeType.OTHER

    @staticmethod
    def _extents(entry: Any, fs_info: Any, volume: EvidenceVolume) -> list[dict[str, int]]:
        extents: list[dict[str, int]] = []
        block_size = int(fs_info.info.block_size)
        try:
            attrs = list(entry)
        except OSError:
            return extents
        for attr in attrs:
            try:
                runs = list(attr)
            except OSError:
                continue
            for run in runs:
                addr = int(getattr(run, "addr", -1))
                length_blocks = int(getattr(run, "len", 0))
                if addr < 0 or length_blocks <= 0:
                    continue
                file_block_offset = int(getattr(run, "offset", 0))
                extents.append(
                    {
                        "file_offset": file_block_offset * block_size,
                        "volume_block": addr,
                        "byte_offset": volume.byte_offset + addr * block_size,
                        "byte_length": length_blocks * block_size,
                    }
                )
        return extents

    @staticmethod
    def _slack(file_size: int | None, extents: list[dict[str, int]]) -> dict[str, Any]:
        if file_size is None or not extents:
            return {"available": False, "reason": "NOT_REGULAR_FILE"}
        allocated_size = sum(int(item["byte_length"]) for item in extents)
        slack_length = allocated_size - file_size
        if slack_length <= 0:
            return {"available": False, "reason": "NO_SLACK"}
        last = max(extents, key=lambda item: int(item["file_offset"]))
        return {
            "available": True,
            "byte_offset": int(last["byte_offset"]) + int(last["byte_length"]) - slack_length,
            "byte_length": slack_length,
            "allocated_size": allocated_size,
            "logical_size": file_size,
            "policy": "BOUNDED_RAW_READ_REQUIRED",
        }

    @staticmethod
    def _timestamp(value: Any) -> datetime | None:
        try:
            seconds = int(value)
        except (TypeError, ValueError):
            return None
        if seconds <= 0:
            return None
        return datetime.fromtimestamp(seconds, UTC)

    @staticmethod
    def _decode_name(value: bytes) -> str:
        return value.decode("utf-8", errors="replace")

    @staticmethod
    def _clean_relative_path(relative_path: str) -> str:
        pure = PurePosixPath(relative_path)
        if pure.is_absolute() or any(part == ".." for part in pure.parts):
            raise ValidationError("Scope escapes image filesystem root.", target="relative_path")
        return "" if relative_path in {"", "."} else str(pure)

    @staticmethod
    def _split_volume_path(relative_path: str) -> tuple[int, str]:
        parts = PurePosixPath(relative_path).parts
        if not parts or not parts[0].startswith("volume-"):
            raise ValidationError("Image filesystem paths must start with volume-N.")
        try:
            volume_index = int(parts[0].removeprefix("volume-"))
        except ValueError as error:
            raise ValidationError("Invalid image volume path.", target="relative_path") from error
        tsk_path = "/" if len(parts) == 1 else "/" + "/".join(parts[1:])
        return volume_index, tsk_path

    @staticmethod
    def _volume_index(node: FileSystemNode) -> int | None:
        value = node.provider_metadata.get("volume_index")
        return value if isinstance(value, int) else None

    @staticmethod
    def _join_tsk_path(parent: str, name: str) -> str:
        return "/" + name if parent == "/" else f"{parent.rstrip('/')}/{name}"

    @staticmethod
    def _join_relative(parent: str, name: str) -> str:
        return name if parent == "" else f"{parent.rstrip('/')}/{name}"

    @staticmethod
    def _entry_sort_key(name: str, inode: str) -> str:
        return f"{unicodedata.normalize('NFC', name).casefold()}:{inode}"

    @staticmethod
    def _provider_sort_key(item: ProviderEntry) -> str:
        if isinstance(item, ProviderScanIssue):
            return item.path or ""
        return str(item.provider_metadata.get("entry_sort_key", item.original_name.casefold()))

    @staticmethod
    def _extension(name: str) -> str | None:
        suffix = PurePosixPath(name).suffix.lower().lstrip(".")
        return suffix or None

    @classmethod
    def _node_id(cls, evidence: Evidence, relative_path: str, inode: str = "") -> str:
        return str(
            uuid5(
                NAMESPACE_URL,
                ":".join(
                    [
                        "apex-pytsk-node-v1",
                        evidence.case_id,
                        evidence.evidence_id,
                        cls.provider_id,
                        cls.provider_version,
                        relative_path,
                        inode,
                    ]
                ),
            )
        )
