"""Logical directory/file filesystem provider."""

from __future__ import annotations

import mimetypes
import os
import stat
import sys
import unicodedata
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any
from uuid import NAMESPACE_URL, uuid5

from apex_forensic.constants import ENGINE_VERSION
from apex_forensic.domain.enums import (
    EvidenceFormat,
    FileSystemNodeType,
    FileSystemProviderCapability,
)
from apex_forensic.domain.errors import UnsupportedCapabilityError, ValidationError
from apex_forensic.domain.models import Evidence, FileSystemNode
from apex_forensic.ports.filesystem_provider import (
    FileSystemProviderCapabilities,
    ProviderEntry,
    ProviderScanIssue,
)

_DISK_IMAGE_SUFFIXES = {".e01", ".raw", ".dd", ".img", ".vhd", ".vhdx"}
_DISK_IMAGE_FORMATS = {
    EvidenceFormat.E01,
    EvidenceFormat.DD,
    EvidenceFormat.IMG,
    EvidenceFormat.VHD,
    EvidenceFormat.VHDX,
}


class LogicalDirectoryFileSystemProvider:
    """Read-only metadata provider for directories and ordinary logical files."""

    provider_id = "apex.logical_directory_provider"
    provider_version = ENGINE_VERSION

    def capabilities(self) -> FileSystemProviderCapabilities:
        return FileSystemProviderCapabilities(
            provider_id=self.provider_id,
            provider_version=self.provider_version,
            capabilities=(
                FileSystemProviderCapability.LOGICAL_DIRECTORY,
                FileSystemProviderCapability.LOGICAL_FILE,
                FileSystemProviderCapability.METADATA_ONLY,
                FileSystemProviderCapability.STABLE_RAW_LOCATOR,
            ),
            unsupported_formats=("E01", "RAW_DISK_IMAGE", "DD", "IMG", "VHD", "VHDX"),
            metadata={
                "follows_symlinks_by_default": False,
                "reads_file_body": False,
                "hashes_during_index": False,
            },
        )

    def supports_evidence(self, evidence: Evidence) -> bool:
        if evidence.evidence_type is EvidenceFormat.DIRECTORY:
            return True
        return not self._is_disk_image(evidence)

    def get_root_node(self, evidence: Evidence, *, index_revision: int) -> FileSystemNode:
        self._ensure_supported(evidence)
        source = self._root_path(evidence)
        try:
            stat_result = source.stat()
        except OSError as error:
            raise ValidationError(
                "Evidence root is not readable for metadata indexing.",
                target="evidence_id",
                details={"path": str(source), "error": str(error)},
            ) from error
        node_type = FileSystemNodeType.ROOT if source.is_dir() else FileSystemNodeType.FILE
        name = source.name or str(source)
        return self._node_from_stat(
            evidence=evidence,
            source_path=source,
            stat_result=stat_result,
            node_type=node_type,
            parent_node_id=None,
            original_name=name,
            relative_path="",
            index_revision=index_revision,
            is_link=False,
            is_traversed=node_type is FileSystemNodeType.ROOT,
            entry_sort_key="",
        )

    def iter_directory_entries(
        self,
        evidence: Evidence,
        parent: FileSystemNode,
        *,
        index_revision: int,
        after_cursor: str | None = None,
    ) -> Iterable[ProviderEntry]:
        self._ensure_supported(evidence)
        if not parent.is_directory_like or not parent.is_traversed:
            return []
        root = self._root_path(evidence)
        directory = self._path_for_relative(root, parent.original_relative_path)
        try:
            with os.scandir(directory) as iterator:
                entries = sorted(
                    iterator,
                    key=lambda entry: self._entry_sort_key(entry.name),
                )
        except PermissionError as error:
            return [
                ProviderScanIssue(
                    severity="WARNING",
                    code="PERMISSION_DENIED",
                    message_key="warning.fs.permission_denied",
                    developer_message=(
                        "Directory cannot be read; indexing continues with partial metadata."
                    ),
                    path=parent.display_path,
                    node_id=parent.node_id,
                    details={"error": str(error)},
                )
            ]
        except FileNotFoundError as error:
            return [
                ProviderScanIssue(
                    severity="WARNING",
                    code="FILE_NOT_FOUND_DURING_SCAN",
                    message_key="warning.fs.file_not_found_during_scan",
                    developer_message="Directory disappeared during scan; indexing continues.",
                    path=parent.display_path,
                    node_id=parent.node_id,
                    details={"error": str(error)},
                )
            ]
        except OSError as error:
            return [
                ProviderScanIssue(
                    severity="ERROR",
                    code="DIRECTORY_SCAN_ERROR",
                    message_key="error.fs.directory_scan",
                    developer_message="Directory metadata scan failed.",
                    path=parent.display_path,
                    node_id=parent.node_id,
                    details={"error": str(error)},
                )
            ]

        results: list[ProviderEntry] = []
        for entry in entries:
            sort_key = self._entry_sort_key(entry.name)
            if after_cursor is not None and sort_key <= after_cursor:
                continue
            child_relative = self._join_relative(parent.original_relative_path, entry.name)
            child_path = Path(entry.path)
            try:
                child_path = self._validate_inside_root(root, child_path, follow=False)
                stat_result = entry.stat(follow_symlinks=False)
            except FileNotFoundError as error:
                results.append(
                    ProviderScanIssue(
                        severity="WARNING",
                        code="FILE_CHANGED_DURING_SCAN",
                        message_key="warning.fs.file_changed_during_scan",
                        developer_message="Entry changed or disappeared during metadata scan.",
                        path=self._display_path(child_relative),
                        node_id=parent.node_id,
                        details={"error": str(error)},
                    )
                )
                continue
            except PermissionError as error:
                results.append(
                    ProviderScanIssue(
                        severity="WARNING",
                        code="PERMISSION_DENIED",
                        message_key="warning.fs.permission_denied",
                        developer_message="Entry metadata cannot be read; indexing continues.",
                        path=self._display_path(child_relative),
                        node_id=parent.node_id,
                        details={"error": str(error)},
                    )
                )
                continue
            except OSError as error:
                results.append(
                    ProviderScanIssue(
                        severity="WARNING",
                        code="FILE_CHANGED_DURING_SCAN",
                        message_key="warning.fs.file_changed_during_scan",
                        developer_message="Entry metadata changed during scan.",
                        path=self._display_path(child_relative),
                        node_id=parent.node_id,
                        details={"error": str(error)},
                    )
                )
                continue
            node_type, is_link, is_traversed = self._node_type(entry, stat_result)
            results.append(
                self._node_from_stat(
                    evidence=evidence,
                    source_path=child_path,
                    stat_result=stat_result,
                    node_type=node_type,
                    parent_node_id=parent.node_id,
                    original_name=entry.name,
                    relative_path=child_relative,
                    index_revision=index_revision,
                    is_link=is_link,
                    is_traversed=is_traversed,
                    entry_sort_key=sort_key,
                )
            )
        return results

    def get_metadata(
        self,
        evidence: Evidence,
        relative_path: str,
        *,
        index_revision: int,
    ) -> FileSystemNode:
        self._ensure_supported(evidence)
        root = self._root_path(evidence)
        target = self._path_for_relative(root, relative_path)
        target = self._validate_inside_root(root, target, follow=False)
        try:
            stat_result = target.stat(follow_symlinks=False)
        except OSError as error:
            raise ValidationError(
                "Selected scope does not exist or cannot be read.",
                target="relative_path",
                details={"path": relative_path, "error": str(error)},
            ) from error
        is_link = target.is_symlink()
        node_type = self._type_from_stat(stat_result, is_link=is_link)
        is_traversed = node_type in {FileSystemNodeType.ROOT, FileSystemNodeType.DIRECTORY}
        if is_link or node_type is FileSystemNodeType.REPARSE_POINT:
            is_traversed = False
        parent_relative = self._parent_relative(relative_path)
        parent_node_id = None if relative_path == "" else self._node_id(evidence, parent_relative)
        original_name = (
            self._root_path(evidence).name
            if relative_path == ""
            else PurePosixPath(relative_path).name
        )
        return self._node_from_stat(
            evidence=evidence,
            source_path=target,
            stat_result=stat_result,
            node_type=node_type,
            parent_node_id=parent_node_id,
            original_name=original_name,
            relative_path=relative_path,
            index_revision=index_revision,
            is_link=is_link,
            is_traversed=is_traversed,
            entry_sort_key=self._entry_sort_key(original_name),
        )

    def get_child_entry(
        self,
        evidence: Evidence,
        parent: FileSystemNode,
        original_name: str,
        *,
        index_revision: int,
    ) -> FileSystemNode | None:
        relative_path = self._join_relative(parent.original_relative_path, original_name)
        try:
            return self.get_metadata(evidence, relative_path, index_revision=index_revision)
        except ValidationError:
            return None

    def make_raw_locator(self, evidence: Evidence, relative_path: str) -> dict[str, Any]:
        return {
            "provider_id": self.provider_id,
            "provider_version": self.provider_version,
            "evidence_id": evidence.evidence_id,
            "relative_path": relative_path,
            "locator_type": "LOGICAL_PATH",
            "reads_file_body": False,
        }

    def _ensure_supported(self, evidence: Evidence) -> None:
        if not self.supports_evidence(evidence):
            raise UnsupportedCapabilityError(
                "Internal filesystem parsing is unavailable for this evidence format in Phase 2.",
                target="evidence_id",
                required_capability="FILESYSTEM_INTERNAL_PARSING",
            )

    @staticmethod
    def _is_disk_image(evidence: Evidence) -> bool:
        if evidence.evidence_type in _DISK_IMAGE_FORMATS:
            return True
        suffix = evidence.source_path.suffix.lower()
        return evidence.evidence_type is EvidenceFormat.RAW and suffix in _DISK_IMAGE_SUFFIXES

    @staticmethod
    def _root_path(evidence: Evidence) -> Path:
        return evidence.source_path.resolve(strict=True)

    def _path_for_relative(self, root: Path, relative_path: str) -> Path:
        if relative_path in {"", "."}:
            return root
        pure = PurePosixPath(relative_path)
        if pure.is_absolute() or any(part == ".." for part in pure.parts):
            raise ValidationError("Scope escapes evidence root.", target="relative_path")
        return root.joinpath(*pure.parts)

    @staticmethod
    def _validate_inside_root(root: Path, path: Path, *, follow: bool) -> Path:
        root_resolved = root.resolve(strict=True)
        candidate = path.resolve(strict=follow) if follow else path.absolute()
        try:
            common = os.path.commonpath([str(root_resolved), str(candidate)])
        except ValueError as error:
            raise ValidationError("Scope escapes evidence root.", target="path") from error
        if common != str(root_resolved):
            raise ValidationError("Scope escapes evidence root.", target="path")
        return path

    @classmethod
    def _node_id(cls, evidence: Evidence, relative_path: str) -> str:
        key = ":".join(
            [
                "apex-fs-node-v1",
                evidence.case_id,
                evidence.evidence_id,
                cls.provider_id,
                cls.provider_version,
                relative_path,
            ]
        )
        return str(uuid5(NAMESPACE_URL, key))

    def _node_from_stat(
        self,
        *,
        evidence: Evidence,
        source_path: Path,
        stat_result: os.stat_result,
        node_type: FileSystemNodeType,
        parent_node_id: str | None,
        original_name: str,
        relative_path: str,
        index_revision: int,
        is_link: bool,
        is_traversed: bool,
        entry_sort_key: str,
    ) -> FileSystemNode:
        now = datetime.now(UTC)
        extension = self._extension(original_name, node_type)
        mime_candidate, mime_confidence = self._mime(original_name, node_type)
        raw_timestamps = self._raw_timestamps(stat_result)
        utc_timestamps = self._utc_timestamps(stat_result)
        display_path = self._display_path(relative_path)
        return FileSystemNode(
            node_id=self._node_id(evidence, relative_path),
            case_id=evidence.case_id,
            evidence_id=evidence.evidence_id,
            provider_id=self.provider_id,
            provider_version=self.provider_version,
            parent_node_id=parent_node_id,
            original_name=original_name,
            original_relative_path=relative_path,
            display_path=display_path,
            comparison_path=self._comparison_path(relative_path),
            node_type=node_type,
            file_size=int(stat_result.st_size)
            if node_type is not FileSystemNodeType.ROOT
            else None,
            extension=extension,
            mime_candidate=mime_candidate,
            mime_confidence=mime_confidence,
            fs_metadata={
                "mode": stat.S_IMODE(stat_result.st_mode),
                "inode": getattr(stat_result, "st_ino", None),
                "device": getattr(stat_result, "st_dev", None),
                "nlink": getattr(stat_result, "st_nlink", None),
            },
            platform=sys.platform,
            timestamp_meanings={
                "created": "birth_time_or_metadata_change",
                "modified": "content_modified",
                "accessed": "last_accessed",
                "changed": "metadata_changed",
            },
            raw_timestamps=raw_timestamps,
            utc_timestamps=utc_timestamps,
            timestamp_sources=dict.fromkeys(raw_timestamps, "os.stat"),
            is_deleted=False,
            is_readable=self._is_readable(source_path, node_type),
            is_link=is_link,
            is_traversed=is_traversed,
            raw_locator=self.make_raw_locator(evidence, relative_path),
            provider_metadata={
                "entry_sort_key": entry_sort_key,
                "source_path_kind": "directory"
                if evidence.evidence_type is EvidenceFormat.DIRECTORY
                else "logical_file",
                "followed_symlink": False,
            },
            is_partial=False,
            index_revision=index_revision,
            created_at=now,
            updated_at=now,
        )

    @staticmethod
    def _type_from_stat(stat_result: os.stat_result, *, is_link: bool) -> FileSystemNodeType:
        if is_link:
            return FileSystemNodeType.SYMLINK
        if LogicalDirectoryFileSystemProvider._is_reparse_point(stat_result):
            return FileSystemNodeType.REPARSE_POINT
        mode = stat_result.st_mode
        if stat.S_ISDIR(mode):
            return FileSystemNodeType.DIRECTORY
        if stat.S_ISREG(mode):
            return FileSystemNodeType.FILE
        return FileSystemNodeType.OTHER

    def _node_type(
        self,
        entry: os.DirEntry[str],
        stat_result: os.stat_result,
    ) -> tuple[FileSystemNodeType, bool, bool]:
        is_link = entry.is_symlink()
        node_type = self._type_from_stat(stat_result, is_link=is_link)
        is_traversed = node_type is FileSystemNodeType.DIRECTORY and not is_link
        if node_type is FileSystemNodeType.REPARSE_POINT:
            is_traversed = False
            is_link = True
        return node_type, is_link, is_traversed

    @staticmethod
    def _is_reparse_point(stat_result: os.stat_result) -> bool:
        attributes = getattr(stat_result, "st_file_attributes", 0)
        return bool(attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))

    @staticmethod
    def _join_relative(parent: str, name: str) -> str:
        return name if parent == "" else f"{parent}/{name}"

    @staticmethod
    def _parent_relative(relative_path: str) -> str:
        if relative_path == "":
            return ""
        parent = str(PurePosixPath(relative_path).parent)
        return "" if parent == "." else parent

    @staticmethod
    def _display_path(relative_path: str) -> str:
        return "/" if relative_path == "" else f"/{relative_path}"

    @staticmethod
    def _comparison_path(relative_path: str) -> str:
        return unicodedata.normalize("NFC", relative_path).casefold()

    @staticmethod
    def _entry_sort_key(name: str) -> str:
        return unicodedata.normalize("NFC", name).casefold() + "\x00" + name

    @staticmethod
    def _extension(name: str, node_type: FileSystemNodeType) -> str | None:
        if node_type is not FileSystemNodeType.FILE:
            return None
        suffix = PurePosixPath(name).suffix
        return suffix[1:].casefold() if suffix else None

    @staticmethod
    def _mime(name: str, node_type: FileSystemNodeType) -> tuple[str | None, str]:
        if node_type is not FileSystemNodeType.FILE:
            return None, "UNKNOWN"
        mime_type, _ = mimetypes.guess_type(name, strict=False)
        return mime_type, "LOW" if mime_type is not None else "UNKNOWN"

    @staticmethod
    def _raw_timestamps(stat_result: os.stat_result) -> dict[str, Any]:
        return {
            "created": getattr(
                stat_result, "st_birthtime_ns", getattr(stat_result, "st_ctime_ns", None)
            ),
            "modified": getattr(stat_result, "st_mtime_ns", None),
            "accessed": getattr(stat_result, "st_atime_ns", None),
            "changed": getattr(stat_result, "st_ctime_ns", None),
        }

    @staticmethod
    def _from_ns(value: Any) -> datetime | None:
        if value is None:
            return None
        return datetime.fromtimestamp(int(value) / 1_000_000_000, UTC)

    def _utc_timestamps(self, stat_result: os.stat_result) -> dict[str, datetime | None]:
        raw = self._raw_timestamps(stat_result)
        return {key: self._from_ns(value) for key, value in raw.items()}

    @staticmethod
    def _is_readable(path: Path, node_type: FileSystemNodeType) -> bool:
        mode = (
            os.R_OK | os.X_OK
            if node_type in {FileSystemNodeType.ROOT, FileSystemNodeType.DIRECTORY}
            else os.R_OK
        )
        return os.access(path, mode)
