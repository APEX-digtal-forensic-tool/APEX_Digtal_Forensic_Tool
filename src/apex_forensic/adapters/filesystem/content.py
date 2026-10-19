"""Read indexed evidence files through their provider, never through display paths."""

from __future__ import annotations

import hashlib
import os
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path, PurePosixPath
from tempfile import TemporaryDirectory
from typing import Any

from apex_forensic.adapters.filesystem.pytsk import PyTskFileSystemProvider
from apex_forensic.domain.enums import EvidenceFormat, FileSystemNodeType
from apex_forensic.domain.errors import RawReadError
from apex_forensic.domain.models import Evidence, FileSystemNode
from apex_forensic.jobs import CancellationToken

CHUNK_SIZE = 1024 * 1024
MAX_MATERIALIZED_BYTES = 512 * 1024 * 1024


def check_cancel(token: CancellationToken | None) -> None:
    if token is not None and token.is_cancelled:
        raise RawReadError("RAW_READ_CANCELLED", "File read was cancelled.")


def regular_path(path: Path) -> Path:
    """Reject symlinks and Windows reparse points in every path component."""
    path = path.absolute()
    for part in (*reversed(path.parents), path):
        info = part.lstat()
        if stat.S_ISLNK(info.st_mode) or (
            getattr(info, "st_file_attributes", 0)
            & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
        ):
            raise RawReadError("RAW_SOURCE_OUTSIDE_EVIDENCE", "Source links are not followed.")
    if not path.is_file():
        raise RawReadError("RAW_LOCATOR_UNSUPPORTED", "Content reads require a regular file.")
    return path


class EvidenceFileContent:
    """Bounded logical-file reads, including allocated files inside disk images.

    Image offsets and inode addresses come exclusively from indexed nodes. TSK
    interprets file attributes/runs, including resident, sparse and compressed
    content; physical extents must not be concatenated as a replacement.
    """

    @staticmethod
    def is_image(node: FileSystemNode) -> bool:
        return node.provider_id == PyTskFileSystemProvider.provider_id

    @classmethod
    def supports(cls, evidence: Evidence | None, node: FileSystemNode | None) -> bool:
        if evidence is None or node is None or node.node_type is not FileSystemNodeType.FILE:
            return False
        if node.is_link or node.is_deleted or not node.is_readable:
            return False
        if cls.is_image(node):
            provider = PyTskFileSystemProvider()
            return provider.supports_evidence(evidence) and provider.available()
        return evidence.evidence_type is EvidenceFormat.DIRECTORY or (
            evidence.evidence_type is EvidenceFormat.RAW
            and node.provider_metadata.get("source_path_kind") == "logical_file"
            and node.original_relative_path in {"", "."}
        )

    @staticmethod
    def logical_path(evidence: Evidence, node: FileSystemNode) -> Path:
        relative = PurePosixPath(node.original_relative_path.replace("\\", "/"))
        if relative.is_absolute() or ".." in relative.parts:
            raise RawReadError("RAW_SOURCE_OUTSIDE_EVIDENCE", "Source path escapes evidence.")
        root = evidence.source_path.absolute()
        if evidence.evidence_type is EvidenceFormat.DIRECTORY:
            return regular_path(root.joinpath(*relative.parts))
        if relative.as_posix() != ".":
            raise RawReadError("RAW_SOURCE_OUTSIDE_EVIDENCE", "Invalid logical file path.")
        return regular_path(root)

    @classmethod
    @contextmanager
    def open(cls, evidence: Evidence, node: FileSystemNode) -> Iterator[Any]:
        if node.case_id != evidence.case_id or node.evidence_id != evidence.evidence_id:
            raise RawReadError("RAW_SOURCE_OUTSIDE_EVIDENCE", "Source belongs to other evidence.")
        if not cls.supports(evidence, node):
            raise RawReadError("RAW_LOCATOR_UNSUPPORTED", "Source does not support content reads.")
        if cls.is_image(node):
            regular_path(evidence.source_path)
            with PyTskFileSystemProvider().open_file(evidence, node) as handle:
                yield handle
        else:
            path = cls.logical_path(evidence, node)
            try:
                path_before = path.stat()
                with path.open("rb") as handle:
                    before = os.fstat(handle.fileno())
                    identity_fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns")
                    if any(
                        getattr(before, key) != getattr(path_before, key)
                        for key in identity_fields
                    ):
                        raise RawReadError("RAW_SOURCE_CHANGED", "File changed while opening.")
                    if not stat.S_ISREG(before.st_mode) or before.st_size != node.file_size:
                        raise RawReadError("RAW_SOURCE_CHANGED", "Indexed file size changed.")
                    indexed = {
                        "st_mtime_ns": node.raw_timestamps.get("modified"),
                        "st_ino": node.fs_metadata.get("inode"),
                        "st_dev": node.fs_metadata.get("device"),
                    }
                    # Older Windows directory indexes used DirEntry.stat(), which
                    # supplies zero for both identifiers. Preserve those indexes
                    # without treating unknown values as real file identities.
                    if node.platform == "win32" and indexed["st_ino"] == indexed["st_dev"] == 0:
                        indexed.pop("st_ino")
                        indexed.pop("st_dev")
                    if any(
                        value is not None and value != getattr(before, key)
                        for key, value in indexed.items()
                    ):
                        raise RawReadError("RAW_SOURCE_CHANGED", "Indexed file identity changed.")
                    yield handle
                    after = os.fstat(handle.fileno())
                    current = regular_path(path).stat()
                    # On Windows/Python 3.12, stat and fstat can expose different
                    # ctime meanings (birth vs change time). Compare ctime only
                    # within the same API, retaining change detection for both.
                    fields = (*identity_fields, "st_ctime_ns")
                    if any(
                        getattr(previous, key) != getattr(info, key)
                        for previous, info in ((before, after), (path_before, current))
                        for key in fields
                    ):
                        raise RawReadError("RAW_SOURCE_CHANGED", "File changed while reading.")
            except OSError as error:
                raise RawReadError(
                    "RAW_SOURCE_UNAVAILABLE", "Source file is unavailable."
                ) from error

    @staticmethod
    def _read(handle: Any, offset: int, length: int) -> bytes:
        if length == 0:
            return b""
        if hasattr(handle, "read_random"):
            return bytes(handle.read_random(offset, length))
        handle.seek(offset)
        return bytes(handle.read(length))

    @classmethod
    def read(
        cls,
        evidence: Evidence,
        node: FileSystemNode,
        *,
        offset: int,
        length: int,
        cancellation_token: CancellationToken | None = None,
    ) -> bytes:
        if offset < 0 or length < 0 or length > CHUNK_SIZE:
            raise RawReadError("RAW_RANGE_INVALID", "Invalid file read range.")
        check_cancel(cancellation_token)
        size = node.file_size or 0
        if offset > size:
            raise RawReadError("RAW_RANGE_INVALID", "Offset is beyond file EOF.")
        with cls.open(evidence, node) as handle:
            expected = min(length, size - offset)
            data = cls._read(handle, offset, expected)
            if len(data) != expected:
                raise RawReadError("RAW_SOURCE_CHANGED", "Unexpected end of source file.")
        check_cancel(cancellation_token)
        return data

    @classmethod
    def chunks(
        cls,
        evidence: Evidence,
        node: FileSystemNode,
        *,
        limit: int,
        cancellation_token: CancellationToken | None = None,
    ) -> Iterator[bytes]:
        size = node.file_size or 0
        if size > limit:
            raise RawReadError("RAW_READ_LIMIT_EXCEEDED", "Source exceeds materialization limit.")
        with cls.open(evidence, node) as handle:
            offset = 0
            while offset < size:
                check_cancel(cancellation_token)
                chunk = cls._read(handle, offset, min(CHUNK_SIZE, size - offset))
                if not chunk:
                    raise RawReadError("RAW_SOURCE_CHANGED", "Unexpected end of source file.")
                offset += len(chunk)
                yield chunk
        check_cancel(cancellation_token)

    @classmethod
    def sha256(cls, evidence: Evidence, node: FileSystemNode) -> str:
        digest = hashlib.sha256()
        for chunk in cls.chunks(evidence, node, limit=MAX_MATERIALIZED_BYTES):
            digest.update(chunk)
        return digest.hexdigest()

    @classmethod
    @contextmanager
    def materialize(
        cls,
        evidence: Evidence,
        node: FileSystemNode,
        *,
        siblings: tuple[FileSystemNode, ...] = (),
        cancellation_token: CancellationToken | None = None,
    ) -> Iterator[Path]:
        """Supply path-only parsers with a disposable copy, including SQLite sidecars."""
        check_cancel(cancellation_token)
        sources = (node, *siblings)
        if sum(item.file_size or 0 for item in sources) > MAX_MATERIALIZED_BYTES:
            raise RawReadError("RAW_READ_LIMIT_EXCEEDED", "Source and sidecars exceed limit.")
        # TemporaryDirectory creates a private directory; it is removed on every exit.
        with TemporaryDirectory(prefix="apex-source-") as temp:
            primary = Path(temp) / "source"
            for item in sources:
                suffix = (
                    ""
                    if item.node_id == node.node_id
                    else item.original_name[len(node.original_name) :]
                )
                if suffix not in {"", "-wal", "-shm", "-journal"}:
                    raise RawReadError("RAW_SOURCE_OUTSIDE_EVIDENCE", "Invalid source sidecar.")
                target = primary.with_name(primary.name + suffix)
                with target.open("xb") as output:
                    for chunk in cls.chunks(
                        evidence,
                        item,
                        limit=MAX_MATERIALIZED_BYTES,
                        cancellation_token=cancellation_token,
                    ):
                        output.write(chunk)
            yield primary
