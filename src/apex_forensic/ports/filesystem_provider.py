"""File system provider port for Phase 2 progressive indexing."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any, Protocol

from apex_forensic.domain.enums import FileSystemProviderCapability
from apex_forensic.domain.models import Evidence, FileSystemNode


@dataclass(frozen=True, slots=True)
class FileSystemProviderCapabilities:
    """Public capability statement for a filesystem provider."""

    provider_id: str
    provider_version: str
    capabilities: tuple[FileSystemProviderCapability, ...]
    unsupported_formats: tuple[str, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_schema_dict(self) -> dict[str, Any]:
        return {
            "id": self.provider_id,
            "version": self.provider_version,
            "capabilities": [capability.value for capability in self.capabilities],
            "unsupported_formats": list(self.unsupported_formats),
            "metadata": self.metadata,
        }


@dataclass(frozen=True, slots=True)
class ProviderScanIssue:
    """A warning or error emitted while a provider scans metadata."""

    severity: str
    code: str
    message_key: str
    developer_message: str
    path: str | None = None
    node_id: str | None = None
    details: dict[str, Any] = field(default_factory=dict)

    def to_warning_dict(self, *, source_id: str | None = None) -> dict[str, Any]:
        return {
            "code": self.code,
            "message_key": self.message_key,
            "developer_message": self.developer_message,
            "source_id": source_id,
            "details": self.details | ({"path": self.path} if self.path is not None else {}),
        }

    def to_error_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "message_key": self.message_key,
            "developer_message": self.developer_message,
            "target": self.path,
            "retryable": self.severity == "WARNING",
            "details": self.details,
        }


ProviderEntry = FileSystemNode | ProviderScanIssue


class FileSystemProvider(Protocol):
    """Provider boundary used by the application coordinator."""

    @property
    def provider_id(self) -> str:
        """Stable provider identifier."""
        ...

    @property
    def provider_version(self) -> str:
        """Provider implementation version."""
        ...

    def capabilities(self) -> FileSystemProviderCapabilities:
        """Return the public provider capability statement."""
        ...

    def supports_evidence(self, evidence: Evidence) -> bool:
        """Return whether this provider can expose filesystem nodes for evidence."""
        ...

    def get_root_node(self, evidence: Evidence, *, index_revision: int) -> FileSystemNode:
        """Return the root node for an evidence source."""
        ...

    def iter_directory_entries(
        self,
        evidence: Evidence,
        parent: FileSystemNode,
        *,
        index_revision: int,
        after_cursor: str | None = None,
    ) -> Iterable[ProviderEntry]:
        """Yield child metadata entries or provider issues for a directory node."""
        ...

    def get_metadata(
        self,
        evidence: Evidence,
        relative_path: str,
        *,
        index_revision: int,
    ) -> FileSystemNode:
        """Return metadata for a known relative path inside evidence."""
        ...

    def get_child_entry(
        self,
        evidence: Evidence,
        parent: FileSystemNode,
        original_name: str,
        *,
        index_revision: int,
    ) -> FileSystemNode | None:
        """Return one child entry by original name, if present."""
        ...

    def make_raw_locator(self, evidence: Evidence, relative_path: str) -> dict[str, Any]:
        """Create a provider-neutral raw locator."""
        ...
