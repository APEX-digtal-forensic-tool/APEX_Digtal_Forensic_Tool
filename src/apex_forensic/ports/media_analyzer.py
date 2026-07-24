"""Provider-neutral media analyzer port for Phase 5."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Protocol

from apex_forensic.domain.models import (
    ArtifactAnalysisResult,
    ArtifactCapability,
    ArtifactSource,
    Evidence,
    FileSystemNode,
    Phase5Checkpoint,
)


class MediaAnalyzer(Protocol):
    """Contract for media candidate detection, metadata, and thumbnail providers."""

    @property
    def analyzer_id(self) -> str: ...

    @property
    def analyzer_version(self) -> str: ...

    @property
    def parser_backend(self) -> str: ...

    @property
    def parser_backend_version(self) -> str: ...

    def capabilities(self) -> ArtifactCapability: ...

    def detect_source(self, node: FileSystemNode) -> ArtifactSource | None: ...

    def supports_source(self, source: ArtifactSource) -> bool: ...

    def analyze(
        self,
        *,
        evidence: Evidence,
        node: FileSystemNode,
        source: ArtifactSource,
        file_path: Path,
        item_budget: int | None = None,
    ) -> ArtifactAnalysisResult: ...

    def request_thumbnail(
        self,
        *,
        evidence: Evidence,
        node: FileSystemNode,
        source: ArtifactSource,
        file_path: Path,
        max_width: int,
        max_height: int,
        max_output_bytes: int,
        output_format: str,
    ) -> dict[str, Any]: ...

    def checkpoint(self) -> Phase5Checkpoint | None: ...

    def restore_checkpoint(self, checkpoint: Phase5Checkpoint) -> None: ...

    def unsupported_reason(self) -> dict[str, Any] | None: ...
