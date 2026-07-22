"""Artifact analyzer port for Phase 3 Windows artifacts."""

from __future__ import annotations

from pathlib import Path
from typing import Protocol

from apex_forensic.domain.models import (
    ArtifactAnalysisResult,
    ArtifactCapability,
    ArtifactSource,
    Evidence,
    FileSystemNode,
)


class ArtifactAnalyzer(Protocol):
    """Provider-neutral contract implemented by Windows artifact analyzers."""

    @property
    def analyzer_id(self) -> str:
        """Stable analyzer identifier."""
        ...

    @property
    def analyzer_version(self) -> str:
        """Analyzer implementation version."""
        ...

    @property
    def parser_backend(self) -> str:
        """Parser backend identifier."""
        ...

    @property
    def parser_backend_version(self) -> str:
        """Parser backend version, including optional dependency version when available."""
        ...

    def capabilities(self) -> ArtifactCapability:
        """Return a public capability statement without leaking backend objects."""
        ...

    def detect_source(self, node: FileSystemNode) -> ArtifactSource | None:
        """Return a source candidate shell for a filesystem node, if supported."""
        ...

    def supports_source(self, source: ArtifactSource) -> bool:
        """Return whether this analyzer can parse the discovered source kind."""
        ...

    def analyze(
        self,
        *,
        evidence: Evidence,
        node: FileSystemNode,
        source: ArtifactSource,
        file_path: Path,
        item_budget: int | None = None,
    ) -> ArtifactAnalysisResult:
        """Parse one source file read-only and return observed facts, warnings, and errors."""
        ...
