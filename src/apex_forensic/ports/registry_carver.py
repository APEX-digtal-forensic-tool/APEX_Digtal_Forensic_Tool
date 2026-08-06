"""Registry deleted-cell carving port."""

from __future__ import annotations

from pathlib import Path
from typing import Protocol

from apex_forensic.domain.models import (
    RegistryCarvingReport,
)


class RegistryDeletedCellCarverPort(Protocol):
    """Boundary for conservative offline registry free-cell/slack carving."""

    @property
    def provider_id(self) -> str: ...

    @property
    def provider_version(self) -> str: ...

    def carve(
        self,
        hive_path: Path,
        *,
        max_candidates: int | None = None,
    ) -> RegistryCarvingReport: ...
