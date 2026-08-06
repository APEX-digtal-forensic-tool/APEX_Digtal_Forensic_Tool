"""OCR runtime provider port."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Protocol

from apex_forensic.domain.models import ProviderCapability


class OcrProviderPort(Protocol):
    """Boundary for local OCR engines."""

    @property
    def provider_id(self) -> str: ...

    @property
    def provider_version(self) -> str: ...

    def capabilities(self) -> ProviderCapability: ...

    def analyze_image(
        self,
        path: Path,
        *,
        languages: list[str],
        cancellation_requested: bool = False,
    ) -> list[dict[str, Any]]: ...
