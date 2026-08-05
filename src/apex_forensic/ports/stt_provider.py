"""STT runtime provider port."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Protocol

from apex_forensic.domain.models import ProviderCapability


class SttProviderPort(Protocol):
    """Boundary for local speech-to-text engines."""

    @property
    def provider_id(self) -> str: ...

    @property
    def provider_version(self) -> str: ...

    def capabilities(self) -> ProviderCapability: ...

    def analyze_audio(
        self,
        path: Path,
        *,
        language: str | None = None,
        cancellation_requested: bool = False,
    ) -> list[dict[str, Any]]: ...
