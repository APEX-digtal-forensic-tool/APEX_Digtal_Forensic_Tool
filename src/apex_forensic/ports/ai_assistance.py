"""Provider-neutral Phase 7 AI assistance port."""

from __future__ import annotations

from typing import Any, ClassVar, Protocol

from apex_forensic.domain.errors import AiAssistanceError
from apex_forensic.domain.models import AiAssistanceRequest, AiProviderCapability


class AiAssistanceProviderPort(Protocol):
    """Boundary for an external AI layer.

    Implementations must not write to repositories directly; service validation owns ingest.
    """

    @property
    def provider_id(self) -> str: ...

    @property
    def provider_version(self) -> str: ...

    @property
    def supported_operations(self) -> list[str]: ...

    @property
    def max_request_items(self) -> int: ...

    @property
    def max_result_items(self) -> int: ...

    @property
    def max_summary_length(self) -> int: ...

    def capabilities(self) -> AiProviderCapability: ...

    def generate_keyword_recommendations(
        self, request: AiAssistanceRequest, *, cancellation_requested: bool = False
    ) -> dict[str, Any]: ...

    def generate_scope_summary(
        self, request: AiAssistanceRequest, *, cancellation_requested: bool = False
    ) -> dict[str, Any]: ...


class UnavailableAiAssistanceProvider:
    """Default provider that advertises no runtime AI capability."""

    provider_id = "apex.ai.unavailable"
    provider_version = "1.0.0"
    supported_operations: ClassVar[tuple[str, ...]] = ()
    max_request_items = 0
    max_result_items = 0
    max_summary_length = 0

    def capabilities(self) -> AiProviderCapability:
        return AiProviderCapability(
            provider_id=self.provider_id,
            provider_version=self.provider_version,
            supported_operations=[],
            max_request_items=0,
            max_result_items=0,
            max_summary_length=0,
            is_available=False,
            unavailable_reason="CAPABILITY_UNAVAILABLE",
            warnings=[
                {
                    "code": "CAPABILITY_UNAVAILABLE",
                    "developer_message": "No runtime AI provider is configured in the engine.",
                }
            ],
        )

    def generate_keyword_recommendations(
        self, request: AiAssistanceRequest, *, cancellation_requested: bool = False
    ) -> dict[str, Any]:
        del request, cancellation_requested
        raise AiAssistanceError(
            "CAPABILITY_UNAVAILABLE",
            "The engine does not implement runtime AI keyword generation.",
            target="provider",
            details={"provider_id": self.provider_id},
        )

    def generate_scope_summary(
        self, request: AiAssistanceRequest, *, cancellation_requested: bool = False
    ) -> dict[str, Any]:
        del request, cancellation_requested
        raise AiAssistanceError(
            "CAPABILITY_UNAVAILABLE",
            "The engine does not implement runtime AI scope summary generation.",
            target="provider",
            details={"provider_id": self.provider_id},
        )
