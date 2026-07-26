"""Provider-neutral Phase 8 report renderer port."""

from __future__ import annotations

from typing import Any, ClassVar, Protocol

from apex_forensic.domain.errors import ReportError
from apex_forensic.domain.models import ReportRendererCapability, ReportRenderPackage


class ReportRendererPort(Protocol):
    """Boundary for an external report renderer.

    Implementations must not write repository rows directly. ReportService validates and stores
    renderer output metadata.
    """

    @property
    def renderer_id(self) -> str: ...

    @property
    def renderer_version(self) -> str: ...

    @property
    def supported_formats(self) -> list[str]: ...

    def capabilities(self) -> ReportRendererCapability: ...

    def validate_package(self, package: ReportRenderPackage) -> None: ...

    def render(
        self,
        package: ReportRenderPackage,
        *,
        export_manifest_id: str,
        requested_filename: str,
    ) -> dict[str, Any]: ...

    def cancel(self, export_manifest_id: str) -> dict[str, Any]: ...

    def verify_output(self, result: dict[str, Any]) -> None: ...


class UnavailableReportRenderer:
    """Default renderer that advertises no PDF/HTML runtime capability."""

    renderer_id = "apex.report.renderer.unavailable"
    renderer_version = "1.0.0"
    supported_formats: ClassVar[tuple[str, ...]] = ()

    def capabilities(self) -> ReportRendererCapability:
        return ReportRendererCapability(
            renderer_id=self.renderer_id,
            renderer_version=self.renderer_version,
            supported_formats=[],
            is_available=False,
            unavailable_reason="CAPABILITY_UNAVAILABLE",
            warnings=[
                {
                    "code": "CAPABILITY_UNAVAILABLE",
                    "developer_message": "No runtime report renderer is configured in the engine.",
                }
            ],
        )

    def validate_package(self, package: ReportRenderPackage) -> None:
        del package
        raise ReportError(
            "CAPABILITY_UNAVAILABLE",
            "The engine does not implement runtime report rendering.",
            target="renderer",
            details={"renderer_id": self.renderer_id},
        )

    def render(
        self,
        package: ReportRenderPackage,
        *,
        export_manifest_id: str,
        requested_filename: str,
    ) -> dict[str, Any]:
        del package, export_manifest_id, requested_filename
        raise ReportError(
            "CAPABILITY_UNAVAILABLE",
            "The engine does not implement runtime report rendering.",
            target="renderer",
            details={"renderer_id": self.renderer_id},
        )

    def cancel(self, export_manifest_id: str) -> dict[str, Any]:
        del export_manifest_id
        raise ReportError(
            "CAPABILITY_UNAVAILABLE",
            "The engine does not implement runtime report rendering.",
            target="renderer",
            details={"renderer_id": self.renderer_id},
        )

    def verify_output(self, result: dict[str, Any]) -> None:
        del result
        raise ReportError(
            "CAPABILITY_UNAVAILABLE",
            "The engine does not implement runtime report rendering.",
            target="renderer",
            details={"renderer_id": self.renderer_id},
        )
