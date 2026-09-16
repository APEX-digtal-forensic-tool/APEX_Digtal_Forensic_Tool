"""Actual HTML/PDF report renderer adapter."""

from __future__ import annotations

import hashlib
import html
import importlib
import io
import os
import re
import stat
import tempfile
from collections.abc import Iterable
from contextlib import suppress
from pathlib import Path, PurePosixPath
from string import Template
from typing import Any

from apex_forensic.constants import ENGINE_VERSION, SCHEMA_VERSION
from apex_forensic.domain.errors import ReportError
from apex_forensic.domain.models import ReportRendererCapability, ReportRenderPackage

DEFAULT_DERIVED_OUTPUT_ROOT_ID = "apex-derived-default"
MAX_RENDER_BYTES = 50 * 1024 * 1024
_PRIVATE_FILE_MODE = stat.S_IRUSR | stat.S_IWUSR
_WINDOWS_DRIVE_PREFIX = re.compile(r"^[A-Za-z]:")
_WINDOWS_FORBIDDEN_NAME_CHARS = re.compile(r'[<>:"\\|?*\x00-\x1f]')
_WINDOWS_RESERVED_BASENAMES = {
    "con",
    "prn",
    "aux",
    "nul",
    *(f"com{index}" for index in range(1, 10)),
    *(f"lpt{index}" for index in range(1, 10)),
}
_HTML_TEMPLATE = Template(
    """<!doctype html>
<html lang="$lang">
<head>
  <meta charset="utf-8">
  <title>$title</title>
  <style>
    body { font-family: system-ui, -apple-system, Segoe UI, sans-serif; margin: 32px; }
    header, footer { border-color: #444; border-style: solid; border-width: 0; }
    header { border-bottom-width: 1px; margin-bottom: 24px; padding-bottom: 12px; }
    footer { border-top-width: 1px; color: #555; margin-top: 32px; padding-top: 12px; }
    h1 { font-size: 28px; margin: 0 0 8px; }
    h2 { font-size: 20px; margin-top: 24px; }
    h3 { font-size: 16px; margin-top: 18px; }
    table { border-collapse: collapse; margin: 12px 0; width: 100%; }
    th, td { border: 1px solid #ccc; padding: 6px 8px; text-align: left; vertical-align: top; }
    code, pre { white-space: pre-wrap; word-break: break-word; }
    .warning { border-left: 4px solid #9a6700; padding-left: 10px; }
    .citation { color: #444; font-size: 12px; }
  </style>
</head>
<body>
  <header>
    <h1>$title</h1>
    $summary
    <p>$version_label $version_number · $locale · $timezone</p>
  </header>
  <nav>
    <h2>$contents_label</h2>
    <ol>$toc</ol>
  </nav>
  <main>$sections</main>
  <section>
    <h2>$evidence_label</h2>
    $evidence
  </section>
  <section>
    <h2>$hashes_label</h2>
    $hashes
  </section>
  <section>
    <h2>$custody_label</h2>
    $custody
  </section>
  <section>
    <h2>$limitations_label</h2>
    $limitations
  </section>
  <section>
    <h2>$citations_label</h2>
    $citations
  </section>
  <footer>
    <p>$renderer_label: $renderer_id $renderer_version</p>
    <p>$fingerprint_label: $package_fingerprint</p>
  </footer>
</body>
</html>
"""
)


_REPORT_KO = {
    "Version": "버전",
    "Table of Contents": "목차",
    "Evidence Summary": "증거 요약",
    "Hash Integrity": "해시 무결성",
    "Chain of Custody": "증거 보관 이력",
    "Limitations": "제한 사항",
    "Citations": "인용 근거",
    "Renderer": "렌더러",
    "Package fingerprint": "패키지 지문",
    "Report": "보고서",
    "Section Citations": "섹션 인용 근거",
    "Structured Data": "구조화 데이터",
    "None": "없음",
    "No custody snapshot linked.": "연결된 증거 보관 이력 스냅샷이 없습니다.",
    "Partial or stale report section. Review limitations.": (
        "일부 결과 또는 갱신이 필요한 섹션입니다. 제한 사항을 확인하세요."
    ),
    "Page": "페이지",
}


def _label(value: str, locale: str) -> str:
    return _REPORT_KO.get(value, value) if locale.lower().startswith("ko") else value


class RuntimeReportRenderer:
    """Render approved report packages to local HTML and optional ReportLab PDF files."""

    renderer_id = "apex.report.runtime"
    renderer_version = ENGINE_VERSION

    def __init__(
        self,
        *,
        output_root: Path,
        derived_output_root_id: str = DEFAULT_DERIVED_OUTPUT_ROOT_ID,
    ) -> None:
        self._output_root = output_root
        self._derived_output_root_id = derived_output_root_id

    @property
    def supported_formats(self) -> list[str]:
        formats = ["HTML"]
        if _reportlab_available():
            formats.append("PDF")
        return formats

    def capabilities(self) -> ReportRendererCapability:
        warnings = []
        if not _reportlab_available():
            warnings.append(
                {
                    "code": "PDF_CAPABILITY_UNAVAILABLE",
                    "developer_message": (
                        "ReportLab is not installed; PDF rendering is unavailable."
                    ),
                    "optional_dependency": "report-renderer",
                }
            )
        return ReportRendererCapability(
            renderer_id=self.renderer_id,
            renderer_version=self.renderer_version,
            supported_formats=self.supported_formats,
            is_available=True,
            unavailable_reason=None,
            warnings=warnings,
        )

    def validate_package(self, package: ReportRenderPackage) -> None:
        if not package.sections:
            raise ReportError(
                "REPORT_PACKAGE_INVALID",
                "Report render package has no sections.",
                target="sections",
            )
        if package.report_metadata.get("approval_state", {}).get("decision") != "APPROVED":
            raise ReportError(
                "REPORT_APPROVAL_REQUIRED",
                "Runtime rendering requires an approved report version.",
                target="report_version_id",
            )
        _validate_json_shape(package.report_metadata, target="report_metadata")
        for section in package.sections:
            _validate_json_shape(section, target="sections")

    def render(
        self,
        package: ReportRenderPackage,
        *,
        export_manifest_id: str,
        requested_filename: str,
    ) -> dict[str, Any]:
        del export_manifest_id
        filename = _safe_filename(requested_filename)
        if filename.casefold().endswith(".html"):
            output = _render_html(package)
            mime_type = "text/html"
            warnings: list[dict[str, Any]] = []
        elif filename.casefold().endswith(".pdf"):
            output = _render_pdf(package)
            mime_type = "application/pdf"
            warnings = []
        else:
            raise ReportError(
                "REPORT_OUTPUT_INVALID",
                "Runtime renderer supports only .html and .pdf filenames.",
                target="requested_filename",
            )
        if len(output) > MAX_RENDER_BYTES:
            raise ReportError(
                "REPORT_OUTPUT_LIMIT_EXCEEDED",
                "Rendered report exceeds the maximum output size.",
                target="render_output",
            )
        path = self._write_output(filename, output)
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        return {
            "schema_version": SCHEMA_VERSION,
            "status": "COMPLETED",
            "output_reference": f"derived://{self._derived_output_root_id}/{filename}",
            "filename": filename,
            "mime_type": mime_type,
            "size_bytes": path.stat().st_size,
            "sha256": digest,
            "renderer_id": self.renderer_id,
            "renderer_version": self.renderer_version,
            "warnings": warnings,
        }

    def cancel(self, export_manifest_id: str) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "status": "CANCELLED",
            "warnings": [
                {
                    "code": "REPORT_RENDER_CANCELLED",
                    "developer_message": "Runtime report render was cancelled.",
                    "export_manifest_id": export_manifest_id,
                }
            ],
        }

    def verify_output(self, result: dict[str, Any]) -> None:
        filename = _safe_filename(str(result.get("filename", "")))
        path = self._resolve_output_path(filename)
        if not path.is_file():
            raise ReportError(
                "REPORT_OUTPUT_INVALID",
                "Renderer output file is missing.",
                target="output_reference",
            )
        data = path.read_bytes()
        expected = str(result.get("sha256", "")).lower()
        if hashlib.sha256(data).hexdigest() != expected:
            raise ReportError(
                "REPORT_OUTPUT_INVALID",
                "Renderer output hash does not match the written file.",
                target="sha256",
            )
        if filename.casefold().endswith(".pdf") and not data.startswith(b"%PDF-"):
            raise ReportError("REPORT_OUTPUT_INVALID", "PDF output magic is invalid.")
        if filename.casefold().endswith(".html") and b"<!doctype html>" not in data[:128].lower():
            raise ReportError("REPORT_OUTPUT_INVALID", "HTML output header is invalid.")

    def _write_output(self, filename: str, data: bytes) -> Path:
        root = self._prepare_output_root()
        destination = self._resolve_output_path(filename)
        if destination.exists():
            raise ReportError(
                "REPORT_OUTPUT_COLLISION",
                "Report renderer refuses to overwrite an existing output file.",
                target="filename",
            )
        fd = -1
        fd, temp_name = tempfile.mkstemp(prefix=f".{filename}.", suffix=".tmp", dir=root)
        temp_path = Path(temp_name)
        try:
            _restrict_temp_file_permissions(fd, temp_path)
            with os.fdopen(fd, "wb") as handle:
                fd = -1
                handle.write(data)
            if destination.exists():
                raise ReportError(
                    "REPORT_OUTPUT_COLLISION",
                    "Report renderer refuses to overwrite an existing output file.",
                    target="filename",
                )
            os.replace(temp_path, destination)
        except Exception as error:
            if fd >= 0:
                with suppress(OSError):
                    os.close(fd)
            _cleanup_temp_output(temp_path, original_error=error)
            if isinstance(error, ReportError):
                raise
            raise ReportError(
                "REPORT_OUTPUT_WRITE_FAILED",
                "Failed to write renderer output file.",
                target="render_output",
                details={"error_type": type(error).__name__},
            ) from error
        return destination

    def _prepare_output_root(self) -> Path:
        self._output_root.mkdir(parents=True, exist_ok=True)
        with suppress(OSError):
            self._output_root.chmod(0o700)
        return self._output_root.resolve()

    def _resolve_output_path(self, filename: str) -> Path:
        root = self._prepare_output_root()
        path = (root / filename).resolve()
        if path.parent != root:
            raise ReportError(
                "REPORT_OUTPUT_OUTSIDE_DERIVED_ROOT",
                "Renderer output path escapes the configured output root.",
                target="filename",
            )
        return path


def _restrict_temp_file_permissions(fd: int, temp_path: Path) -> None:
    fchmod = getattr(os, "fchmod", None)
    if fchmod is not None:
        try:
            fchmod(fd, _PRIVATE_FILE_MODE)
        except OSError as error:
            raise ReportError(
                "REPORT_OUTPUT_PERMISSION_FAILED",
                "Failed to restrict renderer temporary output permissions.",
                target="render_output",
                details={"mode": oct(_PRIVATE_FILE_MODE), "platform": os.name},
            ) from error
        return
    if _is_windows_platform():
        # Windows does not expose fd-based chmod. The temporary file is created under the
        # configured derived-output root and inherits that directory's ACL boundary.
        return
    raise ReportError(
        "REPORT_OUTPUT_PERMISSION_UNSUPPORTED",
        "The current platform does not support fd-based renderer output permissions.",
        target="render_output",
        details={"mode": oct(_PRIVATE_FILE_MODE), "platform": os.name, "path": str(temp_path)},
    )


def _is_windows_platform() -> bool:
    return os.name == "nt"


def _cleanup_temp_output(temp_path: Path, *, original_error: Exception) -> None:
    if not temp_path.exists():
        return
    try:
        temp_path.unlink()
    except OSError as cleanup_error:
        raise ReportError(
            "REPORT_OUTPUT_CLEANUP_FAILED",
            "Failed to remove incomplete renderer temporary output.",
            target="render_output",
            details={
                "cleanup_error_type": type(cleanup_error).__name__,
                "original_error_type": type(original_error).__name__,
                "temp_path": str(temp_path),
            },
        ) from original_error


def _render_html(package: ReportRenderPackage) -> bytes:
    metadata = package.report_metadata
    title = _text(metadata.get("title") or _label("Report", package.locale))
    summary = _paragraph(_text(metadata.get("executive_summary") or ""))
    sections = list(package.sections)
    values = {
        "version_label": _label("Version", package.locale),
        "contents_label": _label("Table of Contents", package.locale),
        "evidence_label": _label("Evidence Summary", package.locale),
        "hashes_label": _label("Hash Integrity", package.locale),
        "custody_label": _label("Chain of Custody", package.locale),
        "limitations_label": _label("Limitations", package.locale),
        "citations_label": _label("Citations", package.locale),
        "renderer_label": _label("Renderer", package.locale),
        "fingerprint_label": _label("Package fingerprint", package.locale),
        "lang": html.escape(_text(package.locale).split("-", 1)[0] or "en"),
        "title": html.escape(title),
        "summary": summary,
        "version_number": html.escape(_text(metadata.get("version_number") or "")),
        "locale": html.escape(package.locale),
        "timezone": html.escape(package.timezone),
        "toc": "".join(
            f'<li><a href="#section-{index}">{html.escape(_text(section.get("title")))}</a></li>'
            for index, section in enumerate(sections, start=1)
        ),
        "sections": "\n".join(
            _section_html(index, section, package.locale)
            for index, section in enumerate(sections, 1)
        ),
        "evidence": _table_from_mappings(package.evidence_manifest, package.locale),
        "hashes": _mapping_table(package.hash_integrity_summary, package.locale),
        "custody": _custody_html(package),
        "limitations": _list_html(package.limitations, package.locale),
        "citations": _citation_html(package.citations, package.locale),
        "renderer_id": html.escape(RuntimeReportRenderer.renderer_id),
        "renderer_version": html.escape(RuntimeReportRenderer.renderer_version),
        "package_fingerprint": html.escape(package.package_fingerprint),
    }
    return _HTML_TEMPLATE.safe_substitute(values).encode("utf-8")


def _render_pdf(package: ReportRenderPackage) -> bytes:
    if not _reportlab_available():
        raise ReportError(
            "CAPABILITY_UNAVAILABLE",
            "ReportLab is not installed; PDF rendering is unavailable.",
            target="report_renderer",
            details={"optional_dependency": "report-renderer"},
        )
    platypus = importlib.import_module("reportlab.platypus")
    styles_mod = importlib.import_module("reportlab.lib.styles")
    pagesizes = importlib.import_module("reportlab.lib.pagesizes")
    units = importlib.import_module("reportlab.lib.units")
    pdfmetrics = importlib.import_module("reportlab.pdfbase.pdfmetrics")
    cidfonts = importlib.import_module("reportlab.pdfbase.cidfonts")
    font_name = _register_pdf_font(pdfmetrics, cidfonts)
    buffer = io.BytesIO()
    doc = platypus.SimpleDocTemplate(
        buffer,
        pagesize=pagesizes.A4,
        rightMargin=18 * units.mm,
        leftMargin=18 * units.mm,
        topMargin=18 * units.mm,
        bottomMargin=18 * units.mm,
        title=_text(package.report_metadata.get("title") or "Report"),
    )
    styles = styles_mod.getSampleStyleSheet()
    for name in ("Title", "Heading1", "Heading2", "Normal", "BodyText"):
        if name in styles:
            styles[name].fontName = font_name
    story: list[Any] = [
        platypus.Paragraph(
            html.escape(_text(package.report_metadata.get("title") or "Report")),
            styles["Title"],
        ),
        platypus.Paragraph(
            html.escape(_text(package.report_metadata.get("executive_summary") or "")),
            styles["BodyText"],
        ),
        platypus.Spacer(1, 8),
    ]
    for index, section in enumerate(package.sections, start=1):
        story.append(
            platypus.Paragraph(
                f"{index}. {html.escape(_text(section.get('title')))}",
                styles["Heading1"],
            )
        )
        story.append(
            platypus.Paragraph(html.escape(_text(section.get("content"))), styles["BodyText"])
        )
        story.append(platypus.Spacer(1, 6))
    story.append(platypus.Paragraph(_label("Evidence Summary", package.locale), styles["Heading1"]))
    for evidence in package.evidence_manifest:
        story.append(
            platypus.Paragraph(html.escape(_compact_mapping(evidence)), styles["BodyText"])
        )
    story.append(platypus.Paragraph(_label("Citations", package.locale), styles["Heading1"]))
    for citation in package.citations:
        story.append(
            platypus.Paragraph(html.escape(_compact_mapping(citation)), styles["BodyText"])
        )

    def page_footer(canvas: Any, document: Any) -> None:
        del document
        canvas.saveState()
        canvas.setFont(font_name, 8)
        canvas.drawRightString(
            190 * units.mm,
            10 * units.mm,
            f"{_label('Page', package.locale)} {canvas.getPageNumber()}",
        )
        canvas.restoreState()

    doc.build(story, onFirstPage=page_footer, onLaterPages=page_footer)
    return buffer.getvalue()


def _register_pdf_font(pdfmetrics: Any, cidfonts: Any) -> str:
    requested = os.environ.get("APEX_REPORT_PDF_FONT_NAME", "HYSMyeongJo-Medium")
    try:
        pdfmetrics.registerFont(cidfonts.UnicodeCIDFont(requested))
        return requested
    except Exception:
        return "Helvetica"


def _section_html(index: int, section: dict[str, Any], locale: str = "en") -> str:
    title = html.escape(_text(section.get("title")))
    content = _paragraph(_text(section.get("content")))
    structured = section.get("structured_data")
    citations = _citation_html([dict(item) for item in section.get("citations", [])], locale)
    warning = ""
    if section.get("is_partial") or section.get("stale_reasons"):
        warning = (
            '<p class="warning">'
            + _label("Partial or stale report section. Review limitations.", locale)
            + "</p>"
        )
    extra = _structured_html(structured, locale) if isinstance(structured, dict) else ""
    return (
        f'<section id="section-{index}"><h2>{title}</h2>{warning}'
        f"{content}{extra}<h3>{_label('Section Citations', locale)}</h3>{citations}</section>"
    )


def _paragraph(value: str) -> str:
    escaped = html.escape(value)
    return "<p>" + escaped.replace("\n", "<br>") + "</p>"


def _structured_html(value: dict[str, Any], locale: str = "en") -> str:
    if not value:
        return ""
    return "<h3>" + _label("Structured Data", locale) + "</h3>" + _mapping_table(value, locale)


def _table_from_mappings(rows: Iterable[dict[str, Any]], locale: str = "en") -> str:
    items = list(rows)
    if not items:
        return "<p>" + _label("None", locale) + "</p>"
    keys = sorted({key for row in items for key in row})
    header = "".join(f"<th>{html.escape(key)}</th>" for key in keys)
    body_rows = []
    for row in items:
        cells = "".join(f"<td>{html.escape(_text(row.get(key)))}</td>" for key in keys)
        body_rows.append(f"<tr>{cells}</tr>")
    return f"<table><thead><tr>{header}</tr></thead><tbody>{''.join(body_rows)}</tbody></table>"


def _mapping_table(value: dict[str, Any], locale: str = "en") -> str:
    if not value:
        return "<p>" + _label("None", locale) + "</p>"
    rows = "".join(
        f"<tr><th>{html.escape(str(key))}</th><td>{html.escape(_text(value[key]))}</td></tr>"
        for key in sorted(value)
    )
    return f"<table><tbody>{rows}</tbody></table>"


def _list_html(values: list[str], locale: str = "en") -> str:
    if not values:
        return "<p>" + _label("None", locale) + "</p>"
    return "<ul>" + "".join(f"<li>{html.escape(value)}</li>" for value in values) + "</ul>"


def _citation_html(values: list[dict[str, Any]], locale: str = "en") -> str:
    if not values:
        return "<p>" + _label("None", locale) + "</p>"
    return (
        "<ol>"
        + "".join(
            f'<li class="citation">{html.escape(_compact_mapping(citation))}</li>'
            for citation in values
        )
        + "</ol>"
    )


def _custody_html(package: ReportRenderPackage) -> str:
    if package.custody_snapshot_id is None:
        return "<p>" + _label("No custody snapshot linked.", package.locale) + "</p>"
    return _mapping_table({"custody_snapshot_id": package.custody_snapshot_id})


def _compact_mapping(value: dict[str, Any]) -> str:
    return "; ".join(f"{key}={_text(value[key])}" for key in sorted(value))


def _text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, list):
        return ", ".join(_text(item) for item in value)
    if isinstance(value, dict):
        return _compact_mapping(value)
    return str(value)


def _validate_json_shape(value: Any, *, target: str, depth: int = 0) -> None:
    if depth > 8:
        raise ReportError(
            "REPORT_CONTENT_LIMIT_EXCEEDED",
            "Report render package JSON nesting is too deep.",
            target=target,
        )
    if isinstance(value, dict):
        for key, item in value.items():
            lowered = str(key).casefold()
            if any(marker in lowered for marker in ("raw_body", "api_key", "password", "secret")):
                raise ReportError(
                    "REPORT_PACKAGE_INVALID",
                    "Report render package contains sensitive or raw provider fields.",
                    target=target,
                )
            _validate_json_shape(item, target=target, depth=depth + 1)
    elif isinstance(value, list):
        for item in value:
            _validate_json_shape(item, target=target, depth=depth + 1)


def _safe_filename(filename: str) -> str:
    cleaned = filename.strip()
    pure = PurePosixPath(cleaned.replace("\\", "/"))
    if (
        _WINDOWS_DRIVE_PREFIX.match(cleaned) is not None
        or pure.is_absolute()
        or len(pure.parts) != 1
        or any(part in {"", ".", ".."} for part in pure.parts)
        or cleaned.rstrip(" .") != cleaned
        or _WINDOWS_FORBIDDEN_NAME_CHARS.search(cleaned) is not None
        or cleaned.split(".", 1)[0].casefold() in _WINDOWS_RESERVED_BASENAMES
    ):
        raise ReportError(
            "REPORT_OUTPUT_INVALID",
            "Report output filename is not portable or safe.",
            target="filename",
        )
    return cleaned


def _reportlab_available() -> bool:
    try:
        importlib.import_module("reportlab.platypus")
    except ImportError:
        return False
    return True
