"""Machine-extracted candidate review service for Phase 5."""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from apex_forensic.domain.errors import NotFoundError, ValidationError
from apex_forensic.domain.models import (
    CandidateReviewEvent,
    CursorPage,
    MachineExtractedCandidate,
    ProviderCapability,
)
from apex_forensic.ports.case_repository import CaseRepository
from apex_forensic.ports.clock import Clock
from apex_forensic.ports.id_generator import IdGenerator
from apex_forensic.ports.machine_extraction import MachineExtractionRepository
from apex_forensic.ports.ocr_provider import OcrProviderPort
from apex_forensic.ports.stt_provider import SttProviderPort

_REVIEW_STATUSES = {"UNREVIEWED", "ACCEPTED", "REJECTED", "CORRECTED"}
_FINAL_REVIEW_STATUSES = {"ACCEPTED", "REJECTED", "CORRECTED"}


@dataclass(frozen=True, slots=True)
class CandidatePage:
    """Stable cursor page of machine-extracted candidates."""

    items: list[MachineExtractedCandidate]
    page: CursorPage

    def to_schema_dict(self) -> dict[str, Any]:
        return {
            "items": [item.to_schema_dict() for item in self.items],
            "page": self.page.to_schema_dict(),
        }


class MachineExtractionService:
    """Runs OCR/STT providers and stores machine-extracted review candidates."""

    def __init__(
        self,
        *,
        case_repository: CaseRepository,
        repository: MachineExtractionRepository,
        clock: Clock,
        id_generator: IdGenerator,
    ) -> None:
        self._case_repository = case_repository
        self._repository = repository
        self._clock = clock
        self._id_generator = id_generator
        self._ensure_default_capabilities()

    def capabilities(self, *, capability_type: str | None = None) -> list[ProviderCapability]:
        """Return OCR/STT provider capabilities; defaults are unavailable contracts."""

        return self._repository.list_provider_capabilities(capability_type=capability_type)

    def analyze_image_file(
        self,
        *,
        case_id: str,
        evidence_id: str,
        source_node_id: str,
        path: str,
        provider: OcrProviderPort,
        languages: list[str] | None = None,
        source_revision: int = 0,
    ) -> list[MachineExtractedCandidate]:
        """Run an OCR provider and persist machine-extracted candidates."""

        self._require_case(case_id)
        capability = provider.capabilities()
        self._repository.save_provider_capability(capability)
        rows = provider.analyze_image(Path(path), languages=languages or ["eng"])
        return self._save_runtime_candidates(
            case_id=case_id,
            evidence_id=evidence_id,
            source_node_id=source_node_id,
            source_type="IMAGE_FILE",
            extraction_type="OCR",
            provider_id=provider.provider_id,
            provider_version=provider.provider_version,
            rows=rows,
            source_revision=source_revision,
            source_path=path,
        )

    def analyze_audio_file(
        self,
        *,
        case_id: str,
        evidence_id: str,
        source_node_id: str,
        path: str,
        provider: SttProviderPort,
        language: str | None = None,
        source_revision: int = 0,
    ) -> list[MachineExtractedCandidate]:
        """Run an STT provider and persist machine-extracted candidates."""

        self._require_case(case_id)
        capability = provider.capabilities()
        self._repository.save_provider_capability(capability)
        rows = provider.analyze_audio(Path(path), language=language)
        return self._save_runtime_candidates(
            case_id=case_id,
            evidence_id=evidence_id,
            source_node_id=source_node_id,
            source_type="AUDIO_FILE",
            extraction_type="STT",
            provider_id=provider.provider_id,
            provider_version=provider.provider_version,
            rows=rows,
            source_revision=source_revision,
            source_path=path,
        )

    def list_candidates(
        self,
        *,
        case_id: str,
        evidence_id: str | None = None,
        review_status: str | None = None,
        cursor: str | None = None,
        limit: int = 100,
    ) -> CandidatePage:
        """List candidates with stable cursor pagination."""

        self._require_case(case_id)
        if limit < 1 or limit > 1000:
            raise ValidationError("limit must be between 1 and 1000.", target="limit")
        status = None if review_status is None else _parse_review_status(review_status)
        after_id = _decode_candidate_cursor(cursor)
        rows = self._repository.list_machine_candidates(
            case_id=case_id,
            evidence_id=evidence_id,
            review_status=status,
            after_candidate_id=after_id,
            limit=limit + 1,
        )
        has_more = len(rows) > limit
        items = rows[:limit]
        next_cursor = (
            _encode_candidate_cursor(items[-1].candidate_id) if has_more and items else None
        )
        return CandidatePage(
            items=items,
            page=CursorPage(next_cursor=next_cursor, has_more=has_more, returned=len(items)),
        )

    def get_candidate(self, candidate_id: str) -> dict[str, Any]:
        """Return one candidate with append-only review history."""

        candidate = self._repository.get_machine_candidate(candidate_id)
        if candidate is None:
            raise NotFoundError(
                "CANDIDATE_NOT_FOUND", "Candidate not found.", target="candidate_id"
            )
        return {
            "candidate": candidate.to_schema_dict(),
            "review_events": [
                item.to_schema_dict()
                for item in self._repository.list_candidate_reviews(candidate_id)
            ],
        }

    def review_candidate(
        self,
        *,
        candidate_id: str,
        review_status: str,
        reviewed_by: str,
        correction_text: str | None = None,
        reason: str | None = None,
    ) -> MachineExtractedCandidate:
        """Append a review decision without overwriting extracted text."""

        status = _parse_final_review_status(review_status)
        reviewed_by = reviewed_by.strip()
        if not reviewed_by:
            raise ValidationError("reviewed_by is required.", target="reviewed_by")
        if status == "CORRECTED" and not (correction_text and correction_text.strip()):
            raise ValidationError(
                "correction_text is required when review_status is CORRECTED.",
                target="correction_text",
            )
        if status != "CORRECTED" and correction_text is not None:
            correction_text = correction_text.strip() or None
        candidate = self._repository.get_machine_candidate(candidate_id)
        if candidate is None:
            raise NotFoundError(
                "CANDIDATE_NOT_FOUND", "Candidate not found.", target="candidate_id"
            )
        event = CandidateReviewEvent(
            review_event_id=self._id_generator.new_id(),
            candidate_id=candidate_id,
            case_id=candidate.case_id,
            review_status=status,
            reviewed_by=reviewed_by,
            reviewed_at=self._clock.now(),
            correction_text=correction_text.strip() if correction_text is not None else None,
            previous_review_status=candidate.review_status,
            reason=reason,
        )
        return self._repository.append_candidate_review(
            event, correction_text=event.correction_text
        )

    def _require_case(self, case_id: str) -> None:
        if self._case_repository.get_case(case_id) is None:
            raise NotFoundError("CASE_NOT_FOUND", "Case not found.", target="case_id")

    def _ensure_default_capabilities(self) -> None:
        now = self._clock.now()
        for capability_type in ("OCR", "STT"):
            self._repository.save_provider_capability(
                ProviderCapability(
                    provider_id="apex.machine-extraction.unavailable",
                    provider_version="1.0.0",
                    capability_type=capability_type,
                    is_available=False,
                    supported_inputs=[],
                    supported_outputs=["MACHINE_EXTRACTED_CANDIDATE"],
                    unavailable_reason=(
                        f"{capability_type} execution is outside the Phase 5 core engine MVP."
                    ),
                    warnings=[
                        {
                            "code": f"{capability_type}_CAPABILITY_UNAVAILABLE",
                            "message_key": "warning.machine_extraction.capability_unavailable",
                            "developer_message": (
                                "The provider port is present, but no OCR/STT engine is executed."
                            ),
                        }
                    ],
                    metadata={"candidate_is_observed_fact": False},
                    updated_at=now,
                )
            )

    def _save_runtime_candidates(
        self,
        *,
        case_id: str,
        evidence_id: str,
        source_node_id: str,
        source_type: str,
        extraction_type: str,
        provider_id: str,
        provider_version: str,
        rows: list[dict[str, Any]],
        source_revision: int,
        source_path: str,
    ) -> list[MachineExtractedCandidate]:
        now = self._clock.now()
        candidates: list[MachineExtractedCandidate] = []
        for index, row in enumerate(rows):
            text = str(row.get("text") or "").strip()
            if not text:
                continue
            candidate = MachineExtractedCandidate(
                candidate_id=self._id_generator.new_id(),
                case_id=case_id,
                evidence_id=evidence_id,
                source_node_id=source_node_id,
                source_type=source_type,
                extraction_type=extraction_type,
                text=text,
                language=None if row.get("language") is None else str(row.get("language")),
                confidence=float(row.get("confidence", 0.0)),
                provider_id=provider_id,
                provider_version=provider_version,
                model_id=None if row.get("model_id") is None else str(row.get("model_id")),
                region=dict(row["region"]) if isinstance(row.get("region"), dict) else None,
                frame_number=None,
                media_timestamp_ms=None,
                audio_start_ms=_optional_int(row.get("audio_start_ms")),
                audio_end_ms=_optional_int(row.get("audio_end_ms")),
                raw_locator={
                    "source_path": source_path,
                    "source_node_id": source_node_id,
                    "candidate_index": index,
                    "locator_type": extraction_type,
                    **(
                        {"source_sha256": str(row["source_sha256"])}
                        if row.get("source_sha256") is not None
                        else {}
                    ),
                },
                citations=[],
                review_status="UNREVIEWED",
                reviewed_by=None,
                reviewed_at=None,
                correction_text=None,
                source_revision=source_revision,
                is_partial=bool(row.get("is_partial", False)),
                created_at=now,
            )
            self._repository.save_machine_candidate(candidate)
            candidates.append(candidate)
        return candidates


def _parse_review_status(value: str) -> str:
    normalized = value.replace("-", "_").replace(".", "_").upper()
    if normalized not in _REVIEW_STATUSES:
        raise ValidationError("Unsupported review status.", target="review_status")
    return normalized


def _parse_final_review_status(value: str) -> str:
    normalized = _parse_review_status(value)
    if normalized not in _FINAL_REVIEW_STATUSES:
        raise ValidationError(
            "Review status must be ACCEPTED, REJECTED, or CORRECTED.", target="review_status"
        )
    return normalized


def _encode_candidate_cursor(candidate_id: str) -> str:
    raw = json.dumps({"candidate_id": candidate_id}, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _decode_candidate_cursor(cursor: str | None) -> str | None:
    if cursor is None:
        return None
    try:
        padded = cursor + "=" * (-len(cursor) % 4)
        data = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8"))
        candidate_id = data["candidate_id"]
        if not isinstance(candidate_id, str) or not candidate_id:
            raise ValueError("candidate_id missing")
        return candidate_id
    except (ValueError, KeyError, TypeError, json.JSONDecodeError) as error:
        raise ValidationError("Invalid candidate cursor.", target="cursor") from error


def _optional_int(value: Any) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
