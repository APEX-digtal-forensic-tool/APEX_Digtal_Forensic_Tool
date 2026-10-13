"""Tests for A08: cross-case / cross-evidence correction references are rejected."""

from __future__ import annotations

from pathlib import Path

import pytest

from apex_forensic.config import build_services
from apex_forensic.domain.enums import CustodyEventType
from apex_forensic.domain.errors import ValidationError


@pytest.fixture
def two_case_services(tmp_path: Path):
    """Yield a ServiceBundle with two distinct cases and one evidence each."""
    bundle = build_services(tmp_path / "apex.db")
    try:
        case_a = bundle.cases.create_case(name="Case A")
        case_b = bundle.cases.create_case(name="Case B")

        # Use a real directory as evidence source.
        src_a = tmp_path / "evidence_a"
        src_a.mkdir()
        (src_a / "file.txt").write_text("case a evidence")

        src_b = tmp_path / "evidence_b"
        src_b.mkdir()
        (src_b / "file.txt").write_text("case b evidence")

        ev_a = bundle.evidence.register_evidence(
            case_id=case_a.case_id, source_path=src_a, display_name="Ev-A"
        )
        ev_b = bundle.evidence.register_evidence(
            case_id=case_b.case_id, source_path=src_b, display_name="Ev-B"
        )
        yield bundle, case_a.case_id, ev_a.evidence_id, case_b.case_id, ev_b.evidence_id
    finally:
        bundle.close()


# ---------------------------------------------------------------------------
# Correction of same evidence: must succeed
# ---------------------------------------------------------------------------


def test_correction_of_same_evidence_accepted(two_case_services):
    bundle, case_a_id, ev_a_id, _case_b_id, _ev_b_id = two_case_services

    first = bundle.custody.add_event(
        evidence_id=ev_a_id,
        event_type=CustodyEventType.ACQUISITION,
        actor_name="analyst",
        action="Initial intake",
    )

    correction = bundle.custody.add_correction(
        evidence_id=ev_a_id,
        correction_of_event_id=first.event_id,
        actor_name="analyst",
        reason="Correcting typo",
    )

    assert correction.event_id != first.event_id
    assert bundle.custody.verify_chain(ev_a_id) is True


# ---------------------------------------------------------------------------
# A08 core: cross-evidence and cross-case corrections must be rejected
# ---------------------------------------------------------------------------


def test_cross_evidence_correction_rejected(two_case_services):
    """Correction target from a different evidence must raise ValidationError."""
    bundle, _case_a_id, ev_a_id, _case_b_id, ev_b_id = two_case_services

    event_b = bundle.custody.add_event(
        evidence_id=ev_b_id,
        event_type=CustodyEventType.ACQUISITION,
        actor_name="analyst",
        action="Intake for B",
    )

    with pytest.raises(ValidationError, match="different evidence"):
        bundle.custody.add_correction(
            evidence_id=ev_a_id,  # different evidence!
            correction_of_event_id=event_b.event_id,
            actor_name="analyst",
            reason="This should fail",
        )


def test_correction_target_nonexistent_rejected(two_case_services):
    bundle, _case_a_id, ev_a_id, _case_b_id, _ev_b_id = two_case_services

    from apex_forensic.domain.errors import NotFoundError

    with pytest.raises(NotFoundError):
        bundle.custody.add_correction(
            evidence_id=ev_a_id,
            correction_of_event_id="ghost-event-id",
            actor_name="analyst",
            reason="Should fail — no such event",
        )


# ---------------------------------------------------------------------------
# find_semantic_violations: detects (pre-fix) cross-case references
# ---------------------------------------------------------------------------


def test_find_semantic_violations_clean_chain(two_case_services):
    """Clean chain reports no violations."""
    bundle, _case_a_id, ev_a_id, _case_b_id, _ev_b_id = two_case_services

    first = bundle.custody.add_event(
        evidence_id=ev_a_id,
        event_type=CustodyEventType.ACQUISITION,
        actor_name="analyst",
        action="clean intake",
    )
    bundle.custody.add_correction(
        evidence_id=ev_a_id,
        correction_of_event_id=first.event_id,
        actor_name="analyst",
        reason="valid correction",
    )

    violations = bundle.custody.find_semantic_violations(ev_a_id)
    assert violations == []


def test_find_semantic_violations_detects_cross_evidence(two_case_services):
    """Artificially insert a cross-evidence correction and verify detection."""
    bundle, _case_a_id, ev_a_id, _case_b_id, ev_b_id = two_case_services

    # Add a legitimate event to evidence B.
    event_b = bundle.custody.add_event(
        evidence_id=ev_b_id,
        event_type=CustodyEventType.ACQUISITION,
        actor_name="analyst",
        action="Intake B",
    )

    # Bypass the guard by injecting directly via the repository.
    from apex_forensic.domain.models import CustodyEvent
    from apex_forensic._time import to_json_timestamp
    from apex_forensic.constants import CUSTODY_LEDGER_VERSION, ENGINE_VERSION, SCHEMA_VERSION
    from apex_forensic.domain.enums import CustodyEventType as CET
    from apex_forensic.domain.services.canonical import canonical_sha256
    import uuid
    from datetime import datetime, timezone, timedelta

    existing = bundle.custody.list_events(ev_a_id)
    prev_hash = existing[-1].event_hash if existing else None
    revision = (existing[-1].immutable_revision + 1) if existing else 1
    now = datetime.now(timezone.utc)
    event_data = {
        "schema_version": SCHEMA_VERSION,
        "event_id": str(uuid.uuid4()),
        "case_id": _case_a_id,
        "evidence_id": ev_a_id,
        "event_type": CET.CORRECTION.value,
        "actor_id": None,
        "actor_name": "analyst",
        "actor_role": None,
        "organization": None,
        "source_location": None,
        "destination_location": None,
        "action": "Correction event appended",
        "reason": "injected",
        "occurred_at_utc": to_json_timestamp(now),
        "displayed_at": now.isoformat(timespec="microseconds"),
        "timezone": "UTC",
        "tool_name": "APEX Forensic Core",
        "tool_version": ENGINE_VERSION,
        "previous_hash": None,
        "current_hash": None,
        "notes": None,
        "created_at": to_json_timestamp(now),
        "immutable_revision": revision,
        "previous_event_hash": prev_hash,
        "event_hash": "",
        "ledger_algorithm": "SHA256",
        "ledger_version": CUSTODY_LEDGER_VERSION,
        "approval": None,
        "correction_of_event_id": event_b.event_id,  # cross-evidence reference
    }
    event_data["event_hash"] = canonical_sha256(event_data, exclude_keys={"event_hash"})
    bad_event = CustodyEvent(event_data)
    bundle.custody._custody_repository.save_custody_event(bad_event)

    violations = bundle.custody.find_semantic_violations(ev_a_id)
    assert any(v["violation"] == "correction_target_wrong_evidence" for v in violations)
    # verify_chain still returns True (hash math is intact, semantics are wrong)
    assert bundle.custody.verify_chain(ev_a_id) is True
