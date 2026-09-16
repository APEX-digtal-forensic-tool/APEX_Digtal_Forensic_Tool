"""Explicit local-operation allowlist wrapping existing application services."""

import json
from pathlib import Path
from typing import Any, Never

from apex_forensic.adapters.report.runtime import RuntimeReportRenderer
from apex_forensic.application.services.image_inspection import ImageInspectionService
from apex_forensic.config import ServiceBundle
from apex_forensic.domain.enums import (
    AiSecretHandling,
    AnalysisProfileType,
    ArtifactType,
    CustodyEventType,
    DataClassification,
    HashAlgorithm,
    SearchQueryMode,
)
from apex_forensic.domain.errors import ApexError, ValidationError
from apex_forensic.domain.models.artifact import ArtifactQuery
from apex_forensic.jobs.cancellation import CancellationToken
from apex_forensic.runtime.capabilities import capability_report

from . import models as m
from .tasks import ProgressCallback, Tasks, encode

MODELS: dict[str, type[m.Input]] = {
    "runtime": m.Empty,
    "cases.list": m.Empty,
    "cases.create": m.CreateCase,
    "evidence.list": m.CaseInput,
    "evidence.register": m.RegisterEvidence,
    "files.list": m.Files,
    "files.roots": m.EvidenceInput,
    "artifacts.list": m.Artifacts,
    "search.query": m.Search,
    "search.history": m.CaseInput,
    "timeline.list": m.PageInput,
    "candidates.list": m.PageInput,
    "candidates.review": m.CandidateReview,
    "view": m.View,
    "raw.read": m.Raw,
    "media.inspect": m.ImageInspect,
    "context.create": m.ContextCreate,
    "context.get": m.ContextGet,
    "context.update": m.ContextUpdate,
    "analysis.start": m.Analysis,
    "tasks.list": m.CaseInput,
    "tasks.cancel": m.TaskAction,
    "custody.list": m.EvidenceInput,
    "custody.add": m.CustodyAdd,
    "custody.verify": m.EvidenceInput,
    "reports.list": m.PageInput,
    "reports.create": m.ReportCreate,
    "reports.get": m.ReportGet,
    "reports.version": m.ReportVersion,
    "reports.action": m.ReportAction,
    "reports.export": m.ReportExport,
    "policy.get": m.CaseInput,
    "policy.save": m.Policy,
    "policy.audit": m.CaseInput,
}
CONTEXT_FIELDS = {
    "current_route",
    "current_panel",
    "active_evidence_id",
    "selected_file_node_ids",
    "selected_artifact_ids",
    "selected_timeline_event_ids",
    "selected_search_result_ids",
    "selected_media_artifact_ids",
    "selected_browser_artifact_ids",
    "selected_candidate_ids",
    "active_filters",
    "active_sort",
    "active_time_range",
    "active_context_scope",
    "active_search_execution_id",
    "ui_preferences",
}


def mismatch() -> Never:
    raise ApexError("CONTEXT_SCOPE_MISMATCH", "error.context_scope_mismatch")


def invoke(
    operation: str,
    p: dict[str, Any],
    s: ServiceBundle,
    *,
    tasks: Tasks,
    actor: str,
    session_id: str,
    exports: Path,
) -> object:
    case_id: str = p.get("case_id", "")
    if case_id:
        s.cases.get_case(case_id)
    if p.get("evidence_id") and s.evidence.get_evidence(p["evidence_id"]).case_id != case_id:
        mismatch()
    if p.get("parent_node_id"):
        parent = s.fs.get_node(p["parent_node_id"])
        if parent.case_id != case_id or parent.evidence_id != p.get("evidence_id"):
            mismatch()
    if p.get("report_id") and s.reports.get_report(p["report_id"]).case_id != case_id:
        mismatch()
    if (
        p.get("report_version_id")
        and s.reports.get_version(p["report_version_id"]).case_id != case_id
    ):
        mismatch()
    if p.get("session_context_id"):
        context = s.contexts.get(p["session_context_id"])
        if context.case_id != case_id or context.session_id != session_id:
            mismatch()
    if operation == "runtime":
        return {
            "capabilities": capability_report(),
            "actor_id": actor,
            "session_id": session_id,
            "mode": "LOCAL_OFFLINE",
            "operations": list(MODELS),
            "ai": s.ai.capabilities(),
            "renderer": RuntimeReportRenderer(output_root=exports).capabilities(),
        }
    if operation == "cases.list":
        return s.cases.list_cases()
    if operation == "cases.create":
        return s.cases.create_case(**p)
    if operation == "evidence.list":
        return s.evidence.list_evidence(case_id)
    if operation == "evidence.register":
        source = Path(p["source_path"]).resolve()
        writable = tasks.database.parent.resolve()
        if source.is_relative_to(writable) or writable.is_relative_to(source):
            raise ValidationError("Evidence must not overlap the application's writable data.")
        s.evidence.reject_archive_image(source)
        return tasks.start(
            case_id,
            "REGISTER",
            lambda b, _t, _cb: b.evidence.register_evidence(
                case_id=case_id, source_path=Path(p["source_path"]), display_name=p["display_name"]
            ),
            cancellable=False,
        )
    if operation == "files.roots":
        return s.fs.get_root_nodes(p["evidence_id"])
    if operation == "files.list":
        return s.fs.list_nodes(**{k: v for k, v in p.items() if k != "case_id"})
    if operation == "artifacts.list":
        if p["artifact_type"]:
            p["artifact_type"] = ArtifactType(p["artifact_type"])
        return s.artifacts.list_artifacts(ArtifactQuery(**p))
    if operation == "search.query":
        mode = SearchQueryMode(p.pop("query_mode"))
        if mode == SearchQueryMode.REGEX_METADATA and len(p["query_text"]) > 512:
            raise ValidationError("Regex maximum is 512 characters.")
        evidence = p.pop("evidence_id")
        return s.search.query(**p, query_mode=mode, evidence_ids=[evidence] if evidence else None)
    if operation == "search.history":
        return s.search.history(case_id=case_id)
    if operation == "timeline.list":
        return s.timeline.list_events(**p)
    if operation == "candidates.list":
        return s.candidates.list_candidates(**p)
    if operation == "candidates.review":
        data = encode(s.candidates.get_candidate(p["candidate_id"]))
        if data.get("candidate", data).get("case_id") != case_id:
            mismatch()
        return s.candidates.review_candidate(
            **{k: v for k, v in p.items() if k != "case_id"}, reviewed_by=actor
        )
    if operation == "view":
        return s.views.project(**p)
    if operation == "raw.read":
        p.pop("view_mode")
        return s.views.raw_read(**p)
    if operation == "media.inspect":
        result = ImageInspectionService(s.repository).inspect(**p)
        if p["action"] == "EXTRACT":
            relative = Path("image-analysis") / (result["result_id"] + ".json")
            destination = exports / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            result["export_relative_path"] = relative.as_posix()
            with destination.open("x", encoding="utf-8") as handle:
                json.dump(result, handle, ensure_ascii=False, indent=2)
        return result
    if operation == "context.create":
        case = s.cases.get_case(case_id)
        return s.contexts.create(
            case_id=case_id,
            actor_id=actor,
            session_id=session_id,
            locale=case.locale,
            timezone=case.timezone,
        )
    if operation == "context.get":
        return s.contexts.get(p["session_context_id"])
    if operation == "context.update":
        if set(p["patch"]) - CONTEXT_FIELDS:
            raise ValidationError("Unsupported context fields.")
        return s.contexts.patch(
            p["session_context_id"], expected_revision=p["expected_revision"], patch=p["patch"]
        )
    if operation == "analysis.start":
        kind = p["kind"]
        args: dict[str, Any] = {
            "case_id": case_id,
            "evidence_id": p["evidence_id"],
            "profile_type": AnalysisProfileType(p["profile_type"]),
        }

        def run(
            b: ServiceBundle,
            token: CancellationToken,
            cb: ProgressCallback,
        ) -> object:
            options: dict[str, Any] = {
                **args,
                "cancellation_token": token,
                "progress_callback": cb,
            }
            if kind == "FILES":
                return b.fs.index_evidence(**options)
            if kind == "ARTIFACTS":
                return b.artifacts.analyze_evidence(**options)
            if kind == "TIMELINE":
                return b.timeline.build(**options)
            if kind == "SEARCH":
                options["evidence_ids"] = [options.pop("evidence_id")]
                return b.search.index(**options)
            if kind == "VERIFY":
                return b.evidence.verify_evidence(
                    evidence_id=p["evidence_id"],
                    algorithm=HashAlgorithm(p["algorithm"]),
                    cancellation_token=token,
                )
            return b.evidence.calculate_hash(
                evidence_id=p["evidence_id"],
                algorithm=HashAlgorithm(p["algorithm"]),
                cancellation_token=token,
            )

        return tasks.start(case_id, kind, run)
    if operation == "tasks.list":
        return tasks.list(case_id)
    if operation == "tasks.cancel":
        return tasks.cancel(case_id, p["task_id"])
    if operation == "custody.list":
        return s.custody.list_events(p["evidence_id"])
    if operation == "custody.verify":
        return {"verified": s.custody.verify_chain(p["evidence_id"])}
    if operation == "custody.add":
        if p["correction_of_event_id"]:
            return s.custody.add_correction(
                evidence_id=p["evidence_id"],
                correction_of_event_id=p["correction_of_event_id"],
                actor_name=actor,
                reason=p["reason"],
                notes=p["action"],
            )
        return s.custody.add_event(
            evidence_id=p["evidence_id"],
            actor_id=actor,
            actor_name=actor,
            event_type=CustodyEventType(p["event_type"]),
            reason=p["reason"],
            action=p["action"],
        )
    if operation == "reports.list":
        p.pop("evidence_id")
        return s.reports.list_reports(**p)
    if operation == "reports.create":
        return s.reports.create_report(**p, created_by=actor)
    if operation == "reports.get":
        versions = s.reports.list_versions(p["report_id"])
        return {
            "report": s.reports.get_report(p["report_id"]),
            "versions": versions,
            "approvals": {
                v.report_version_id: s.reports.get_approval(v.report_version_id) for v in versions
            },
            "reviews": {
                v.report_version_id: s.reports.review_history(v.report_version_id) for v in versions
            },
        }
    if operation == "reports.version":
        p.pop("case_id")
        return s.reports.create_version_from_analyst_draft(**p, created_by=actor)
    if operation == "reports.action":
        args = {
            "report_version_id": p["report_version_id"],
            "reason": p["reason"],
            "actor_id": actor,
            "expected_review_revision": p["expected_review_revision"],
        }
        action = p["action"]
        if action == "submit":
            return s.reports.submit_review(**args)
        if action == "accept_section":
            return s.reports.accept_section(**args, section_id=p["section_id"])
        if action == "request_changes":
            return s.reports.request_changes(
                **args, requested_changes=[p["reason"]], section_id=p["section_id"]
            )
        if action == "complete":
            return s.reports.complete_review(**args)
        if action == "reopen":
            return s.reports.reopen_review(**args)
        args["expected_approval_revision"] = p["expected_approval_revision"]
        if action == "approve":
            args["approver_id"] = args.pop("actor_id")
            snapshot = s.reports.create_custody_snapshot(
                report_version_id=p["report_version_id"], captured_by=actor
            )
            return s.reports.approve(**args, custody_snapshot_id=snapshot.custody_snapshot_id)
        args.pop("expected_review_revision")
        if action == "reject":
            args["approver_id"] = args.pop("actor_id")
            return s.reports.reject(**args)
        return s.reports.revoke_approval(**args)
    if operation == "reports.export":
        p.pop("case_id")
        renderer = RuntimeReportRenderer(output_root=exports / p["report_version_id"])
        manifest = s.reports.prepare_export(**p, created_by=actor, renderer=renderer)
        if manifest.status == "PREPARED":
            s.reports.render_export(
                export_manifest_id=manifest.export_manifest_id, renderer=renderer
            )
        return s.reports.export_status(manifest.export_manifest_id)
    if operation == "policy.get":
        return s.ai_policies.get(case_id)
    if operation == "policy.save":
        p["allowed_classifications"] = tuple(
            DataClassification(v) for v in p["allowed_classifications"]
        )
        p["secret_handling"] = AiSecretHandling(p["secret_handling"])
        return s.ai_policies.configure(**p)
    if operation == "policy.audit":
        return s.repository.list_ai_egress_audits(case_id=case_id)
    raise ValidationError("Unknown operation.")
