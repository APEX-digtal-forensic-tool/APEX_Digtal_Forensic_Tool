"""CLI command handlers."""

from __future__ import annotations

import base64
import binascii
import json
import os
import sys
from argparse import Namespace
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from apex_forensic.adapters.ai import OpenAICompatibleConfig, OpenAICompatibleProvider
from apex_forensic.adapters.decryption import (
    DpapiExternalKeyProvider,
    DpapiOfflineProvider,
    DpapiUnavailableProvider,
    KakaoTalkEncryptedStoreProvider,
    NssLibProvider,
    NssUnavailableProvider,
)
from apex_forensic.adapters.machine_extraction import (
    FasterWhisperSttProvider,
    RapidOcrProvider,
    TesseractCliOcrProvider,
    WhisperCppCliSttProvider,
)
from apex_forensic.adapters.report import RuntimeReportRenderer
from apex_forensic.config import build_services
from apex_forensic.domain.enums import (
    AnalysisContextPurpose,
    AnalysisProfileType,
    AnalysisScopeType,
    ArtifactParseStatus,
    ArtifactType,
    CaseStatus,
    CustodyEventType,
    HashAlgorithm,
    KeywordMatchMode,
    KeywordSetStatus,
    KeywordType,
    ResourceType,
    SearchDocumentType,
    SearchQueryMode,
    SearchSourceType,
    TimelineEventType,
    TimelineSourceType,
    TimezoneConfidence,
)
from apex_forensic.domain.errors import ApexError, ValidationError
from apex_forensic.domain.models import (
    AiProviderCapability,
    ArtifactQuery,
    DecryptionResult,
    SecretDerivationInput,
    SecretMaterial,
    SecretProviderCapability,
    SecretReference,
)

from .parser import build_parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the ``apex-forensic`` command line interface."""

    parser = build_parser()
    args = parser.parse_args(argv)
    db_path = args.db if getattr(args, "db", None) is not None else Path("./apex.db")
    if args.command == "init" and getattr(args, "init_db", None) is not None:
        db_path = args.init_db
    try:
        services = build_services(db_path)
        try:
            result = _dispatch(args, services)
        finally:
            services.close()
        _emit(args, result)
        return 0
    except ApexError as error:
        if _json_requested(args):
            print(json.dumps({"errors": [error.to_api_error()]}, ensure_ascii=False, indent=2))
        else:
            print(f"{error.code}: {error.developer_message}", file=sys.stderr)
        return 2 if error.code == "VALIDATION_ERROR" else 1


def _dispatch(args: Namespace, services: Any) -> Any:
    if args.command == "init":
        return {"database": str(args.init_db or services.repository.db_path), "initialized": True}
    if args.command == "case":
        return _case(args, services)
    if args.command == "evidence":
        return _evidence(args, services)
    if args.command == "custody":
        return _custody(args, services)
    if args.command == "fs":
        return _fs(args, services)
    if args.command == "artifact":
        return _artifact(args, services)
    if args.command == "browser":
        return _browser(args, services)
    if args.command == "media":
        return _media(args, services)
    if args.command == "machine":
        return _machine(args, services)
    if args.command == "secret":
        return _secret(args, services)
    if args.command == "candidate":
        return _candidate(args, services)
    if args.command == "ai":
        return _ai(args, services)
    if args.command == "search":
        return _search(args, services)
    if args.command == "keyword-set":
        return _keyword_set(args, services)
    if args.command == "timeline":
        return _timeline(args, services)
    if args.command == "context":
        return _context(args, services)
    if args.command == "view":
        return _view(args, services)
    if args.command == "report":
        return _report(args, services)
    if args.command == "interface":
        return _interface(args, services)
    raise ValidationError("Unknown command.", target="command")


def _case(args: Namespace, services: Any) -> Any:
    if args.case_command == "create":
        case = services.cases.create_case(
            name=args.name,
            investigator=args.investigator,
            description=args.description,
            locale=args.locale,
            timezone=args.timezone,
        )
        return case.to_schema_dict()
    if args.case_command == "list":
        return [case.to_schema_dict() for case in services.cases.list_cases()]
    if args.case_command == "show":
        return services.cases.get_case(args.case_id).to_schema_dict()
    if args.case_command == "set-status":
        return services.cases.change_status(
            args.case_id,
            CaseStatus(args.status),
        ).to_schema_dict()
    raise ValidationError("Unknown case command.", target="case_command")


def _evidence(args: Namespace, services: Any) -> Any:
    if args.evidence_command == "add":
        evidence = services.evidence.register_evidence(
            case_id=args.case_id,
            source_path=args.path,
            display_name=args.display_name,
        )
        return evidence.to_schema_dict()
    if args.evidence_command == "list":
        return [item.to_schema_dict() for item in services.evidence.list_evidence(args.case_id)]
    if args.evidence_command == "show":
        return services.evidence.get_evidence(args.evidence_id).to_schema_dict()
    if args.evidence_command == "hash":
        record, job = services.evidence.calculate_hash(
            evidence_id=args.evidence_id,
            algorithm=_parse_algorithm(args.algorithm),
            chunk_size=args.chunk_size,
        )
        return {"hash": _hash_record_output(record), "job": job.to_schema_dict()}
    if args.evidence_command == "verify":
        verification, job = services.evidence.verify_evidence(
            evidence_id=args.evidence_id,
            algorithm=_parse_algorithm(args.algorithm),
            chunk_size=args.chunk_size,
        )
        return {"verification": verification.to_schema_dict(), "job": job.to_schema_dict()}
    if args.evidence_command == "volumes":
        return [item.to_schema_dict() for item in services.images.list_volumes(args.evidence_id)]
    if args.evidence_command == "read-range":
        return services.images.read_range(
            evidence_id=args.evidence_id,
            offset=args.offset,
            length=args.length,
        )
    if args.evidence_command == "unallocated-ranges":
        return services.images.list_unallocated_ranges(args.evidence_id)
    if args.evidence_command == "export-range":
        return services.images.export_range(
            evidence_id=args.evidence_id,
            offset=args.offset,
            length=args.length,
            output_root=args.output_root,
            filename=args.filename,
            overwrite=args.overwrite,
        )
    if args.evidence_command == "index":
        job, coverage = services.fs.index_evidence(
            case_id=args.case_id,
            evidence_id=args.evidence_id,
            profile_type=AnalysisProfileType(args.profile),
            max_depth=args.max_depth,
            item_budget=args.item_budget,
            batch_size=args.batch_size,
            selected_paths=args.selected_path,
            selected_node_ids=args.selected_node_id,
            include_patterns=args.include,
            exclude_patterns=args.exclude,
            max_queue_size=args.max_queue_size,
        )
        return {"job": job.to_schema_dict(), "coverage": coverage.to_schema_dict()}
    if args.evidence_command == "index-status":
        return services.fs.index_status(args.job_id)
    if args.evidence_command == "index-resume":
        job, coverage = services.fs.resume_index_job(args.job_id, item_budget=args.item_budget)
        return {"job": job.to_schema_dict(), "coverage": coverage.to_schema_dict()}
    if args.evidence_command == "index-cancel":
        return services.fs.cancel_index_job(args.job_id).to_schema_dict()
    raise ValidationError("Unknown evidence command.", target="evidence_command")


def _fs(args: Namespace, services: Any) -> Any:
    if args.fs_command == "roots":
        return [node.to_schema_dict() for node in services.fs.get_root_nodes(args.evidence_id)]
    if args.fs_command == "list":
        page = services.fs.list_nodes(
            evidence_id=args.evidence_id,
            parent_node_id=args.parent_node_id,
            all_nodes=args.all_nodes,
            directories_only=args.directories_only,
            files_only=args.files_only,
            extension=args.extension,
            name_or_path=args.filter,
            cursor=args.cursor,
            limit=args.limit,
        )
        return page.to_schema_dict()
    if args.fs_command == "show":
        return services.fs.get_node(args.node_id).to_schema_dict()
    if args.fs_command == "prioritize":
        return services.fs.prioritize_node(
            args.job_id,
            args.node_id,
            priority=args.priority,
        ).to_schema_dict()
    if args.fs_command == "recover-deleted":
        return services.images.recover_deleted_file(
            node_id=args.node_id,
            output_root=args.output_root,
            filename=args.filename,
            overwrite=args.overwrite,
        )
    if args.fs_command == "export-slack":
        return services.images.export_file_slack(
            node_id=args.node_id,
            output_root=args.output_root,
            filename=args.filename,
            overwrite=args.overwrite,
        )
    raise ValidationError("Unknown filesystem command.", target="fs_command")


def _artifact(args: Namespace, services: Any) -> Any:
    if args.artifact_command == "discover":
        return services.artifacts.discover_sources(
            case_id=args.case_id,
            evidence_id=args.evidence_id,
            profile_type=AnalysisProfileType(args.profile),
            analyzers=args.analyzer,
            artifact_types=_parse_artifact_types(args.artifact_type),
            selected_paths=args.selected_path,
            selected_node_ids=args.selected_node_id,
            include_patterns=args.include,
            exclude_patterns=args.exclude,
            batch_size=args.batch_size,
        )
    if args.artifact_command == "analyze":
        job, coverage = services.artifacts.analyze_evidence(
            case_id=args.case_id,
            evidence_id=args.evidence_id,
            profile_type=AnalysisProfileType(args.profile),
            item_budget=args.item_budget,
            batch_size=args.batch_size,
            analyzers=args.analyzer,
            artifact_types=_parse_artifact_types(args.artifact_type),
            selected_paths=args.selected_path,
            selected_node_ids=args.selected_node_id,
            include_patterns=args.include,
            exclude_patterns=args.exclude,
        )
        return {"job": job.to_schema_dict(), "coverage": coverage.to_schema_dict()}
    if args.artifact_command == "status":
        return services.artifacts.artifact_status(args.job_id)
    if args.artifact_command == "resume":
        job, coverage = services.artifacts.resume_artifact_job(
            args.job_id,
            item_budget=args.item_budget,
        )
        return {"job": job.to_schema_dict(), "coverage": coverage.to_schema_dict()}
    if args.artifact_command == "cancel":
        return services.artifacts.cancel_artifact_job(args.job_id).to_schema_dict()
    if args.artifact_command == "list":
        return services.artifacts.list_artifacts(_artifact_query(args)).to_schema_dict()
    if args.artifact_command == "show":
        return services.artifacts.get_artifact(args.artifact_id).to_schema_dict()
    if args.artifact_command == "warnings":
        return services.artifacts.list_warnings(
            job_id=args.job_id,
            artifact_id=args.artifact_id,
            evidence_id=args.evidence_id,
        )
    if args.artifact_command == "registry":
        if args.registry_command == "carve-deleted":
            query = _artifact_query(args)
            query = ArtifactQuery(
                case_id=query.case_id,
                evidence_id=query.evidence_id,
                source_file_node_id=query.source_file_node_id,
                analyzer_id=query.analyzer_id or "windows.registry",
                parse_status=query.parse_status,
                has_warnings=query.has_warnings,
                limit=query.limit,
                cursor=query.cursor,
            )
            page = services.artifacts.list_artifacts(query)
            items = [
                item.to_schema_dict()
                for item in page.items
                if item.artifact_subtype.startswith("REGISTRY_BINARY_DELETED_")
            ]
            return {
                "items": items,
                "page": {
                    "next_cursor": page.next_cursor,
                    "has_more": page.has_more,
                    "returned": len(items),
                },
            }
        query = _artifact_query(args)
        type_by_command = {
            "autoruns": ArtifactType.REGISTRY_AUTORUN,
            "usb": ArtifactType.REGISTRY_USB_DEVICE,
            "timezone": ArtifactType.REGISTRY_TIMEZONE,
            "userassist": ArtifactType.REGISTRY_USERASSIST,
        }
        query = _replace_query_artifact_type(query, type_by_command[args.registry_command])
        return services.artifacts.list_artifacts(query).to_schema_dict()
    if args.artifact_command == "eventlog":
        if args.eventlog_command == "show":
            return services.artifacts.get_artifact(args.artifact_id).to_schema_dict()
        query = _replace_query_artifact_type(
            _artifact_query(args),
            ArtifactType.EVENT_LOG_RECORD,
        )
        return services.artifacts.list_artifacts(query).to_schema_dict()
    if args.artifact_command == "prefetch":
        if args.prefetch_command == "show":
            return services.artifacts.get_artifact(args.artifact_id).to_schema_dict()
        query = _replace_query_artifact_type(
            _artifact_query(args),
            ArtifactType.PREFETCH_EXECUTION,
        )
        return services.artifacts.list_artifacts(query).to_schema_dict()
    if args.artifact_command == "media":
        if args.media_command == "show":
            return services.artifacts.get_artifact(args.artifact_id).to_schema_dict()
        query = _artifact_query(args)
        if query.media_kind == "VIDEO":
            query = _replace_query_artifact_type(query, ArtifactType.MEDIA_VIDEO)
        elif query.media_kind == "AUDIO":
            query = _replace_query_artifact_type(query, ArtifactType.MEDIA_AUDIO)
        elif query.media_kind == "IMAGE":
            query = _replace_query_artifact_type(query, ArtifactType.MEDIA_IMAGE)
        return services.artifacts.list_artifacts(query).to_schema_dict()
    if args.artifact_command == "browser":
        if args.browser_command == "show":
            return services.artifacts.get_artifact(args.artifact_id).to_schema_dict()
        type_by_command = {
            "profiles": ArtifactType.BROWSER_PROFILE,
            "visits": ArtifactType.BROWSER_VISIT,
            "searches": ArtifactType.BROWSER_SEARCH,
            "downloads": ArtifactType.BROWSER_DOWNLOAD,
            "cookies": ArtifactType.BROWSER_COOKIE,
            "credentials": ArtifactType.BROWSER_CREDENTIAL,
            "cache": ArtifactType.BROWSER_CACHE_ENTRY,
            "deleted": ArtifactType.BROWSER_DELETED_SQLITE_ROW,
            "private-mode": ArtifactType.BROWSER_PRIVATE_MODE_CANDIDATE,
        }
        query = _replace_query_artifact_type(
            _artifact_query(args),
            type_by_command[args.browser_command],
        )
        return services.artifacts.list_artifacts(query).to_schema_dict()
    if args.artifact_command == "communication":
        type_by_command = {
            "messages": ArtifactType.COMMUNICATION_MESSAGE,
            "attachments": ArtifactType.COMMUNICATION_ATTACHMENT,
            "unsupported": ArtifactType.COMMUNICATION_UNSUPPORTED_STORE,
            "kakaotalk": ArtifactType.COMMUNICATION_UNSUPPORTED_STORE,
        }
        query = _replace_query_artifact_type(
            _artifact_query(args),
            type_by_command[args.communication_command],
        )
        page = services.artifacts.list_artifacts(query)
        if args.communication_command != "kakaotalk":
            return page.to_schema_dict()
        items = [
            item.to_schema_dict()
            for item in page.items
            if item.fields.get("communication_app") == "KAKAOTALK"
        ]
        return {
            "items": items,
            "page": {
                "next_cursor": page.next_cursor,
                "has_more": page.has_more,
                "returned": len(items),
            },
        }
    raise ValidationError("Unknown artifact command.", target="artifact_command")


def _browser(args: Namespace, services: Any) -> Any:
    if args.browser_command == "discover":
        return services.artifacts.discover_sources(
            case_id=args.case_id,
            evidence_id=args.evidence_id,
            profile_type=AnalysisProfileType(args.profile),
            analyzers=_default_analyzers(args.analyzer, "browser.history"),
            artifact_types=_parse_artifact_types(args.artifact_type),
            selected_paths=args.selected_path,
            selected_node_ids=args.selected_node_id,
            include_patterns=args.include,
            exclude_patterns=args.exclude,
            batch_size=args.batch_size,
        )
    if args.browser_command == "analyze":
        job, coverage = services.artifacts.analyze_evidence(
            case_id=args.case_id,
            evidence_id=args.evidence_id,
            profile_type=AnalysisProfileType(args.profile),
            item_budget=args.item_budget,
            batch_size=args.batch_size,
            analyzers=_default_analyzers(args.analyzer, "browser.history"),
            artifact_types=_parse_artifact_types(args.artifact_type),
            selected_paths=args.selected_path,
            selected_node_ids=args.selected_node_id,
            include_patterns=args.include,
            exclude_patterns=args.exclude,
        )
        return {"job": job.to_schema_dict(), "coverage": coverage.to_schema_dict()}
    if args.browser_command == "status":
        return services.artifacts.artifact_status(args.job_id)
    if args.browser_command == "resume":
        job, coverage = services.artifacts.resume_artifact_job(
            args.job_id, item_budget=args.item_budget
        )
        return {"job": job.to_schema_dict(), "coverage": coverage.to_schema_dict()}
    if args.browser_command == "cancel":
        return services.artifacts.cancel_artifact_job(args.job_id).to_schema_dict()
    if args.browser_command == "show":
        return services.artifacts.get_artifact(args.artifact_id).to_schema_dict()
    if args.browser_command == "warnings":
        return services.artifacts.list_warnings(
            job_id=args.job_id,
            artifact_id=args.artifact_id,
            evidence_id=args.evidence_id,
        )
    type_by_command = {
        "profiles": ArtifactType.BROWSER_PROFILE,
        "history": ArtifactType.BROWSER_VISIT,
        "searches": ArtifactType.BROWSER_SEARCH,
        "downloads": ArtifactType.BROWSER_DOWNLOAD,
        "cookies": ArtifactType.BROWSER_COOKIE,
        "credentials": ArtifactType.BROWSER_CREDENTIAL,
        "cache": ArtifactType.BROWSER_CACHE_ENTRY,
        "deleted": ArtifactType.BROWSER_DELETED_SQLITE_ROW,
        "private-mode": ArtifactType.BROWSER_PRIVATE_MODE_CANDIDATE,
    }
    if args.browser_command in type_by_command:
        query = _replace_query_artifact_type(
            _artifact_query(args), type_by_command[args.browser_command]
        )
        return services.artifacts.list_artifacts(query).to_schema_dict()
    raise ValidationError("Unknown browser command.", target="browser_command")


def _media(args: Namespace, services: Any) -> Any:
    if args.media_command == "discover":
        return services.artifacts.discover_sources(
            case_id=args.case_id,
            evidence_id=args.evidence_id,
            profile_type=AnalysisProfileType(args.profile),
            analyzers=_default_analyzers(args.analyzer, "media.metadata"),
            artifact_types=_parse_artifact_types(args.artifact_type),
            selected_paths=args.selected_path,
            selected_node_ids=args.selected_node_id,
            include_patterns=args.include,
            exclude_patterns=args.exclude,
            batch_size=args.batch_size,
        )
    if args.media_command == "analyze":
        job, coverage = services.artifacts.analyze_evidence(
            case_id=args.case_id,
            evidence_id=args.evidence_id,
            profile_type=AnalysisProfileType(args.profile),
            item_budget=args.item_budget,
            batch_size=args.batch_size,
            analyzers=_default_analyzers(args.analyzer, "media.metadata"),
            artifact_types=_parse_artifact_types(args.artifact_type),
            selected_paths=args.selected_path,
            selected_node_ids=args.selected_node_id,
            include_patterns=args.include,
            exclude_patterns=args.exclude,
        )
        return {"job": job.to_schema_dict(), "coverage": coverage.to_schema_dict()}
    if args.media_command == "status":
        return services.artifacts.artifact_status(args.job_id)
    if args.media_command == "resume":
        job, coverage = services.artifacts.resume_artifact_job(
            args.job_id, item_budget=args.item_budget
        )
        return {"job": job.to_schema_dict(), "coverage": coverage.to_schema_dict()}
    if args.media_command == "cancel":
        return services.artifacts.cancel_artifact_job(args.job_id).to_schema_dict()
    if args.media_command == "list":
        query = _artifact_query(args)
        if query.media_kind == "VIDEO":
            query = _replace_query_artifact_type(query, ArtifactType.MEDIA_VIDEO)
        elif query.media_kind == "AUDIO":
            query = _replace_query_artifact_type(query, ArtifactType.MEDIA_AUDIO)
        elif query.media_kind == "IMAGE":
            query = _replace_query_artifact_type(query, ArtifactType.MEDIA_IMAGE)
        return services.artifacts.list_artifacts(query).to_schema_dict()
    if args.media_command == "show":
        return services.artifacts.get_artifact(args.artifact_id).to_schema_dict()
    if args.media_command == "thumbnail":
        artifact = services.artifacts.get_artifact(args.artifact_id)
        return {
            "artifact_id": artifact.artifact_id,
            "thumbnail": artifact.fields.get("thumbnail_cache"),
            "thumbnail_status": artifact.fields.get("thumbnail_status")
            or ("GENERATED" if artifact.fields.get("thumbnail_cache") else "NOT_REQUESTED"),
        }
    if args.media_command == "warnings":
        return services.artifacts.list_warnings(
            job_id=args.job_id,
            artifact_id=args.artifact_id,
            evidence_id=args.evidence_id,
        )
    raise ValidationError("Unknown media command.", target="media_command")


def _candidate(args: Namespace, services: Any) -> Any:
    if args.candidate_command == "capabilities":
        return [
            item.to_schema_dict()
            for item in services.candidates.capabilities(capability_type=args.type)
        ]
    if args.candidate_command == "list":
        return services.candidates.list_candidates(
            case_id=args.case_id,
            evidence_id=args.evidence_id,
            review_status=args.review_status,
            cursor=args.cursor,
            limit=args.limit,
        ).to_schema_dict()
    if args.candidate_command == "show":
        return services.candidates.get_candidate(args.candidate_id)
    if args.candidate_command == "review":
        return services.candidates.review_candidate(
            candidate_id=args.candidate_id,
            review_status=args.status,
            reviewed_by=args.reviewed_by,
            reason=args.reason,
        ).to_schema_dict()
    if args.candidate_command == "correct":
        return services.candidates.review_candidate(
            candidate_id=args.candidate_id,
            review_status="CORRECTED",
            reviewed_by=args.reviewed_by,
            correction_text=args.correction_text,
            reason=args.reason,
        ).to_schema_dict()
    raise ValidationError("Unknown candidate command.", target="candidate_command")


def _machine(args: Namespace, services: Any) -> Any:
    if args.machine_command == "ocr" and args.ocr_command == "analyze":
        ocr_provider = (
            RapidOcrProvider(timeout=args.timeout)
            if args.provider == "rapidocr"
            else TesseractCliOcrProvider(
                executable=args.tesseract,
                tessdata_prefix=args.tessdata_prefix,
                timeout=args.timeout,
            )
        )
        rows = services.candidates.analyze_image_file(
            case_id=args.case_id,
            evidence_id=args.evidence_id,
            source_node_id=args.source_node_id,
            path=str(args.path),
            provider=ocr_provider,
            languages=args.language or ["eng"],
            source_revision=args.source_revision,
        )
        return [row.to_schema_dict() for row in rows]
    if args.machine_command == "stt" and args.stt_command == "analyze":
        stt_provider = (
            FasterWhisperSttProvider(
                model_path=args.model_path,
                device=args.device,
                compute_type=args.compute_type,
                timeout=args.timeout,
            )
            if args.provider == "faster-whisper"
            else WhisperCppCliSttProvider(
                executable=args.whisper,
                model_path=args.model_path,
                timeout=args.timeout,
            )
        )
        rows = services.candidates.analyze_audio_file(
            case_id=args.case_id,
            evidence_id=args.evidence_id,
            source_node_id=args.source_node_id,
            path=str(args.path),
            provider=stt_provider,
            language=args.language,
            source_revision=args.source_revision,
        )
        return [row.to_schema_dict() for row in rows]
    raise ValidationError("Unknown machine command.", target="machine_command")


def _secret(args: Namespace, services: Any) -> Any:
    if args.secret_command == "capability":
        providers = _secret_runtime_providers()
        if args.provider == "all":
            return [
                _record_secret_provider_capability(services, provider.capabilities())
                for provider in providers.values()
            ]
        return _record_secret_provider_capability(
            services,
            providers[args.provider].capabilities(),
        )
    if args.secret_command == "decrypt-dpapi":
        derivation = _dpapi_derivation_input(args, key_source_kind=args.key_source_kind)
        result = DpapiOfflineProvider().decrypt_blob(
            derivation,
            _read_secret_runtime_file(args.input_file),
        )
        return _record_decryption_result(services, result)
    if args.secret_command == "decrypt-nss":
        primary_password = (
            os.environ.get(args.primary_password_env)
            if args.primary_password_env is not None
            else None
        )
        derivation = _secret_derivation_input(args, key_source_kind=args.key_source_kind)
        return _record_decryption_results(
            services,
            NssLibProvider().decrypt_logins(
                derivation,
                profile_path=str(args.profile_path),
                primary_password=primary_password,
            ),
        )
    if args.secret_command == "dpapi":
        dpapi_provider = DpapiOfflineProvider()
        if args.dpapi_command == "decrypt-blob":
            derivation = _dpapi_derivation_input(args, key_source_kind=args.key_source_kind)
            result = dpapi_provider.decrypt_blob(
                derivation,
                _read_secret_runtime_file(args.input_file),
            )
            return _record_decryption_result(services, result)
        if args.dpapi_command == "inspect-local-state":
            return dpapi_provider.inspect_chromium_local_state(
                case_id=args.case_id,
                evidence_id=args.evidence_id,
                local_state_path=str(args.local_state_path),
                source_revision=args.source_revision,
            )
        if args.dpapi_command == "decrypt-local-state-key":
            derivation = _dpapi_derivation_input(args, key_source_kind=args.key_source_kind)
            result = dpapi_provider.decrypt_chromium_local_state_key(
                derivation,
                local_state_path=str(args.local_state_path),
                source_revision=args.source_revision,
            )
            return _record_decryption_result(services, result)
        if args.dpapi_command == "decrypt-chromium-secret":
            derivation = _secret_derivation_input(args, key_source_kind=args.key_source_kind)
            key_material = _secret_material_from_env(args, derivation)
            result = DpapiExternalKeyProvider().decrypt_chromium_secret(
                derivation,
                _read_secret_runtime_file(args.input_file),
                key_material,
                include_plaintext=False,
            )
            return _record_decryption_result(services, result)
        if args.dpapi_command == "discover-profiles":
            return dpapi_provider.discover_profiles(
                case_id=args.case_id,
                evidence_id=args.evidence_id,
                root_path=str(args.root_path),
            )
        raise ValidationError("Unknown DPAPI command.", target="dpapi_command")
    if args.secret_command == "nss":
        nss_provider = NssLibProvider()
        if args.nss_command == "discover-profiles":
            return nss_provider.discover_profiles(
                case_id=args.case_id,
                evidence_id=args.evidence_id,
                root_path=str(args.root_path),
            )
        if args.nss_command == "decrypt-logins":
            primary_password = (
                os.environ.get(args.primary_password_env)
                if args.primary_password_env is not None
                else None
            )
            derivation = _secret_derivation_input(args, key_source_kind=args.key_source_kind)
            return _record_decryption_results(
                services,
                nss_provider.decrypt_logins(
                    derivation,
                    profile_path=str(args.profile_path),
                    primary_password=primary_password,
                ),
            )
        raise ValidationError("Unknown NSS command.", target="nss_command")
    if args.secret_command == "kakaotalk":
        kakaotalk_provider = KakaoTalkEncryptedStoreProvider()
        if args.kakaotalk_command == "inspect":
            return kakaotalk_provider.inspect_store(
                case_id=args.case_id,
                evidence_id=args.evidence_id,
                store_path=str(args.path),
            )
        if args.kakaotalk_command == "decrypt-store":
            derivation = _kakaotalk_derivation_input(
                args,
                key_source_kind=args.key_source_kind,
            )
            return _record_decryption_result(
                services,
                kakaotalk_provider.decrypt_store(derivation, store_path=str(args.path)),
            )
        raise ValidationError("Unknown KakaoTalk command.", target="kakaotalk_command")
    raise ValidationError("Unknown secret command.", target="secret_command")


def _record_secret_provider_capability(
    services: Any,
    capability: SecretProviderCapability,
) -> dict[str, Any]:
    services.repository.save_secret_provider_capability(capability)
    return capability.to_schema_dict()


def _record_decryption_result(services: Any, result: DecryptionResult) -> dict[str, Any]:
    if services.repository.get_case(result.attempt.case_id) is not None:
        services.repository.save_decryption_result(result)
    return result.to_schema_dict()


def _record_decryption_results(
    services: Any,
    results: list[DecryptionResult],
) -> list[dict[str, Any]]:
    return [_record_decryption_result(services, item) for item in results]


def _record_ai_provider_capability(
    services: Any,
    capability: AiProviderCapability,
) -> dict[str, Any]:
    services.repository.save_ai_provider_capability(capability)
    return capability.to_schema_dict()


def _ai(args: Namespace, services: Any) -> Any:
    if args.ai_command == "request-capabilities":
        return services.ai.capabilities()
    if args.ai_command == "provider-capability":
        return _record_ai_provider_capability(
            services,
            _ai_runtime_provider(args).capabilities(),
        )
    if args.ai_command == "request-create":
        return services.ai.create_request_from_context_snapshot(
            case_id=args.case_id,
            context_snapshot_id=args.context_snapshot_id,
            purpose=args.purpose,
            requested_operations=args.operation or None,
            requested_scopes=args.scope or None,
            scope_context_ids=args.scope_context_id or None,
            locale=args.locale,
            timezone=args.timezone,
            max_keyword_candidates=args.max_keyword_candidates,
            max_summary_length=args.max_summary_length,
            ttl_seconds=args.ttl_seconds,
            correlation_id=args.correlation_id,
        ).to_schema_dict()
    if args.ai_command == "request-show":
        return services.ai.get_request(args.assistance_request_id).to_schema_dict()
    if args.ai_command == "request-list":
        return [
            item.to_schema_dict()
            for item in services.ai.list_requests_by_case(args.case_id, limit=args.limit)
        ]
    if args.ai_command == "request-compare":
        return services.ai.compare_requests(args.left_request_id, args.right_request_id)
    if args.ai_command == "keyword-ingest":
        return services.ai.ingest_keyword_batch(
            assistance_request_id=args.assistance_request_id,
            payload=_json_input(args),
        )
    if args.ai_command == "generate-keywords":
        return services.ai.generate_keyword_recommendations(
            assistance_request_id=args.assistance_request_id,
            provider=_ai_runtime_provider(args),
        )
    if args.ai_command == "keyword-batch-show":
        return services.ai.get_keyword_batch(args.recommendation_batch_id)
    if args.ai_command == "keyword-list":
        return services.ai.list_keyword_recommendations(
            case_id=args.case_id,
            recommendation_batch_id=args.recommendation_batch_id,
            cursor=args.cursor,
            limit=args.limit,
        )
    if args.ai_command == "keyword-show":
        return services.ai.get_keyword_recommendation(args.recommendation_id).to_schema_dict()
    if args.ai_command == "keyword-review":
        return services.ai.review_keyword_recommendation(
            recommendation_id=args.recommendation_id,
            action=args.action,
            actor_id=args.actor_id,
            reason=args.reason,
            expected_review_revision=args.expected_review_revision,
        ).to_schema_dict()
    if args.ai_command == "keyword-correct":
        return services.ai.review_keyword_recommendation(
            recommendation_id=args.recommendation_id,
            action="CORRECT",
            actor_id=args.actor_id,
            reason=args.reason,
            expected_review_revision=args.expected_review_revision,
            corrected_value=args.corrected_value,
            corrected_reason=args.corrected_reason,
        ).to_schema_dict()
    if args.ai_command == "keyword-promotion-preview":
        return services.ai.preview_keyword_promotion(
            recommendation_id=args.recommendation_id,
            keyword_set_id=args.keyword_set_id,
            regex_confirmed=args.regex_confirmed,
        )
    if args.ai_command == "keyword-promote":
        return services.ai.promote_accepted_keyword(
            recommendation_id=args.recommendation_id,
            keyword_set_id=args.keyword_set_id,
            actor_id=args.actor_id,
            reason=args.reason,
            expected_review_revision=args.expected_review_revision,
            regex_confirmed=args.regex_confirmed,
            confirmation_metadata=_json_arg(args.confirmation_json, "confirmation_json")
            if args.confirmation_json is not None
            else None,
        ).to_schema_dict()
    if args.ai_command == "summary-ingest":
        return services.ai.ingest_scope_summary(
            assistance_request_id=args.assistance_request_id,
            payload=_json_input(args),
        ).to_schema_dict()
    if args.ai_command == "generate-summary":
        return services.ai.generate_scope_summary(
            assistance_request_id=args.assistance_request_id,
            provider=_ai_runtime_provider(args),
        ).to_schema_dict()
    if args.ai_command == "generate-report-draft":
        request = services.ai.get_request(args.assistance_request_id)
        payload = _ai_runtime_provider(args).generate_report_draft(request)
        return services.reports.ingest_ai_draft(
            payload=payload,
            report_id=args.report_id,
            created_by=args.created_by,
        ).to_schema_dict()
    if args.ai_command == "summary-list":
        if args.scope_summary_id is not None:
            return services.ai.get_scope_summary(args.scope_summary_id).to_schema_dict()
        return [
            item.to_schema_dict()
            for item in services.ai.list_scope_summaries(
                case_id=args.case_id,
                context_snapshot_id=args.context_snapshot_id,
                scope_context_id=args.scope_context_id,
                limit=args.limit,
            )
        ]
    if args.ai_command == "summary-show":
        return services.ai.get_scope_summary(args.scope_summary_id).to_schema_dict()
    if args.ai_command == "summary-review":
        return services.ai.review_scope_summary(
            scope_summary_id=args.scope_summary_id,
            action=args.action,
            actor_id=args.actor_id,
            reason=args.reason,
            expected_review_revision=args.expected_review_revision,
        ).to_schema_dict()
    if args.ai_command == "summary-correct":
        return services.ai.review_scope_summary(
            scope_summary_id=args.scope_summary_id,
            action="CORRECT",
            actor_id=args.actor_id,
            reason=args.reason,
            expected_review_revision=args.expected_review_revision,
            corrected_value=args.corrected_value,
            corrected_reason=args.corrected_reason,
        ).to_schema_dict()
    if args.ai_command == "review-history":
        return [
            item.to_schema_dict()
            for item in services.ai.review_history(
                target_type=args.target_type,
                target_id=args.target_id,
            )
        ]
    raise ValidationError("Unknown AI command.", target="ai_command")


def _custody(args: Namespace, services: Any) -> Any:
    if args.custody_command == "list":
        return [event.to_schema_dict() for event in services.custody.list_events(args.evidence_id)]
    if args.custody_command == "verify-chain":
        return {
            "evidence_id": args.evidence_id,
            "valid": services.custody.verify_chain(args.evidence_id),
        }
    if args.custody_command == "add":
        event = services.custody.add_event(
            evidence_id=args.evidence_id,
            event_type=CustodyEventType(args.event_type),
            actor_name=args.actor_name,
            action=args.action,
            reason=args.reason,
            correction_of_event_id=args.correction_of_event_id,
        )
        return event.to_schema_dict()
    raise ValidationError("Unknown custody command.", target="custody_command")


def _search(args: Namespace, services: Any) -> Any:
    if args.search_command == "index":
        job, coverage = services.search.index(
            case_id=args.case_id,
            evidence_ids=args.evidence_id,
            source_types=[_parse_search_source_type(item) for item in args.source_type],
            profile_type=AnalysisProfileType(args.profile),
            item_budget=args.item_budget,
            batch_size=args.batch_size,
        )
        return {"job": job.to_schema_dict(), "coverage": coverage}
    if args.search_command == "index-status":
        return services.search.index_status(args.job_id)
    if args.search_command == "resume":
        job, coverage = services.search.resume_index_job(
            args.job_id,
            item_budget=args.item_budget,
        )
        return {"job": job.to_schema_dict(), "coverage": coverage}
    if args.search_command == "cancel":
        return services.search.cancel_index_job(args.job_id).to_schema_dict()
    if args.search_command == "query":
        page = services.search.query(
            case_id=args.case_id,
            query_text=args.query,
            query_mode=SearchQueryMode(args.mode),
            evidence_ids=args.evidence_id,
            source_types=[_parse_search_source_type(item) for item in args.source_type],
            document_types=[_parse_search_document_type(item) for item in args.document_type],
            time_from=_parse_timestamp_arg(args.time_from, "time_from"),
            time_to=_parse_timestamp_arg(args.time_to, "time_to"),
            path_scope=args.path_scope,
            keyword_set_id=args.keyword_set_id,
            keyword_set_version=args.keyword_set_version,
            case_sensitive=args.case_sensitive,
            cursor=args.cursor,
            limit=args.limit,
            sort=args.sort,
            use_cache=not args.no_cache,
        )
        return page.to_schema_dict()
    if args.search_command == "show":
        return services.search.show_execution(args.execution_id, limit=args.limit)
    if args.search_command == "history":
        return services.search.history(case_id=args.case_id, limit=args.limit)
    if args.search_command == "rerun":
        return services.search.rerun(
            args.execution_id,
            use_cache=not args.no_cache,
        ).to_schema_dict()
    if args.search_command == "cache-status":
        return services.search.cache_status(case_id=args.case_id)
    if args.search_command == "rebuild":
        return services.search.rebuild(case_id=args.case_id)
    raise ValidationError("Unknown search command.", target="search_command")


def _keyword_set(args: Namespace, services: Any) -> Any:
    if args.keyword_command == "create":
        keyword_set = services.search.create_keyword_set(
            case_id=args.case_id,
            name=args.name,
            description=args.description,
            created_by=args.created_by,
            keywords=[
                {"term": term, "keyword_type": "OTHER", "match_mode": "TERM"}
                for term in args.keyword
            ],
        )
        return keyword_set.to_schema_dict()
    if args.keyword_command == "list":
        status = None if args.status is None else KeywordSetStatus(args.status)
        return [
            item.to_schema_dict()
            for item in services.search.list_keyword_sets(case_id=args.case_id, status=status)
        ]
    if args.keyword_command == "show":
        return services.search.get_keyword_set(
            args.keyword_set_id,
            version=args.version,
        ).to_schema_dict()
    if args.keyword_command == "add":
        return services.search.add_keyword(
            args.keyword_set_id,
            term=args.term,
            keyword_type=_parse_keyword_type(args.keyword_type),
            match_mode=_parse_keyword_match_mode(args.match_mode),
            case_sensitive=args.case_sensitive,
            enabled=not args.disabled,
            notes=args.notes,
            source=args.source,
        ).to_schema_dict()
    if args.keyword_command == "remove":
        return services.search.remove_keyword(
            args.keyword_set_id,
            keyword_id=args.keyword_id,
        ).to_schema_dict()
    if args.keyword_command == "activate":
        return services.search.activate_keyword_set(args.keyword_set_id).to_schema_dict()
    if args.keyword_command == "archive":
        return services.search.archive_keyword_set(args.keyword_set_id).to_schema_dict()
    if args.keyword_command == "version":
        return services.search.version_keyword_set(args.keyword_set_id).to_schema_dict()
    raise ValidationError("Unknown keyword set command.", target="keyword_command")


def _timeline(args: Namespace, services: Any) -> Any:
    if args.timeline_command == "build":
        job, coverage = services.timeline.build(
            case_id=args.case_id,
            evidence_id=args.evidence_id,
            source_types=[_parse_timeline_source_type(item) for item in args.source_type],
            profile_type=AnalysisProfileType(args.profile),
            item_budget=args.item_budget,
            batch_size=args.batch_size,
        )
        return {"job": job.to_schema_dict(), "coverage": coverage.to_schema_dict()}
    if args.timeline_command == "status":
        return services.timeline.status(args.job_id)
    if args.timeline_command == "resume":
        job, coverage = services.timeline.resume_build_job(
            args.job_id,
            item_budget=args.item_budget,
        )
        return {"job": job.to_schema_dict(), "coverage": coverage.to_schema_dict()}
    if args.timeline_command == "cancel":
        return services.timeline.cancel_build_job(args.job_id).to_schema_dict()
    if args.timeline_command == "list":
        confidence = (
            None if args.confidence is None else _parse_timezone_confidence(args.confidence)
        )
        return services.timeline.list_events(
            case_id=args.case_id,
            evidence_id=args.evidence_id,
            source_types=[_parse_timeline_source_type(item) for item in args.source_type],
            event_types=[_parse_timeline_event_type(item) for item in args.event_type],
            analyzer_id=args.analyzer,
            keyword=args.keyword,
            path=args.path,
            artifact_type=args.artifact_type,
            is_partial=True if args.partial else None,
            confidence=confidence,
            time_from=_parse_timestamp_arg(args.time_from, "time_from"),
            time_to=_parse_timestamp_arg(args.time_to, "time_to"),
            timezone=args.timezone,
            cursor=args.cursor,
            limit=args.limit,
            order=args.order.upper(),
        ).to_schema_dict()
    if args.timeline_command == "show":
        return services.timeline.get_event(args.timeline_event_id).to_schema_dict()
    raise ValidationError("Unknown timeline command.", target="timeline_command")


def _context(args: Namespace, services: Any) -> Any:
    if args.context_command == "create":
        return services.contexts.create(
            session_id=args.session_id,
            case_id=args.case_id,
            actor_id=args.actor_id,
            locale=args.locale,
            timezone=args.timezone,
            current_route=args.current_route,
            current_panel=args.current_panel,
            active_evidence_id=args.evidence_id,
            selected_file_node_ids=args.file_node_id,
            selected_artifact_ids=args.artifact_id,
            selected_timeline_event_ids=args.timeline_event_id,
            selected_search_result_ids=args.search_result_id,
            selected_media_artifact_ids=args.media_artifact_id,
            selected_browser_artifact_ids=args.browser_artifact_id,
            selected_candidate_ids=args.candidate_id,
            active_filters=_json_arg(args.filters_json, "filters_json"),
            active_sort=_json_arg(args.sort_json, "sort_json"),
            active_time_range=_json_arg(args.time_range_json, "time_range_json"),
            active_keyword_set_id=args.keyword_set_id,
            active_keyword_set_version=args.keyword_set_version,
            active_search_execution_id=args.search_execution_id,
            active_timeline_revision=args.timeline_revision,
            active_context_scope=AnalysisScopeType(args.scope),
            ui_preferences=_json_arg(args.ui_preferences_json, "ui_preferences_json"),
            expires_at=args.expires_at,
        ).to_schema_dict()
    if args.context_command == "get":
        return services.contexts.get(args.session_context_id).to_schema_dict()
    if args.context_command == "update":
        updates = _context_updates(args)
        return services.contexts.update(
            args.session_context_id,
            expected_revision=args.expected_revision,
            **updates,
        ).to_schema_dict()
    if args.context_command == "select":
        return services.contexts.select_items(
            args.session_context_id,
            expected_revision=args.expected_revision,
            resource_type=ResourceType(args.resource_type),
            resource_ids=args.resource_id,
            mode=args.mode,
        ).to_schema_dict()
    if args.context_command == "filters":
        return services.contexts.set_filters(
            args.session_context_id,
            expected_revision=args.expected_revision,
            filters=_json_arg(args.filters_json, "filters_json"),
        ).to_schema_dict()
    if args.context_command == "snapshot":
        return services.contexts.build_from_session(
            args.session_context_id,
            purpose=AnalysisContextPurpose(args.purpose),
            scopes=args.scope,
            previous_snapshot_id=args.previous_snapshot_id,
        ).to_schema_dict()
    if args.context_command == "snapshot-show":
        return services.contexts.get_snapshot(args.context_snapshot_id).to_schema_dict()
    if args.context_command == "compare":
        if args.left_snapshot_id and args.right_snapshot_id:
            return services.contexts.compare(args.left_snapshot_id, args.right_snapshot_id)
        return services.contexts.compare_revisions(
            args.session_context_id,
            args.left_revision,
            args.right_revision,
        )
    if args.context_command == "scopes":
        return [
            item.to_schema_dict()
            for item in services.contexts.list_scopes(args.context_snapshot_id)
        ]
    if args.context_command == "scope-page":
        return services.contexts.paginate_scope(
            args.context_snapshot_id,
            AnalysisScopeType(args.scope),
            cursor=args.cursor,
            limit=args.limit,
        )
    if args.context_command == "refresh":
        if args.context_snapshot_id:
            return services.contexts.refresh(args.context_snapshot_id).to_schema_dict()
        return services.contexts.refresh_revision_state(
            args.session_context_id,
            expected_revision=args.expected_revision,
        )
    if args.context_command == "expire":
        return services.contexts.expire(
            args.session_context_id,
            expected_revision=args.expected_revision,
        ).to_schema_dict()
    raise ValidationError("Unknown context command.", target="context_command")


def _view(args: Namespace, services: Any) -> Any:
    if args.view_command == "simple":
        return services.views.simple(
            case_id=args.case_id,
            resource_type=ResourceType(args.resource_type),
            resource_id=args.resource_id,
            redaction_policy=args.redaction_policy,
        ).to_schema_dict()
    if args.view_command == "detailed":
        return services.views.detailed(
            case_id=args.case_id,
            resource_type=ResourceType(args.resource_type),
            resource_id=args.resource_id,
            redaction_policy=args.redaction_policy,
        ).to_schema_dict()
    if args.view_command == "raw":
        return services.views.raw(
            case_id=args.case_id,
            resource_type=ResourceType(args.resource_type),
            resource_id=args.resource_id,
            redaction_policy=args.redaction_policy,
        ).to_schema_dict()
    if args.view_command == "raw-read":
        return services.views.raw_read(
            case_id=args.case_id,
            resource_type=ResourceType(args.resource_type),
            resource_id=args.resource_id,
            offset=args.offset,
            length=args.length,
            correlation_id=args.correlation_id,
        ).to_schema_dict()
    if args.view_command == "capabilities":
        return services.views.capabilities()
    raise ValidationError("Unknown view command.", target="view_command")


def _report(args: Namespace, services: Any) -> Any:
    if args.report_command == "create":
        return services.reports.create_report(
            case_id=args.case_id,
            title=args.title,
            created_by=args.created_by,
            description=args.description,
            report_type=args.report_type,
            locale=args.locale,
            timezone=args.timezone,
        ).to_schema_dict()
    if args.report_command == "list":
        return services.reports.list_reports(
            case_id=args.case_id,
            cursor=args.cursor,
            limit=args.limit,
        )
    if args.report_command == "show":
        return services.reports.get_report(args.report_id).to_schema_dict()
    if args.report_command == "version-create":
        payload = _json_input(args)
        return services.reports.create_version(
            report_id=args.report_id,
            source_kind=args.source_kind,
            created_by=args.created_by,
            title=_required_json_field(payload, "title"),
            executive_summary=_required_json_field(payload, "executive_summary"),
            sections=_required_json_list(payload, "sections"),
            source_reference_id=payload.get("source_reference_id"),
            context_snapshot_ids=payload.get("context_snapshot_ids"),
            evidence_ids=payload.get("evidence_ids"),
            search_execution_ids=payload.get("search_execution_ids"),
            timeline_revisions=payload.get("timeline_revisions"),
            ai_assistance_request_ids=payload.get("ai_assistance_request_ids"),
            ai_result_ids=payload.get("ai_result_ids"),
            citations=payload.get("citations"),
            limitations=payload.get("limitations"),
            analyzer_versions=payload.get("analyzer_versions"),
        ).to_schema_dict()
    if args.report_command == "version-list":
        return [item.to_schema_dict() for item in services.reports.list_versions(args.report_id)]
    if args.report_command == "version-show":
        return services.reports.get_version(args.report_version_id).to_schema_dict()
    if args.report_command == "version-compare":
        return services.reports.compare_versions(
            args.left_report_version_id,
            args.right_report_version_id,
        )
    if args.report_command == "ai-draft-ingest":
        return services.reports.ingest_ai_draft(
            payload=_json_input(args),
            report_id=args.report_id,
            created_by=args.created_by,
        ).to_schema_dict()
    if args.report_command == "archive":
        return services.reports.archive_report(
            report_id=args.report_id,
            actor_id=args.actor_id,
            reason=args.reason,
        ).to_schema_dict()
    if args.report_command == "review-submit":
        return services.reports.submit_review(
            report_version_id=args.report_version_id,
            actor_id=args.actor_id,
            reason=args.reason,
            expected_review_revision=args.expected_review_revision,
        ).to_schema_dict()
    if args.report_command == "review-comment":
        return services.reports.comment_review(
            report_version_id=args.report_version_id,
            actor_id=args.actor_id,
            reason=args.reason,
            comment=args.comment,
            section_id=args.section_id,
            expected_review_revision=args.expected_review_revision,
        ).to_schema_dict()
    if args.report_command == "review-request-changes":
        return services.reports.request_changes(
            report_version_id=args.report_version_id,
            actor_id=args.actor_id,
            reason=args.reason,
            requested_changes=args.requested_change,
            section_id=args.section_id,
            expected_review_revision=args.expected_review_revision,
        ).to_schema_dict()
    if args.report_command == "review-accept-section":
        return services.reports.accept_section(
            report_version_id=args.report_version_id,
            section_id=args.section_id,
            actor_id=args.actor_id,
            reason=args.reason,
            comment=args.comment,
            expected_review_revision=args.expected_review_revision,
        ).to_schema_dict()
    if args.report_command == "review-reject-section":
        return services.reports.reject_section(
            report_version_id=args.report_version_id,
            section_id=args.section_id,
            actor_id=args.actor_id,
            reason=args.reason,
            requested_changes=args.requested_change,
            comment=args.comment,
            expected_review_revision=args.expected_review_revision,
        ).to_schema_dict()
    if args.report_command == "review-complete":
        return services.reports.complete_review(
            report_version_id=args.report_version_id,
            actor_id=args.actor_id,
            reason=args.reason,
            expected_review_revision=args.expected_review_revision,
        ).to_schema_dict()
    if args.report_command == "review-reopen":
        return services.reports.reopen_review(
            report_version_id=args.report_version_id,
            actor_id=args.actor_id,
            reason=args.reason,
            expected_review_revision=args.expected_review_revision,
        ).to_schema_dict()
    if args.report_command == "review-history":
        return [
            item.to_schema_dict()
            for item in services.reports.review_history(args.report_version_id)
        ]
    if args.report_command == "approve":
        return services.reports.approve(
            report_version_id=args.report_version_id,
            approver_id=args.approver_id,
            reason=args.reason,
            custody_snapshot_id=args.custody_snapshot_id,
            expected_review_revision=args.expected_review_revision,
            expected_approval_revision=args.expected_approval_revision,
        ).to_schema_dict()
    if args.report_command == "reject":
        return services.reports.reject(
            report_version_id=args.report_version_id,
            approver_id=args.approver_id,
            reason=args.reason,
            expected_approval_revision=args.expected_approval_revision,
        ).to_schema_dict()
    if args.report_command == "revoke-approval":
        return services.reports.revoke_approval(
            report_version_id=args.report_version_id,
            actor_id=args.actor_id,
            reason=args.reason,
            expected_approval_revision=args.expected_approval_revision,
        ).to_schema_dict()
    if args.report_command == "approval-show":
        approval = services.reports.get_approval(args.report_version_id)
        return None if approval is None else approval.to_schema_dict()
    if args.report_command == "custody-snapshot-create":
        return services.reports.create_custody_snapshot(
            report_version_id=args.report_version_id,
            captured_by=args.captured_by,
            evidence_ids=args.evidence_id or None,
        ).to_schema_dict()
    if args.report_command == "custody-snapshot-show":
        return services.reports.get_custody_snapshot(args.custody_snapshot_id).to_schema_dict()
    if args.report_command == "package-create":
        return services.reports.create_render_package(
            report_version_id=args.report_version_id,
            created_by=args.created_by,
            for_export=args.for_export,
            custody_snapshot_id=args.custody_snapshot_id,
            stale_confirmed=args.stale_confirmed,
        ).to_schema_dict()
    if args.report_command == "package-show":
        return services.reports.get_render_package(args.package_id).to_schema_dict()
    if args.report_command == "export-prepare":
        return services.reports.prepare_export(
            report_version_id=args.report_version_id,
            format=args.format,
            filename=args.filename,
            created_by=args.created_by,
            redaction_policy=args.redaction_policy,
            overwrite_policy=args.overwrite_policy,
            include_citations=not args.no_citations,
            include_custody=not args.no_custody,
            include_technical_appendix=not args.no_technical_appendix,
            stale_confirmed=args.stale_confirmed,
        ).to_schema_dict()
    if args.report_command == "export-status":
        return services.reports.export_status(args.export_manifest_id)
    if args.report_command == "export-record-result":
        result = services.reports.record_export_result(
            export_manifest_id=args.export_manifest_id,
            payload=_json_input(args),
        )
        return result.to_schema_dict()
    if args.report_command == "export-capabilities":
        return services.reports.renderer_capabilities().to_schema_dict()
    if args.report_command == "render-html":
        return _render_report_runtime(args, services, "HTML")
    if args.report_command == "render-pdf":
        return _render_report_runtime(args, services, "PDF")
    raise ValidationError("Unknown report command.", target="report_command")


def _interface(args: Namespace, services: Any) -> Any:
    if args.interface_command == "version":
        return services.interface.version().to_schema_dict()
    if args.interface_command == "tools":
        return [item.to_schema_dict() for item in services.interface.tools()]
    if args.interface_command == "capability":
        return services.interface.capability(args.capability)
    if args.interface_command == "invoke-read":
        return services.interface.invoke_read(
            args.operation,
            _json_arg(args.payload_json, "payload_json"),
            correlation_id=args.correlation_id,
        )
    if args.interface_command == "invoke-mutation":
        return services.interface.invoke_mutation(
            args.operation,
            _json_arg(args.payload_json, "payload_json"),
            correlation_id=args.correlation_id,
        )
    raise ValidationError("Unknown interface command.", target="interface_command")


def _hash_record_output(record: Any) -> dict[str, Any]:
    return {
        "hash_id": record.hash_id,
        "evidence_id": record.evidence_id,
        "algorithm": record.algorithm.value,
        "digest": record.digest,
        "calculated_at": record.to_schema_dict()["completed_at"],
        "file_size": record.file_size,
        "chunk_size": record.chunk_size,
        "verified": record.verified,
        "verification_status": record.verification_status,
        "bytes_hashed": record.bytes_hashed,
    }


def _render_report_runtime(args: Namespace, services: Any, format_value: str) -> Any:
    renderer = RuntimeReportRenderer(output_root=args.output_root)
    manifest = services.reports.prepare_export(
        report_version_id=args.report_version_id,
        format=format_value,
        filename=args.filename,
        created_by=args.created_by,
        redaction_policy=args.redaction_policy,
        include_citations=not args.no_citations,
        include_custody=not args.no_custody,
        include_technical_appendix=not args.no_technical_appendix,
        stale_confirmed=args.stale_confirmed,
        renderer=renderer,
    )
    if manifest.status == "PREPARED":
        services.reports.render_export(
            export_manifest_id=manifest.export_manifest_id,
            renderer=renderer,
        )
    return services.reports.export_status(manifest.export_manifest_id)


def _ai_runtime_provider(args: Namespace) -> OpenAICompatibleProvider:
    return OpenAICompatibleProvider(
        OpenAICompatibleConfig(
            provider_id=args.provider_id,
            base_url=args.base_url,
            model=args.model,
            api_key_env=args.api_key_env,
            timeout=args.timeout,
            max_output=args.max_output,
            temperature=args.temperature,
            request_policy=args.request_policy,
        )
    )


def _secret_runtime_providers() -> dict[str, Any]:
    return {
        "dpapi": DpapiOfflineProvider(),
        "dpapi-external": DpapiExternalKeyProvider(),
        "dpapi-unavailable": DpapiUnavailableProvider(),
        "nss": NssLibProvider(),
        "nss-unavailable": NssUnavailableProvider(),
        "kakaotalk": KakaoTalkEncryptedStoreProvider(),
    }


def _secret_derivation_input(args: Namespace, *, key_source_kind: str) -> SecretDerivationInput:
    return SecretDerivationInput(
        case_id=args.case_id,
        evidence_id=args.evidence_id,
        key_source_kind=key_source_kind,
        references=[],
        parameters={},
    )


def _kakaotalk_derivation_input(
    args: Namespace,
    *,
    key_source_kind: str,
) -> SecretDerivationInput:
    parameters: dict[str, Any] = {
        "platform": args.platform,
        "application_version": args.application_version,
        "database_schema_version": args.database_schema_version,
    }
    env_mappings = (
        ("pragma_key_env", "pragma_key"),
        ("user_nonce_env", "user_nonce"),
        ("db_key_hex_env", "db_key_hex"),
        ("db_iv_hex_env", "db_iv_hex"),
    )
    for attr, parameter_name in env_mappings:
        env_name = getattr(args, attr, None)
        if env_name:
            value = os.environ.get(env_name)
            if value:
                parameters[parameter_name] = value
    return SecretDerivationInput(
        case_id=args.case_id,
        evidence_id=args.evidence_id,
        key_source_kind=key_source_kind,
        references=[],
        parameters=parameters,
    )


def _dpapi_derivation_input(args: Namespace, *, key_source_kind: str) -> SecretDerivationInput:
    parameters: dict[str, Any] = {}
    for attr, parameter_name in (
        ("sid", "sid"),
        ("masterkey_guid", "masterkey_guid"),
    ):
        value = getattr(args, attr, None)
        if value:
            parameters[parameter_name] = value
    masterkey_path = getattr(args, "masterkey_path", None)
    if masterkey_path is not None:
        parameters["masterkey_path"] = str(masterkey_path)
    env_mappings = (
        ("password_env", "password"),
        ("nt_hash_hex_env", "nt_hash_hex"),
        ("nt_hash_b64_env", "nt_hash_b64"),
        ("masterkey_hex_env", "masterkey_hex"),
        ("masterkey_b64_env", "masterkey_b64"),
        ("entropy_hex_env", "entropy_hex"),
        ("entropy_b64_env", "entropy_b64"),
    )
    for attr, parameter_name in env_mappings:
        env_name = getattr(args, attr, None)
        if env_name is not None:
            parameters[parameter_name] = _secret_env_value(env_name, target=attr)
    return SecretDerivationInput(
        case_id=args.case_id,
        evidence_id=args.evidence_id,
        key_source_kind=key_source_kind,
        references=[],
        parameters=parameters,
    )


def _secret_env_value(env_name: str, *, target: str) -> str:
    value = os.environ.get(env_name)
    if value is None:
        raise ValidationError(
            "Secret environment variable is not set.",
            target=target,
            details={"env_name": env_name},
        )
    return value


def _secret_material_from_env(args: Namespace, derivation: SecretDerivationInput) -> SecretMaterial:
    env_name = args.key_hex_env or args.key_b64_env
    value = os.environ.get(env_name)
    if value is None:
        raise ValidationError(
            "Secret key environment variable is not set.",
            target="key_env",
            details={"key_env": env_name},
        )
    try:
        key = (
            bytes.fromhex(value.strip())
            if args.key_hex_env
            else base64.b64decode(value.encode("ascii"), validate=True)
        )
    except (ValueError, binascii.Error) as error:
        raise ValidationError(
            "Secret key environment variable is not valid hex/base64.",
            target="key_env",
            details={"key_env": env_name},
        ) from error
    return SecretMaterial(
        reference=SecretReference(
            secret_id=args.secret_id,
            case_id=derivation.case_id,
            evidence_id=derivation.evidence_id,
            key_source_kind=derivation.key_source_kind,
            provider_id="cli-env",
            source_kind="ENVIRONMENT_VARIABLE",
            source_path=None,
            raw_locator={"env_name": env_name, "value_emitted": False},
        ),
        value=key,
        algorithm="AES-GCM",
    )


def _read_secret_runtime_file(path: Path) -> bytes:
    size = path.stat().st_size
    if size > 64 * 1024 * 1024:
        raise ValidationError(
            "Secret runtime input file exceeds the size limit.",
            target="input_file",
            details={"max_bytes": 64 * 1024 * 1024},
        )
    return path.read_bytes()


def _json_arg(value: str | None, target: str) -> dict[str, Any]:
    if value in {None, ""}:
        return {}
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError as error:
        raise ValidationError("Invalid JSON option.", target=target) from error
    if not isinstance(parsed, dict):
        raise ValidationError("JSON option must be an object.", target=target)
    return parsed


def _json_input(args: Namespace) -> dict[str, Any]:
    if getattr(args, "input_json", None) and getattr(args, "input_file", None):
        raise ValidationError("Use either --input-json or --input-file, not both.", target="input")
    if getattr(args, "input_file", None) is not None:
        path = args.input_file
        if path.stat().st_size > 1024 * 1024:
            raise ValidationError("Input JSON file exceeds the size limit.", target="input_file")
        value = path.read_text(encoding="utf-8")
    else:
        value = getattr(args, "input_json", None)
    if not value:
        raise ValidationError("JSON input is required.", target="input_json")
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError as error:
        raise ValidationError("Invalid JSON input.", target="input_json") from error
    if not isinstance(parsed, dict):
        raise ValidationError("JSON input must be an object.", target="input_json")
    return parsed


def _required_json_field(payload: dict[str, Any], field: str) -> str:
    value = payload.get(field)
    if not isinstance(value, str) or value == "":
        raise ValidationError("JSON input field must be a non-empty string.", target=field)
    return value


def _required_json_list(payload: dict[str, Any], field: str) -> list[Any]:
    value = payload.get(field)
    if not isinstance(value, list):
        raise ValidationError("JSON input field must be a list.", target=field)
    return value


def _context_updates(args: Namespace) -> dict[str, Any]:
    updates: dict[str, Any] = {}
    for attr in (
        "session_id",
        "actor_id",
        "locale",
        "timezone",
        "current_route",
        "current_panel",
        "active_evidence_id",
        "active_keyword_set_id",
        "active_keyword_set_version",
        "active_search_execution_id",
        "active_timeline_revision",
        "expires_at",
    ):
        value = getattr(args, attr, None)
        if value is not None:
            updates[attr] = value
    if args.scope is not None:
        updates["active_context_scope"] = args.scope
    if args.filters_json is not None:
        updates["active_filters"] = _json_arg(args.filters_json, "filters_json")
    if args.sort_json is not None:
        updates["active_sort"] = _json_arg(args.sort_json, "sort_json")
    if args.time_range_json is not None:
        updates["active_time_range"] = _json_arg(args.time_range_json, "time_range_json")
    if args.ui_preferences_json is not None:
        updates["ui_preferences"] = _json_arg(args.ui_preferences_json, "ui_preferences_json")
    return updates


def _parse_algorithm(value: str) -> HashAlgorithm:
    normalized = value.replace("-", "").replace("_", "").upper()
    aliases = {
        "MD5": HashAlgorithm.MD5,
        "SHA1": HashAlgorithm.SHA1,
        "SHA256": HashAlgorithm.SHA256,
    }
    try:
        return aliases[normalized]
    except KeyError as error:
        raise ValidationError("Unsupported hash algorithm.", target="algorithm") from error


def _default_analyzers(values: list[str], default_analyzer: str) -> list[str]:
    return values if values else [default_analyzer]


def _parse_artifact_types(values: list[str]) -> list[ArtifactType]:
    artifact_types: list[ArtifactType] = []
    for value in values:
        parsed = _parse_artifact_type(value)
        if parsed is not None:
            artifact_types.append(parsed)
    return artifact_types


def _parse_artifact_type(value: str | None) -> ArtifactType | None:
    if value is None:
        return None
    normalized = value.replace(".", "_").replace("-", "_").upper()
    try:
        return ArtifactType(normalized)
    except ValueError as error:
        raise ValidationError("Unsupported artifact type.", target="artifact_type") from error


def _parse_search_source_type(value: str) -> SearchSourceType:
    normalized = value.replace("-", "_").replace(".", "_").upper()
    try:
        return SearchSourceType(normalized)
    except ValueError as error:
        raise ValidationError("Unsupported search source type.", target="source_type") from error


def _parse_search_document_type(value: str) -> SearchDocumentType:
    normalized = value.replace("-", "_").replace(".", "_").upper()
    try:
        return SearchDocumentType(normalized)
    except ValueError as error:
        raise ValidationError(
            "Unsupported search document type.",
            target="document_type",
        ) from error


def _parse_keyword_type(value: str) -> KeywordType:
    normalized = value.replace("-", "_").replace(".", "_").upper()
    try:
        return KeywordType(normalized)
    except ValueError as error:
        raise ValidationError("Unsupported keyword type.", target="keyword_type") from error


def _parse_keyword_match_mode(value: str) -> KeywordMatchMode:
    normalized = value.replace("-", "_").replace(".", "_").upper()
    try:
        return KeywordMatchMode(normalized)
    except ValueError as error:
        raise ValidationError("Unsupported keyword match mode.", target="match_mode") from error


def _parse_timeline_source_type(value: str) -> TimelineSourceType:
    normalized = value.replace("-", "_").replace(".", "_").upper()
    try:
        return TimelineSourceType(normalized)
    except ValueError as error:
        raise ValidationError("Unsupported timeline source type.", target="source_type") from error


def _parse_timeline_event_type(value: str) -> TimelineEventType:
    normalized = value.replace("-", "_").replace(".", "_").upper()
    try:
        return TimelineEventType(normalized)
    except ValueError as error:
        raise ValidationError("Unsupported timeline event type.", target="event_type") from error


def _parse_timezone_confidence(value: str) -> TimezoneConfidence:
    normalized = value.replace("-", "_").replace(".", "_").upper()
    try:
        return TimezoneConfidence(normalized)
    except ValueError as error:
        raise ValidationError("Unsupported timezone confidence.", target="confidence") from error


def _parse_parse_status(value: str | None) -> ArtifactParseStatus | None:
    if value is None:
        return None
    try:
        return ArtifactParseStatus(value.upper())
    except ValueError as error:
        raise ValidationError(
            "Unsupported artifact parse status.", target="parse_status"
        ) from error


def _parse_timestamp_arg(value: str | None, target: str) -> Any:
    if value is None:
        return None
    try:
        from apex_forensic._time import parse_timestamp

        return parse_timestamp(value)
    except ValueError as error:
        raise ValidationError("Invalid timestamp.", target=target) from error


def _artifact_query(args: Namespace) -> ArtifactQuery:
    return ArtifactQuery(
        case_id=args.case_id,
        evidence_id=getattr(args, "evidence_id", None),
        source_file_node_id=getattr(args, "source_node_id", None),
        artifact_type=_parse_artifact_type(getattr(args, "artifact_type", None)),
        artifact_subtype=getattr(args, "artifact_subtype", None),
        analyzer_id=getattr(args, "analyzer", None),
        event_id=getattr(args, "event_id", None),
        registry_path=getattr(args, "registry_path", None),
        executable_name=getattr(args, "executable_name", None),
        media_kind=_parse_media_kind(getattr(args, "media_kind", None)),
        browser_profile=getattr(args, "browser_profile", None),
        browser_database=getattr(args, "browser_database", None),
        browser_table=getattr(args, "browser_table", None),
        browser_row_id=getattr(args, "browser_row_id", None),
        observed_from=_parse_timestamp_arg(getattr(args, "observed_from", None), "observed_from"),
        observed_to=_parse_timestamp_arg(getattr(args, "observed_to", None), "observed_to"),
        parse_status=_parse_parse_status(getattr(args, "parse_status", None)),
        has_warnings=True if getattr(args, "has_warnings", False) else None,
        cursor=getattr(args, "cursor", None),
        limit=getattr(args, "limit", 100),
    )


def _replace_query_artifact_type(
    query: ArtifactQuery, artifact_type: ArtifactType
) -> ArtifactQuery:
    return ArtifactQuery(
        case_id=query.case_id,
        evidence_id=query.evidence_id,
        source_file_node_id=query.source_file_node_id,
        artifact_type=artifact_type,
        artifact_subtype=query.artifact_subtype,
        analyzer_id=query.analyzer_id,
        event_id=query.event_id,
        registry_path=query.registry_path,
        executable_name=query.executable_name,
        media_kind=query.media_kind,
        browser_profile=query.browser_profile,
        browser_database=query.browser_database,
        browser_table=query.browser_table,
        browser_row_id=query.browser_row_id,
        observed_from=query.observed_from,
        observed_to=query.observed_to,
        parse_status=query.parse_status,
        has_warnings=query.has_warnings,
        limit=query.limit,
        cursor=query.cursor,
    )


def _parse_media_kind(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = value.replace("-", "_").replace(".", "_").upper()
    if normalized not in {"IMAGE", "VIDEO", "AUDIO"}:
        raise ValidationError("Unsupported media kind.", target="media_kind")
    return normalized


def _json_requested(args: Namespace) -> bool:
    return bool(getattr(args, "json", False))


def _emit(args: Namespace, result: Any) -> None:
    if _json_requested(args):
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return
    if isinstance(result, list):
        for item in result:
            print(_human_line(item))
        return
    print(_human_line(result))


def _human_line(value: Any) -> str:
    if isinstance(value, dict):
        if "id" in value and "name" in value:
            return f"{value['id']}  {value['name']}"
        if "id" in value and "display_name" in value:
            return f"{value['id']}  {value['display_name']}"
        if "event_id" in value:
            return f"{value['immutable_revision']}  {value['event_type']}  {value['event_hash']}"
        if "hash" in value:
            return f"{value['hash']['algorithm']}  {value['hash']['digest']}"
        if "verification" in value:
            return f"{value['verification']['algorithm']}  {value['verification']['status']}"
        if "node_type" in value and "display_path" in value:
            return f"{value['node_type']}  {value['display_path']}"
        if "items" in value and "page" in value:
            return json.dumps(value, ensure_ascii=False)
        if "artifact_id" in value and "artifact_type" in value:
            return f"{value['artifact_type']}  {value['title']}"
        return json.dumps(value, ensure_ascii=False)
    return str(value)
