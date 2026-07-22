"""CLI command handlers."""

from __future__ import annotations

import json
import sys
from argparse import Namespace
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from apex_forensic.config import build_services
from apex_forensic.domain.enums import (
    AnalysisProfileType,
    CaseStatus,
    CustodyEventType,
    HashAlgorithm,
)
from apex_forensic.domain.errors import ApexError, ValidationError

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
    raise ValidationError("Unknown filesystem command.", target="fs_command")


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
        return json.dumps(value, ensure_ascii=False)
    return str(value)
