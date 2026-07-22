"""argparse parser construction."""

from __future__ import annotations

import argparse
from pathlib import Path


def build_parser() -> argparse.ArgumentParser:
    """Build the Phase 1 CLI parser."""

    parser = argparse.ArgumentParser(prog="apex-forensic")
    parser.add_argument("--db", type=Path, default=Path("./apex.db"), help="SQLite database path")
    subcommands = parser.add_subparsers(dest="command", required=True)

    init_parser = subcommands.add_parser("init", help="Initialize the SQLite database")
    init_parser.add_argument(
        "--db",
        dest="init_db",
        type=Path,
        default=None,
        help="SQLite database path",
    )
    init_parser.add_argument("--json", action="store_true", help="Emit JSON")

    case_parser = subcommands.add_parser("case", help="Case commands")
    case_commands = case_parser.add_subparsers(dest="case_command", required=True)
    case_create = case_commands.add_parser("create", help="Create a case")
    case_create.add_argument("--name", required=True)
    case_create.add_argument("--investigator")
    case_create.add_argument("--description")
    case_create.add_argument("--locale", default="ko-KR")
    case_create.add_argument("--timezone", default="Asia/Seoul")
    case_create.add_argument("--json", action="store_true")

    case_list = case_commands.add_parser("list", help="List cases")
    case_list.add_argument("--json", action="store_true")

    case_show = case_commands.add_parser("show", help="Show a case")
    case_show.add_argument("case_id")
    case_show.add_argument("--json", action="store_true")

    case_status = case_commands.add_parser("set-status", help="Change case status")
    case_status.add_argument("case_id")
    case_status.add_argument("--status", required=True, choices=["OPEN", "CLOSED", "ARCHIVED"])
    case_status.add_argument("--json", action="store_true")

    evidence_parser = subcommands.add_parser("evidence", help="Evidence commands")
    evidence_commands = evidence_parser.add_subparsers(dest="evidence_command", required=True)
    evidence_add = evidence_commands.add_parser("add", help="Register evidence")
    evidence_add.add_argument("--case-id", required=True)
    evidence_add.add_argument("--path", type=Path, required=True)
    evidence_add.add_argument("--display-name")
    evidence_add.add_argument("--json", action="store_true")

    evidence_list = evidence_commands.add_parser("list", help="List evidence")
    evidence_list.add_argument("--case-id", required=True)
    evidence_list.add_argument("--json", action="store_true")

    evidence_show = evidence_commands.add_parser("show", help="Show evidence")
    evidence_show.add_argument("evidence_id")
    evidence_show.add_argument("--json", action="store_true")

    evidence_hash = evidence_commands.add_parser("hash", help="Calculate evidence hash")
    evidence_hash.add_argument("--evidence-id", required=True)
    evidence_hash.add_argument("--algorithm", default="sha256")
    evidence_hash.add_argument("--chunk-size", type=int, default=1024 * 1024)
    evidence_hash.add_argument("--json", action="store_true")

    evidence_verify = evidence_commands.add_parser("verify", help="Verify evidence hash")
    evidence_verify.add_argument("--evidence-id", required=True)
    evidence_verify.add_argument("--algorithm", default="sha256")
    evidence_verify.add_argument("--chunk-size", type=int, default=1024 * 1024)
    evidence_verify.add_argument("--json", action="store_true")

    evidence_index = evidence_commands.add_parser("index", help="Index filesystem metadata")
    evidence_index.add_argument("--case-id", required=True)
    evidence_index.add_argument("--evidence-id", required=True)
    evidence_index.add_argument(
        "--profile",
        default="QUICK_TRIAGE",
        choices=["QUICK_TRIAGE", "SELECTED_SCOPE", "FULL_ANALYSIS", "CUSTOM"],
    )
    evidence_index.add_argument("--max-depth", type=int)
    evidence_index.add_argument("--item-budget", type=int)
    evidence_index.add_argument("--batch-size", type=int, default=100)
    evidence_index.add_argument("--max-queue-size", type=int, default=100_000)
    evidence_index.add_argument("--selected-path", action="append", default=[])
    evidence_index.add_argument("--selected-node-id", action="append", default=[])
    evidence_index.add_argument("--include", action="append", default=[])
    evidence_index.add_argument("--exclude", action="append", default=[])
    evidence_index.add_argument("--json", action="store_true")

    evidence_index_status = evidence_commands.add_parser(
        "index-status", help="Show index job status"
    )
    evidence_index_status.add_argument("--job-id", required=True)
    evidence_index_status.add_argument("--json", action="store_true")

    evidence_index_resume = evidence_commands.add_parser("index-resume", help="Resume an index job")
    evidence_index_resume.add_argument("--job-id", required=True)
    evidence_index_resume.add_argument("--item-budget", type=int)
    evidence_index_resume.add_argument("--json", action="store_true")

    evidence_index_cancel = evidence_commands.add_parser("index-cancel", help="Cancel an index job")
    evidence_index_cancel.add_argument("--job-id", required=True)
    evidence_index_cancel.add_argument("--json", action="store_true")

    fs_parser = subcommands.add_parser("fs", help="Filesystem tree commands")
    fs_commands = fs_parser.add_subparsers(dest="fs_command", required=True)
    fs_roots = fs_commands.add_parser("roots", help="List indexed root nodes")
    fs_roots.add_argument("--evidence-id", required=True)
    fs_roots.add_argument("--json", action="store_true")

    fs_list = fs_commands.add_parser("list", help="List filesystem nodes")
    fs_list.add_argument("--evidence-id", required=True)
    fs_list.add_argument("--parent-node-id")
    fs_list.add_argument("--all", action="store_true", dest="all_nodes")
    fs_list.add_argument("--directories-only", action="store_true")
    fs_list.add_argument("--files-only", action="store_true")
    fs_list.add_argument("--extension")
    fs_list.add_argument("--filter")
    fs_list.add_argument("--cursor")
    fs_list.add_argument("--limit", type=int, default=100)
    fs_list.add_argument("--json", action="store_true")

    fs_show = fs_commands.add_parser("show", help="Show one filesystem node")
    fs_show.add_argument("--node-id", required=True)
    fs_show.add_argument("--json", action="store_true")

    fs_prioritize = fs_commands.add_parser("prioritize", help="Prioritize a directory node")
    fs_prioritize.add_argument("--job-id", required=True)
    fs_prioritize.add_argument("--node-id", required=True)
    fs_prioritize.add_argument("--priority", type=int, default=0)
    fs_prioritize.add_argument("--json", action="store_true")

    artifact_parser = subcommands.add_parser("artifact", help="Windows artifact commands")
    artifact_commands = artifact_parser.add_subparsers(dest="artifact_command", required=True)
    artifact_discover = artifact_commands.add_parser("discover", help="Discover artifact sources")
    _add_artifact_scope_args(artifact_discover, include_case=True)
    artifact_discover.add_argument("--batch-size", type=int, default=100)
    artifact_discover.add_argument("--json", action="store_true")

    artifact_analyze = artifact_commands.add_parser("analyze", help="Analyze artifact sources")
    _add_artifact_scope_args(artifact_analyze, include_case=True)
    artifact_analyze.add_argument("--item-budget", type=int)
    artifact_analyze.add_argument("--batch-size", type=int, default=100)
    artifact_analyze.add_argument("--json", action="store_true")

    artifact_status = artifact_commands.add_parser("status", help="Show artifact job status")
    artifact_status.add_argument("--job-id", required=True)
    artifact_status.add_argument("--json", action="store_true")

    artifact_resume = artifact_commands.add_parser("resume", help="Resume an artifact job")
    artifact_resume.add_argument("--job-id", required=True)
    artifact_resume.add_argument("--item-budget", type=int)
    artifact_resume.add_argument("--json", action="store_true")

    artifact_cancel = artifact_commands.add_parser("cancel", help="Cancel an artifact job")
    artifact_cancel.add_argument("--job-id", required=True)
    artifact_cancel.add_argument("--json", action="store_true")

    artifact_list = artifact_commands.add_parser("list", help="List artifacts")
    _add_artifact_query_args(artifact_list)

    artifact_show = artifact_commands.add_parser("show", help="Show one artifact")
    artifact_show.add_argument("--artifact-id", required=True)
    artifact_show.add_argument("--json", action="store_true")

    artifact_warnings = artifact_commands.add_parser("warnings", help="List artifact warnings")
    artifact_warnings.add_argument("--job-id")
    artifact_warnings.add_argument("--artifact-id")
    artifact_warnings.add_argument("--evidence-id")
    artifact_warnings.add_argument("--json", action="store_true")

    registry_parser = artifact_commands.add_parser("registry", help="Registry artifact helpers")
    registry_commands = registry_parser.add_subparsers(dest="registry_command", required=True)
    for command_name in ("autoruns", "usb", "timezone", "userassist"):
        registry_command = registry_commands.add_parser(command_name)
        _add_artifact_query_args(registry_command, artifact_type_required=False)

    eventlog_parser = artifact_commands.add_parser("eventlog", help="Event Log artifact helpers")
    eventlog_commands = eventlog_parser.add_subparsers(dest="eventlog_command", required=True)
    eventlog_list = eventlog_commands.add_parser("list")
    _add_artifact_query_args(eventlog_list, artifact_type_required=False)
    eventlog_show = eventlog_commands.add_parser("show")
    eventlog_show.add_argument("--artifact-id", required=True)
    eventlog_show.add_argument("--json", action="store_true")

    prefetch_parser = artifact_commands.add_parser("prefetch", help="Prefetch artifact helpers")
    prefetch_commands = prefetch_parser.add_subparsers(dest="prefetch_command", required=True)
    prefetch_list = prefetch_commands.add_parser("list")
    _add_artifact_query_args(prefetch_list, artifact_type_required=False)
    prefetch_show = prefetch_commands.add_parser("show")
    prefetch_show.add_argument("--artifact-id", required=True)
    prefetch_show.add_argument("--json", action="store_true")

    custody_parser = subcommands.add_parser("custody", help="Custody commands")
    custody_commands = custody_parser.add_subparsers(dest="custody_command", required=True)
    custody_list = custody_commands.add_parser("list", help="List custody events")
    custody_list.add_argument("--evidence-id", required=True)
    custody_list.add_argument("--json", action="store_true")

    custody_verify = custody_commands.add_parser("verify-chain", help="Verify custody hash chain")
    custody_verify.add_argument("--evidence-id", required=True)
    custody_verify.add_argument("--json", action="store_true")

    custody_add = custody_commands.add_parser("add", help="Append a custody event")
    custody_add.add_argument("--evidence-id", required=True)
    custody_add.add_argument("--event-type", required=True)
    custody_add.add_argument("--actor-name", required=True)
    custody_add.add_argument("--action", required=True)
    custody_add.add_argument("--reason")
    custody_add.add_argument("--correction-of-event-id")
    custody_add.add_argument("--json", action="store_true")

    return parser


def _add_artifact_scope_args(parser: argparse.ArgumentParser, *, include_case: bool) -> None:
    if include_case:
        parser.add_argument("--case-id", required=True)
    parser.add_argument("--evidence-id", required=True)
    parser.add_argument(
        "--profile",
        default="QUICK_TRIAGE",
        choices=["QUICK_TRIAGE", "SELECTED_SCOPE", "FULL_ANALYSIS", "CUSTOM"],
    )
    parser.add_argument("--analyzer", action="append", default=[])
    parser.add_argument("--artifact-type", action="append", default=[])
    parser.add_argument("--selected-path", action="append", default=[])
    parser.add_argument("--selected-node-id", action="append", default=[])
    parser.add_argument("--include", action="append", default=[])
    parser.add_argument("--exclude", action="append", default=[])


def _add_artifact_query_args(
    parser: argparse.ArgumentParser,
    *,
    artifact_type_required: bool = True,
) -> None:
    parser.add_argument("--case-id", required=True)
    parser.add_argument("--evidence-id")
    parser.add_argument("--source-node-id")
    del artifact_type_required
    parser.add_argument("--artifact-type")
    parser.add_argument("--artifact-subtype")
    parser.add_argument("--analyzer")
    parser.add_argument("--event-id", type=int)
    parser.add_argument("--registry-path")
    parser.add_argument("--executable-name")
    parser.add_argument("--observed-from")
    parser.add_argument("--observed-to")
    parser.add_argument("--parse-status")
    parser.add_argument("--has-warnings", action="store_true")
    parser.add_argument("--cursor")
    parser.add_argument("--limit", type=int, default=100)
    parser.add_argument("--json", action="store_true")
