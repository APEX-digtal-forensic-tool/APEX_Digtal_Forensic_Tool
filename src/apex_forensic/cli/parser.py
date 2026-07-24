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

    media_parser = artifact_commands.add_parser("media", help="Media artifact helpers")
    media_commands = media_parser.add_subparsers(dest="media_command", required=True)
    media_list = media_commands.add_parser("list")
    _add_artifact_query_args(media_list, artifact_type_required=False)
    media_show = media_commands.add_parser("show")
    media_show.add_argument("--artifact-id", required=True)
    media_show.add_argument("--json", action="store_true")

    browser_parser = artifact_commands.add_parser("browser", help="Browser artifact helpers")
    browser_commands = browser_parser.add_subparsers(dest="browser_command", required=True)
    for command_name in ("profiles", "visits", "searches", "downloads"):
        browser_command = browser_commands.add_parser(command_name)
        _add_artifact_query_args(browser_command, artifact_type_required=False)
    browser_show = browser_commands.add_parser("show")
    browser_show.add_argument("--artifact-id", required=True)
    browser_show.add_argument("--json", action="store_true")

    browser_top = subcommands.add_parser("browser", help="Browser artifact commands")
    browser_top_commands = browser_top.add_subparsers(dest="browser_command", required=True)
    browser_discover = browser_top_commands.add_parser("discover")
    _add_artifact_scope_args(browser_discover, include_case=True)
    browser_discover.add_argument("--batch-size", type=int, default=100)
    browser_discover.add_argument("--json", action="store_true")
    browser_analyze = browser_top_commands.add_parser("analyze")
    _add_artifact_scope_args(browser_analyze, include_case=True)
    browser_analyze.add_argument("--item-budget", type=int)
    browser_analyze.add_argument("--batch-size", type=int, default=100)
    browser_analyze.add_argument("--json", action="store_true")
    browser_status = browser_top_commands.add_parser("status")
    browser_status.add_argument("--job-id", required=True)
    browser_status.add_argument("--json", action="store_true")
    browser_resume = browser_top_commands.add_parser("resume")
    browser_resume.add_argument("--job-id", required=True)
    browser_resume.add_argument("--item-budget", type=int)
    browser_resume.add_argument("--json", action="store_true")
    browser_cancel = browser_top_commands.add_parser("cancel")
    browser_cancel.add_argument("--job-id", required=True)
    browser_cancel.add_argument("--json", action="store_true")
    for command_name in ("profiles", "history", "searches", "downloads"):
        browser_query = browser_top_commands.add_parser(command_name)
        _add_artifact_query_args(browser_query, artifact_type_required=False)
    browser_show = browser_top_commands.add_parser("show")
    browser_show.add_argument("--artifact-id", required=True)
    browser_show.add_argument("--json", action="store_true")
    browser_warnings = browser_top_commands.add_parser("warnings")
    browser_warnings.add_argument("--job-id")
    browser_warnings.add_argument("--artifact-id")
    browser_warnings.add_argument("--evidence-id")
    browser_warnings.add_argument("--json", action="store_true")

    media_top = subcommands.add_parser("media", help="Media artifact commands")
    media_top_commands = media_top.add_subparsers(dest="media_command", required=True)
    media_discover = media_top_commands.add_parser("discover")
    _add_artifact_scope_args(media_discover, include_case=True)
    media_discover.add_argument("--batch-size", type=int, default=100)
    media_discover.add_argument("--json", action="store_true")
    media_analyze = media_top_commands.add_parser("analyze")
    _add_artifact_scope_args(media_analyze, include_case=True)
    media_analyze.add_argument("--item-budget", type=int)
    media_analyze.add_argument("--batch-size", type=int, default=100)
    media_analyze.add_argument("--json", action="store_true")
    media_status = media_top_commands.add_parser("status")
    media_status.add_argument("--job-id", required=True)
    media_status.add_argument("--json", action="store_true")
    media_resume = media_top_commands.add_parser("resume")
    media_resume.add_argument("--job-id", required=True)
    media_resume.add_argument("--item-budget", type=int)
    media_resume.add_argument("--json", action="store_true")
    media_cancel = media_top_commands.add_parser("cancel")
    media_cancel.add_argument("--job-id", required=True)
    media_cancel.add_argument("--json", action="store_true")
    media_list = media_top_commands.add_parser("list")
    _add_artifact_query_args(media_list, artifact_type_required=False)
    media_show = media_top_commands.add_parser("show")
    media_show.add_argument("--artifact-id", required=True)
    media_show.add_argument("--json", action="store_true")
    media_thumbnail = media_top_commands.add_parser("thumbnail")
    media_thumbnail.add_argument("--artifact-id", required=True)
    media_thumbnail.add_argument("--json", action="store_true")
    media_warnings = media_top_commands.add_parser("warnings")
    media_warnings.add_argument("--job-id")
    media_warnings.add_argument("--artifact-id")
    media_warnings.add_argument("--evidence-id")
    media_warnings.add_argument("--json", action="store_true")

    candidate_parser = subcommands.add_parser(
        "candidate", help="Machine-extracted candidate commands"
    )
    candidate_commands = candidate_parser.add_subparsers(dest="candidate_command", required=True)
    candidate_list = candidate_commands.add_parser("list")
    candidate_list.add_argument("--case-id", required=True)
    candidate_list.add_argument("--evidence-id")
    candidate_list.add_argument("--review-status")
    candidate_list.add_argument("--cursor")
    candidate_list.add_argument("--limit", type=int, default=100)
    candidate_list.add_argument("--json", action="store_true")
    candidate_show = candidate_commands.add_parser("show")
    candidate_show.add_argument("--candidate-id", required=True)
    candidate_show.add_argument("--json", action="store_true")
    candidate_review = candidate_commands.add_parser("review")
    candidate_review.add_argument("--candidate-id", required=True)
    candidate_review.add_argument("--status", required=True, choices=["ACCEPTED", "REJECTED"])
    candidate_review.add_argument("--reviewed-by", required=True)
    candidate_review.add_argument("--reason")
    candidate_review.add_argument("--json", action="store_true")
    candidate_correct = candidate_commands.add_parser("correct")
    candidate_correct.add_argument("--candidate-id", required=True)
    candidate_correct.add_argument("--reviewed-by", required=True)
    candidate_correct.add_argument("--correction-text", required=True)
    candidate_correct.add_argument("--reason")
    candidate_correct.add_argument("--json", action="store_true")
    candidate_capabilities = candidate_commands.add_parser("capabilities")
    candidate_capabilities.add_argument("--type")
    candidate_capabilities.add_argument("--json", action="store_true")

    search_parser = subcommands.add_parser("search", help="Search index and query commands")
    search_commands = search_parser.add_subparsers(dest="search_command", required=True)
    search_index = search_commands.add_parser("index", help="Build metadata/artifact search index")
    search_index.add_argument("--case-id", required=True)
    search_index.add_argument("--evidence-id", action="append", default=[])
    search_index.add_argument("--source-type", action="append", default=[])
    search_index.add_argument(
        "--profile",
        default="QUICK_TRIAGE",
        choices=["QUICK_TRIAGE", "SELECTED_SCOPE", "FULL_ANALYSIS", "CUSTOM"],
    )
    search_index.add_argument("--item-budget", type=int)
    search_index.add_argument("--batch-size", type=int, default=100)
    search_index.add_argument("--json", action="store_true")

    search_status = search_commands.add_parser("index-status", help="Show search index job status")
    search_status.add_argument("--job-id", required=True)
    search_status.add_argument("--json", action="store_true")

    search_resume = search_commands.add_parser("resume", help="Resume a search index job")
    search_resume.add_argument("--job-id", required=True)
    search_resume.add_argument("--item-budget", type=int)
    search_resume.add_argument("--json", action="store_true")

    search_cancel = search_commands.add_parser("cancel", help="Cancel a search index job")
    search_cancel.add_argument("--job-id", required=True)
    search_cancel.add_argument("--json", action="store_true")

    search_query = search_commands.add_parser("query", help="Execute a search")
    search_query.add_argument("--case-id", required=True)
    search_query.add_argument("--query", required=True)
    search_query.add_argument(
        "--mode",
        default="TERM",
        choices=["TERM", "PHRASE", "PREFIX", "EXACT", "REGEX_METADATA"],
    )
    search_query.add_argument("--evidence-id", action="append", default=[])
    search_query.add_argument("--source-type", action="append", default=[])
    search_query.add_argument("--document-type", action="append", default=[])
    search_query.add_argument("--keyword-set-id")
    search_query.add_argument("--keyword-set-version", type=int)
    search_query.add_argument("--time-from")
    search_query.add_argument("--time-to")
    search_query.add_argument("--path-scope")
    search_query.add_argument("--case-sensitive", action="store_true")
    search_query.add_argument("--cursor")
    search_query.add_argument("--limit", type=int, default=100)
    search_query.add_argument("--sort", default="rank")
    search_query.add_argument("--no-cache", action="store_true")
    search_query.add_argument("--json", action="store_true")

    search_show = search_commands.add_parser("show", help="Show a search execution")
    search_show.add_argument("--execution-id", required=True)
    search_show.add_argument("--limit", type=int, default=100)
    search_show.add_argument("--json", action="store_true")

    search_history = search_commands.add_parser("history", help="List search execution history")
    search_history.add_argument("--case-id", required=True)
    search_history.add_argument("--limit", type=int, default=100)
    search_history.add_argument("--json", action="store_true")

    search_rerun = search_commands.add_parser("rerun", help="Rerun a search execution")
    search_rerun.add_argument("--execution-id", required=True)
    search_rerun.add_argument("--no-cache", action="store_true")
    search_rerun.add_argument("--json", action="store_true")

    search_cache = search_commands.add_parser("cache-status", help="Show search cache status")
    search_cache.add_argument("--case-id", required=True)
    search_cache.add_argument("--json", action="store_true")

    search_rebuild = search_commands.add_parser("rebuild", help="Rebuild the FTS search index")
    search_rebuild.add_argument("--case-id")
    search_rebuild.add_argument("--json", action="store_true")

    keyword_parser = subcommands.add_parser("keyword-set", help="Keyword set commands")
    keyword_commands = keyword_parser.add_subparsers(dest="keyword_command", required=True)
    keyword_create = keyword_commands.add_parser("create", help="Create a keyword set")
    keyword_create.add_argument("--case-id", required=True)
    keyword_create.add_argument("--name", required=True)
    keyword_create.add_argument("--description")
    keyword_create.add_argument("--created-by")
    keyword_create.add_argument("--keyword", action="append", default=[])
    keyword_create.add_argument("--json", action="store_true")

    keyword_list = keyword_commands.add_parser("list", help="List keyword sets")
    keyword_list.add_argument("--case-id", required=True)
    keyword_list.add_argument("--status", choices=["DRAFT", "ACTIVE", "ARCHIVED"])
    keyword_list.add_argument("--json", action="store_true")

    keyword_show = keyword_commands.add_parser("show", help="Show a keyword set")
    keyword_show.add_argument("--keyword-set-id", required=True)
    keyword_show.add_argument("--version", type=int)
    keyword_show.add_argument("--json", action="store_true")

    keyword_add = keyword_commands.add_parser("add", help="Add a keyword")
    keyword_add.add_argument("--keyword-set-id", required=True)
    keyword_add.add_argument("--term", required=True)
    keyword_add.add_argument("--keyword-type", default="OTHER")
    keyword_add.add_argument("--match-mode", default="TERM")
    keyword_add.add_argument("--case-sensitive", action="store_true")
    keyword_add.add_argument("--disabled", action="store_true")
    keyword_add.add_argument("--notes")
    keyword_add.add_argument("--source", default="ANALYST")
    keyword_add.add_argument("--json", action="store_true")

    keyword_remove = keyword_commands.add_parser("remove", help="Remove a keyword")
    keyword_remove.add_argument("--keyword-set-id", required=True)
    keyword_remove.add_argument("--keyword-id", required=True)
    keyword_remove.add_argument("--json", action="store_true")

    for command_name in ("activate", "archive", "version"):
        keyword_command = keyword_commands.add_parser(command_name)
        keyword_command.add_argument("--keyword-set-id", required=True)
        keyword_command.add_argument("--json", action="store_true")

    timeline_parser = subcommands.add_parser("timeline", help="Timeline commands")
    timeline_commands = timeline_parser.add_subparsers(dest="timeline_command", required=True)
    timeline_build = timeline_commands.add_parser("build", help="Build timeline events")
    timeline_build.add_argument("--case-id", required=True)
    timeline_build.add_argument("--evidence-id")
    timeline_build.add_argument("--source-type", action="append", default=[])
    timeline_build.add_argument(
        "--profile",
        default="QUICK_TRIAGE",
        choices=["QUICK_TRIAGE", "SELECTED_SCOPE", "FULL_ANALYSIS", "CUSTOM"],
    )
    timeline_build.add_argument("--item-budget", type=int)
    timeline_build.add_argument("--batch-size", type=int, default=100)
    timeline_build.add_argument("--json", action="store_true")

    timeline_status = timeline_commands.add_parser("status", help="Show timeline job status")
    timeline_status.add_argument("--job-id", required=True)
    timeline_status.add_argument("--json", action="store_true")

    timeline_resume = timeline_commands.add_parser("resume", help="Resume a timeline job")
    timeline_resume.add_argument("--job-id", required=True)
    timeline_resume.add_argument("--item-budget", type=int)
    timeline_resume.add_argument("--json", action="store_true")

    timeline_cancel = timeline_commands.add_parser("cancel", help="Cancel a timeline job")
    timeline_cancel.add_argument("--job-id", required=True)
    timeline_cancel.add_argument("--json", action="store_true")

    timeline_list = timeline_commands.add_parser("list", help="List timeline events")
    timeline_list.add_argument("--case-id", required=True)
    timeline_list.add_argument("--evidence-id")
    timeline_list.add_argument("--source-type", action="append", default=[])
    timeline_list.add_argument("--event-type", action="append", default=[])
    timeline_list.add_argument("--analyzer")
    timeline_list.add_argument("--keyword")
    timeline_list.add_argument("--path")
    timeline_list.add_argument("--artifact-type")
    timeline_list.add_argument("--partial", action="store_true")
    timeline_list.add_argument("--confidence")
    timeline_list.add_argument("--time-from")
    timeline_list.add_argument("--time-to")
    timeline_list.add_argument("--timezone")
    timeline_list.add_argument("--cursor")
    timeline_list.add_argument("--limit", type=int, default=100)
    timeline_list.add_argument("--order", default="ASC", choices=["ASC", "DESC", "asc", "desc"])
    timeline_list.add_argument("--json", action="store_true")

    timeline_show = timeline_commands.add_parser("show", help="Show one timeline event")
    timeline_show.add_argument("--timeline-event-id", required=True)
    timeline_show.add_argument("--json", action="store_true")

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
    parser.add_argument("--media-kind")
    parser.add_argument("--browser-profile")
    parser.add_argument("--browser-database")
    parser.add_argument("--browser-table")
    parser.add_argument("--browser-row-id", type=int)
    parser.add_argument("--observed-from")
    parser.add_argument("--observed-to")
    parser.add_argument("--parse-status")
    parser.add_argument("--has-warnings", action="store_true")
    parser.add_argument("--cursor")
    parser.add_argument("--limit", type=int, default=100)
    parser.add_argument("--json", action="store_true")
