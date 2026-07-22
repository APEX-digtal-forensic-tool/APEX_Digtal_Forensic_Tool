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
