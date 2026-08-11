"""Command line interface entry point with dependency-light diagnostics."""

from __future__ import annotations

import sys
from collections.abc import Sequence


def main(argv: Sequence[str] | None = None) -> int:
    """Dispatch diagnostics before importing the dependency-heavy engine CLI."""

    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments and arguments[0] == "doctor":
        from apex_forensic.runtime.capabilities import doctor_main

        return doctor_main(arguments[1:])
    if arguments and arguments[0] == "benchmark":
        from apex_forensic.runtime.benchmark import benchmark_main

        return benchmark_main(arguments[1:])
    from apex_forensic.cli.commands import main as command_main

    return command_main(arguments)


__all__ = ["main"]
