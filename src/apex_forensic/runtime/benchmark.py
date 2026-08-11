"""Reproducible APEX Core Engine benchmark harness."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import platform
import sqlite3
import struct
import tempfile
import time
from collections.abc import Iterator, Sequence
from pathlib import Path
from typing import Any

from apex_forensic.constants import ENGINE_VERSION
from apex_forensic.runtime.capabilities import capability_report

SYNTHETIC_FIXTURE_ID = "apex-benchmark-synthetic-v1"
BENCHMARK_SCHEMA_VERSION = "1.0.0"
DEFAULT_SEARCH_ITERATIONS = 5
MAX_SEARCH_ITERATIONS = 100
MAX_RUNS = 10


def benchmark_main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="apex-forensic benchmark")
    parser.add_argument("--evidence", type=Path, help="Optional read-only evidence path")
    parser.add_argument(
        "--profile",
        choices=("BOTH", "QUICK_TRIAGE", "FULL_ANALYSIS"),
        default="BOTH",
    )
    parser.add_argument("--runs", type=int, default=1)
    parser.add_argument("--search-iterations", type=int, default=DEFAULT_SEARCH_ITERATIONS)
    parser.add_argument("--json", action="store_true", help="Emit structured JSON")
    args = parser.parse_args(argv)
    if not 1 <= args.runs <= MAX_RUNS:
        parser.error(f"--runs must be between 1 and {MAX_RUNS}")
    if not 1 <= args.search_iterations <= MAX_SEARCH_ITERATIONS:
        parser.error(f"--search-iterations must be between 1 and {MAX_SEARCH_ITERATIONS}")

    report = run_benchmark(
        evidence_path=args.evidence,
        profile=args.profile,
        runs=args.runs,
        search_iterations=args.search_iterations,
    )
    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    else:
        print(f"APEX benchmark: {report['status']}")
        for result in report.get("results", []):
            print(
                f"{result['profile']} run {result['run']}: "
                f"{result['elapsed_wall_seconds']:.6f}s, "
                f"{result['index']['indexed_files']} indexed files"
            )
    return 0 if report["status"] == "COMPLETED" else 1


def run_benchmark(
    *,
    evidence_path: Path | None,
    profile: str,
    runs: int,
    search_iterations: int,
) -> dict[str, Any]:
    runtime_capabilities = capability_report()
    try:
        from apex_forensic.config import build_services
        from apex_forensic.domain.enums import AnalysisProfileType
        from apex_forensic.domain.errors import ApexError
    except ModuleNotFoundError as error:
        return _unavailable_report(runtime_capabilities, error.name)

    profiles = (
        ["QUICK_TRIAGE", "FULL_ANALYSIS"] if profile == "BOTH" else [profile]
    )
    with tempfile.TemporaryDirectory(prefix="apex-benchmark-") as temporary_directory:
        temporary_root = Path(temporary_directory)
        if evidence_path is None:
            evidence = temporary_root / "fixture"
            _create_synthetic_fixture(evidence)
            fixture_id = SYNTHETIC_FIXTURE_ID
            fixture_kind = "DETERMINISTIC_SYNTHETIC"
        else:
            evidence = evidence_path.expanduser().resolve(strict=False)
            fixture_id = "user-provided-evidence"
            fixture_kind = "USER_PROVIDED_READ_ONLY"
        if not evidence.exists():
            return _failed_report(
                runtime_capabilities,
                "EVIDENCE_PATH_UNAVAILABLE",
                "The benchmark evidence path does not exist.",
            )
        try:
            fixture = _fingerprint_evidence(evidence)
        except OSError as error:
            return _failed_report(
                runtime_capabilities,
                "EVIDENCE_FINGERPRINT_FAILED",
                "The benchmark evidence fingerprint could not be calculated.",
                error_type=type(error).__name__,
            )
        initial_snapshot = _metadata_snapshot(evidence)
        results: list[dict[str, Any]] = []
        try:
            for profile_name in profiles:
                profile_type = AnalysisProfileType(profile_name)
                for run_number in range(1, runs + 1):
                    database = temporary_root / f"{profile_name.casefold()}-{run_number}.db"
                    results.append(
                        _run_once(
                            build_services=build_services,
                            profile_type=profile_type,
                            profile_name=profile_name,
                            run_number=run_number,
                            evidence=evidence,
                            database=database,
                            evidence_bytes=fixture["evidence_bytes"],
                            search_iterations=search_iterations,
                        )
                    )
        except ApexError as error:
            return _failed_report(
                runtime_capabilities,
                error.code,
                error.developer_message or "The benchmark engine operation failed.",
                error_type=type(error).__name__,
            )
        except (OSError, sqlite3.Error, ValueError) as error:
            return _failed_report(
                runtime_capabilities,
                "BENCHMARK_EXECUTION_FAILED",
                "The benchmark engine operation failed.",
                error_type=type(error).__name__,
            )
        final_snapshot = _metadata_snapshot(evidence)
        evidence_unchanged = initial_snapshot == final_snapshot
        status = "COMPLETED" if evidence_unchanged else "FAILED"
        return {
            "schema_version": BENCHMARK_SCHEMA_VERSION,
            "status": status,
            "engine_version": ENGINE_VERSION,
            "fixture": {
                "id": fixture_id,
                "kind": fixture_kind,
                "sha256": fixture["sha256"],
                "evidence_bytes": fixture["evidence_bytes"],
                "file_count": fixture["file_count"],
            },
            "configuration": {
                "profiles": profiles,
                "runs_per_profile": runs,
                "search_iterations": search_iterations,
                "cache_policy": "SEPARATE_COLD_AND_WARM_MEASUREMENTS",
                "database_policy": "FRESH_DATABASE_PER_PROFILE_RUN",
            },
            "environment": _benchmark_environment(runtime_capabilities),
            "read_only_invariant": {
                "evidence_unchanged": evidence_unchanged,
                "writes_to_evidence": False,
                "snapshot_entry_count": initial_snapshot["entry_count"],
            },
            "results": results,
            "comparative_superiority_claimed": False,
        }


def _run_once(
    *,
    build_services: Any,
    profile_type: Any,
    profile_name: str,
    run_number: int,
    evidence: Path,
    database: Path,
    evidence_bytes: int,
    search_iterations: int,
) -> dict[str, Any]:
    started = time.perf_counter()
    peak_before = _peak_rss_bytes()
    services = build_services(database)
    try:
        case = services.cases.create_case(
            name=f"APEX Benchmark {profile_name}",
            locale="ko-KR",
            timezone="Asia/Seoul",
        )
        registered = services.evidence.register_evidence(
            case_id=case.case_id,
            source_path=evidence,
            display_name="benchmark-evidence",
        )

        index_started = time.perf_counter()
        index_job, index_coverage = services.fs.index_evidence(
            case_id=case.case_id,
            evidence_id=registered.evidence_id,
            profile_type=profile_type,
            batch_size=100,
        )
        index_seconds = time.perf_counter() - index_started

        artifact_started = time.perf_counter()
        artifact_job, artifact_coverage = services.artifacts.analyze_evidence(
            case_id=case.case_id,
            evidence_id=registered.evidence_id,
            profile_type=profile_type,
            batch_size=100,
        )
        artifact_seconds = time.perf_counter() - artifact_started

        search_index_job, search_index_metrics = services.search.index(
            case_id=case.case_id,
            evidence_ids=[registered.evidence_id],
            profile_type=profile_type,
            batch_size=100,
        )
        cold_latencies = [
            _measure_search(services, case.case_id, use_cache=False)[0]
            for _ in range(search_iterations)
        ]
        populate_latency, populate_hit = _measure_search(
            services,
            case.case_id,
            use_cache=True,
        )
        warm_samples = [
            _measure_search(services, case.case_id, use_cache=True)
            for _ in range(search_iterations)
        ]
        warm_latencies = [sample[0] for sample in warm_samples]
        cache_hits = sum(sample[1] for sample in warm_samples) + int(populate_hit)
        cache_misses = len(cold_latencies) + int(not populate_hit)

        timeline_build_job, timeline_coverage = services.timeline.build(
            case_id=case.case_id,
            evidence_id=registered.evidence_id,
            profile_type=profile_type,
            batch_size=100,
        )
        timeline_started = time.perf_counter()
        timeline_page = services.timeline.list_events(case_id=case.case_id, limit=100)
        timeline_latency_ms = (time.perf_counter() - timeline_started) * 1000

        analyzer_counts = {
            str(row["analyzer_id"]): int(row["item_count"])
            for row in services.repository.connection.execute(
                """
                SELECT analyzer_id, COUNT(*) AS item_count
                FROM artifacts
                WHERE case_id = ?
                GROUP BY analyzer_id
                ORDER BY analyzer_id
                """,
                (case.case_id,),
            ).fetchall()
        }
        elapsed = time.perf_counter() - started
        peak_after = _peak_rss_bytes()
        return {
            "profile": profile_name,
            "run": run_number,
            "elapsed_wall_seconds": elapsed,
            "evidence_bytes": evidence_bytes,
            "index": {
                "status": index_job.status.value,
                "coverage_status": index_coverage.status.value,
                "discovered_files": index_coverage.discovered_items,
                "indexed_files": index_coverage.processed_items,
                "skipped_files": index_coverage.skipped_items,
                "elapsed_seconds": index_seconds,
                "items_per_second": _rate(index_coverage.processed_items, index_seconds),
                "evidence_bytes_per_second": _rate(evidence_bytes, index_seconds),
                "batch_size": 100,
                "warning_count": index_coverage.warning_count,
                "error_count": index_coverage.error_count,
            },
            "artifacts": {
                "status": artifact_job.status.value,
                "coverage_status": artifact_coverage.status.value,
                "source_count": artifact_coverage.source_count,
                "processed_sources": artifact_coverage.processed_sources,
                "artifact_count": artifact_coverage.artifact_count,
                "elapsed_seconds": artifact_seconds,
                "items_per_second": _rate(artifact_coverage.artifact_count, artifact_seconds),
                "analyzer_counts": analyzer_counts,
                "warning_count": artifact_coverage.warning_count,
                "error_count": artifact_coverage.error_count,
            },
            "search": {
                "index_status": search_index_job.status.value,
                "indexed_documents": int(search_index_metrics.get("indexed_items", 0)),
                "cold_cache": _latency_summary(cold_latencies),
                "cache_population_latency_ms": populate_latency,
                "warm_cache": _latency_summary(warm_latencies),
                "cache_hits": cache_hits,
                "cache_misses": cache_misses,
            },
            "timeline": {
                "build_status": timeline_build_job.status.value,
                "event_count": timeline_coverage.event_count,
                "returned_events": timeline_page.page.returned,
                "latency_ms": timeline_latency_ms,
                "warning_count": timeline_coverage.warning_count,
                "error_count": timeline_coverage.error_count,
            },
            "resources": {
                "peak_rss_bytes": peak_after,
                "peak_rss_delta_bytes": None
                if peak_after is None or peak_before is None
                else max(0, peak_after - peak_before),
                "sqlite_db_size_bytes": _database_size(database),
            },
            "warning_count": (
                index_coverage.warning_count
                + artifact_coverage.warning_count
                + timeline_coverage.warning_count
            ),
            "error_count": (
                index_coverage.error_count
                + artifact_coverage.error_count
                + timeline_coverage.error_count
            ),
        }
    finally:
        services.close()


def _measure_search(services: Any, case_id: str, *, use_cache: bool) -> tuple[float, bool]:
    started = time.perf_counter()
    result = services.search.query(
        case_id=case_id,
        query_text="apex",
        limit=100,
        use_cache=use_cache,
    )
    latency_ms = (time.perf_counter() - started) * 1000
    return latency_ms, bool(result.execution.cache_hit)


def _latency_summary(values: list[float]) -> dict[str, Any]:
    return {
        "samples": len(values),
        "latency_ms": values,
        "p50_ms": _percentile(values, 0.50),
        "p95_ms": _percentile(values, 0.95),
    }


def _percentile(values: list[float], percentile: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    index = max(0, math.ceil(percentile * len(ordered)) - 1)
    return ordered[index]


def _rate(items: int, seconds: float) -> float | None:
    return None if seconds <= 0 else items / seconds


def _database_size(path: Path) -> int:
    candidates = (
        path,
        path.with_name(path.name + "-wal"),
        path.with_name(path.name + "-shm"),
    )
    return sum(
        candidate.stat().st_size
        for candidate in candidates
        if candidate.exists()
    )


def _peak_rss_bytes() -> int | None:
    if platform.system() == "Windows":
        return _windows_peak_rss_bytes()

    try:
        import resource
    except ImportError:
        return None

    resource_api = vars(resource)
    getrusage = resource_api.get("getrusage")
    rusage_self = resource_api.get("RUSAGE_SELF")
    if not callable(getrusage) or rusage_self is None:
        return None

    observed = int(getrusage(rusage_self).ru_maxrss)
    return observed if platform.system() == "Darwin" else observed * 1024


def _windows_peak_rss_bytes() -> int | None:
    try:
        import ctypes
    except ImportError:
        return None

    ctypes_api = vars(ctypes)
    win_dll = ctypes_api.get("WinDLL")
    if not callable(win_dll):
        return None

    class ProcessMemoryCounters(ctypes.Structure):
        _fields_ = [
            ("cb", ctypes.c_ulong),
            ("PageFaultCount", ctypes.c_ulong),
            ("PeakWorkingSetSize", ctypes.c_size_t),
            ("WorkingSetSize", ctypes.c_size_t),
            ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
            ("QuotaPagedPoolUsage", ctypes.c_size_t),
            ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
            ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
            ("PagefileUsage", ctypes.c_size_t),
            ("PeakPagefileUsage", ctypes.c_size_t),
        ]

    try:
        kernel32 = win_dll("kernel32", use_last_error=True)
        psapi = win_dll("psapi", use_last_error=True)

        get_current_process = kernel32.GetCurrentProcess
        get_current_process.restype = ctypes.c_void_p

        get_process_memory_info = psapi.GetProcessMemoryInfo
        get_process_memory_info.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ProcessMemoryCounters),
            ctypes.c_ulong,
        ]
        get_process_memory_info.restype = ctypes.c_int

        counters = ProcessMemoryCounters()
        counters.cb = ctypes.sizeof(counters)

        process = get_current_process()
        if not process:
            return None

        if not get_process_memory_info(
            process,
            ctypes.byref(counters),
            counters.cb,
        ):
            return None

        return int(counters.PeakWorkingSetSize)
    except (AttributeError, OSError, TypeError, ValueError):
        return None


def _create_synthetic_fixture(root: Path) -> None:
    root.mkdir(parents=True, exist_ok=False)
    (root / "apex-note.txt").write_text(
        "APEX deterministic benchmark fixture\n한글 forensic timeline\n",
        encoding="utf-8",
    )
    nested = root / "nested"
    nested.mkdir()
    (nested / "evidence.bin").write_bytes(bytes(range(256)) * 16)
    (root / "system.reg").write_text(
        "Windows Registry Editor Version 5.00\n\n"
        "[HKEY_CURRENT_USER\\Software\\APEX]\n"
        '"Fixture"="benchmark"\n',
        encoding="utf-16",
    )
    (root / "security.xml").write_text(_synthetic_event_xml(), encoding="utf-8")
    (root / "APEXBENCH.EXE-12345678.pf").write_bytes(_synthetic_prefetch_bytes())
    browser_root = root / "Chrome" / "Default"
    browser_root.mkdir(parents=True)
    with sqlite3.connect(browser_root / "History") as connection:
        connection.executescript(
            """
            CREATE TABLE urls (
                id INTEGER PRIMARY KEY,
                url TEXT,
                title TEXT,
                visit_count INTEGER,
                typed_count INTEGER,
                last_visit_time INTEGER,
                hidden INTEGER
            );
            CREATE TABLE visits (
                id INTEGER PRIMARY KEY,
                url INTEGER,
                visit_time INTEGER,
                from_visit INTEGER,
                transition INTEGER
            );
            INSERT INTO urls VALUES (
                1, 'https://example.invalid/apex', 'APEX benchmark', 1, 0,
                13348551845000000, 0
            );
            INSERT INTO visits VALUES (1, 1, 13348551845000000, 0, 1);
            """
        )


def _synthetic_event_xml() -> str:
    return """<?xml version="1.0" encoding="utf-8"?>
<Events xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <Event>
    <System>
      <Provider Name="APEX-Benchmark" />
      <EventID>4624</EventID>
      <TimeCreated SystemTime="2024-01-02T03:04:05Z" />
      <EventRecordID>1</EventRecordID>
      <Channel>Security</Channel>
    </System>
    <EventData><Data Name="TargetUserName">benchmark-user</Data></EventData>
    <RenderingInfo Culture="en-US"><Message>APEX benchmark event.</Message></RenderingInfo>
  </Event>
</Events>
"""


def _synthetic_prefetch_bytes() -> bytes:
    data = bytearray(0xD8)
    struct.pack_into("<I", data, 0x00, 30)
    data[0x04:0x08] = b"SCCA"
    struct.pack_into("<I", data, 0x0C, len(data))
    data[0x10 : 0x10 + 60 * 2] = "APEXBENCH.EXE".encode("utf-16le").ljust(60 * 2, b"\x00")
    struct.pack_into("<I", data, 0x4C, 0x12345678)
    struct.pack_into("<Q", data, 0x80, 133485518450000000)
    struct.pack_into("<I", data, 0xD0, 1)
    return bytes(data)


def _fingerprint_evidence(path: Path) -> dict[str, Any]:
    digest = hashlib.sha256()
    evidence_bytes = 0
    file_count = 0
    for relative, candidate in _evidence_files(path):
        digest.update(relative.encode("utf-8", errors="surrogateescape"))
        digest.update(b"\0")
        size = candidate.stat().st_size
        evidence_bytes += size
        file_count += 1
        with candidate.open("rb") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)
        digest.update(b"\0")
    return {
        "sha256": digest.hexdigest(),
        "evidence_bytes": evidence_bytes,
        "file_count": file_count,
    }


def _metadata_snapshot(path: Path) -> dict[str, Any]:
    digest = hashlib.sha256()
    entry_count = 0
    for relative, candidate in _evidence_files(path):
        metadata = candidate.stat()
        digest.update(relative.encode("utf-8", errors="surrogateescape"))
        digest.update(b"\0")
        digest.update(str(metadata.st_size).encode("ascii"))
        digest.update(b"\0")
        digest.update(str(metadata.st_mtime_ns).encode("ascii"))
        digest.update(b"\0")
        entry_count += 1
    return {"sha256": digest.hexdigest(), "entry_count": entry_count}


def _evidence_files(path: Path) -> Iterator[tuple[str, Path]]:
    if path.is_file():
        yield path.name, path
        return
    for root, directory_names, file_names in os.walk(path, followlinks=False):
        directory_names[:] = sorted(
            name for name in directory_names if not (Path(root) / name).is_symlink()
        )
        for name in sorted(file_names):
            candidate = Path(root) / name
            if candidate.is_symlink() or not candidate.is_file():
                continue
            yield candidate.relative_to(path).as_posix(), candidate


def _benchmark_environment(runtime_capabilities: dict[str, Any]) -> dict[str, Any]:
    return {
        "os": platform.system(),
        "kernel_platform": platform.platform(),
        "python_version": platform.python_version(),
        "cpu_count": os.cpu_count(),
        "engine_version": ENGINE_VERSION,
        "runtime_dependencies": {
            item["id"]: item["status"] for item in runtime_capabilities["capabilities"]
        },
    }


def _unavailable_report(
    runtime_capabilities: dict[str, Any],
    dependency: str | None,
) -> dict[str, Any]:
    return {
        "schema_version": BENCHMARK_SCHEMA_VERSION,
        "status": "CAPABILITY_UNAVAILABLE",
        "engine_version": ENGINE_VERSION,
        "reason": "REQUIRED_ENGINE_DEPENDENCY_UNAVAILABLE",
        "details": {"missing_dependency": dependency},
        "environment": _benchmark_environment(runtime_capabilities),
        "results": [],
        "comparative_superiority_claimed": False,
    }


def _failed_report(
    runtime_capabilities: dict[str, Any],
    code: str,
    message: str,
    *,
    error_type: str | None = None,
) -> dict[str, Any]:
    details = {} if error_type is None else {"error_type": error_type}
    return {
        "schema_version": BENCHMARK_SCHEMA_VERSION,
        "status": "FAILED",
        "engine_version": ENGINE_VERSION,
        "reason": code,
        "message": message,
        "details": details,
        "environment": _benchmark_environment(runtime_capabilities),
        "results": [],
        "comparative_superiority_claimed": False,
    }


if __name__ == "__main__":
    raise SystemExit(benchmark_main())
