"""Bounded background work, each with its own Core/SQLite connection."""

import contextlib
import logging
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path
from threading import Lock
from typing import Any, NotRequired, TypedDict
from uuid import uuid4

from apex_forensic.config import ServiceBundle, build_services
from apex_forensic.domain.errors import ApexError
from apex_forensic.domain.models.job import Job
from apex_forensic.jobs.cancellation import CancellationToken

_logger = logging.getLogger(__name__)


def encode(value: Any) -> Any:
    if hasattr(value, "to_schema_dict"):
        return encode(value.to_schema_dict())
    if hasattr(value, "to_dict"):
        return encode(value.to_dict())
    if isinstance(value, (tuple, list)):
        return [encode(v) for v in value]
    if isinstance(value, dict):
        return {k: encode(v) for k, v in value.items()}
    return value


def public_error(error: Exception) -> dict[str, Any]:
    if isinstance(error, ApexError):
        return {
            "code": error.code,
            "message_key": error.message_key,
            "retryable": error.retryable,
            "target": error.target,
        }
    return {
        "code": "DESKTOP_OPERATION_FAILED",
        "message_key": "error.desktop_operation_failed",
        "retryable": False,
    }


class TaskRecord(TypedDict):
    task_id: str
    case_id: str
    kind: str
    status: str
    job: dict[str, Any] | None
    error: dict[str, Any] | None
    actions: list[str]
    result: NotRequired[Any]
    receipt_error: NotRequired[dict[str, Any]]


ProgressCallback = Callable[[Job], None]
TaskRun = Callable[[ServiceBundle, CancellationToken, ProgressCallback], object]


class Tasks:
    def __init__(self, database: Path, journal: Path) -> None:
        self.database = database
        self.journal = journal
        self.pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="apex-analysis")
        self.lock = Lock()
        self.records: dict[str, TaskRecord] = {}
        self.tokens: dict[str, CancellationToken] = {}
        self.journal_recovered: bool = False  # True if journal was corrupt and reset
        # Receipts keep status and derived-output references. Evidence content and
        # full analysis results remain in Core storage or exported manifests.
        if journal.exists():
            import json

            parsed_ok = False
            records_raw: list[Any] = []
            try:
                raw = journal.read_text(encoding="utf-8")
                data = json.loads(raw)
                if not isinstance(data, list):
                    raise ValueError(
                        f"tasks.json top-level must be a list, got {type(data).__name__}"
                    )
                for item in data:
                    if not isinstance(item, dict):
                        raise ValueError(f"tasks.json item is not a dict: {item!r}")
                    if "task_id" not in item or "status" not in item or "case_id" not in item:
                        raise ValueError(f"tasks.json item missing required keys: {item!r}")
                    for key in ("task_id", "case_id", "status"):
                        if not isinstance(item[key], str) or not item[key].strip():
                            raise ValueError(f"tasks.json item has invalid {key}")
                records_raw = data
                parsed_ok = True
            except Exception as exc:
                # Preserve the corrupt file next to the original, then start clean.
                ts = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
                corrupt_path = journal.with_name(f"tasks.json.corrupt-{ts}")
                try:
                    journal.rename(corrupt_path)
                except OSError:
                    with contextlib.suppress(OSError):
                        corrupt_path.write_bytes(journal.read_bytes())
                self.journal_recovered = True
                _logger.warning(
                    "tasks.json was corrupt and has been moved to %s; "
                    "starting with empty task history. Reason: %s",
                    corrupt_path,
                    exc,
                )

            if parsed_ok:
                for record in records_raw:
                    if record["status"] in {"RUNNING", "QUEUED", "CANCELLING"}:
                        record["status"] = "INTERRUPTED"
                    record["actions"] = []  # No live cancellation tokens survive a restart.
                    record.setdefault("kind", "UNKNOWN")
                    record.setdefault("job", None)
                    record.setdefault("error", None)
                    self.records[record["task_id"]] = record

    def _save(self) -> None:
        import json

        receipts = []
        for record in self.records.values():
            receipt = {k: v for k, v in record.items() if k not in {"result", "receipt_error"}}
            result = record.get("result")
            if record["kind"] in {
                "RECOVERY",
                "STREAM_EXPORT",
                "CARVING",
                "OCR",
                "STT",
            } and isinstance(result, dict):
                summary = {
                    key: result[key]
                    for key in (
                        "node_id",
                        "evidence_id",
                        "output_path",
                        "manifest_path",
                        "run_id",
                        "sha256",
                        "stream",
                        "exported_bytes",
                        "logical_size",
                        "output_size",
                        "recovered_bytes",
                        "missing_ranges",
                        "missing_range_policy",
                        "partial",
                        "recovery_method",
                        "warnings",
                        "scope",
                        "semantics",
                        "next_offset",
                        "coverage_complete",
                        "scanned_bytes",
                        "candidate_read_bytes",
                        "max_file_bytes",
                        "skipped_signatures",
                        "candidate_count",
                        "candidate_ids",
                    )
                    if key in result
                }
                if isinstance(result.get("candidates"), list):
                    summary["candidate_count"] = len(result["candidates"])
                receipt["result"] = summary
            receipts.append(receipt)
        tmp = self.journal.with_suffix(".tmp")
        try:
            tmp.write_text(json.dumps(receipts, ensure_ascii=False), encoding="utf-8")
            tmp.replace(self.journal)
        except OSError as exc:
            _logger.error("Failed to persist task journal to %s: %s", self.journal, exc)
            raise
        for record in self.records.values():
            record.pop("receipt_error", None)

    def list(self, case_id: str, *, retry_receipts: bool = False) -> list[TaskRecord]:
        with self.lock:
            # A user-requested retry writes receipts once; it never re-runs work.
            # Ordinary UI polling remains read-only even if the disk stays full.
            if retry_receipts and any(
                r["case_id"] == case_id and r.get("receipt_error") for r in self.records.values()
            ):
                with contextlib.suppress(OSError):
                    self._save()
            return [r.copy() for r in self.records.values() if r["case_id"] == case_id][-100:]

    def start(
        self,
        case_id: str,
        kind: str,
        run: TaskRun,
        cancellable: bool = True,
    ) -> TaskRecord:
        with self.lock:
            if (
                sum(
                    r["status"] in {"QUEUED", "RUNNING", "CANCELLING"}
                    for r in self.records.values()
                )
                >= 16
            ):
                raise ApexError("WORK_QUEUE_FULL", "error.work_queue_full", retryable=True)
            task_id = str(uuid4())
            record: TaskRecord = {
                "task_id": task_id,
                "case_id": case_id,
                "kind": kind,
                "status": "QUEUED",
                "job": None,
                "error": None,
                "actions": ["CANCEL"] if cancellable else [],
            }
            self.records[task_id] = record
            token = CancellationToken.new()
            self.tokens[task_id] = token
            try:
                self._save()
            except Exception:
                # Admission failed: no worker will run this record. Leaving it
                # QUEUED would permanently consume one of the 16 queue slots.
                self.records.pop(task_id, None)
                self.tokens.pop(task_id, None)
                raise

        def progress(job: Job) -> None:
            with self.lock:
                record["job"] = encode(job)

        def worker() -> None:
            services = None
            try:
                with self.lock:
                    record["status"] = "RUNNING"
                if token.is_cancelled:
                    with self.lock:
                        record["status"] = "CANCELLED"
                    return
                services = build_services(self.database, initialize=False)
                result = encode(run(services, token, progress))
                with self.lock:
                    record["result"] = result
                    job = record.get("job")
                    record["status"] = (job or {}).get("status", "SUCCEEDED")
                    if isinstance(result, dict) and (
                        result.get("partial") or result.get("coverage_complete") is False
                    ):
                        record["status"] = "PARTIAL"
                    if isinstance(result, list):
                        for item in result:
                            if isinstance(item, dict) and "job_type" in item:
                                record["job"] = item
                                record["status"] = item["status"]
                    if token.is_cancelled:
                        record["status"] = "CANCELLED"
            except Exception as error:
                with self.lock:
                    record["status"] = "CANCELLED" if token.is_cancelled else "FAILED"
                    record["error"] = public_error(error)
            finally:
                if services is not None:
                    services.close()
                with self.lock:
                    record["actions"] = []
                    self.tokens.pop(task_id, None)
                    try:
                        self._save()
                    except OSError:
                        # Preserve the actual analysis outcome and expose the separate
                        # risk that restart will see the last successfully saved receipt.
                        record["receipt_error"] = {
                            "code": "TASK_RECEIPT_NOT_SAVED",
                            "message_key": "error.task_receipt_not_saved",
                            "retryable": True,
                        }

        try:
            self.pool.submit(worker)
        except Exception:
            with self.lock:
                self.records.pop(task_id, None)
                self.tokens.pop(task_id, None)
                # The executor may have shut down between admission and submit.
                # Remove the already-written receipt as well as the in-memory slot.
                with contextlib.suppress(OSError):
                    self._save()
            raise
        return record.copy()

    def cancel(self, case_id: str, task_id: str) -> TaskRecord:
        with self.lock:
            record = self.records.get(task_id)
            if not record or record["case_id"] != case_id:
                raise ApexError("TASK_NOT_FOUND", "error.task_not_found")
            if "CANCEL" not in record["actions"] or task_id not in self.tokens:
                raise ApexError("STATE_CONFLICT", "error.state_conflict")
            self.tokens[task_id].cancel()
            record["status"] = "CANCELLING"
            return record.copy()

    def close(self) -> None:
        for token in list(self.tokens.values()):
            token.cancel()
        self.pool.shutdown(wait=True, cancel_futures=False)
        with self.lock:
            if any(r.get("receipt_error") for r in self.records.values()):
                with contextlib.suppress(OSError):
                    self._save()
