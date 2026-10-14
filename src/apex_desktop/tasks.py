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
        # Receipts contain status/IDs only; forensic results remain in Core storage.
        if journal.exists():
            import json

            raw = journal.read_text(encoding="utf-8")
            parsed_ok = False
            records_raw: list[Any] = []
            try:
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
                    if not isinstance(item["case_id"], str) or not item["case_id"].strip():
                        raise ValueError(f"tasks.json item has invalid case_id: {item!r}")
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
                    self.records[record["task_id"]] = record

    def _save(self) -> None:
        import json

        receipts = [{k: v for k, v in r.items() if k != "result"} for r in self.records.values()]
        tmp = self.journal.with_suffix(".tmp")
        try:
            tmp.write_text(json.dumps(receipts, ensure_ascii=False), encoding="utf-8")
            tmp.replace(self.journal)
        except OSError as exc:
            _logger.error("Failed to persist task journal to %s: %s", self.journal, exc)
            raise

    def list(self, case_id: str) -> list[TaskRecord]:
        with self.lock:
            return [r.copy() for r in self.records.values() if r["case_id"] == case_id][-100:]

    def start(
        self, case_id: str, kind: str, run: TaskRun, cancellable: bool = True,
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
            self._save()

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
                    self._save()

        self.pool.submit(worker)
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
