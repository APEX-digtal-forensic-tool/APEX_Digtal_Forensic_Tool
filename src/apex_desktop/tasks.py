"""Bounded background work, each with its own Core/SQLite connection."""

from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Lock
from typing import Any, NotRequired, TypedDict
from uuid import uuid4

from apex_forensic.config import ServiceBundle, build_services
from apex_forensic.domain.errors import ApexError
from apex_forensic.domain.models.job import Job
from apex_forensic.jobs.cancellation import CancellationToken


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
        # Receipts contain status/IDs only; forensic results remain in Core storage.
        if journal.exists():
            import json

            for record in json.loads(journal.read_text(encoding="utf-8")):
                if record["status"] in {"RUNNING", "QUEUED", "CANCELLING"}:
                    record["status"] = "INTERRUPTED"
                self.records[record["task_id"]] = record

    def _save(self) -> None:
        import json

        receipts = [{k: v for k, v in r.items() if k != "result"} for r in self.records.values()]
        tmp = self.journal.with_suffix(".tmp")
        tmp.write_text(json.dumps(receipts, ensure_ascii=False), encoding="utf-8")
        tmp.replace(self.journal)

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
