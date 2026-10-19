"""Smoke a packaged runtime on the build host without writing to user evidence."""

import base64
import gzip
import hashlib
import http.client
import json
import os
import secrets
import subprocess
import sys
import time
from pathlib import Path
from queue import Queue
from tempfile import TemporaryDirectory
from threading import Thread


def main() -> None:
    token = secrets.token_hex(32)
    executable = (
        Path(sys.argv[1])
        if len(sys.argv) > 1
        else (
            Path(__file__).resolve().parents[1]
            / "desktop-runtime"
            / ("apex-local-api.exe" if sys.platform == "win32" else "apex-local-api")
        )
    )
    with TemporaryDirectory() as tmp:
        root = Path(tmp).resolve()
        process = subprocess.Popen(
            [str(executable.resolve()), "--data-dir", str(root / "data")],
            env={**os.environ, "APEX_DESKTOP_TOKEN": token},
            stdout=subprocess.PIPE,
            text=True,
        )
        try:
            assert process.stdout is not None
            messages: Queue[str] = Queue()
            Thread(target=lambda: messages.put(process.stdout.readline()), daemon=True).start()
            readiness = json.loads(messages.get(timeout=30))
            assert readiness["type"] == "apex-ready"
            port = readiness["port"]
            if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
                raise ValueError("Packaged runtime returned an invalid port")

            def request_json(method, path, *, payload=None, timeout=60):
                # Connect only to the child runtime; never use proxies or follow redirects.
                connection = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
                headers = {"Authorization": f"Bearer {token}"}
                body = None
                if payload is not None:
                    body = json.dumps(payload).encode("utf-8")
                    headers["Content-Type"] = "application/json"
                try:
                    connection.request(method, path, body=body, headers=headers)
                    with connection.getresponse() as response:
                        if response.status != 200:
                            raise OSError(
                                f"Packaged runtime returned HTTP {response.status} for {path}"
                            )
                        return json.load(response)
                finally:
                    connection.close()

            for attempt in range(50):
                try:
                    assert request_json("GET", "/health", timeout=2)["data"]["ready"]
                    break
                except OSError:
                    if attempt == 49:
                        raise
                    time.sleep(0.1)

            def operation(name, payload):
                result = request_json(
                    "POST",
                    "/v1/operations/" + name,
                    payload=payload,
                )
                assert result["ok"], result.get("error")
                return result["data"]

            assert operation("runtime", {})["capabilities"]
            case_id = operation("cases.create", {"name": "Packaged runtime fixture"})["id"]
            assert operation("cases.list", {})[0]["id"] == case_id

            def wait_task(task):
                deadline = time.monotonic() + 60
                while time.monotonic() < deadline:
                    record = next(
                        item
                        for item in operation("tasks.list", {"case_id": case_id})
                        if item["task_id"] == task["task_id"]
                    )
                    if record["status"] not in {"RUNNING", "QUEUED", "CANCELLING"}:
                        assert record["status"] == "SUCCEEDED", record
                        return record
                    time.sleep(0.05)
                raise AssertionError("Packaged analysis task did not complete")

            evidence = root / "synthetic-evidence"
            evidence.mkdir()
            (evidence / "packaged-fixture.txt").write_text("synthetic only", encoding="utf-8")
            registered = wait_task(
                operation(
                    "evidence.register",
                    {
                        "case_id": case_id,
                        "source_path": str(evidence),
                    },
                )
            )
            evidence_id = registered["result"]["id"]
            for kind in ["FILES", "SEARCH"]:
                wait_task(
                    operation(
                        "analysis.start",
                        {
                            "case_id": case_id,
                            "evidence_id": evidence_id,
                            "kind": kind,
                            "profile_type": "FULL_ANALYSIS",
                        },
                    )
                )
            roots = operation("files.roots", {"case_id": case_id, "evidence_id": evidence_id})
            page = operation(
                "files.list",
                {
                    "case_id": case_id,
                    "evidence_id": evidence_id,
                    "parent_node_id": roots[0]["id"],
                },
            )
            assert page["items"][0]["original_name"] == "packaged-fixture.txt"
            assert operation(
                "search.query",
                {
                    "case_id": case_id,
                    "query_text": "packaged",
                },
            )["results"]
            fixtures = json.loads(
                (
                    Path(__file__).resolve().parents[1] / "tests/fixtures/container-images.json"
                ).read_text()
            )
            for filename in ("compressed.E01", "disk.vhd", "disk.vhdx", "ocr.png"):
                item = fixtures[filename]
                data = gzip.decompress(base64.b64decode(item["gzip_base64"]))
                assert hashlib.sha256(data).hexdigest() == item["sha256"]
                source = root / filename
                source.write_bytes(data)
                eid = wait_task(
                    operation(
                        "evidence.register",
                        {
                            "case_id": case_id,
                            "source_path": str(source),
                        },
                    )
                )["result"]["id"]
                wait_task(
                    operation(
                        "analysis.start",
                        {
                            "case_id": case_id,
                            "evidence_id": eid,
                            "kind": "FILES",
                            "profile_type": "FULL_ANALYSIS",
                        },
                    )
                )
                queue = operation("files.roots", {"case_id": case_id, "evidence_id": eid})
                while queue and queue[0]["node_type"] != "FILE":
                    queue = operation(
                        "files.list",
                        {"case_id": case_id, "evidence_id": eid, "parent_node_id": queue[0]["id"]},
                    )["items"]
                assert queue, filename
                node = next(n for n in queue if n["node_type"] == "FILE")
                if filename == "ocr.png":
                    operation("machine.configure", {"ocr_provider": "rapidocr"})
                    wait_task(
                        operation(
                            "machine.run",
                            {
                                "case_id": case_id,
                                "node_id": node["id"],
                                "kind": "OCR",
                                "language": "eng",
                            },
                        )
                    )
                    candidates = operation(
                        "candidates.list", {"case_id": case_id, "evidence_id": eid}
                    )["items"]
                    assert "HELLO" in " ".join(c["text"] for c in candidates)
                else:
                    raw = operation(
                        "raw.read",
                        {
                            "case_id": case_id,
                            "resource_type": "FILE_SYSTEM_NODE",
                            "resource_id": node["id"],
                        },
                    )
                    assert raw["text_preview"] == "E01 가상 디스크의 실제 내용", raw
                assert hashlib.sha256(source.read_bytes()).hexdigest() == item["sha256"]
            print("Packaged indexing, search, E01/VHD/VHDX content and local OCR: PASS")
        finally:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)


if __name__ == "__main__":
    main()
