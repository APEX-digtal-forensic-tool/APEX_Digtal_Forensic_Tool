"""Desktop transport-to-engine workflows, including case boundaries and result persistence."""

import base64
import gzip
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from test_local_api import call, wait
from test_local_api import client as api_client

from apex_desktop import machine

client = api_client


def registered(client, path):
    cid = call(client, "cases.create", name="Forensic workflow")["id"]
    eid = wait(client, cid, call(client, "evidence.register", case_id=cid, source_path=str(path)))[
        "result"
    ]["id"]
    wait(
        client,
        cid,
        call(
            client,
            "analysis.start",
            case_id=cid,
            evidence_id=eid,
            kind="FILES",
            profile_type="FULL_ANALYSIS",
        ),
    )
    return cid, eid


def test_ads_task_and_case_boundaries(client, tmp_path):
    fixture = json.loads((Path(__file__).parents[1] / "fixtures/container-images.json").read_text())
    path = tmp_path / "streams.img"
    path.write_bytes(gzip.decompress(base64.b64decode(fixture["streams.img"]["gzip_base64"])))
    cid, eid = registered(client, path)
    root = call(client, "files.roots", case_id=cid, evidence_id=eid)[0]
    nodes = call(client, "files.list", case_id=cid, evidence_id=eid, parent_node_id=root["id"])
    queue = nodes["items"]
    while not any(n["original_name"] == "document.txt" for n in queue):
        folders = [n for n in queue if n["node_type"] == "DIRECTORY"]
        assert folders, queue
        queue = [
            n
            for folder in folders
            for n in call(
                client, "files.list", case_id=cid, evidence_id=eid, parent_node_id=folder["id"]
            )["items"]
        ]
    node = next(n for n in queue if n["original_name"] == "document.txt")
    args = {"case_id": cid, "node_id": node["id"]}
    streams = call(client, "files.streams", **args)["streams"]
    hidden = next(s for s in streams if s["name"] == "hidden")
    assert call(client, "streams.read", **args, stream_id=hidden["id"])["text_preview"] == (
        "ADS secret forensic stream"
    )
    task = wait(client, cid, call(client, "streams.export", **args, stream_id=hidden["id"]))
    assert Path(task["result"]["output_path"]).read_bytes() == b"ADS secret forensic stream"
    other = call(client, "cases.create", name="Other")["id"]
    for operation in ("files.streams", "files.recover", "machine.run"):
        extra = {"kind": "OCR"} if operation == "machine.run" else {}
        response = client.post(
            "/v1/operations/" + operation, json={**args, "case_id": other, **extra}
        )
        assert response.json()["error"]["code"] == "CONTEXT_SCOPE_MISMATCH"
    response = client.post(
        "/v1/operations/evidence.carve", json={"case_id": other, "evidence_id": eid}
    )
    assert response.json()["error"]["code"] == "CONTEXT_SCOPE_MISMATCH"
    assert call(client, "tasks.list", case_id=other) == []
    carve = wait(
        client,
        cid,
        call(
            client,
            "evidence.carve",
            case_id=cid,
            evidence_id=eid,
            scope="IMAGE",
            formats=["PNG"],
            max_scan_bytes=512,
        ),
    )
    assert carve["status"] == "PARTIAL"
    assert carve["result"]["next_offset"] is not None
    assert Path(carve["result"]["manifest_path"]).exists()


@pytest.mark.parametrize("kind", ["OCR", "STT"])
def test_machine_task_persists_candidates_and_real_source_locator(
    client, tmp_path, monkeypatch, kind
):
    source = tmp_path / ("image.png" if kind == "OCR" else "audio.wav")
    payload = b"synthetic local source"
    source.write_bytes(payload)
    cid, eid = registered(client, source)
    node = call(client, "files.roots", case_id=cid, evidence_id=eid)[0]
    seen = []

    class Provider:
        provider_id = "synthetic-runtime"
        provider_version = "1.0"

        def capabilities(self):
            return SimpleNamespace(metadata={"languages": ["eng", "kor"]})

        def analyze_image(self, path, **kwargs):
            seen.append((path.read_bytes(), kwargs))
            return [{"text": "known OCR result", "confidence": 0.98}]

        def analyze_audio(self, path, **kwargs):
            seen.append((path.read_bytes(), kwargs))
            return [
                {
                    "text": "known STT result",
                    "confidence": 0.95,
                    "audio_start_ms": 50,
                    "audio_end_ms": 1250,
                }
            ]

    monkeypatch.setattr(machine, "providers", lambda root: (Provider(), Provider()))
    task = wait(
        client,
        cid,
        call(
            client,
            "machine.run",
            case_id=cid,
            node_id=node["id"],
            kind=kind,
            language="eng" if kind == "OCR" else "en",
        ),
    )
    assert task["result"]["candidate_count"] == 1
    assert seen[0][0] == payload
    candidates = call(client, "candidates.list", case_id=cid, evidence_id=eid)["items"]
    assert candidates[0]["text"] == f"known {kind} result"
    assert candidates[0]["source_node_id"] == node["id"]
    assert candidates[0]["review_status"] == "UNREVIEWED"
    assert candidates[0]["raw_locator"]["source_path"] == node["display_path"]
    if kind == "STT":
        assert candidates[0]["audio_end_ms"] == 1250
