"""A stale image must produce a structured error, not a successful new raw response."""

import base64
import gzip
import json
import os
from pathlib import Path

import pytest
from test_forensic_operations import registered
from test_local_api import call
from test_local_api import client as api_client

client = api_client


def test_raw_http_rejects_image_changed_after_indexing(client, tmp_path):
    pytest.importorskip("pytsk3")
    image = tmp_path / "source.img"
    fixture = json.loads(
        (Path(__file__).parents[1] / "fixtures/container-images.json").read_text()
    )
    image.write_bytes(gzip.decompress(base64.b64decode(fixture["streams.img"]["gzip_base64"])))
    cid, eid = registered(client, image)
    root = call(client, "files.roots", case_id=cid, evidence_id=eid)[0]
    volumes = call(client, "files.list", case_id=cid, evidence_id=eid, parent_node_id=root["id"])[
        "items"
    ]
    nodes = call(
        client, "files.list", case_id=cid, evidence_id=eid, parent_node_id=volumes[0]["id"]
    )["items"]
    node = next(node for node in nodes if node["original_name"] == "document.txt")
    payload = {"case_id": cid, "resource_type": "FILE_SYSTEM_NODE", "resource_id": node["id"]}
    assert call(client, "raw.read", **payload)["text_preview"] == "normal file body"
    before = image.stat()
    image.write_bytes(image.read_bytes().replace(b"normal file body", b"edited file body"))
    os.utime(image, ns=(before.st_atime_ns, before.st_mtime_ns + 2_000_000_000))
    response = client.post("/v1/operations/raw.read", json=payload)
    assert response.status_code == 409
    result = response.json()
    assert result["ok"] is False
    assert result["error"]["code"] == "RAW_SOURCE_CHANGED"
    assert "edited file body" not in response.text
