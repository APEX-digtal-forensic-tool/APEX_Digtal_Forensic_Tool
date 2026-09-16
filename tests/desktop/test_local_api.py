from time import monotonic, sleep

import pytest
from fastapi.testclient import TestClient

from apex_desktop.app import create_app

TOKEN = "a" * 48


@pytest.fixture
def client(tmp_path):
    with TestClient(
        create_app(tmp_path / "data", TOKEN),
        base_url="http://127.0.0.1",
        headers={"Authorization": f"Bearer {TOKEN}"},
    ) as client:
        yield client


def call(client, op, **payload):
    response = client.post("/v1/operations/" + op, json=payload)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["ok"], body
    return body["data"]


def wait(client, case_id, task):
    deadline = monotonic() + 15
    while monotonic() < deadline:
        record = next(
            r
            for r in call(client, "tasks.list", case_id=case_id)
            if r["task_id"] == task["task_id"]
        )
        if record["status"] not in {"QUEUED", "RUNNING", "CANCELLING"}:
            assert record["status"] in {"SUCCEEDED", "PARTIAL"}, record
            return record
        sleep(0.02)
    pytest.fail("Task did not complete")


def fixture_case(client, tmp_path):
    root = tmp_path / "evidence"
    root.mkdir()
    (root / "한글.txt").write_text("alpha forensic note", encoding="utf8")
    (root / "other.txt").write_text("beta", encoding="utf8")
    case = call(client, "cases.create", name="사건 테스트")
    cid = case["id"]
    task = call(client, "evidence.register", case_id=cid, source_path=str(root))
    evidence = wait(client, cid, task)["result"]
    eid = evidence["id"]
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


def test_boundary(client):
    assert client.get("/health", headers={"Authorization": ""}).status_code == 401
    assert client.get("/health", headers={"Origin": "https://example.test"}).status_code == 403
    assert client.get("/health", headers={"Host": "attacker.test"}).status_code == 403
    assert client.post("/v1/operations/nope", json={}).status_code == 404
    assert (
        client.post(
            "/v1/operations/cases.create", json={"name": "x", "actor_id": "admin"}
        ).status_code
        == 422
    )
    assert client.post("/v1/operations/cases.create", content="x" * 1048577).status_code == 413


def test_case_files_context_raw_search_and_timeline(client, tmp_path):
    cid, eid = fixture_case(client, tmp_path)
    roots = call(client, "files.roots", case_id=cid, evidence_id=eid)
    page = call(
        client, "files.list", case_id=cid, evidence_id=eid, parent_node_id=roots[0]["id"], limit=1
    )
    assert page["page"]["has_more"]
    next_page = call(
        client,
        "files.list",
        case_id=cid,
        evidence_id=eid,
        parent_node_id=roots[0]["id"],
        limit=1,
        cursor=page["page"]["next_cursor"],
    )
    assert page["items"][0]["id"] != next_page["items"][0]["id"]
    node = page["items"][0]
    view = call(
        client, "view", case_id=cid, resource_type="FILE_SYSTEM_NODE", resource_id=node["id"]
    )
    assert view["resource_id"] == node["id"]
    raw = call(
        client,
        "raw.read",
        case_id=cid,
        resource_type="FILE_SYSTEM_NODE",
        resource_id=node["id"],
        length=4,
    )
    assert raw
    assert (
        client.post(
            "/v1/operations/raw.read",
            json={
                "case_id": cid,
                "resource_type": "FILE_SYSTEM_NODE",
                "resource_id": node["id"],
                "length": 1048577,
            },
        ).status_code
        == 422
    )
    ctx = call(client, "context.create", case_id=cid)
    payload = {
        "case_id": cid,
        "session_context_id": ctx["session_context_id"],
        "expected_revision": 1,
        "patch": {"current_route": "FILE_SYSTEM", "selected_file_node_ids": [node["id"]]},
    }
    assert call(client, "context.update", **payload)["context_revision"] == 2
    assert (
        client.post("/v1/operations/context.update", json=payload).json()["error"]["code"]
        == "CONTEXT_REVISION_CONFLICT"
    )
    other = call(client, "cases.create", name="다른 사건")["id"]
    assert (
        client.post(
            "/v1/operations/files.list", json={"case_id": other, "evidence_id": eid}
        ).json()["error"]["code"]
        == "CONTEXT_SCOPE_MISMATCH"
    )
    for kind in ["SEARCH", "TIMELINE"]:
        wait(
            client,
            cid,
            call(
                client,
                "analysis.start",
                case_id=cid,
                evidence_id=eid,
                kind=kind,
                profile_type="FULL_ANALYSIS",
            ),
        )
    assert call(client, "search.query", case_id=cid, query_text="한글")["results"]
    assert call(client, "timeline.list", case_id=cid)["items"]
    assert (
        client.post(
            "/v1/operations/search.query",
            json={"case_id": cid, "query_text": "x" * 513, "query_mode": "REGEX_METADATA"},
        ).status_code
        == 409
    )
    assert call(client, "custody.verify", case_id=cid, evidence_id=eid)["verified"]


def test_report_review_export_and_governance(client, tmp_path):
    cid, eid = fixture_case(client, tmp_path)
    assert call(client, "policy.get", case_id=cid) is None
    policy = call(client, "policy.save", case_id=cid, expected_revision=0)
    assert not policy["ai_enabled"]
    report = call(client, "reports.create", case_id=cid, title="조사 보고서")
    version = call(
        client,
        "reports.version",
        case_id=cid,
        report_id=report["report_id"],
        title="조사 보고서",
        executive_summary="분석자 작성",
        limitations=["디렉터리 증거 무결성 검증 한계"],
        evidence_ids=[eid],
        sections=[
            {
                "section_type": "KEY_FINDINGS",
                "title": "관찰 결과",
                "order": 1,
                "content": "분석자가 작성한 내용",
            }
        ],
    )
    vid = version["report_version_id"]
    r = client.post(
        "/v1/operations/reports.export",
        json={
            "case_id": cid,
            "report_version_id": vid,
            "format": "HTML",
            "filename": "report.html",
        },
    )
    assert not r.json()["ok"]
    for action in ["submit", "accept_section", "complete", "approve"]:
        data = call(client, "reports.get", case_id=cid, report_id=report["report_id"])
        current = data["versions"][0]
        state = current["review_state"]
        call(
            client,
            "reports.action",
            case_id=cid,
            report_version_id=vid,
            action=action,
            reason="사용자 검토",
            section_id=version["sections"][0]["section_id"],
            expected_review_revision=state["review_revision"],
        )
    result = call(
        client,
        "reports.export",
        case_id=cid,
        report_version_id=vid,
        format="HTML",
        filename="report.html",
    )
    assert result
    assert list((tmp_path / "data" / "exports").rglob("report.html"))


def test_hash_verification_preserves_mismatch(client, tmp_path):
    source = tmp_path / "synthetic.dd"
    source.write_bytes(b"synthetic evidence bytes" * 1024)
    cid = call(client, "cases.create", name="Hash fixture")["id"]
    evidence = wait(
        client, cid, call(client, "evidence.register", case_id=cid, source_path=str(source))
    )["result"]
    payload = {"case_id": cid, "evidence_id": evidence["id"], "algorithm": "SHA256"}
    baseline = wait(client, cid, call(client, "analysis.start", kind="HASH", **payload))
    digest = baseline["result"][0]["digest_hex"]
    matching = wait(client, cid, call(client, "analysis.start", kind="VERIFY", **payload))
    assert matching["result"][0]["status"] == "MATCH"
    # Mutate only this generated test fixture to exercise evidence-change reporting.
    source.write_bytes(b"changed synthetic bytes" * 1024)
    changed = wait(client, cid, call(client, "analysis.start", kind="VERIFY", **payload))
    assert changed["result"][0]["status"] == "MISMATCH"
    assert changed["result"][0]["expected_digest"] == digest


@pytest.mark.parametrize("target", ["self", "ancestor", "child", "file"])
def test_rejects_evidence_overlapping_writable_data(client, tmp_path, target):
    cid = call(client, "cases.create", name="Writable boundary")["id"]
    data = tmp_path / "data"
    child = data / "exports"
    child.mkdir()
    image = child / "synthetic.dd"
    image.write_bytes(b"synthetic" * 1024)
    source = {"self": data, "ancestor": tmp_path, "child": child, "file": image}[target]
    response = client.post(
        "/v1/operations/evidence.register",
        json={"case_id": cid, "source_path": str(source)},
    )
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "VALIDATION_ERROR"
    assert call(client, "tasks.list", case_id=cid) == []
    assert call(client, "evidence.list", case_id=cid) == []


def test_allows_sibling_evidence_with_same_path_prefix(client, tmp_path):
    cid = call(client, "cases.create", name="Separate evidence")["id"]
    source = tmp_path / "data-evidence"
    source.mkdir()
    registered = wait(
        client, cid, call(client, "evidence.register", case_id=cid, source_path=str(source))
    )
    assert registered["result"]["read_only"] is True


def image_fixture(client, tmp_path):
    from PIL import Image

    cid, eid = fixture_case(client, tmp_path)
    path = tmp_path / "evidence" / "pixels.png"
    payload = b"TEST{pixel_bits}"
    bits = [(byte >> shift) & 1 for byte in payload for shift in range(7, -1, -1)]
    pixels = bytearray([128] * (32 * 4 * 3))
    for index, value in enumerate(bits):
        pixels[index] |= value
    Image.frombytes("RGB", (32, 4), bytes(pixels)).save(path)
    for kind in ("FILES", "ARTIFACTS"):
        wait(
            client,
            cid,
            call(
                client,
                "analysis.start",
                case_id=cid,
                evidence_id=eid,
                kind=kind,
                profile_type="FULL_ANALYSIS",
            ),
        )
    artifact = call(
        client, "artifacts.list", case_id=cid, evidence_id=eid, artifact_type="MEDIA_IMAGE"
    )["items"][0]
    args = {"case_id": cid, "resource_type": "ARTIFACT", "resource_id": artifact["id"]}
    return path, payload, args, artifact


def test_image_preview_extraction_provenance_and_detail(client, tmp_path):
    import base64
    import hashlib
    import json
    from io import BytesIO

    from PIL import Image

    path, payload, args, artifact = image_fixture(client, tmp_path)
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    preview = call(client, "media.inspect", **args)
    assert (preview["width"], preview["height"]) == (32, 4)
    assert preview["source_sha256"] == digest
    with Image.open(BytesIO(base64.b64decode(preview["image_url"].split(",")[1]))) as image:
        assert image.size == (32, 4)
    plane = call(client, "media.inspect", **args, channel="R", bit=0)
    with Image.open(BytesIO(base64.b64decode(plane["image_url"].split(",")[1]))) as image:
        assert set(image.tobytes()) <= {0, 255}
    result = call(client, "media.inspect", **args, action="EXTRACT", byte_limit=len(payload))
    assert result["text"] == payload.decode()
    assert bytes.fromhex(result["hex"]) == payload
    assert result["source_sha256"] == digest
    assert result["output_sha256"] == hashlib.sha256(payload).hexdigest()
    assert result["has_more"] is True
    saved = tmp_path / "data" / "exports" / result["export_relative_path"]
    assert json.loads(saved.read_text()) == result
    # The byte packing order changes actual output, not just the label.
    lsb = call(
        client, "media.inspect", **args, action="EXTRACT", bit_order="LSB_FIRST", byte_limit=1
    )
    assert lsb["hex"] == "2a"  # bit-reversed 'T' (0x54)
    tail = call(client, "media.inspect", **args, action="EXTRACT", pixel_offset=125)
    assert tail["returned_bytes"] == 1 and tail["unused_tail_bits"] == 1
    assert tail["has_more"] is False
    view = call(client, "view", **args, view_mode="DETAILED")
    assert view["primary_fields"]["width"] == 32
    assert view["secondary_fields"]["image_metadata"]["height"] == 4
    assert hashlib.sha256(path.read_bytes()).hexdigest() == digest
    # Node-ID access uses the same read-only resolver.
    node = call(
        client,
        "media.inspect",
        case_id=args["case_id"],
        resource_type="FILE_SYSTEM_NODE",
        resource_id=artifact["source_file_node_id"],
    )
    assert node["source_sha256"] == digest


def test_image_scope_changed_source_links_and_bounds(client, tmp_path, monkeypatch):
    from apex_forensic.application.services import image_inspection

    path, _, args, artifact = image_fixture(client, tmp_path)
    other = call(client, "cases.create", name="다른 사건")["id"]
    response = client.post("/v1/operations/media.inspect", json={**args, "case_id": other})
    assert response.json()["error"]["code"] == "CONTEXT_SCOPE_MISMATCH"
    for change in ({"bit": 8}, {"byte_limit": 65537}, {"source_path": str(path)}):
        assert (
            client.post("/v1/operations/media.inspect", json={**args, **change}).status_code == 422
        )
    for change, code in [
        ({"channels": "RR"}, "VALIDATION_ERROR"),
        ({"action": "EXTRACT", "pixel_offset": 128}, "MEDIA_OFFSET_OUT_OF_RANGE"),
    ]:
        assert (
            client.post("/v1/operations/media.inspect", json={**args, **change}).json()["error"][
                "code"
            ]
            == code
        )
    monkeypatch.setattr(image_inspection, "MAX_IMAGE_PIXELS", 10)
    assert (
        client.post("/v1/operations/media.inspect", json=args).json()["error"]["code"]
        == "MEDIA_LIMIT_EXCEEDED"
    )
    monkeypatch.setattr(image_inspection, "MAX_IMAGE_PIXELS", 25_000_000)
    original = path.read_bytes()
    path.write_bytes(original + b"changed")
    assert (
        client.post("/v1/operations/media.inspect", json=args).json()["error"]["code"]
        == "MEDIA_SOURCE_CHANGED"
    )
    path.unlink()
    outside = tmp_path / "outside.png"
    outside.write_bytes(original)
    path.symlink_to(outside)
    assert (
        client.post("/v1/operations/media.inspect", json=args).json()["error"]["code"]
        == "MEDIA_SOURCE_UNAVAILABLE"
    )
    path.unlink()
    path.write_bytes(b"not an image")
    node_args = {
        **args,
        "resource_type": "FILE_SYSTEM_NODE",
        "resource_id": artifact["source_file_node_id"],
    }
    assert (
        client.post("/v1/operations/media.inspect", json=node_args).json()["error"]["code"]
        == "MEDIA_DECODE_FAILED"
    )


def test_zip_import_explains_extraction_before_creating_task(client, tmp_path):
    import zipfile

    cid = call(client, "cases.create", name="압축 파일 안내")["id"]
    archive = tmp_path / "misleading.raw"
    with zipfile.ZipFile(archive, "w") as handle:
        handle.writestr("image.png", b"fixture")
    response = client.post(
        "/v1/operations/evidence.register", json={"case_id": cid, "source_path": str(archive)}
    )
    assert response.json()["error"]["code"] == "ARCHIVE_REQUIRES_EXTRACTION"
    assert call(client, "evidence.list", case_id=cid) == []
    assert call(client, "tasks.list", case_id=cid) == []
