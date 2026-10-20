"""Generate labeled, synthetic UI fixtures through the real Core services."""

import base64
import gzip
import json
from pathlib import Path
from tempfile import TemporaryDirectory

from apex_forensic.config import build_services
from apex_forensic.domain.enums import AnalysisProfileType
from apex_forensic.runtime.capabilities import capability_report


def main():
    with TemporaryDirectory() as tmp:
        root = Path(tmp).resolve() / "교육용-증거"
        root.mkdir()
        (root / "문서").mkdir()
        for name, content in {
            "한글-분석노트.txt": "교육용 합성 자료입니다. 원본을 검토하세요.",
            "다운로드-내역.csv": "file,time\nmanual.pdf,2026-09-01",
            "README.txt": "Synthetic desktop fixture, not an investigation result.",
        }.items():
            (root / name).write_text(content, encoding="utf8")
        services = build_services(Path(tmp) / "case.db")
        try:
            case = services.cases.create_case(name="교육용 모의 사건", investigator="교육용 분석자")
            evidence = services.evidence.register_evidence(case_id=case.case_id, source_path=root)
            services.fs.index_evidence(
                case_id=case.case_id,
                evidence_id=evidence.evidence_id,
                profile_type=AnalysisProfileType.FULL_ANALYSIS,
            )
            roots = services.fs.get_root_nodes(evidence.evidence_id)
            page = services.fs.list_nodes(
                evidence_id=evidence.evidence_id, parent_node_id=roots[0].node_id
            )
            context = services.contexts.create(
                case_id=case.case_id, session_id="demo-session", actor_id="demo-analyst"
            )
            views = {}
            for node in page.items:
                views[node.node_id] = {
                    mode: services.views.project(
                        case_id=case.case_id,
                        resource_type="FILE_SYSTEM_NODE",
                        resource_id=node.node_id,
                        view_mode=mode,
                    ).to_schema_dict()
                    for mode in ["SIMPLE", "DETAILED", "RAW"]
                }
            data = {
                "cases": [case.to_schema_dict()],
                "evidence": [evidence.to_schema_dict()],
                "roots": [n.to_schema_dict() for n in roots],
                "files": page.to_schema_dict(),
                "context": context.to_schema_dict(),
                "views": views,
                "runtime": {
                    "capabilities": capability_report(),
                    "mode": "DEMO_READ_ONLY",
                    "renderer": {"supported_formats": ["HTML"]},
                    "operations": [],
                    "actor_id": "demo-analyst",
                    "session_id": "demo-session",
                },
            }
            target = FIXTURES / "core.json"
            target.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf8")
        finally:
            services.close()
    write_ntfs_fixture()


REPO = Path(__file__).resolve().parents[1]
FIXTURES = REPO / "frontend/src/__fixtures__"


def ntfs_document_node(services, image: Path) -> dict:
    """Index the synthetic NTFS image and return the serialized `/document.txt` DTO."""
    case = services.cases.create_case(name="교육용 NTFS 사건")
    evidence = services.evidence.register_evidence(case_id=case.case_id, source_path=image)
    services.fs.index_evidence(
        case_id=case.case_id,
        evidence_id=evidence.evidence_id,
        profile_type=AnalysisProfileType.FULL_ANALYSIS,
    )
    nodes = services.repository.list_fs_nodes_for_evidence(evidence.evidence_id)
    return next(n for n in nodes if n.original_name == "document.txt").to_schema_dict()


def write_ntfs_fixture():
    entries = json.loads((REPO / "tests/fixtures/container-images.json").read_text())
    with TemporaryDirectory() as tmp:
        image = Path(tmp).resolve() / "streams.img"
        image.write_bytes(gzip.decompress(base64.b64decode(entries["streams.img"]["gzip_base64"])))
        services = build_services(Path(tmp) / "case.db")
        try:
            node = ntfs_document_node(services, image)
        finally:
            services.close()
    (FIXTURES / "ntfs-file.json").write_text(
        json.dumps(node, ensure_ascii=False, indent=2) + "\n", encoding="utf8"
    )


if __name__ == "__main__":
    main()
