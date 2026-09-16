"""Generate labeled, synthetic UI fixtures through the real Core services."""

import json
from pathlib import Path
from tempfile import TemporaryDirectory

from apex_forensic.config import build_services
from apex_forensic.domain.enums import AnalysisProfileType
from apex_forensic.runtime.capabilities import capability_report


def main():
    with TemporaryDirectory() as tmp:
        root = Path(tmp) / "교육용-증거"
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
            target = Path(__file__).resolve().parents[1] / "frontend/src/__fixtures__/core.json"
            target.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf8")
        finally:
            services.close()


if __name__ == "__main__":
    main()
