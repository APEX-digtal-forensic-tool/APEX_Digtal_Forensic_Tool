from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path


def _load_release_gate(project_root: Path):
    spec = importlib.util.spec_from_file_location(
        "verify_engine_release_test",
        project_root / "tools" / "verify_engine_release.py",
    )
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _bandit_report_from_manifest(manifest: dict[str, object]) -> dict[str, object]:
    results = []
    for group in manifest["classifications"]:
        assert isinstance(group, dict)
        for location in group["locations"]:
            filename, line_number = str(location).rsplit(":", 1)
            results.append(
                {
                    "test_id": group["test_id"],
                    "filename": filename,
                    "line_number": int(line_number),
                    "issue_severity": "MEDIUM",
                }
            )
    return {
        "metrics": {
            "_totals": {
                "SEVERITY.LOW": 2,
                "SEVERITY.MEDIUM": len(results),
                "SEVERITY.HIGH": 0,
            }
        },
        "results": results,
    }


def test_security_manifest_classifies_every_current_medium_finding(project_root: Path) -> None:
    module = _load_release_gate(project_root)
    manifest = json.loads(
        (project_root / "tools" / "security_findings.json").read_text(encoding="utf-8")
    )
    report = _bandit_report_from_manifest(manifest)

    audit = module.audit_bandit_report(report, manifest)

    assert audit["complete"] is True
    assert audit["medium_or_high_count"] == 43
    assert audit["classified_count"] == 43
    assert audit["bandit_clean"] is False
    assert audit["unclassified"] == []


def test_security_manifest_audit_fails_on_scanner_drift(project_root: Path) -> None:
    module = _load_release_gate(project_root)
    manifest = json.loads(
        (project_root / "tools" / "security_findings.json").read_text(encoding="utf-8")
    )
    report = _bandit_report_from_manifest(manifest)
    report["results"].append(
        {
            "test_id": "B999",
            "filename": "src/apex_forensic/new_finding.py",
            "line_number": 10,
            "issue_severity": "HIGH",
        }
    )

    audit = module.audit_bandit_report(report, manifest)

    assert audit["complete"] is False
    assert audit["unclassified"] == [
        "B999|src/apex_forensic/new_finding.py:10"
    ]


def test_release_gate_preserves_runtime_limitations(project_root: Path) -> None:
    module = _load_release_gate(project_root)
    status, reason, details = module._classify_runtime_verifier(
        {
            "host_platform_status": "HOST_VERIFICATION_REQUIRED",
            "secret_values_emitted": False,
            "windows_runtime_success_claimed": False,
            "probes": [
                {"name": "report-renderers", "status": "PASSED"},
                {"name": "ocr", "status": "CAPABILITY_UNAVAILABLE"},
                {"name": "windows-event-message-renderer", "status": "HOST_VERIFICATION_REQUIRED"},
                {
                    "name": "kakaotalk",
                    "status": "SKIPPED_WITH_REASON",
                    "reason": "EXCLUDED_BY_REQUEST",
                },
            ],
        },
        0,
    )

    assert status == "CAPABILITY_UNAVAILABLE"
    assert reason == "OPTIONAL_RUNTIME_UNAVAILABLE"
    assert details["windows_runtime_success_claimed"] is False
