import json

import pytest

from apex_desktop.ai import GovernedDesktopProvider, analyze
from apex_forensic.domain.enums import AnalysisProfileType, DataClassification
from apex_forensic.domain.errors import ApexError


@pytest.fixture
def selection(services, tmp_path):
    source = tmp_path / "private-name.txt"
    source.write_text("private forensic content that must not leave the device")
    case = services.cases.create_case(name="Private case name")
    evidence = services.evidence.register_evidence(case_id=case.case_id, source_path=source)
    services.fs.index_evidence(
        case_id=case.case_id,
        evidence_id=evidence.evidence_id,
        profile_type=AnalysisProfileType.FULL_ANALYSIS,
    )
    node = services.repository.list_fs_nodes_for_evidence(evidence.evidence_id)[0]
    return {
        "case_id": case.case_id,
        "resource_type": "FILE_SYSTEM_NODE",
        "resource_id": node.node_id,
        "actor": "local:test",
    }


@pytest.fixture
def provider(monkeypatch):
    monkeypatch.setenv(
        "APEX_DESKTOP_AI_CONFIG",
        json.dumps(
            {
                "provider_id": "test",
                "base_url": "https://example.invalid/v1",
                "model_id": "test-model",
                "api_key_env": "APEX_TEST_AI_KEY",
            }
        ),
    )
    monkeypatch.setenv("APEX_TEST_AI_KEY", "test-credential")
    outgoing = []

    def post(_self, body, **_kwargs):
        outgoing.append(body)
        return {
            "choices": [
                {
                    "message": {
                        "content": json.dumps(
                            {
                                "title": "선택 범위 요약",
                                "summary_text": "선택한 자료의 구조 정보입니다.",
                                "key_points": ["원본 내용을 해석하지 않았습니다."],
                                "citations": [],
                            }
                        )
                    }
                }
            ]
        }

    monkeypatch.setattr(GovernedDesktopProvider, "_post_json", post)
    return outgoing


def test_ai_without_configuration_persists_exact_selection(services, selection, monkeypatch):
    monkeypatch.delenv("APEX_DESKTOP_AI_CONFIG", raising=False)
    result = analyze(services, **selection)
    assert result["status"] == "CONFIGURATION_REQUIRED"
    snapshot = services.contexts.get_snapshot(result["request"]["context_snapshot_id"])
    assert snapshot.included_resource_ids == {"FILE_SYSTEM_NODE": [selection["resource_id"]]}


def test_denied_case_never_calls_provider(services, selection, provider):
    result = analyze(services, **selection)
    assert result["status"] == "POLICY_DENIED"
    assert result["audit"]["result"]["decision"] == "DENY"
    assert provider == []


def test_allowed_projection_is_exact_payload_and_result_is_validated(services, selection, provider):
    services.ai_policies.configure(
        case_id=selection["case_id"],
        expected_revision=0,
        ai_enabled=True,
        external_allowed=True,
        local_only=False,
        allowed_classifications=(DataClassification.SECRET,),
    )
    result = analyze(services, **selection)
    assert result["status"] == "COMPLETED", result
    assert len(provider) == 1
    outgoing = json.loads(provider[0]["messages"][1]["content"])["request"]
    assert outgoing == result["projection"]
    serialized = json.dumps(provider)
    assert "private-name" not in serialized
    assert "private forensic content" not in serialized
    assert "Private case name" not in serialized
    assert "test-credential" not in serialized
    summary = result["execution"]["result"]
    assert summary["summary_text"] == "선택한 자료의 구조 정보입니다."
    assert summary["citations"]
    assert result["execution"]["observed_fact_status"] == "NOT_OBSERVED_FACT"
    assert result["audit"]["result"]["data"]["classification"] == "SECRET"


def test_saved_result_replays_without_new_egress(services, selection, provider, monkeypatch):
    services.ai_policies.configure(
        case_id=selection["case_id"],
        expected_revision=0,
        ai_enabled=True,
        external_allowed=True,
        local_only=False,
        allowed_classifications=(DataClassification.SECRET,),
    )
    first = analyze(services, **selection)
    snapshot = services.contexts.get_snapshot(first["request"]["context_snapshot_id"])
    monkeypatch.setattr(services.contexts, "build_from_selection", lambda **_kwargs: snapshot)
    replay = analyze(services, **selection)
    assert replay["status"] == "COMPLETED"
    assert replay["execution"]["replayed"] is True
    assert replay["execution"]["result"] == first["execution"]["result"]
    assert replay["audit"] is None
    assert replay["projection"] is None
    assert len(provider) == 1


def test_ai_selection_cannot_cross_case(services, selection, provider):
    selection["case_id"] = services.cases.create_case(name="Other").case_id
    with pytest.raises(ApexError):
        analyze(services, **selection)
    assert provider == []
