"""INT-01: an invalid optional AI configuration must not break local bootstrap."""

import json

import pytest
from test_local_api import call
from test_local_api import client as api_client

client = api_client

INVALID = [
    "{broken",
    json.dumps({"provider_id": "x"}),
    json.dumps({"provider_id": "x", "base_url": 7, "model_id": "m", "api_key_env": "K"}),
]


@pytest.mark.parametrize("raw", INVALID)
def test_invalid_optional_ai_config_must_not_break_local_bootstrap(client, monkeypatch, raw):
    monkeypatch.setenv("APEX_DESKTOP_AI_CONFIG", raw)
    runtime = call(client, "runtime")
    assert runtime["ai"]["configuration_error"]["code"] == "AI_CONFIGURATION_INVALID"
    assert "RUNTIME_LLM_PROVIDER" not in runtime["ai"]["engine_capabilities"]
    case = call(client, "cases.create", name="local case")
    assert [c["id"] for c in call(client, "cases.list")] == [case["id"]]
    # AI requests themselves still refuse to run with the broken configuration.
    response = client.post(
        "/v1/operations/ai.prepare",
        json={
            "case_id": case["id"],
            "resource_type": "FILE_SYSTEM_NODE",
            "resource_id": "missing",
        },
    )
    assert response.status_code != 200 or not response.json()["ok"]


def test_missing_ai_config_and_missing_key_keep_runtime(client, monkeypatch):
    monkeypatch.delenv("APEX_DESKTOP_AI_CONFIG", raising=False)
    assert call(client, "runtime")["ai"]["configuration_error"] is None
    monkeypatch.setenv(
        "APEX_DESKTOP_AI_CONFIG",
        json.dumps(
            {
                "provider_id": "x",
                "base_url": "https://example.invalid/v1",
                "model_id": "m",
                "api_key_env": "APEX_ABSENT_TEST_KEY",
            }
        ),
    )
    monkeypatch.delenv("APEX_ABSENT_TEST_KEY", raising=False)
    ai = call(client, "runtime")["ai"]
    assert ai["configuration_error"] is None
    assert ai["runtime_capability"]["is_available"] is False
