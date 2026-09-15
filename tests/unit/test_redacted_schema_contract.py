from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from apex_forensic.domain.models.secret import redact_secret_fields

PASSWORD_INDICATORS = (
    "primary_password_supplied",
    "primary_password_required",
    "primary_password_emitted",
    "password_plaintext_emitted",
    "password_value_present",
)


@pytest.fixture(params=[
    ("common", "/$defs/redactedObject"),
    ("decryption-request", "/$defs/decryptionRequest/properties/parameters"),
    ("decryption-result", "/$defs/decryptionResult/properties/metadata"),
    ("dpapi-key-source", "/$defs/warning"),
    ("nss-profile", "/$defs/warning"),
    ("secret-provider-capability", "/$defs/warning"),
])
def redacted_validator(request: pytest.FixtureRequest, project_root: Path):
    schemas = [
        json.loads(path.read_text())
        for path in (project_root / "schemas" / "v1").glob("*.schema.json")
    ]
    registry = Registry().with_resources(
        (schema["$id"], Resource.from_contents(schema)) for schema in schemas
    )
    name, pointer = request.param
    return Draft202012Validator(
        {"$ref": f"https://schemas.apex-forensics.dev/v1/{name}.schema.json#{pointer}"},
        registry=registry,
    )


@pytest.mark.parametrize("value", [True, False, None])
@pytest.mark.parametrize("uppercase", [False, True])
def test_password_indicators_survive_redaction_and_schema_validation(
    redacted_validator, value: bool | None, uppercase: bool,
) -> None:
    indicators = {
        name.upper() if uppercase else name: value for name in PASSWORD_INDICATORS
    }
    fields = {**indicators, "password": "synthetic-sensitive-value"}
    payload = {"code": "STATUS", **fields, "profile": fields, "entries": [fields]}
    serialized = redact_secret_fields(payload)

    for node in (serialized, serialized["profile"], serialized["entries"][0]):
        assert all(node[name] is value for name in indicators)
        assert node["password"] == "<redacted>"
    assert "synthetic-sensitive-value" not in json.dumps(serialized)
    redacted_validator.validate(serialized)


@pytest.mark.parametrize("field", [
    "password", "PASSWORD", "primary_password", "password_supplied",
    "account_password_required", "other_primary_password_supplied",
    "primary_password_supplied_value", "password_value_present_token",
    "primary_password_supplied\n", "prefix\npassword",
])
def test_password_exception_does_not_allow_other_sensitive_fields(redacted_validator, field):
    for value in ("synthetic-sensitive-value", False, None):
        for container in ({field: value}, {"profile": {field: value}},
                          {"entries": [{field: value}]}):
            payload = {"code": "STATUS", **container}
            assert not redacted_validator.is_valid(payload)
            redacted_validator.validate(redact_secret_fields(payload))


@pytest.mark.parametrize("value", ["synthetic-sensitive-value", 0, {}, []])
def test_password_indicators_only_accept_boolean_or_null(redacted_validator, value: Any):
    for name in PASSWORD_INDICATORS:
        assert not redacted_validator.is_valid({"code": "STATUS", name: value})
        assert not redacted_validator.is_valid({"code": "STATUS", name.upper(): value})
