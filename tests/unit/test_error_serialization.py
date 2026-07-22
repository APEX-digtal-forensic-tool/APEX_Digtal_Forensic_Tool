from __future__ import annotations

from apex_forensic.domain.errors import ValidationError


def test_error_serialization() -> None:
    error = ValidationError("Bad input", target="name", details={"minLength": 1})

    assert error.to_api_error() == {
        "code": "VALIDATION_ERROR",
        "message_key": "error.validation",
        "developer_message": "Bad input",
        "target": "name",
        "retryable": False,
        "details": {"minLength": 1},
    }
