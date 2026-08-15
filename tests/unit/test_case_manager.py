from __future__ import annotations

import pytest

from apex_forensic.domain.enums import CaseStatus
from apex_forensic.domain.errors import ValidationError


def test_case_creation_defaults_round_trip(services, schema_validator) -> None:
    case = services.cases.create_case(name="테스트 사건", investigator="권태욱")

    assert case.locale == "ko-KR"
    assert case.timezone == "Asia/Seoul"
    assert case.status is CaseStatus.OPEN
    assert services.cases.get_case(case.case_id).name == "테스트 사건"
    schema_validator.validate_case(case.to_schema_dict())


def test_invalid_timezone_is_rejected(services) -> None:
    with pytest.raises(ValidationError):
        services.cases.create_case(name="Bad TZ", timezone="Not/AZone")


def test_case_name_and_locale_schema_boundaries_are_enforced_before_persistence(
    services,
) -> None:
    accepted = services.cases.create_case(name="한" * 255, locale="fil")
    assert accepted.name == "한" * 255
    assert accepted.locale == "fil"
    before_count = len(services.cases.list_cases())

    with pytest.raises(ValidationError):
        services.cases.create_case(name="한" * 256, locale="ko-KR")
    for locale in ("en-us", "EN-US", "en_US", "english-US", ""):
        with pytest.raises(ValidationError):
            services.cases.create_case(name="Invalid locale", locale=locale)

    assert len(services.cases.list_cases()) == before_count
    with pytest.raises(ValidationError):
        services.cases.change_locale(accepted.case_id, "ko-kr")
    assert services.cases.get_case(accepted.case_id).locale == "fil"


def test_case_metadata_status_locale_timezone_changes(services) -> None:
    case = services.cases.create_case(name="Original")

    updated = services.cases.update_metadata(
        case.case_id,
        name="Updated",
        description="description",
        investigator="analyst",
    )
    assert updated.name == "Updated"
    assert updated.description == "description"
    assert updated.investigator == "analyst"

    assert services.cases.change_status(case.case_id, CaseStatus.CLOSED).status is CaseStatus.CLOSED
    assert services.cases.change_locale(case.case_id, "en-US").locale == "en-US"
    assert services.cases.change_timezone(case.case_id, "UTC").timezone == "UTC"
    assert services.cases.delete_case(case.case_id).status is CaseStatus.ARCHIVED


def test_case_name_update_rejects_schema_max_plus_one_without_mutation(services) -> None:
    case = services.cases.create_case(name="Original")
    assert services.cases.update_metadata(case.case_id, name="가" * 255).name == "가" * 255

    with pytest.raises(ValidationError):
        services.cases.update_metadata(case.case_id, name="가" * 256)

    assert services.cases.get_case(case.case_id).name == "가" * 255
