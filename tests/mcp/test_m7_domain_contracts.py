from __future__ import annotations

import json
from pathlib import Path

import pytest

from apex_forensic.adapters.decryption.kakaotalk import KakaoTalkEncryptedStoreProvider
from apex_forensic.config import ServiceBundle
from apex_forensic.domain.enums import HashAlgorithm, SearchQueryMode
from apex_forensic.domain.errors import ValidationError
from apex_mcp.config import McpConfig
from apex_mcp.engine_adapter import EngineAdapter
from apex_mcp.m7_tools import M7_NEW_DOMAIN_TOOL_NAMES, M7_TOOL_NAMES, m7_bindings
from apex_mcp.server import ApexMcpRuntime, create_runtime

_UNAVAILABLE_DOMAIN_PREFIXES = (
    "apex.annotation.",
    "apex.tag.",
    "apex.evidence.",
    "apex.search.",
    "apex.timeline.",
    "apex.kakaotalk.",
)


def _m7_surface(
    project_root: Path,
    tmp_path: Path,
    services: ServiceBundle,
) -> ApexMcpRuntime:
    return create_runtime(
        McpConfig(
            database_path=tmp_path / "apex.db",
            schema_dir=project_root / "schemas" / "v1",
            allowed_tools=M7_TOOL_NAMES,
        ),
        adapter=EngineAdapter(services),
        bindings=m7_bindings(),
    )


def test_mt037_annotation_and_tag_tools_have_no_descriptor_or_binding(
    project_root: Path,
    tmp_path: Path,
    services: ServiceBundle,
) -> None:
    runtime = _m7_surface(project_root, tmp_path, services)
    try:
        descriptors = {
            item["tool_name"] for item in runtime.adapter.list_tool_descriptors()
        }
        exposed = {tool.name for tool in runtime.registry.list_tools()}

        assert not M7_NEW_DOMAIN_TOOL_NAMES
        assert exposed == M7_TOOL_NAMES
        assert len(exposed) == 52
        assert not any(
            name.startswith(("apex.annotation.", "apex.tag."))
            for name in descriptors | exposed
        )
    finally:
        runtime.close()


def test_mt038_sha512_is_neither_a_core_hash_option_nor_mcp_input(
    project_root: Path,
    tmp_path: Path,
    services: ServiceBundle,
) -> None:
    runtime = _m7_surface(project_root, tmp_path, services)
    try:
        exposed_tools = runtime.registry.list_tools()
        serialized_inputs = json.dumps(
            [tool.input_schema for tool in exposed_tools],
            ensure_ascii=False,
            sort_keys=True,
        )

        assert {algorithm.value for algorithm in HashAlgorithm} == {"MD5", "SHA1", "SHA256"}
        assert "SHA512" not in serialized_inputs
        assert not any(tool.name.startswith("apex.evidence.") for tool in exposed_tools)
        with pytest.raises(ValueError):
            HashAlgorithm("SHA512")
    finally:
        runtime.close()


def test_mt039_regex_513_characters_is_rejected_before_persistence(
    services: ServiceBundle,
) -> None:
    case = services.cases.create_case(name="M7 regex upper bound")
    before = services.repository.connection.execute(
        "SELECT COUNT(*) AS count FROM search_queries"
    ).fetchone()["count"]

    with pytest.raises(ValidationError):
        services.search.query(
            case_id=case.case_id,
            query_text="a" * 513,
            query_mode=SearchQueryMode.REGEX_METADATA,
        )

    after = services.repository.connection.execute(
        "SELECT COUNT(*) AS count FROM search_queries"
    ).fetchone()["count"]
    assert after == before


def test_mt040_term_4096_characters_remains_within_core_limit(
    services: ServiceBundle,
) -> None:
    case = services.cases.create_case(name="M7 term accepted bound")

    result = services.search.query(case_id=case.case_id, query_text="가" * 4096)

    assert result.query.query_text == "가" * 4096


def test_mt041_term_4097_characters_is_rejected_before_persistence(
    services: ServiceBundle,
) -> None:
    case = services.cases.create_case(name="M7 term rejected bound")
    before = services.repository.connection.execute(
        "SELECT COUNT(*) AS count FROM search_queries"
    ).fetchone()["count"]

    with pytest.raises(ValidationError):
        services.search.query(case_id=case.case_id, query_text="가" * 4097)

    after = services.repository.connection.execute(
        "SELECT COUNT(*) AS count FROM search_queries"
    ).fetchone()["count"]
    assert after == before


def test_mt042_kakaotalk_android_is_explicitly_unsupported() -> None:
    provider = KakaoTalkEncryptedStoreProvider()

    result = provider.acquire_key_material(
        case_id="m7-case",
        evidence_id="m7-evidence",
        platform="android",
    )

    assert result["status"] == "UNSUPPORTED_PLATFORM"
    assert result["reason"] == "KAKAOTALK_UNSUPPORTED_PLATFORM"
    assert result["automatic_key_acquisition"] is False


def test_mt043_kakaotalk_does_not_claim_automatic_key_acquisition() -> None:
    provider = KakaoTalkEncryptedStoreProvider()
    capability = provider.capabilities().to_schema_dict()
    result = provider.acquire_key_material(
        case_id="m7-case",
        evidence_id="m7-evidence",
        platform="windows",
    )

    assert capability["runtime_status"] == "AVAILABLE_WITH_EXTERNAL_KEY"
    assert capability["supported_key_sources"] == [
        "KAKAOTALK_KPRAGMA_AND_SERVER_NONCE",
        "KAKAOTALK_RAW_DB_KEY_IV",
    ]
    assert any(
        warning["code"] == "PARTIAL"
        and "automatic key acquisition is unsupported"
        in warning["developer_message"]
        for warning in capability["warnings"]
    )
    assert result["automatic_key_acquisition"] is False
    assert result["key_material_status"] == "KEY_UNAVAILABLE"


def test_m7_surface_has_no_unreviewed_domain_prefixes(
    project_root: Path,
    tmp_path: Path,
    services: ServiceBundle,
) -> None:
    runtime = _m7_surface(project_root, tmp_path, services)
    try:
        exposed = {tool.name for tool in runtime.registry.list_tools()}

        assert not any(name.startswith(_UNAVAILABLE_DOMAIN_PREFIXES) for name in exposed)
    finally:
        runtime.close()
