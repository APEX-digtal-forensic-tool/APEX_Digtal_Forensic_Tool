from __future__ import annotations

import sqlite3
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

import pytest

from apex_forensic.application.services.context import SafeRawRangeReader
from apex_forensic.config import build_services
from apex_forensic.domain.enums import (
    AnalysisProfileType,
    ArtifactParseStatus,
    ArtifactSourceKind,
    ArtifactType,
    SearchSourceType,
)
from apex_forensic.domain.errors import ApexError
from apex_forensic.domain.models import ArtifactRecord


def _case_evidence_file(services, root: Path):
    case = services.cases.create_case(name="Phase 6 Case")
    evidence = services.evidence.register_evidence(case_id=case.case_id, source_path=root)
    services.fs.index_evidence(
        case_id=case.case_id,
        evidence_id=evidence.evidence_id,
        profile_type=AnalysisProfileType.FULL_ANALYSIS,
    )
    node = next(
        item
        for item in services.repository.list_fs_nodes_for_evidence(evidence.evidence_id)
        if item.node_type.value == "FILE"
    )
    return case, evidence, node


def _add_evidence_file_to_case(services, case_id: str, root: Path, filename: str):
    root.mkdir()
    (root / filename).write_text(filename, encoding="utf-8")
    evidence = services.evidence.register_evidence(case_id=case_id, source_path=root)
    services.fs.index_evidence(
        case_id=case_id,
        evidence_id=evidence.evidence_id,
        profile_type=AnalysisProfileType.FULL_ANALYSIS,
    )
    node = next(
        item
        for item in services.repository.list_fs_nodes_for_evidence(evidence.evidence_id)
        if item.node_type.value == "FILE"
    )
    return evidence, node


def _save_artifact(
    services,
    *,
    case_id: str,
    evidence_id: str,
    node,
    artifact_id: str,
    artifact_type: ArtifactType,
) -> str:
    source_kind = {
        ArtifactType.BROWSER_VISIT: ArtifactSourceKind.BROWSER_SQLITE_DB,
        ArtifactType.MEDIA_IMAGE: ArtifactSourceKind.IMAGE_FILE,
    }.get(artifact_type, ArtifactSourceKind.REGISTRY_EXPORT)
    now = datetime(2024, 1, 2, tzinfo=UTC)
    services.repository.save_artifacts(
        [
            ArtifactRecord(
                artifact_id=artifact_id,
                case_id=case_id,
                evidence_id=evidence_id,
                source_file_node_id=node.node_id,
                artifact_type=artifact_type,
                artifact_subtype=artifact_type.value,
                analyzer_id="test.phase6",
                analyzer_version="1",
                parser_backend="test",
                parser_backend_version="1",
                source_path=node.original_relative_path,
                source_kind=source_kind,
                observed_at_raw=None,
                observed_at_utc=None,
                timezone_source=None,
                timezone_confidence="UNKNOWN",
                title=artifact_id,
                summary=f"{artifact_type.value} summary",
                fields={"artifact_type": artifact_type.value},
                raw_locator={
                    "locator_type": "BYTE_RANGE",
                    "evidence_id": evidence_id,
                    "source_id": node.node_id,
                    "relative_path": node.original_relative_path,
                    "offset": 0,
                    "length": max(1, int(node.file_size or 1)),
                },
                citations=[],
                warnings=[],
                parse_status=ArtifactParseStatus.SUCCESS,
                confidence=1.0,
                is_partial=False,
                index_revision=1,
                created_at=now,
                updated_at=now,
                dedup_key=artifact_id,
            )
        ]
    )
    return artifact_id


def _scope_map(services, snapshot):
    return {
        scope.scope_type: scope
        for scope in services.contexts.list_scopes(snapshot.context_snapshot_id)
    }


def test_session_context_revision_ttl_limits_and_reopen(tmp_path: Path) -> None:
    root = tmp_path / "evidence"
    root.mkdir()
    (root / "note.txt").write_text("phase6", encoding="utf-8")
    db_path = tmp_path / "apex.db"
    services = build_services(db_path)
    try:
        case, _, node = _case_evidence_file(services, root)
        context = services.contexts.create(
            session_id="session-1",
            case_id=case.case_id,
            selected_file_node_ids=[node.node_id],
            active_filters={"kind": "file"},
        )
        assert context.context_revision == 1
        assert context.source_revision_fingerprint

        updated = services.contexts.update(
            context.session_context_id,
            expected_revision=1,
            current_route="FILE_SYSTEM",
        )
        assert updated.context_revision == 2
        with pytest.raises(ApexError) as conflict:
            services.contexts.update(
                context.session_context_id,
                expected_revision=1,
                current_route="SEARCH",
            )
        assert conflict.value.code == "CONTEXT_REVISION_CONFLICT"

        expired = services.contexts.expire(updated.session_context_id, expected_revision=2)
        with pytest.raises(ApexError) as expired_error:
            services.contexts.update(
                expired.session_context_id,
                expected_revision=3,
                current_route="MEDIA",
            )
        assert expired_error.value.code == "CONTEXT_EXPIRED"

        with pytest.raises(ApexError) as limit_error:
            services.contexts.create(
                session_id="session-2",
                case_id=case.case_id,
                active_filters={"nested": {"a": {"b": {"c": {"d": {"e": {"f": {"g": 1}}}}}}}},
            )
        assert limit_error.value.code == "CONTEXT_FILTER_LIMIT_EXCEEDED"
    finally:
        services.close()

    reopened = build_services(db_path)
    try:
        loaded = reopened.contexts.get(context.session_context_id)
        assert loaded.context_revision == 3
        assert loaded.selected_file_node_ids == [node.node_id]
    finally:
        reopened.close()


def test_cross_case_selection_is_rejected(tmp_path: Path) -> None:
    root_a = tmp_path / "a"
    root_b = tmp_path / "b"
    root_a.mkdir()
    root_b.mkdir()
    (root_a / "a.txt").write_text("a", encoding="utf-8")
    (root_b / "b.txt").write_text("b", encoding="utf-8")
    services = build_services(tmp_path / "cross.db")
    try:
        case_a, _, _ = _case_evidence_file(services, root_a)
        _, _, node_b = _case_evidence_file(services, root_b)
        with pytest.raises(ApexError) as mismatch:
            services.contexts.create(
                session_id="session-x",
                case_id=case_a.case_id,
                selected_file_node_ids=[node_b.node_id],
            )
        assert mismatch.value.code == "CONTEXT_SCOPE_MISMATCH"
    finally:
        services.close()


def test_snapshot_scope_previous_link_and_append_only(tmp_path: Path) -> None:
    root = tmp_path / "evidence"
    root.mkdir()
    (root / "note.txt").write_text("snapshot", encoding="utf-8")
    services = build_services(tmp_path / "snapshot.db")
    try:
        case, _, node = _case_evidence_file(services, root)
        context = services.contexts.create(
            session_id="session-s",
            case_id=case.case_id,
            selected_file_node_ids=[node.node_id],
        )
        snapshot = services.contexts.build_from_session(
            context.session_context_id,
            purpose="MCP_REQUEST",
            scopes=["filesystem"],
        )
        assert snapshot.included_resource_ids["FILE_SYSTEM_NODE"] == [node.node_id]
        assert snapshot.context_fingerprint
        assert services.contexts.list_scopes(snapshot.context_snapshot_id)[0].result_count == 1

        refreshed = services.contexts.refresh(snapshot.context_snapshot_id)
        assert refreshed.previous_snapshot_id == snapshot.context_snapshot_id
        assert refreshed.context_fingerprint == snapshot.context_fingerprint

        with pytest.raises(sqlite3.IntegrityError):
            services.repository.connection.execute(
                "UPDATE analysis_context_snapshots SET purpose = ? WHERE context_snapshot_id = ?",
                ("AUDIT", snapshot.context_snapshot_id),
            )
        with pytest.raises(sqlite3.IntegrityError):
            services.repository.connection.execute(
                "DELETE FROM analysis_context_snapshots WHERE context_snapshot_id = ?",
                (snapshot.context_snapshot_id,),
            )
    finally:
        services.close()


def test_view_modes_raw_reader_errors_and_logical_locator(tmp_path: Path) -> None:
    root = tmp_path / "evidence"
    root.mkdir()
    (root / "note.txt").write_text("hello phase6 raw", encoding="utf-8")
    services = build_services(tmp_path / "view.db")
    try:
        case, _, node = _case_evidence_file(services, root)
        simple = services.views.simple(
            case_id=case.case_id,
            resource_type="FILE_SYSTEM_NODE",
            resource_id=node.node_id,
        )
        detailed = services.views.detailed(
            case_id=case.case_id,
            resource_type="FILE_SYSTEM_NODE",
            resource_id=node.node_id,
        )
        raw = services.views.raw(
            case_id=case.case_id,
            resource_type="FILE_SYSTEM_NODE",
            resource_id=node.node_id,
        )
        assert simple.source_revision == detailed.source_revision == raw.source_revision
        assert simple.to_schema_dict()["primary_fields"]["next_recommended_view"] == "DETAILED"

        chunk = services.views.raw_read(
            case_id=case.case_id,
            resource_type="FILE_SYSTEM_NODE",
            resource_id=node.node_id,
            offset=0,
            length=5,
        )
        assert chunk.text_preview == "hello"
        assert chunk.returned_length == 5
        eof = services.views.raw_read(
            case_id=case.case_id,
            resource_type="FILE_SYSTEM_NODE",
            resource_id=node.node_id,
            offset=12,
            length=100,
        )
        assert eof.truncated is True
        with pytest.raises(ApexError) as negative:
            services.views.raw_read(
                case_id=case.case_id,
                resource_type="FILE_SYSTEM_NODE",
                resource_id=node.node_id,
                offset=-1,
            )
        assert negative.value.code == "RAW_RANGE_INVALID"
        with pytest.raises(ApexError) as too_large:
            services.views.raw_read(
                case_id=case.case_id,
                resource_type="FILE_SYSTEM_NODE",
                resource_id=node.node_id,
                length=1024 * 1024 + 1,
            )
        assert too_large.value.code == "RAW_READ_LIMIT_EXCEEDED"

        logical = services.views.raw_read(
            case_id=case.case_id,
            resource_type="FILE_SYSTEM_NODE",
            resource_id=node.node_id,
        )
        assert logical.hash["algorithm"] == "SHA256"
        logical_projection = services.interface.invoke_read(
            "view.raw-read",
            {
                "case_id": case.case_id,
                "resource_type": "FILE_SYSTEM_NODE",
                "resource_id": node.node_id,
                "offset": 0,
                "length": 5,
            },
        )
        assert logical_projection["status"] == "OK"
        assert len(services.repository.list_raw_read_audit_records(case_id=case.case_id)) >= 2
    finally:
        services.close()


def test_phase6_json_schemas_validate_outputs(tmp_path: Path, schema_validator) -> None:
    root = tmp_path / "schema-evidence"
    root.mkdir()
    (root / "note.txt").write_text("schema raw", encoding="utf-8")
    services = build_services(tmp_path / "schema.db")
    try:
        case, _, node = _case_evidence_file(services, root)
        context = services.contexts.create(
            session_id="session-schema",
            case_id=case.case_id,
            selected_file_node_ids=[node.node_id],
        )
        snapshot = services.contexts.build_from_session(
            context.session_context_id,
            purpose="MCP_REQUEST",
            scopes=["filesystem"],
        )
        scope = services.contexts.list_scopes(snapshot.context_snapshot_id)[0]
        view = services.views.simple(
            case_id=case.case_id,
            resource_type="FILE_SYSTEM_NODE",
            resource_id=node.node_id,
        )
        raw = services.views.raw_read(
            case_id=case.case_id,
            resource_type="FILE_SYSTEM_NODE",
            resource_id=node.node_id,
            length=4,
        )
        version = services.interface.version()
        tool = services.interface.tools()[0]

        schema_validator.validate(
            "gui-session-context.schema.json",
            context.to_schema_dict(),
        )
        schema_validator.validate(
            "analysis-context-snapshot.schema.json",
            snapshot.to_schema_dict(),
        )
        schema_validator.validate(
            "analysis-scope-context.schema.json",
            scope.to_schema_dict(),
        )
        schema_validator.validate("view-projection.schema.json", view.to_schema_dict())
        schema_validator.validate("raw-view.schema.json", raw.to_schema_dict())
        schema_validator.validate("raw-read-response.schema.json", raw.to_schema_dict())
        schema_validator.validate("engine-interface.schema.json", version.to_schema_dict())
        schema_validator.validate("engine-tool-descriptor.schema.json", tool.to_schema_dict())
    finally:
        services.close()


def test_interface_version_and_tool_descriptors(tmp_path: Path) -> None:
    services = build_services(tmp_path / "interface.db")
    try:
        version = services.interface.version().to_schema_dict()
        assert version["interface_version"] == "1.0.0"
        assert "MCP_SERVER" in version["unavailable_capabilities"]
        tools = [tool.to_schema_dict() for tool in services.interface.tools()]
        assert {tool["tool_name"] for tool in tools} >= {
            "apex.context.get",
            "apex.view.raw_read",
        }
        raw_tool = next(tool for tool in tools if tool["tool_name"] == "apex.view.raw_read")
        assert raw_tool["requires_confirmation"] is True
        assert raw_tool["supports_citation"] is True
    finally:
        services.close()



def test_generic_artifacts_resolve_only_to_matching_artifact_scopes(tmp_path: Path) -> None:
    root = tmp_path / "artifact-scopes"
    root.mkdir()
    (root / "source.txt").write_text("artifact scopes", encoding="utf-8")
    services = build_services(tmp_path / "artifact-scopes.db")
    try:
        case, evidence, node = _case_evidence_file(services, root)
        registry_id = _save_artifact(
            services,
            case_id=case.case_id,
            evidence_id=evidence.evidence_id,
            node=node,
            artifact_id="artifact-registry",
            artifact_type=ArtifactType.REGISTRY_KEY,
        )
        browser_id = _save_artifact(
            services,
            case_id=case.case_id,
            evidence_id=evidence.evidence_id,
            node=node,
            artifact_id="artifact-browser",
            artifact_type=ArtifactType.BROWSER_VISIT,
        )
        media_id = _save_artifact(
            services,
            case_id=case.case_id,
            evidence_id=evidence.evidence_id,
            node=node,
            artifact_id="artifact-media",
            artifact_type=ArtifactType.MEDIA_IMAGE,
        )

        for artifact_id, expected_scope in (
            (registry_id, "registry"),
            (browser_id, "browser"),
            (media_id, "media"),
        ):
            context = services.contexts.create(
                session_id=f"session-{artifact_id}",
                case_id=case.case_id,
                selected_artifact_ids=[artifact_id],
            )
            snapshot = services.contexts.build_from_session(
                context.session_context_id, purpose="MCP_REQUEST"
            )
            scopes = _scope_map(services, snapshot)
            assert scopes[expected_scope].resource_ids == [artifact_id]
            unrelated_scopes = {"registry", "browser", "media"} - {expected_scope}
            assert all(scope not in scopes for scope in unrelated_scopes)

        context = services.contexts.create(
            session_id="session-mixed-artifacts",
            case_id=case.case_id,
            selected_artifact_ids=[registry_id, browser_id, media_id, browser_id],
        )
        snapshot = services.contexts.build_from_session(
            context.session_context_id, purpose="MCP_REQUEST"
        )
        scopes = _scope_map(services, snapshot)
        assert scopes["registry"].resource_ids == [registry_id]
        assert scopes["browser"].resource_ids == [browser_id]
        assert scopes["media"].resource_ids == [media_id]
        assert "eventlog" not in scopes
        assert "prefetch" not in scopes
        assert scopes["selection"].resource_ids == sorted({registry_id, browser_id, media_id})
    finally:
        services.close()


def test_refresh_preserves_provenance_and_links_previous_snapshot(tmp_path: Path) -> None:
    root = tmp_path / "refresh-provenance"
    root.mkdir()
    (root / "refresh-secret.txt").write_text("refresh", encoding="utf-8")
    services = build_services(tmp_path / "refresh.db")
    try:
        case, evidence, _ = _case_evidence_file(services, root)
        services.search.index(
            case_id=case.case_id,
            evidence_ids=[evidence.evidence_id],
            source_types=[SearchSourceType.FILE_SYSTEM_NODE],
        )
        page = services.search.query(case_id=case.case_id, query_text="refresh", limit=10)
        keyword_set = services.search.create_keyword_set(
            case_id=case.case_id,
            name="Refresh Keywords",
            keywords=[{"term": "refresh", "keyword_type": "DOCUMENT_TERM"}],
        )
        _, coverage = services.timeline.build(
            case_id=case.case_id, evidence_id=evidence.evidence_id
        )
        context = services.contexts.create(
            session_id="session-refresh",
            case_id=case.case_id,
            active_evidence_id=evidence.evidence_id,
            active_filters={"name": "refresh"},
            active_time_range={"start": "2024-01-01T00:00:00Z"},
            active_keyword_set_id=keyword_set.keyword_set_id,
            active_keyword_set_version=keyword_set.version,
            active_search_execution_id=page.execution.execution_id,
            active_timeline_revision=coverage.timeline_revision,
        )
        snapshot = services.contexts.build_from_session(
            context.session_context_id, purpose="MCP_REQUEST", scopes=["evidence"]
        )

        refreshed = services.contexts.refresh(snapshot.context_snapshot_id)
        original = services.contexts.get_snapshot(snapshot.context_snapshot_id)

        assert refreshed.context_snapshot_id != snapshot.context_snapshot_id
        assert refreshed.previous_snapshot_id == snapshot.context_snapshot_id
        assert original.previous_snapshot_id is None
        assert original.context_fingerprint == snapshot.context_fingerprint
        assert refreshed.keyword_set_id == keyword_set.keyword_set_id
        assert refreshed.keyword_set_version == keyword_set.version
        assert refreshed.search_execution_id == page.execution.execution_id
        assert refreshed.search_index_revision == page.execution.index_revision
        assert refreshed.timeline_revision == coverage.timeline_revision
        assert refreshed.filters == snapshot.filters == {"name": "refresh"}
        assert refreshed.time_range == snapshot.time_range
        assert refreshed.context_fingerprint == snapshot.context_fingerprint
    finally:
        services.close()


def test_raw_locator_rejects_forged_sources_before_audit(tmp_path: Path) -> None:
    root = tmp_path / "raw-root"
    root.mkdir()
    (root / "readme.txt").write_text("valid raw bytes", encoding="utf-8")
    db_path = tmp_path / "raw.db"
    services = build_services(db_path)
    try:
        case, evidence, node = _case_evidence_file(services, root)
        evidence_b, node_b = _add_evidence_file_to_case(
            services, case.case_id, tmp_path / "raw-root-b", "other.txt"
        )
        root_c = tmp_path / "raw-root-c"
        root_c.mkdir()
        (root_c / "foreign.txt").write_text("foreign", encoding="utf-8")
        case_c, _, node_c = _case_evidence_file(services, root_c)
        reader = SafeRawRangeReader(
            repository=services.repository,
            clock=services.contexts._clock,
            id_generator=services.contexts._id_generator,
        )
        base_locator = {
            "locator_type": "BYTE_RANGE",
            "evidence_id": evidence.evidence_id,
            "source_id": node.node_id,
            "relative_path": node.original_relative_path,
            "offset": 0,
            "length": 5,
        }
        before = len(services.repository.list_raw_read_audit_records(case_id=case.case_id))

        invalid_locators = [
            ({**base_locator, "source_id": "missing-node"}, "RAW_RESOURCE_NOT_FOUND"),
            ({**base_locator, "source_id": node_b.node_id}, "RAW_SOURCE_OUTSIDE_EVIDENCE"),
            ({**base_locator, "source_id": node_c.node_id}, "RAW_SOURCE_OUTSIDE_EVIDENCE"),
            ({**base_locator, "relative_path": "forged.txt"}, "RAW_SOURCE_OUTSIDE_EVIDENCE"),
            ({**base_locator, "relative_path": "../outside.txt"}, "RAW_SOURCE_OUTSIDE_EVIDENCE"),
        ]
        for locator, expected_code in invalid_locators:
            with pytest.raises(ApexError) as error:
                reader.read_locator(
                    case_id=case.case_id,
                    resource_type="FILE_SYSTEM_NODE",
                    resource_id=node.node_id,
                    raw_locator=locator,
                    offset=0,
                    length=1,
                )
            assert error.value.code == expected_code

        outside = tmp_path / "outside.txt"
        outside.write_text("outside", encoding="utf-8")
        (root / "escape.txt").symlink_to(outside)
        escape_node = replace(
            node,
            node_id="escape-node",
            original_name="escape.txt",
            original_relative_path="escape.txt",
            display_path="/escape.txt",
            comparison_path="/escape.txt",
            raw_locator={**base_locator, "source_id": "escape-node", "relative_path": "escape.txt"},
            is_link=False,
        )
        services.repository.upsert_fs_node(escape_node)
        with pytest.raises(ApexError) as escape_error:
            reader.read_locator(
                case_id=case.case_id,
                resource_type="FILE_SYSTEM_NODE",
                resource_id="escape-node",
                raw_locator={
                    **base_locator,
                    "source_id": "escape-node",
                    "relative_path": "escape.txt",
                },
            )
        assert escape_error.value.code == "RAW_SOURCE_OUTSIDE_EVIDENCE"

        valid = reader.read_locator(
            case_id=case.case_id,
            resource_type="FILE_SYSTEM_NODE",
            resource_id=node.node_id,
            raw_locator=base_locator,
            offset=0,
            length=5,
        )
        assert valid.text_preview == "valid"
        after = len(services.repository.list_raw_read_audit_records(case_id=case.case_id))
        assert after == before + 1
        assert evidence_b.case_id == case.case_id
        assert case_c.case_id != case.case_id
    finally:
        services.close()


def test_interface_descriptors_aliases_and_validation_errors(tmp_path: Path) -> None:
    root = tmp_path / "interface-ops"
    root.mkdir()
    (root / "note.txt").write_text("interface operations", encoding="utf-8")
    services = build_services(tmp_path / "interface-ops.db")
    try:
        case, _, node = _case_evidence_file(services, root)
        context = services.contexts.create(
            session_id="session-interface",
            case_id=case.case_id,
            selected_file_node_ids=[node.node_id],
        )
        snapshot = services.contexts.build_from_session(
            context.session_context_id, purpose="MCP_REQUEST", scopes=["filesystem"]
        )
        payloads = {
            "apex.context.get": {"session_context_id": context.session_context_id},
            "apex.context.snapshot": {
                "session_context_id": context.session_context_id,
                "purpose": "MCP_REQUEST",
                "scopes": ["filesystem"],
            },
            "apex.context.snapshot_show": {"context_snapshot_id": snapshot.context_snapshot_id},
            "apex.context.scope_page": {
                "context_snapshot_id": snapshot.context_snapshot_id,
                "scope": "filesystem",
                "limit": 1,
            },
            "apex.view.simple": {
                "case_id": case.case_id,
                "resource_type": "FILE_SYSTEM_NODE",
                "resource_id": node.node_id,
            },
            "apex.view.detailed": {
                "case_id": case.case_id,
                "resource_type": "FILE_SYSTEM_NODE",
                "resource_id": node.node_id,
            },
            "apex.view.raw": {
                "case_id": case.case_id,
                "resource_type": "FILE_SYSTEM_NODE",
                "resource_id": node.node_id,
            },
            "apex.view.raw_read": {
                "case_id": case.case_id,
                "resource_type": "FILE_SYSTEM_NODE",
                "resource_id": node.node_id,
                "offset": 0,
                "length": 4,
            },
        }
        for tool in services.interface.tools():
            result = services.interface.invoke_read(
                tool.tool_name,
                payloads[tool.tool_name],
                request_id=f"req-{tool.tool_name}",
                correlation_id="corr-tools",
            )
            assert result["status"] == "OK", result

        advertised = services.interface.invoke_read(
            "apex.view.raw_read", payloads["apex.view.raw_read"]
        )
        alias = services.interface.invoke_read("view.raw-read", payloads["apex.view.raw_read"])
        assert advertised["data"]["returned_length"] == alias["data"]["returned_length"] == 4

        unknown = services.interface.invoke_read(
            "apex.unknown", {}, request_id="req-unknown", correlation_id="corr-unknown"
        )
        assert unknown["status"] == "ERROR"
        assert unknown["request_id"] == "req-unknown"
        assert unknown["correlation_id"] == "corr-unknown"
        assert unknown["errors"][0]["code"] == "CAPABILITY_UNAVAILABLE"

        malformed = [
            ("view.simple", {"resource_type": "FILE_SYSTEM_NODE", "resource_id": node.node_id}),
            ("view.simple", {"case_id": case.case_id, "resource_type": "FILE_SYSTEM_NODE"}),
            ("view.raw-read", {**payloads["apex.view.raw_read"], "offset": "bad"}),
            ("view.raw-read", {**payloads["apex.view.raw_read"], "length": 0}),
            ("view.simple", {**payloads["apex.view.simple"], "resource_type": "NOPE"}),
            (
                "apex.context.snapshot",
                {"session_context_id": context.session_context_id, "scopes": "filesystem"},
            ),
            (
                "context.scope-page",
                {
                    "context_snapshot_id": snapshot.context_snapshot_id,
                    "scope": "filesystem",
                    "cursor": "not-a-cursor",
                },
            ),
            ("view.simple", ["not", "an", "object"]),
        ]
        for operation, payload in malformed:
            error = services.interface.invoke_read(
                operation, payload, request_id="req-error", correlation_id="corr-error"
            )
            assert error["status"] == "ERROR", (operation, error)
            assert error["request_id"] == "req-error"
            assert error["correlation_id"] == "corr-error"
            assert error["errors"]

        valid = services.interface.invoke_read("view.simple", payloads["apex.view.simple"])
        assert valid["status"] == "OK"
        assert valid["data"]["resource_id"] == node.node_id
    finally:
        services.close()


def test_evidence_scope_paginates_reopens_and_rejects_cross_case(tmp_path: Path) -> None:
    db_path = tmp_path / "evidence-scope.db"
    root = tmp_path / "evidence-a"
    root.mkdir()
    (root / "a.txt").write_text("a", encoding="utf-8")
    services = build_services(db_path)
    snapshot_id = ""
    snapshot_fingerprint = ""
    evidence_ids: list[str] = []
    try:
        case, evidence_a, _ = _case_evidence_file(services, root)
        evidence_b, _ = _add_evidence_file_to_case(
            services, case.case_id, tmp_path / "evidence-b", "b.txt"
        )
        evidence_c, _ = _add_evidence_file_to_case(
            services, case.case_id, tmp_path / "evidence-c", "c.txt"
        )
        evidence_ids = sorted(
            [evidence_a.evidence_id, evidence_b.evidence_id, evidence_c.evidence_id]
        )
        context = services.contexts.create(
            session_id="session-evidence",
            case_id=case.case_id,
            active_evidence_id=evidence_a.evidence_id,
        )
        snapshot = services.contexts.build_from_session(
            context.session_context_id, purpose="MCP_REQUEST"
        )
        scopes = _scope_map(services, snapshot)
        assert scopes["evidence"].resource_ids == [evidence_a.evidence_id]
        assert scopes["evidence"].result_count == 1
        assert scopes["evidence"].included_count == 1

        same_snapshot = services.contexts.build_from_session(
            context.session_context_id, purpose="MCP_REQUEST"
        )
        assert same_snapshot.context_fingerprint == snapshot.context_fingerprint

        all_evidence = services.contexts.build_by_scope(
            case_id=case.case_id,
            actor_id=None,
            purpose="MCP_REQUEST",
            scope="evidence",
            limit=10,
        )
        page_one = services.contexts.paginate_scope(
            all_evidence.context_snapshot_id, "evidence", limit=2
        )
        page_two = services.contexts.paginate_scope(
            all_evidence.context_snapshot_id,
            "evidence",
            cursor=page_one["page"]["next_cursor"],
            limit=2,
        )
        paged_ids = [item["resource_id"] for item in page_one["items"] + page_two["items"]]
        assert sorted(paged_ids) == evidence_ids
        assert page_one["page"]["returned"] == 2
        assert page_two["page"]["returned"] == 1

        other_root = tmp_path / "evidence-other-case"
        other_root.mkdir()
        (other_root / "other.txt").write_text("other", encoding="utf-8")
        _, other_evidence, _ = _case_evidence_file(services, other_root)
        with pytest.raises(ApexError) as mismatch:
            services.contexts.create(
                session_id="session-cross-evidence",
                case_id=case.case_id,
                active_evidence_id=other_evidence.evidence_id,
            )
        assert mismatch.value.code == "CONTEXT_SCOPE_MISMATCH"

        snapshot_id = all_evidence.context_snapshot_id
        snapshot_fingerprint = all_evidence.context_fingerprint
    finally:
        services.close()

    reopened = build_services(db_path)
    try:
        reopened_snapshot = reopened.contexts.get_snapshot(snapshot_id)
        reopened_scopes = _scope_map(reopened, reopened_snapshot)
        assert reopened_snapshot.context_fingerprint == snapshot_fingerprint
        assert reopened_scopes["evidence"].resource_ids == evidence_ids
        assert reopened_scopes["evidence"].scope_fingerprint
    finally:
        reopened.close()
