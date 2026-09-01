from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx2
import pytest
from mcp.client import Client
from mcp.client.streamable_http import streamable_http_client
from mcp.server.auth.provider import AccessToken
from starlette.applications import Starlette

from apex_forensic.config import build_services
from apex_forensic.domain.enums import AnalysisProfileType
from apex_mcp.config import McpConfig
from apex_mcp.confirmation import ConfirmationGrant
from apex_mcp.engine_adapter import EngineAdapter
from apex_mcp.errors import McpConfigurationError
from apex_mcp.frontend_security import (
    FrontendSession,
    InMemoryFrontendSecurityProvider,
    StaticBearerTokenVerifier,
)
from apex_mcp.http_transport import HttpTransportConfig, create_http_app
from apex_mcp.m5_tools import M5_TOOL_NAMES, m5_bindings
from apex_mcp.server import create_runtime
from apex_mcp.telemetry import request_fingerprint

_BASE_URL = "http://127.0.0.1:8765"
_ORIGIN = "http://127.0.0.1:8765"
_SECRET = "m6-test-secret"


def _seed(project_root: Path, tmp_path: Path) -> dict[str, Any]:
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    (evidence_root / "selected.bin").write_bytes(b"APEX-M6-HTTP")
    database_path = tmp_path / "m6.db"
    services = build_services(database_path)
    case = services.cases.create_case(name="MCP M6 HTTP")
    other_case = services.cases.create_case(name="MCP M6 Other Tenant")
    evidence = services.evidence.register_evidence(
        case_id=case.case_id,
        source_path=evidence_root,
    )
    services.fs.index_evidence(
        case_id=case.case_id,
        evidence_id=evidence.evidence_id,
        profile_type=AnalysisProfileType.FULL_ANALYSIS,
    )
    node = next(
        item
        for item in services.fs.list_nodes(
            evidence_id=evidence.evidence_id,
            all_nodes=True,
        ).items
        if item.node_type.value == "FILE"
    )
    context = services.contexts.create(
        session_id="frontend-http-session",
        case_id=case.case_id,
        actor_id="analyst-http",
        selected_file_node_ids=[node.node_id],
        active_context_scope="filesystem",
    )
    other_session_context = services.contexts.create(
        session_id="another-frontend-session",
        case_id=case.case_id,
        actor_id="another-analyst",
    )
    token = AccessToken(
        token=_SECRET,
        client_id="apex-m6-client",
        subject="analyst-http",
        scopes=[
            "apex:mcp",
            "apex:read",
            "apex:write",
            "apex:confirm",
            "apex:raw",
            "apex:approve",
            "apex:export",
        ],
        resource=f"{_BASE_URL}/mcp",
        claims={"iss": _BASE_URL},
    )
    security = InMemoryFrontendSecurityProvider()
    security.register(
        token,
        FrontendSession(
            actor_id="analyst-http",
            session_id="frontend-http-session",
            tenant_id="tenant-a",
            allowed_case_ids=frozenset({case.case_id}),
            roles=frozenset({"ANALYST"}),
        ),
    )
    runtime = create_runtime(
        McpConfig(
            database_path=database_path,
            schema_dir=project_root / "schemas" / "v1",
            allowed_tools=M5_TOOL_NAMES,
        ),
        adapter=EngineAdapter(services),
        bindings=m5_bindings(),
        frontend_security_provider=security,
    )
    app = create_http_app(
        runtime,
        HttpTransportConfig(),
        token_verifier=StaticBearerTokenVerifier(_SECRET, token),
    )
    return {
        "services": services,
        "runtime": runtime,
        "security": security,
        "app": app,
        "case_id": case.case_id,
        "other_case_id": other_case.case_id,
        "context_id": context.session_context_id,
        "other_session_context_id": other_session_context.session_context_id,
        "node_id": node.node_id,
    }


@asynccontextmanager
async def _mcp_client(seeded: dict[str, Any]) -> AsyncIterator[Client]:
    app = seeded["app"]
    assert isinstance(app, Starlette)
    async with app.router.lifespan_context(app), httpx2.AsyncClient(
        transport=httpx2.ASGITransport(app=app),
        base_url=_BASE_URL,
        headers={
            "Authorization": f"Bearer {_SECRET}",
            "Origin": _ORIGIN,
        },
    ) as http_client:
        transport = streamable_http_client(
            f"{_BASE_URL}/mcp",
            http_client=http_client,
        )
        async with Client(transport, mode="2026-07-28") as client:
            yield client


def _error_code(result: Any) -> str:
    return str(result.structured_content["errors"][0]["code"])


def test_m6_http_network_guards_and_rate_limit(project_root: Path, tmp_path: Path) -> None:
    with pytest.raises(McpConfigurationError):
        HttpTransportConfig(allowed_hosts=("*",)).validate()
    with pytest.raises(McpConfigurationError):
        HttpTransportConfig(
            host="0.0.0.0",
            allowed_hosts=("apex.example:443",),
            allowed_origins=("https://apex.example",),
            issuer_url="http://apex.example",
            resource_url="http://apex.example/mcp",
        ).validate()
    seeded = _seed(project_root, tmp_path)
    app = seeded["app"]

    async def exercise() -> None:
        assert isinstance(app, Starlette)
        async with app.router.lifespan_context(app), httpx2.AsyncClient(
            transport=httpx2.ASGITransport(app=app),
            base_url=_BASE_URL,
        ) as client:
            unauthenticated = await client.post(
                "/mcp",
                json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            )
            bad_host = await client.post(
                "/mcp",
                headers={
                    "Authorization": f"Bearer {_SECRET}",
                    "Host": "attacker.invalid",
                },
                json={"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
            )
            bad_origin = await client.post(
                "/mcp",
                headers={
                    "Authorization": f"Bearer {_SECRET}",
                    "Origin": "https://attacker.invalid",
                },
                json={"jsonrpc": "2.0", "id": 3, "method": "tools/list"},
            )
            preflight = await client.options(
                "/mcp",
                headers={
                    "Origin": _ORIGIN,
                    "Access-Control-Request-Method": "POST",
                    "Access-Control-Request-Headers": (
                        "authorization,content-type,mcp-protocol-version,"
                        "mcp-method,mcp-name"
                    ),
                },
            )
            oversized = await client.post(
                "/mcp",
                headers={
                    "Authorization": f"Bearer {_SECRET}",
                    "Content-Type": "application/json",
                },
                content=b"x" * (1024 * 1024 + 1),
            )

        limited_app = create_http_app(
            seeded["runtime"],
            HttpTransportConfig(max_requests=1),
            token_verifier=StaticBearerTokenVerifier(
                _SECRET,
                AccessToken(
                    token=_SECRET,
                    client_id="rate-limit-client",
                    subject="analyst-http",
                    scopes=["apex:mcp"],
                    resource=f"{_BASE_URL}/mcp",
                    claims={"iss": _BASE_URL},
                ),
            ),
        )
        assert isinstance(limited_app, Starlette)
        async with limited_app.router.lifespan_context(limited_app), httpx2.AsyncClient(
            transport=httpx2.ASGITransport(app=limited_app),
            base_url=_BASE_URL,
        ) as limited:
            first = await limited.post("/mcp", json={})
            second = await limited.post("/mcp", json={})

        assert unauthenticated.status_code == 401
        assert bad_host.status_code == 421
        assert bad_origin.status_code == 403
        assert preflight.status_code == 200
        assert preflight.headers["access-control-allow-origin"] == _ORIGIN
        allowed_headers = preflight.headers["access-control-allow-headers"].casefold()
        assert "mcp-method" in allowed_headers
        assert "mcp-name" in allowed_headers
        assert oversized.status_code == 413
        assert first.status_code == 401
        assert second.status_code == 429
        assert "retry-after" in second.headers

    try:
        asyncio.run(exercise())
    finally:
        seeded["runtime"].close()
        seeded["services"].close()


def test_m6_http_contract_tenant_and_frontend_context(
    project_root: Path,
    tmp_path: Path,
) -> None:
    seeded = _seed(project_root, tmp_path)

    async def exercise() -> None:
        async with _mcp_client(seeded) as client:
            tools = await client.list_tools(cache_mode="refresh")
            assert client.session.protocol_version == "2026-07-28"
            assert {tool.name for tool in tools.tools} == M5_TOOL_NAMES
            assert {tool.name for tool in tools.tools} == {
                tool.name for tool in seeded["runtime"].registry.list_tools()
            }

            allowed = await client.call_tool(
                "report.list",
                {"case_id": seeded["case_id"]},
            )
            cross_tenant = await client.call_tool(
                "report.list",
                {"case_id": seeded["other_case_id"]},
            )
            wrong_frontend_session = await client.call_tool(
                "apex.context.get",
                {"session_context_id": seeded["other_session_context_id"]},
            )
            snapshot = await client.call_tool(
                "apex.context.snapshot",
                {
                    "session_context_id": seeded["context_id"],
                    "scopes": ["filesystem"],
                },
            )
            created = await client.call_tool(
                "report.create",
                {"case_id": seeded["case_id"], "title": "Created over HTTP"},
            )

            assert allowed.is_error is False
            assert cross_tenant.is_error is True
            assert _error_code(cross_tenant) == "MCP_TENANT_SCOPE_VIOLATION"
            assert wrong_frontend_session.is_error is True
            assert _error_code(wrong_frontend_session) == "MCP_AUTHORIZATION_DENIED"
            assert snapshot.is_error is False
            assert snapshot.structured_content["data"]["purpose"] == "MCP_REQUEST"
            assert snapshot.structured_content["data"]["actor_id"] == "analyst-http"
            assert created.is_error is False
            assert created.structured_content["data"]["created_by"] == "analyst-http"

    try:
        asyncio.run(exercise())
    finally:
        seeded["runtime"].close()
        seeded["services"].close()


def test_m6_http_rbac_and_ui_approval_fingerprint(
    project_root: Path,
    tmp_path: Path,
) -> None:
    seeded = _seed(project_root, tmp_path)
    raw_arguments = {
        "case_id": seeded["case_id"],
        "resource_type": "FILE_SYSTEM_NODE",
        "resource_id": seeded["node_id"],
        "offset": 0,
        "length": 4,
    }

    async def exercise() -> None:
        async with _mcp_client(seeded) as client:
            analyst_cannot_approve = await client.call_tool(
                "report.approve",
                {
                    "case_id": seeded["case_id"],
                    "report_version_id": "untrusted-target",
                    "reason": "Must be denied before Core execution.",
                    "expected_review_revision": 1,
                    "expected_approval_revision": 0,
                },
            )
            no_ui_grant = await client.call_tool("apex.view.raw_read", raw_arguments)
            altered_without_grant = await client.call_tool(
                "apex.view.raw_read",
                {**raw_arguments, "length": 5},
            )

            seeded["security"].issue(
                ConfirmationGrant(
                    grant_id="frontend-ui-raw-approval",
                    actor_id="analyst-http",
                    session_id="frontend-http-session",
                    case_id=seeded["case_id"],
                    tool_name="apex.view.raw_read",
                    request_fingerprint=request_fingerprint(raw_arguments),
                    target_ids=(seeded["node_id"],),
                    expires_at=datetime.now(UTC) + timedelta(minutes=5),
                )
            )
            approved = await client.call_tool("apex.view.raw_read", raw_arguments)
            replay = await client.call_tool("apex.view.raw_read", raw_arguments)

            assert analyst_cannot_approve.is_error is True
            assert _error_code(analyst_cannot_approve) == "MCP_AUTHORIZATION_DENIED"
            assert _error_code(no_ui_grant) == "HUMAN_CONFIRMATION_REQUIRED"
            assert _error_code(altered_without_grant) == "HUMAN_CONFIRMATION_REQUIRED"
            assert approved.is_error is False
            assert approved.structured_content["data"]["returned_length"] == 4
            assert replay.is_error is True
            assert _error_code(replay) == "HUMAN_CONFIRMATION_REQUIRED"

    try:
        asyncio.run(exercise())
    finally:
        seeded["runtime"].close()
        seeded["services"].close()
