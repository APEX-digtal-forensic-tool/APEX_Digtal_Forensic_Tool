"""Phase 6 E2E: JwtTokenVerifier + PersistentFrontendSecurityProvider wired into MCP HTTP."""

from __future__ import annotations

import asyncio
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import httpx2
from mcp.client import Client
from mcp.client.streamable_http import streamable_http_client
from mcp.server.auth.provider import AccessToken
from starlette.applications import Starlette

from apex_backend.auth.jwt_utils import issue_access_token
from apex_backend.auth.jwt_verifier import JwtTokenVerifier, _jwk_to_pem
from apex_backend.auth.keys import load_private_key, public_key_to_jwk
from apex_backend.auth.scopes import scopes_for_roles
from apex_forensic.config import build_services
from apex_forensic.domain.enums import AnalysisProfileType
from apex_mcp.config import McpConfig
from apex_mcp.engine_adapter import EngineAdapter
from apex_mcp.frontend_security import (
    FrontendSession,
    InMemoryFrontendSecurityProvider,
    PersistentFrontendSecurityProvider,
    StaticBearerTokenVerifier,
)
from apex_mcp.http_transport import HttpTransportConfig, create_http_app
from apex_mcp.m5_tools import M5_TOOL_NAMES, m5_bindings
from apex_mcp.server import create_runtime

_BASE_URL = "http://127.0.0.1:8765"
_ORIGIN = "http://127.0.0.1:8765"
_SESSION_ID = "e2e-session"
_ACTOR_ID = "e2e-analyst"


def _seed_forensic_db(project_root: Path, tmp_path: Path) -> dict[str, Any]:
    """Seed forensic DB with evidence, file nodes, and a session context."""
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    (evidence_root / "e2e.bin").write_bytes(b"APEX-E2E-BACKEND")
    database_path = tmp_path / "e2e.db"

    services = build_services(database_path)
    case = services.cases.create_case(name="E2E Backend Integration")
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
        for item in services.fs.list_nodes(evidence_id=evidence.evidence_id, all_nodes=True).items
        if item.node_type.value == "FILE"
    )
    context = services.contexts.create(
        session_id=_SESSION_ID,
        case_id=case.case_id,
        actor_id=_ACTOR_ID,
        selected_file_node_ids=[node.node_id],
        active_context_scope="filesystem",
    )
    return {
        "services": services,
        "database_path": database_path,
        "case_id": case.case_id,
        "context_id": context.session_context_id,
        "node_id": node.node_id,
        "project_root": project_root,
    }


def _build_jwt_stack(seeded: dict[str, Any]) -> dict[str, Any]:
    """Build JwtTokenVerifier + PersistentFrontendSecurityProvider MCP stack."""
    private_key, kid = load_private_key()
    roles = ["ANALYST"]
    scopes = sorted(scopes_for_roles(frozenset(roles)))
    access_token_str = issue_access_token(
        private_key=private_key,
        kid=kid,
        actor_id=_ACTOR_ID,
        session_id=_SESSION_ID,
        tenant_id="tenant-e2e",
        allowed_case_ids=[seeded["case_id"]],
        roles=roles,
        scopes=scopes,
    )

    jwk = public_key_to_jwk(private_key.public_key(), kid)
    verifier = JwtTokenVerifier(
        jwks_uri=f"{_BASE_URL}/.well-known/jwks.json",
        cache_ttl_seconds=300,
    )
    verifier._keys = {kid: _jwk_to_pem(jwk)}
    verifier._fetched_at = time.monotonic()

    security = PersistentFrontendSecurityProvider()
    runtime = create_runtime(
        McpConfig(
            database_path=seeded["database_path"],
            schema_dir=seeded["project_root"] / "schemas" / "v1",
            allowed_tools=M5_TOOL_NAMES,
        ),
        adapter=EngineAdapter(seeded["services"]),
        bindings=m5_bindings(),
        frontend_security_provider=security,
    )
    app = create_http_app(runtime, HttpTransportConfig(), token_verifier=verifier)
    return {**seeded, "app": app, "access_token": access_token_str, "verifier": verifier}


@asynccontextmanager
async def _mcp_client(seeded: dict[str, Any]) -> AsyncIterator[Client]:
    app = seeded["app"]
    assert isinstance(app, Starlette)
    async with app.router.lifespan_context(app), httpx2.AsyncClient(
        transport=httpx2.ASGITransport(app=app),
        base_url=_BASE_URL,
        headers={"Authorization": f"Bearer {seeded['access_token']}", "Origin": _ORIGIN},
    ) as http_client:
        transport = streamable_http_client(f"{_BASE_URL}/mcp", http_client=http_client)
        async with Client(transport, mode="2026-07-28") as client:
            yield client


def _error_code(result: Any) -> str:
    return str(result.structured_content["errors"][0]["code"])


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_e2e_jwt_read_only_tool_succeeds(project_root: Path, tmp_path: Path) -> None:
    """Full chain: JWT → JwtTokenVerifier → PersistentFrontendSecurityProvider → tool OK."""
    seeded = _build_jwt_stack(_seed_forensic_db(project_root, tmp_path))

    async def run() -> None:
        async with _mcp_client(seeded) as client:
            result = await client.call_tool(
                "apex.context.snapshot",
                {"session_context_id": seeded["context_id"], "scopes": ["filesystem"]},
            )
            content = result.structured_content
            assert content is not None
            assert content.get("status") == "OK", f"unexpected: {content}"

    asyncio.run(run())


def test_e2e_jwt_invalid_token_rejected(project_root: Path, tmp_path: Path) -> None:
    """Tampered JWT → verifier returns None → MCP returns 401."""
    seeded = _build_jwt_stack(_seed_forensic_db(project_root, tmp_path))
    tampered = seeded["access_token"][:-10] + "tampered!!"

    async def run() -> None:
        app = seeded["app"]
        assert isinstance(app, Starlette)
        async with app.router.lifespan_context(app), httpx2.AsyncClient(
            transport=httpx2.ASGITransport(app=app),
            base_url=_BASE_URL,
            headers={"Authorization": f"Bearer {tampered}", "Origin": _ORIGIN},
        ) as http_client:
            resp = await http_client.post(
                "/mcp",
                json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            )
            assert resp.status_code == 401

    asyncio.run(run())


def test_e2e_jwt_wrong_case_denied(project_root: Path, tmp_path: Path) -> None:
    """JWT allows case-A; tool targets case-B → TENANT_SCOPE_VIOLATION."""
    seeded = _build_jwt_stack(_seed_forensic_db(project_root, tmp_path))

    async def run() -> None:
        async with _mcp_client(seeded) as client:
            result = await client.call_tool(
                "report.list",
                {"case_id": "case-not-in-token"},
            )
            content = result.structured_content
            assert content is not None
            assert content.get("status") == "ERROR"
            assert "TENANT_SCOPE_VIOLATION" in _error_code(result)

    asyncio.run(run())


def test_e2e_inmemory_security_still_works(project_root: Path, tmp_path: Path) -> None:
    """InMemoryFrontendSecurityProvider + StaticBearerTokenVerifier path unchanged."""
    secret = "e2e-static-secret"
    db_seed = _seed_forensic_db(project_root, tmp_path)

    static_token = AccessToken(
        token=secret,
        client_id="static-client",
        subject=_ACTOR_ID,
        scopes=["apex:mcp", "apex:read", "apex:write", "apex:confirm"],
        resource=f"{_BASE_URL}/mcp",
        claims={"iss": _BASE_URL},
    )
    security = InMemoryFrontendSecurityProvider()
    security.register(
        static_token,
        FrontendSession(
            actor_id=_ACTOR_ID,
            session_id=_SESSION_ID,
            tenant_id="tenant-static",
            allowed_case_ids=frozenset({db_seed["case_id"]}),
            roles=frozenset({"ANALYST"}),
        ),
    )
    runtime = create_runtime(
        McpConfig(
            database_path=db_seed["database_path"],
            schema_dir=db_seed["project_root"] / "schemas" / "v1",
            allowed_tools=M5_TOOL_NAMES,
        ),
        adapter=EngineAdapter(db_seed["services"]),
        bindings=m5_bindings(),
        frontend_security_provider=security,
    )
    verifier = StaticBearerTokenVerifier(secret, static_token)
    app = create_http_app(runtime, HttpTransportConfig(), token_verifier=verifier)

    async def run() -> None:
        assert isinstance(app, Starlette)
        async with app.router.lifespan_context(app), httpx2.AsyncClient(
            transport=httpx2.ASGITransport(app=app),
            base_url=_BASE_URL,
            headers={"Authorization": f"Bearer {secret}", "Origin": _ORIGIN},
        ) as http_client:
            transport = streamable_http_client(f"{_BASE_URL}/mcp", http_client=http_client)
            async with Client(transport, mode="2026-07-28") as client:
                result = await client.call_tool(
                    "apex.context.snapshot",
                    {"session_context_id": db_seed["context_id"], "scopes": ["filesystem"]},
                )
                assert result.structured_content is not None
                assert result.structured_content.get("status") == "OK"

    asyncio.run(run())
