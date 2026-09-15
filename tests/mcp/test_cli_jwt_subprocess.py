"""Phase 10: apex-mcp CLI subprocess test — JWT production mode wiring.

Starts apex-mcp as a real subprocess with --http-jwks-uri and verifies that
a valid JWT succeeds and a tampered JWT is rejected (401).
"""

from __future__ import annotations

import json
import socket
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import httpx

from apex_backend.auth.jwt_utils import AUDIENCE, ISSUER, issue_access_token
from apex_backend.auth.keys import load_private_key, public_key_to_jwk
from apex_backend.auth.scopes import scopes_for_roles
from apex_backend.database import Base
from apex_forensic.config import build_services


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _make_jwks_handler(jwks: dict) -> type[BaseHTTPRequestHandler]:
    class _Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            if self.path == "/.well-known/jwks.json":
                body = json.dumps(jwks).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            else:
                self.send_response(404)
                self.end_headers()

        def log_message(self, fmt: str, *args: object) -> None:
            pass  # suppress output

    return _Handler


def _wait_for_server(base_url: str, timeout: float = 20.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            httpx.get(f"{base_url}/mcp", timeout=1.0)
            return
        except httpx.ConnectError:
            time.sleep(0.3)
    raise TimeoutError(f"apex-mcp did not start at {base_url} within {timeout}s")


def test_cli_jwt_valid_token_accepted_tampered_rejected(
    project_root: Path, tmp_path: Path, cli_env: dict
) -> None:
    """apex-mcp CLI subprocess: valid JWT → non-401, tampered JWT → 401."""
    from sqlalchemy import create_engine

    # 1. Forensics DB (minimal — just needs to exist and be valid)
    db_path = tmp_path / "forensics.db"
    svc = build_services(db_path)
    svc.close()

    # 2. Confirmation DB (SQLite sync)
    confirm_db_path = tmp_path / "confirm.db"
    confirm_db_url = f"sqlite:///{confirm_db_path}"
    sync_engine = create_engine(confirm_db_url)
    Base.metadata.create_all(sync_engine)
    sync_engine.dispose()

    # 3. Key pair, JWKS, JWT
    private_key, kid = load_private_key()
    jwk = public_key_to_jwk(private_key.public_key(), kid)
    jwks = {"keys": [jwk]}

    token = issue_access_token(
        private_key=private_key,
        kid=kid,
        actor_id="cli-test-actor",
        session_id="cli-test-session",
        tenant_id="cli-test-tenant",
        allowed_case_ids=["case-cli-001"],
        roles=["ANALYST"],
        scopes=sorted(scopes_for_roles(frozenset(["ANALYST"]))),
    )

    # 4. Mock JWKS HTTP server
    jwks_port = _free_port()
    jwks_server = HTTPServer(("127.0.0.1", jwks_port), _make_jwks_handler(jwks))
    jwks_thread = threading.Thread(target=jwks_server.serve_forever, daemon=True)
    jwks_thread.start()

    # 5. Start apex-mcp subprocess in JWT mode
    mcp_port = _free_port()
    jwks_uri = f"http://127.0.0.1:{jwks_port}/.well-known/jwks.json"
    base_url = f"http://127.0.0.1:{mcp_port}"

    cmd = [
        sys.executable,
        "-m",
        "apex_mcp",
        "--database",
        str(db_path),
        "--schema-dir",
        str(project_root / "schemas" / "v1"),
        "--transport",
        "http",
        "--http-port",
        str(mcp_port),
        "--http-jwks-uri",
        jwks_uri,
        "--http-db-url",
        confirm_db_url,
        # issuer/audience must match what issue_access_token uses (ISSUER/AUDIENCE constants)
        "--http-issuer-url",
        ISSUER,
        "--http-resource-url",
        AUDIENCE,
    ]
    proc = subprocess.Popen(
        cmd,
        env=cli_env,
        cwd=str(project_root),
        stderr=subprocess.PIPE,
    )

    try:
        _wait_for_server(base_url)

        origin = base_url
        init_payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2026-07-28",
                "capabilities": {},
                "clientInfo": {"name": "test-cli", "version": "0.0.1"},
            },
        }

        # Valid JWT → server must respond (not 401)
        resp = httpx.post(
            f"{base_url}/mcp",
            json=init_payload,
            headers={"Authorization": f"Bearer {token}", "Origin": origin},
            timeout=10.0,
        )
        assert resp.status_code != 401, (
            f"Valid JWT rejected (got {resp.status_code}): {resp.text[:200]}"
        )

        # Tampered JWT → must be 401
        tampered = token[:-10] + "tampered!!"
        resp_bad = httpx.post(
            f"{base_url}/mcp",
            json=init_payload,
            headers={"Authorization": f"Bearer {tampered}", "Origin": origin},
            timeout=10.0,
        )
        assert resp_bad.status_code == 401, (
            f"Tampered JWT should be 401, got {resp_bad.status_code}: {resp_bad.text[:200]}"
        )
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        jwks_server.shutdown()
