"""Command-line entry point for stdio or authenticated Streamable HTTP."""

from __future__ import annotations

import argparse
import os
from collections.abc import Sequence
from pathlib import Path

from mcp.server.auth.provider import AccessToken

from apex_forensic.config import AiProviderRuntimeConfig
from apex_mcp.config import McpConfig
from apex_mcp.frontend_security import (
    FrontendSession,
    InMemoryFrontendSecurityProvider,
    StaticBearerTokenVerifier,
)
from apex_mcp.http_transport import HttpTransportConfig, run_http
from apex_mcp.m7_tools import M7_TOOL_NAMES, m7_bindings
from apex_mcp.server import create_runtime


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="apex-mcp")
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--schema-dir", type=Path, required=True)
    parser.add_argument("--log-level", default="INFO")
    parser.add_argument("--transport", choices=("stdio", "http"), default="stdio")
    parser.add_argument("--ai-provider-id")
    parser.add_argument("--ai-base-url")
    parser.add_argument("--ai-model")
    parser.add_argument("--ai-api-key-env")
    parser.add_argument("--ai-timeout", type=float, default=30.0)
    parser.add_argument("--ai-max-output", type=int, default=4096)
    parser.add_argument("--ai-temperature", type=float, default=0.0)
    parser.add_argument("--http-host", default="127.0.0.1")
    parser.add_argument("--http-port", type=int, default=8765)
    parser.add_argument("--http-path", default="/mcp")
    parser.add_argument("--http-allowed-host", action="append", default=[])
    parser.add_argument("--http-allowed-origin", action="append", default=[])
    parser.add_argument("--http-issuer-url")
    parser.add_argument("--http-resource-url")
    parser.add_argument("--http-token-env", default="APEX_MCP_HTTP_TOKEN")
    parser.add_argument("--http-actor-id")
    parser.add_argument("--http-session-id")
    parser.add_argument("--http-tenant-id")
    parser.add_argument("--http-case-id", action="append", default=[])
    parser.add_argument(
        "--http-role",
        action="append",
        choices=("VIEWER", "ANALYST", "APPROVER", "EXPORTER", "ADMIN"),
        default=[],
    )
    parser.add_argument("--http-scope", action="append", default=[])
    parser.add_argument("--http-max-requests", type=int, default=120)
    parser.add_argument("--http-rate-window", type=float, default=60.0)
    args = parser.parse_args(argv)
    ai_values = (
        args.ai_provider_id,
        args.ai_base_url,
        args.ai_model,
        args.ai_api_key_env,
    )
    if any(ai_values) and not all(ai_values):
        parser.error(
            "--ai-provider-id, --ai-base-url, --ai-model, and --ai-api-key-env "
            "must be supplied together"
        )
    ai_provider = (
        AiProviderRuntimeConfig(
            provider_id=args.ai_provider_id,
            base_url=args.ai_base_url,
            model_id=args.ai_model,
            api_key_env=args.ai_api_key_env,
            timeout=args.ai_timeout,
            max_output=args.ai_max_output,
            temperature=args.ai_temperature,
        )
        if all(ai_values)
        else None
    )
    config = McpConfig(
        database_path=args.database,
        schema_dir=args.schema_dir,
        allowed_tools=M7_TOOL_NAMES,
        initialize_database=False,
        log_level=args.log_level.upper(),
        ai_provider=ai_provider,
    ).validate()
    if args.transport == "stdio":
        create_runtime(config, bindings=m7_bindings()).run_stdio()
        return 0

    required_http = {
        "--http-actor-id": args.http_actor_id,
        "--http-session-id": args.http_session_id,
        "--http-tenant-id": args.http_tenant_id,
        "--http-case-id": args.http_case_id,
    }
    missing_http = [name for name, value in required_http.items() if not value]
    if missing_http:
        parser.error(f"HTTP transport requires: {', '.join(missing_http)}")
    secret = os.environ.get(args.http_token_env)
    if not secret:
        parser.error(f"{args.http_token_env} must contain the HTTP bearer token")

    public_host = args.http_host if args.http_host not in {"0.0.0.0", "::"} else "127.0.0.1"
    url_host = f"[{public_host}]" if ":" in public_host else public_host
    base_url = f"http://{url_host}:{args.http_port}"
    allowed_hosts = tuple(args.http_allowed_host) or (
        f"{url_host}:{args.http_port}",
        f"localhost:{args.http_port}",
    )
    allowed_origins = tuple(args.http_allowed_origin) or (
        base_url,
        f"http://localhost:{args.http_port}",
    )
    issuer_url = args.http_issuer_url or base_url
    resource_url = args.http_resource_url or f"{base_url}{args.http_path}"
    scopes = list(args.http_scope) or [
        "apex:mcp",
        "apex:read",
        "apex:write",
        "apex:confirm",
        "apex:raw",
    ]
    if "apex:mcp" not in scopes:
        parser.error("HTTP transport scopes must include apex:mcp")
    access_token = AccessToken(
        token=secret,
        client_id=f"apex-http:{args.http_tenant_id}",
        subject=args.http_actor_id,
        scopes=scopes,
        resource=resource_url,
        claims={"iss": issuer_url},
    )
    frontend_security = InMemoryFrontendSecurityProvider()
    frontend_security.register(
        access_token,
        FrontendSession(
            actor_id=args.http_actor_id,
            session_id=args.http_session_id,
            tenant_id=args.http_tenant_id,
            allowed_case_ids=frozenset(args.http_case_id),
            roles=frozenset(args.http_role or ["ANALYST"]),
        ),
    )
    runtime = create_runtime(
        config,
        bindings=m7_bindings(),
        frontend_security_provider=frontend_security,
    )
    run_http(
        runtime,
        HttpTransportConfig(
            host=args.http_host,
            port=args.http_port,
            path=args.http_path,
            allowed_hosts=allowed_hosts,
            allowed_origins=allowed_origins,
            issuer_url=issuer_url,
            resource_url=resource_url,
            max_requests=args.http_max_requests,
            rate_window_seconds=args.http_rate_window,
        ),
        token_verifier=StaticBearerTokenVerifier(secret, access_token),
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
