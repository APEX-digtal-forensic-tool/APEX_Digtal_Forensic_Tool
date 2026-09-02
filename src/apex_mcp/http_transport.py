"""Authenticated MCP Streamable HTTP transport."""

from __future__ import annotations

import hashlib
import ipaddress
import threading
import time
from collections import deque
from dataclasses import dataclass
from urllib.parse import urlparse

import uvicorn
from mcp.server.auth.provider import TokenVerifier
from mcp.server.auth.settings import AuthSettings
from mcp.server.transport_security import TransportSecuritySettings
from starlette.applications import Starlette
from starlette.datastructures import Headers
from starlette.middleware.cors import CORSMiddleware
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp, Receive, Scope, Send

from apex_mcp.errors import McpConfigurationError
from apex_mcp.server import ApexMcpRuntime


@dataclass(frozen=True, slots=True)
class HttpTransportConfig:
    host: str = "127.0.0.1"
    port: int = 8765
    path: str = "/mcp"
    allowed_hosts: tuple[str, ...] = ("127.0.0.1:8765", "localhost:8765")
    allowed_origins: tuple[str, ...] = (
        "http://127.0.0.1:8765",
        "http://localhost:8765",
    )
    issuer_url: str = "http://127.0.0.1:8765"
    resource_url: str = "http://127.0.0.1:8765/mcp"
    max_request_body_size: int = 1024 * 1024
    max_requests: int = 120
    rate_window_seconds: float = 60.0

    def validate(self) -> HttpTransportConfig:
        if not self.host:
            raise McpConfigurationError("HTTP bind host must be non-empty.", target="host")
        if not 1 <= self.port <= 65535:
            raise McpConfigurationError("HTTP port is outside the valid range.", target="port")
        if (
            not self.path.startswith("/")
            or self.path.startswith("//")
            or "?" in self.path
            or "#" in self.path
            or any(part in {".", ".."} for part in self.path.split("/"))
        ):
            raise McpConfigurationError("HTTP MCP path must be an absolute path.", target="path")
        if not self.allowed_hosts or any(
            not self._valid_host(value) for value in self.allowed_hosts
        ):
            raise McpConfigurationError(
                "HTTP allowed hosts must be an explicit non-empty allowlist.",
                target="allowed_hosts",
            )
        if not self.allowed_origins or any(
            not self._valid_origin(value) for value in self.allowed_origins
        ):
            raise McpConfigurationError(
                "HTTP allowed origins must be explicit HTTP(S) origins.",
                target="allowed_origins",
            )
        if not self._valid_http_url(self.issuer_url):
            raise McpConfigurationError("OAuth issuer URL is invalid.", target="issuer_url")
        if urlparse(self.issuer_url).query or urlparse(self.issuer_url).fragment:
            raise McpConfigurationError(
                "OAuth issuer URL cannot contain a query or fragment.",
                target="issuer_url",
            )
        if not self._valid_http_url(self.resource_url):
            raise McpConfigurationError("OAuth resource URL is invalid.", target="resource_url")
        if urlparse(self.resource_url).path != self.path:
            raise McpConfigurationError(
                "OAuth resource URL path must match the MCP endpoint path.",
                target="resource_url",
            )
        if urlparse(self.resource_url).query or urlparse(self.resource_url).fragment:
            raise McpConfigurationError(
                "OAuth resource URL cannot contain a query or fragment.",
                target="resource_url",
            )
        if not self._is_loopback_host(self.host) and (
            urlparse(self.issuer_url).scheme != "https"
            or urlparse(self.resource_url).scheme != "https"
        ):
            raise McpConfigurationError(
                "Non-loopback HTTP binds require public HTTPS issuer and resource URLs.",
                target="resource_url",
            )
        if not 1024 <= self.max_request_body_size <= 8 * 1024 * 1024:
            raise McpConfigurationError(
                "HTTP body limit must be between 1 KiB and 8 MiB.",
                target="max_request_body_size",
            )
        if self.max_requests < 1 or self.rate_window_seconds <= 0:
            raise McpConfigurationError("HTTP rate limit is invalid.", target="max_requests")
        return self

    @staticmethod
    def _valid_http_url(value: str) -> bool:
        parsed = urlparse(value)
        try:
            port = parsed.port
        except ValueError:
            return False
        return (
            parsed.scheme in {"http", "https"}
            and bool(parsed.netloc)
            and parsed.username is None
            and parsed.password is None
            and (port is None or 1 <= port <= 65535)
            and "*" not in value
        )

    @staticmethod
    def _valid_host(value: str) -> bool:
        if not value or "*" in value or any(char.isspace() for char in value):
            return False
        parsed = urlparse(f"//{value}")
        try:
            port = parsed.port
        except ValueError:
            return False
        return (
            bool(parsed.hostname)
            and parsed.username is None
            and parsed.password is None
            and parsed.path == ""
            and (port is None or 1 <= port <= 65535)
        )

    @classmethod
    def _valid_origin(cls, value: str) -> bool:
        if "*" in value or not cls._valid_http_url(value):
            return False
        parsed = urlparse(value)
        return parsed.path in {"", "/"} and not parsed.query and not parsed.fragment

    @staticmethod
    def _is_loopback_host(value: str) -> bool:
        if value.casefold() == "localhost":
            return True
        try:
            return ipaddress.ip_address(value.strip("[]")).is_loopback
        except ValueError:
            return False


class HttpRateLimitMiddleware:
    """Bounded per-client-address limiter that never retains bearer tokens."""

    _MAX_BUCKETS = 4096

    def __init__(self, app: ASGIApp, *, max_requests: int, window_seconds: float) -> None:
        self._app = app
        self._max_requests = max_requests
        self._window_seconds = window_seconds
        self._requests: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return
        key = self._key(scope)
        now = time.monotonic()
        retry_after = 0.0
        threshold = now - self._window_seconds
        with self._lock:
            if key not in self._requests and len(self._requests) >= self._MAX_BUCKETS:
                for bucket_key, bucket in tuple(self._requests.items()):
                    while bucket and bucket[0] <= threshold:
                        bucket.popleft()
                    if not bucket:
                        del self._requests[bucket_key]
            if key not in self._requests and len(self._requests) >= self._MAX_BUCKETS:
                key = "overflow"
            requests = self._requests.setdefault(key, deque())
            while requests and requests[0] <= threshold:
                requests.popleft()
            if len(requests) >= self._max_requests:
                retry_after = max(0.0, self._window_seconds - (now - requests[0]))
            else:
                requests.append(now)
        if retry_after > 0:
            response = JSONResponse(
                {"error": "rate_limit_exceeded"},
                status_code=429,
                headers={"Retry-After": str(max(1, int(retry_after + 0.999)))},
            )
            await response(scope, receive, send)
            return
        await self._app(scope, receive, send)

    @staticmethod
    def _key(scope: Scope) -> str:
        client = scope.get("client")
        material = str(client[0] if client else "unknown").encode()
        return hashlib.sha256(material).hexdigest()


class HttpHostOriginMiddleware:
    """Reject non-allowlisted network authorities before token verification."""

    def __init__(
        self,
        app: ASGIApp,
        *,
        allowed_hosts: tuple[str, ...],
        allowed_origins: tuple[str, ...],
    ) -> None:
        self._app = app
        self._allowed_hosts = frozenset(allowed_hosts)
        self._allowed_origins = frozenset(allowed_origins)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return
        headers = Headers(scope=scope)
        if headers.get("host") not in self._allowed_hosts:
            await Response("Invalid Host header", status_code=421)(scope, receive, send)
            return
        origin = headers.get("origin")
        if origin is not None and origin not in self._allowed_origins:
            await Response("Invalid Origin header", status_code=403)(scope, receive, send)
            return
        await self._app(scope, receive, send)


def create_http_app(
    runtime: ApexMcpRuntime,
    config: HttpTransportConfig,
    *,
    token_verifier: TokenVerifier,
) -> Starlette:
    """Build an authenticated Streamable HTTP app with exact network allowlists."""

    validated = config.validate()
    app = runtime.server.streamable_http_app(
        streamable_http_path=validated.path,
        json_response=True,
        stateless_http=False,
        max_request_body_size=validated.max_request_body_size,
        transport_security=TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=list(validated.allowed_hosts),
            allowed_origins=list(validated.allowed_origins),
        ),
        host=validated.host,
        auth=AuthSettings.model_validate(
            {
                "issuer_url": validated.issuer_url,
                "resource_server_url": validated.resource_url,
                "required_scopes": ["apex:mcp"],
            }
        ),
        token_verifier=token_verifier,
    )
    app.add_middleware(
        HttpRateLimitMiddleware,
        max_requests=validated.max_requests,
        window_seconds=validated.rate_window_seconds,
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(validated.allowed_origins),
        allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
        allow_headers=[
            "Authorization",
            "Content-Type",
            "Mcp-Session-Id",
            "MCP-Protocol-Version",
            "MCP-Method",
            "MCP-Name",
            "Last-Event-ID",
        ],
        expose_headers=["Mcp-Session-Id"],
        allow_credentials=False,
    )
    app.add_middleware(
        HttpHostOriginMiddleware,
        allowed_hosts=validated.allowed_hosts,
        allowed_origins=validated.allowed_origins,
    )
    return app


def run_http(
    runtime: ApexMcpRuntime,
    config: HttpTransportConfig,
    *,
    token_verifier: TokenVerifier,
) -> None:
    validated = config.validate()
    app = create_http_app(runtime, validated, token_verifier=token_verifier)
    try:
        uvicorn.run(
            app,
            host=validated.host,
            port=validated.port,
            log_level="warning",
        )
    finally:
        runtime.close()


__all__ = [
    "HttpHostOriginMiddleware",
    "HttpRateLimitMiddleware",
    "HttpTransportConfig",
    "create_http_app",
    "run_http",
]
