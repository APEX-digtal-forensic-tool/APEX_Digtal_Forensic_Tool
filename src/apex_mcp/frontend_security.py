"""Trusted frontend session, tenant, RBAC, and approval integration."""

from __future__ import annotations

import hashlib
import hmac
import threading
from dataclasses import dataclass
from typing import Protocol

from mcp.server.auth.provider import AccessToken, principal_components

from apex_mcp.confirmation import (
    ConfirmationGrant,
    ConfirmationProvider,
    ConfirmationRequest,
    DenyAllConfirmationProvider,
    InMemoryConfirmationProvider,
)
from apex_mcp.context_bridge import is_authenticated_actor
from apex_mcp.errors import (
    AuthenticatedActorRequiredError,
    McpAuthorizationDeniedError,
    McpTenantScopeViolationError,
)

_APPROVAL_TOOLS = frozenset(
    {
        "report.approve",
        "report.reject",
        "report.approval.revoke",
    }
)
_EXPORT_TOOLS = frozenset(
    {
        "report.render-package.create",
        "report.export.prepare",
    }
)
_HUMAN_MUTATION_ROLES = frozenset({"ANALYST", "APPROVER", "ADMIN"})
_APPROVAL_ROLES = frozenset({"APPROVER", "ADMIN"})
_EXPORT_ROLES = frozenset({"APPROVER", "EXPORTER", "ADMIN"})
_ALL_ROLES = frozenset({"VIEWER", "ANALYST", "APPROVER", "EXPORTER", "ADMIN"})


@dataclass(frozen=True, slots=True)
class FrontendSession:
    """Server-resolved identity and tenancy boundary for one frontend session."""

    actor_id: str
    session_id: str
    tenant_id: str
    allowed_case_ids: frozenset[str]
    roles: frozenset[str]

    def __post_init__(self) -> None:
        if not self.actor_id.strip() or not is_authenticated_actor(self.actor_id):
            raise AuthenticatedActorRequiredError("frontend.session")
        if not self.session_id.strip() or not self.tenant_id.strip():
            raise ValueError("Frontend session and tenant identifiers must be non-empty.")
        if not self.allowed_case_ids or any(
            not isinstance(case_id, str) or not case_id.strip()
            for case_id in self.allowed_case_ids
        ):
            raise ValueError("A frontend session must allow at least one non-empty case id.")
        normalized_roles = frozenset(role.strip().upper() for role in self.roles if role.strip())
        if not normalized_roles:
            raise ValueError("A frontend session must have at least one role.")
        if not normalized_roles.issubset(_ALL_ROLES):
            raise ValueError("A frontend session contains an unsupported role.")
        object.__setattr__(self, "roles", normalized_roles)

    @property
    def budget_scope(self) -> str:
        value = f"{self.tenant_id}\0{self.session_id}".encode()
        return f"http:{hashlib.sha256(value).hexdigest()}"


class FrontendSecurityProvider(ConfirmationProvider, Protocol):
    """Backend boundary implemented by the authenticated APEX frontend."""

    def resolve_session(self, access_token: AccessToken) -> FrontendSession: ...

    def confirmation_for(
        self,
        session: FrontendSession,
        *,
        case_id: str,
        tool_name: str,
        request_fingerprint: str,
        target_ids: tuple[str, ...],
    ) -> ConfirmationRequest | None: ...


class FrontendAuthorizationGate:
    """Apply per-tool OAuth scope, role, and case tenancy requirements."""

    def require(
        self,
        session: FrontendSession,
        access_token: AccessToken,
        descriptor: dict[str, object],
        *,
        tool_name: str,
        target_case_ids: frozenset[str],
    ) -> None:
        if not target_case_ids.issubset(session.allowed_case_ids):
            raise McpTenantScopeViolationError(tool_name)

        token_scopes = frozenset(access_token.scopes)
        required_scopes = {"apex:mcp", "apex:read"}
        if bool(descriptor.get("mutates_state")):
            required_scopes.add("apex:write")
        if bool(descriptor.get("requires_confirmation")):
            required_scopes.add("apex:confirm")
        if tool_name == "apex.view.raw_read":
            required_scopes.add("apex:raw")
        if tool_name in _APPROVAL_TOOLS:
            required_scopes.add("apex:approve")
        if tool_name in _EXPORT_TOOLS:
            required_scopes.add("apex:export")
        missing = sorted(required_scopes - token_scopes)
        if missing:
            raise McpAuthorizationDeniedError(
                tool_name,
                required=tuple(f"scope:{scope}" for scope in missing),
            )

        required_roles: frozenset[str] = frozenset()
        if tool_name in _APPROVAL_TOOLS:
            required_roles = _APPROVAL_ROLES
        elif tool_name in _EXPORT_TOOLS:
            required_roles = _EXPORT_ROLES
        elif bool(descriptor.get("mutates_state")):
            required_roles = _HUMAN_MUTATION_ROLES
        if required_roles and session.roles.isdisjoint(required_roles):
            raise McpAuthorizationDeniedError(
                tool_name,
                required=tuple(f"role:{role}" for role in sorted(required_roles)),
            )


_Principal = tuple[str, str | None, str | None]
_ConfirmationKey = tuple[str, str, str, str, str, tuple[str, ...]]


class InMemoryFrontendSecurityProvider:
    """Thread-safe integration fixture for a trusted frontend/backend.

    Production deployments can implement ``FrontendSecurityProvider`` against their
    session and approval stores. This implementation deliberately indexes sessions by
    verified principal components, never by a model-supplied actor or a raw bearer token.
    """

    def __init__(self) -> None:
        self._sessions: dict[_Principal, FrontendSession] = {}
        self._confirmation_ids: dict[_ConfirmationKey, str] = {}
        self._confirmations = InMemoryConfirmationProvider()
        self._lock = threading.Lock()

    def register(self, access_token: AccessToken, session: FrontendSession) -> None:
        principal = principal_components(access_token)
        if not principal[0] or not principal[1] or not principal[2]:
            raise ValueError(
                "Frontend session tokens must identify client, issuer, and subject."
            )
        with self._lock:
            self._sessions[principal] = session

    def resolve_session(self, access_token: AccessToken) -> FrontendSession:
        with self._lock:
            session = self._sessions.get(principal_components(access_token))
        if session is None:
            raise McpAuthorizationDeniedError("frontend.session")
        return session

    def issue(self, grant: ConfirmationGrant) -> None:
        key = self._confirmation_key(
            actor_id=grant.actor_id,
            session_id=grant.session_id,
            case_id=grant.case_id,
            tool_name=grant.tool_name,
            request_fingerprint=grant.request_fingerprint,
            target_ids=grant.target_ids,
        )
        self._confirmations.issue(grant)
        with self._lock:
            self._confirmation_ids[key] = grant.grant_id

    def confirmation_for(
        self,
        session: FrontendSession,
        *,
        case_id: str,
        tool_name: str,
        request_fingerprint: str,
        target_ids: tuple[str, ...],
    ) -> ConfirmationRequest | None:
        key = self._confirmation_key(
            actor_id=session.actor_id,
            session_id=session.session_id,
            case_id=case_id,
            tool_name=tool_name,
            request_fingerprint=request_fingerprint,
            target_ids=target_ids,
        )
        with self._lock:
            grant_id = self._confirmation_ids.get(key)
        if grant_id is None:
            return None
        return ConfirmationRequest(
            grant_id=grant_id,
            actor_id=session.actor_id,
            session_id=session.session_id,
            case_id=case_id,
            tool_name=tool_name,
            request_fingerprint=request_fingerprint,
            target_ids=target_ids,
        )

    def authorize(self, request: ConfirmationRequest) -> bool:
        return self._confirmations.authorize(request)

    @staticmethod
    def _confirmation_key(
        *,
        actor_id: str,
        session_id: str,
        case_id: str,
        tool_name: str,
        request_fingerprint: str,
        target_ids: tuple[str, ...],
    ) -> _ConfirmationKey:
        return (
            actor_id,
            session_id,
            case_id,
            tool_name,
            request_fingerprint,
            target_ids,
        )


class PersistentFrontendSecurityProvider:
    """JWT-claims-backed FrontendSecurityProvider for production deployments.

    ``resolve_session`` reconstructs ``FrontendSession`` directly from the
    verified ``AccessToken.claims`` — no DB round-trip needed (Option A benefit).

    ``confirmation_for`` and ``authorize`` delegate to an injected
    ``ConfirmationProvider``; swap in a DB-backed implementation (Phase 5) to
    enable persistent confirmation grants.
    """

    def __init__(
        self,
        confirmation_provider: ConfirmationProvider | None = None,
    ) -> None:
        self._confirmations: ConfirmationProvider = (
            confirmation_provider if confirmation_provider is not None
            else DenyAllConfirmationProvider()
        )

    def resolve_session(self, access_token: AccessToken) -> FrontendSession:
        """Build FrontendSession from JWT claims in *access_token*."""
        claims = access_token.claims or {}

        actor_id = str(claims.get("sub") or access_token.subject or "").strip()
        session_id = str(claims.get("session_id", "")).strip()
        tenant_id = str(claims.get("tenant_id", "")).strip()

        if not actor_id or not session_id or not tenant_id:
            raise McpAuthorizationDeniedError("frontend.session")

        raw_case_ids = claims.get("allowed_case_ids") or []
        raw_roles = claims.get("roles") or []

        allowed_case_ids = frozenset(
            str(c).strip() for c in raw_case_ids if isinstance(c, str) and c.strip()
        )
        roles = frozenset(
            str(r).strip().upper() for r in raw_roles if isinstance(r, str) and r.strip()
        )

        return FrontendSession(
            actor_id=actor_id,
            session_id=session_id,
            tenant_id=tenant_id,
            allowed_case_ids=allowed_case_ids,
            roles=roles,
        )

    def confirmation_for(
        self,
        session: FrontendSession,
        *,
        case_id: str,
        tool_name: str,
        request_fingerprint: str,
        target_ids: tuple[str, ...],
    ) -> ConfirmationRequest | None:
        return None

    def authorize(self, request: ConfirmationRequest) -> bool:
        return self._confirmations.authorize(request)


class StaticBearerTokenVerifier:
    """Constant-time verifier for local development and deployment smoke tests."""

    def __init__(self, secret: str, access_token: AccessToken) -> None:
        if not secret:
            raise ValueError("Bearer token secret must be non-empty.")
        if not hmac.compare_digest(secret.encode(), access_token.token.encode()):
            raise ValueError("Bearer token metadata must carry the verified token value.")
        issuer = (access_token.claims or {}).get("iss")
        if (
            not access_token.client_id
            or not access_token.subject
            or not issuer
            or not access_token.resource
            or "apex:mcp" not in access_token.scopes
        ):
            raise ValueError(
                "Static bearer tokens require client, issuer, subject, resource, and apex:mcp."
            )
        self._secret = secret
        self._access_token = access_token

    async def verify_token(self, token: str) -> AccessToken | None:
        if not hmac.compare_digest(token.encode(), self._secret.encode()):
            return None
        return self._access_token


__all__ = [
    "FrontendAuthorizationGate",
    "FrontendSecurityProvider",
    "FrontendSession",
    "InMemoryFrontendSecurityProvider",
    "PersistentFrontendSecurityProvider",
    "StaticBearerTokenVerifier",
]
