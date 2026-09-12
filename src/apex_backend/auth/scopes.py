"""Role → OAuth scope mapping for APEX JWT tokens.

Derived from FrontendAuthorizationGate.require in apex_mcp/frontend_security.py.
Scopes are unioned across all of the user's roles.
"""

from __future__ import annotations

_BASE_SCOPES = frozenset({"apex:mcp", "apex:read"})

_ROLE_SCOPES: dict[str, frozenset[str]] = {
    "VIEWER": _BASE_SCOPES,
    "ANALYST": _BASE_SCOPES | {"apex:write", "apex:confirm"},
    "EXPORTER": _BASE_SCOPES | {"apex:export"},
    "APPROVER": _BASE_SCOPES | {"apex:write", "apex:confirm", "apex:approve", "apex:export"},
    "ADMIN": (
        _BASE_SCOPES | {"apex:write", "apex:confirm", "apex:approve", "apex:export", "apex:raw"}
    ),
}


def scopes_for_roles(roles: frozenset[str]) -> frozenset[str]:
    """Return the union of all scopes granted by *roles*."""
    result: frozenset[str] = frozenset()
    for role in roles:
        result = result | _ROLE_SCOPES.get(role.upper(), frozenset())
    return result


__all__ = ["scopes_for_roles"]
