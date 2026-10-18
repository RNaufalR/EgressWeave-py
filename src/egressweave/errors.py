"""Shared error vocabulary for EgressWeave-py.

Error codes are stable, machine-readable strings an agent can branch on.
Human-readable messages must never contain secrets: no proxy credentials,
no authorization headers, no cookies, no secret-bearing URL userinfo.

Only assign a specific code when the evidence supports it; otherwise use
UNKNOWN. Guessing a diagnosis is worse than reporting uncertainty.
"""

from __future__ import annotations

from enum import Enum


class ErrorCode(str, Enum):
    """Machine-readable failure categories for mediated network operations."""

    POLICY_DENIED = "policy_denied"
    ROUTE_UNAVAILABLE = "route_unavailable"
    DNS_ERROR = "dns_error"
    TLS_ERROR = "tls_error"
    TIMEOUT = "timeout"
    UPSTREAM_ERROR = "upstream_error"
    AUTH_REQUIRED = "auth_required"
    INVALID_REQUEST = "invalid_request"
    RESPONSE_TOO_LARGE = "response_too_large"
    UNKNOWN = "unknown"


class PolicyValidationError(ValueError):
    """A policy document or policy input failed strict validation.

    Raised instead of producing a permissive policy (fail-closed).
    ``where`` locates the problem (e.g. ``"rules[2].ports"``); ``reason``
    explains it in plain language. A ``ValueError`` subclass so callers
    need exactly one except clause for all validation failures.
    """

    def __init__(self, where: str, reason: str) -> None:
        self.where = where
        self.reason = reason
        super().__init__(f"{where}: {reason}")


class CapabilityValidationError(ValueError):
    """A capability record or registry document failed strict validation.

    ``where`` locates the problem (e.g. ``"capability 'https-proxy'"``);
    ``reason`` explains it. A ``ValueError`` subclass, same single-except
    contract as :class:`PolicyValidationError`.
    """

    def __init__(self, where: str, reason: str) -> None:
        self.where = where
        self.reason = reason
        super().__init__(f"{where}: {reason}")


class DestinationValidationError(ValueError):
    """A destination URL failed strict syntactic validation.

    Raised instead of producing a partially-parsed destination
    (fail-closed). ``where`` locates the problem (e.g. ``"url.host"``);
    ``reason`` explains it. A ``ValueError`` subclass, same single-except
    contract as the other validation errors.
    """

    def __init__(self, where: str, reason: str) -> None:
        self.where = where
        self.reason = reason
        super().__init__(f"{where}: {reason}")


class EgressError(Exception):
    """Typed failure for an EgressWeave-py mediated operation.

    ``message`` is safe to surface to an agent and to write to audit logs:
    constructors must not be given secrets. ``detail`` carries optional
    non-sensitive context (e.g. which policy rule matched).
    """

    def __init__(
        self,
        code: ErrorCode,
        message: str,
        *,
        detail: str | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.detail = detail

    def __str__(self) -> str:
        base = super().__str__()
        if self.detail:
            return f"[{self.code.value}] {base} ({self.detail})"
        return f"[{self.code.value}] {base}"
