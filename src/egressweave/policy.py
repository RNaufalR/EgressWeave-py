"""Versioned, default-deny egress policy schema (v0.1).

A policy is a list of exact-match rules over ``(hostname, port, method)``
triples. Anything not explicitly allowed is denied. Deny rules take
precedence over allow rules.

Security properties enforced by construction:

- ``from_dict`` / ``from_json`` are fail-closed: any malformed policy raises
  ``PolicyValidationError`` (a ``ValueError``) instead of producing a
  permissive policy.
- Hostnames are exact DNS names only. IP literals, wildcards, userinfo,
  ports, paths, and backslashes are rejected at construction.
- ``CONNECT`` can never appear in a method allowlist.
- ``decide()`` never raises: malformed request inputs produce a deny
  decision with code ``INVALID_REQUEST``.

v0.1 limitations (documented, not silently worked around):

- Exact hostnames only; no wildcard or suffix matching.
- The policy describes intent. Enforcement happens only where the policy
  object is actually consulted on the request path; this module alone does
  not intercept traffic.
"""

from __future__ import annotations

import ipaddress
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Literal

from egressweave.errors import ErrorCode, PolicyValidationError

POLICY_SCHEMA_VERSION = "0.1"

#: Methods permitted when a rule does not name its own set.
DEFAULT_METHODS: tuple[str, ...] = (
    "GET",
    "HEAD",
    "POST",
    "PUT",
    "PATCH",
    "DELETE",
    "OPTIONS",
)

_METHOD_TOKEN = re.compile(r"^[A-Za-z0-9!#$%&'*+\-.^_`|~]+$")


def normalize_hostname(host: object) -> str:
    """Normalize a DNS hostname for exact-match policy comparison.

    Lowercases and strips a single trailing dot. v0.1 accepts ASCII DNS
    names only; internationalized names must be written in their punycode
    (A-label) form, e.g. ``xn--mnchen-3ya.de``. Raises
    ``PolicyValidationError`` for non-strings and for anything that is not
    a plain ASCII DNS name (empty, non-ASCII, IP literal, wildcard,
    userinfo, port, path, whitespace, or control characters).
    """
    where = "hostname"
    if not isinstance(host, str):
        raise PolicyValidationError(where, "must be str")
    h = host.strip().lower().rstrip(".")
    if not h:
        raise PolicyValidationError(where, "must not be empty")
    if any(ord(c) < 33 or ord(c) > 126 or c.isspace() for c in h):
        raise PolicyValidationError(where, f"contains invalid characters: {host!r}")
    try:
        ipaddress.ip_address(h)
    except ValueError:
        pass  # Not an IP literal; that is what we want.
    else:
        raise PolicyValidationError(where, f"IP literals not allowed: {host!r}")
    for bad, why in (
        ("*", "wildcards are not supported in v0.1"),
        ("@", "userinfo is not allowed in policy hosts"),
        ("/", "paths are not allowed in policy hosts"),
        (":", "ports are not allowed in policy hosts"),
        ("\\", "backslashes are not allowed in policy hosts"),
    ):
        if bad in h:
            raise PolicyValidationError(where, f"invalid hostname {host!r}: {why}")
    if len(h) > 253:
        raise PolicyValidationError(where, f"hostname too long: {host!r}")
    return h


def _check_port(port: object, *, where: str) -> int:
    if isinstance(port, bool) or not isinstance(port, int):
        raise PolicyValidationError(where, f"port must be an int, got {port!r}")
    if not 1 <= port <= 65535:
        raise PolicyValidationError(where, f"port out of range: {port!r}")
    return port


def _check_method(method: object, *, where: str) -> str:
    if not isinstance(method, str):
        raise PolicyValidationError(where, f"method must be str, got {method!r}")
    m = method.strip().upper()
    if not m or not _METHOD_TOKEN.match(m):
        raise PolicyValidationError(where, f"invalid HTTP method: {method!r}")
    if m == "CONNECT":
        raise PolicyValidationError(where, "CONNECT can never be authorized")
    return m


@dataclass(frozen=True)
class EgressRule:
    """One exact-match rule. Deny rules beat allow rules."""

    action: Literal["allow", "deny"]
    hosts: tuple[str, ...]
    ports: tuple[int, ...]
    methods: tuple[str, ...] = DEFAULT_METHODS

    def matches(self, host: str, port: int, method: str) -> bool:
        return host in self.hosts and port in self.ports and method in self.methods


@dataclass(frozen=True)
class PolicyDecision:
    """Outcome of :meth:`EgressPolicy.decide`.

    ``code`` is ``None`` when the request is allowed; otherwise it names
    the failure category. ``reason`` is human-readable and secret-free.
    """

    allowed: bool
    code: ErrorCode | None
    reason: str
    rule_index: int | None


@dataclass(frozen=True)
class EgressPolicy:
    """An immutable, validated egress policy."""

    version: str
    rules: tuple[EgressRule, ...]

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> EgressPolicy:
        """Parse and strictly validate a policy mapping. Fail-closed."""
        where = "policy"
        if not isinstance(data, Mapping):
            raise PolicyValidationError(where, "must be a mapping")
        unknown = set(data) - {"version", "rules"}
        if unknown:
            raise PolicyValidationError(where, f"unknown keys: {sorted(unknown)}")
        version = data.get("version")
        if version != POLICY_SCHEMA_VERSION:
            raise PolicyValidationError(
                where,
                f"unsupported version {version!r} (expected {POLICY_SCHEMA_VERSION!r})",
            )
        raw_rules = data.get("rules")
        if not isinstance(raw_rules, list):
            raise PolicyValidationError(where, "'rules' must be a list")
        rules = tuple(cls._parse_rule(r, i) for i, r in enumerate(raw_rules))
        return cls(version=POLICY_SCHEMA_VERSION, rules=rules)

    @staticmethod
    def _parse_rule(data: object, index: int) -> EgressRule:
        where = f"rules[{index}]"
        if not isinstance(data, Mapping):
            raise PolicyValidationError(where, "rule must be a mapping")
        unknown = set(data) - {"action", "hosts", "ports", "methods"}
        if unknown:
            raise PolicyValidationError(where, f"unknown keys: {sorted(unknown)}")
        action = data.get("action")
        if action not in ("allow", "deny"):
            raise PolicyValidationError(where, "action must be 'allow' or 'deny'")
        raw_hosts = data.get("hosts")
        if not isinstance(raw_hosts, list) or not raw_hosts:
            raise PolicyValidationError(where, "'hosts' must be a non-empty list")
        hosts = tuple(normalize_hostname(h) for h in raw_hosts)
        raw_ports = data.get("ports")
        if not isinstance(raw_ports, list) or not raw_ports:
            raise PolicyValidationError(where, "'ports' must be a non-empty list")
        ports = tuple(_check_port(p, where=f"{where}.ports") for p in raw_ports)
        raw_methods = data.get("methods", None)
        if raw_methods is None:
            methods = DEFAULT_METHODS
        else:
            if not isinstance(raw_methods, list) or not raw_methods:
                raise PolicyValidationError(where, "'methods' must be a non-empty list")
            methods = tuple(
                _check_method(m, where=f"{where}.methods") for m in raw_methods
            )
        return EgressRule(
            action=action,
            hosts=hosts,
            ports=ports,
            methods=methods,
        )

    @classmethod
    def from_json(cls, text: str) -> EgressPolicy:
        """Parse a JSON policy document. Fail-closed."""
        where = "policy"
        if not isinstance(text, str):
            raise PolicyValidationError(where, "JSON document must be str")
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise PolicyValidationError(where, f"not valid JSON: {exc}") from exc
        return cls.from_dict(data)

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "rules": [
                {
                    "action": r.action,
                    "hosts": list(r.hosts),
                    "ports": list(r.ports),
                    "methods": list(r.methods),
                }
                for r in self.rules
            ],
        }

    def decide(self, host: str, port: int, method: str) -> PolicyDecision:
        """Evaluate one ``(host, port, method)`` triple. Never raises.

        Malformed inputs are denied with ``INVALID_REQUEST`` (fail-closed).
        Deny rules take precedence over allow rules; with no matching rule
        the request is denied (default-deny).
        """
        try:
            norm_host = normalize_hostname(host)
            norm_method = _check_method(method, where="decide")
            norm_port = _check_port(port, where="decide")
        except (TypeError, PolicyValidationError) as exc:
            return PolicyDecision(
                allowed=False,
                code=ErrorCode.INVALID_REQUEST,
                reason=f"malformed request target: {exc}",
                rule_index=None,
            )
        for i, rule in enumerate(self.rules):
            if rule.action == "deny" and rule.matches(
                norm_host, norm_port, norm_method
            ):
                return PolicyDecision(
                    allowed=False,
                    code=ErrorCode.POLICY_DENIED,
                    reason=f"denied by rule #{i}",
                    rule_index=i,
                )
        for i, rule in enumerate(self.rules):
            if rule.action == "allow" and rule.matches(
                norm_host, norm_port, norm_method
            ):
                return PolicyDecision(
                    allowed=True,
                    code=None,
                    reason=f"allowed by rule #{i}",
                    rule_index=i,
                )
        return PolicyDecision(
            allowed=False,
            code=ErrorCode.POLICY_DENIED,
            reason="no allow rule matched (default-deny)",
            rule_index=None,
        )
