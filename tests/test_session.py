"""Tests for the Session authorization contract."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from egressweave.capabilities import (
    Capability,
    CapabilityRegistry,
    CapabilityStatus,
)
from egressweave.errors import EgressError, ErrorCode
from egressweave.policy import EgressPolicy
from egressweave.session import AuthorizationResult, Session

NOW = datetime(2026, 10, 18, 12, 0, tzinfo=timezone.utc)

POLICY = EgressPolicy.from_dict(
    {
        "version": "0.1",
        "rules": [
            {
                "action": "allow",
                "hosts": ["example.com"],
                "ports": [443],
                "methods": ["GET"],
            },
            {
                "action": "deny",
                "hosts": ["blocked.example.com"],
                "ports": [443],
                "methods": ["GET"],
            },
        ],
    }
)


def registry_with(*caps: Capability) -> CapabilityRegistry:
    reg = CapabilityRegistry()
    for cap in caps:
        reg.register(cap)
    return reg


def verified_cap() -> Capability:
    return Capability(
        id="proxy",
        kind="http-proxy",
        status=CapabilityStatus.VERIFIED,
        evidence="HTTP 200 via proxy",
        verified_at=NOW,
    )


def test_policy_deny_wins() -> None:
    session = Session(POLICY)
    result = session.authorize("GET", "blocked.example.com", 443)
    assert not result.authorized
    assert result.code is ErrorCode.POLICY_DENIED


def test_default_deny_without_capability() -> None:
    session = Session(POLICY)
    result = session.authorize("GET", "other.example.com", 443)
    assert not result.authorized
    assert result.code is ErrorCode.POLICY_DENIED


def test_policy_allow_without_capability_id() -> None:
    session = Session(POLICY)
    result = session.authorize("GET", "example.com", 443)
    assert result.authorized
    assert result.code is None
    assert result.transport_verified is False
    assert result.capability_status is None
    # The five states stay distinct: authorized does not imply verified.
    assert result.policy_decision.allowed


def test_malformed_input_denies_invalid_request() -> None:
    session = Session(POLICY)
    result = session.authorize("GET", "", 443)
    assert not result.authorized
    assert result.code is ErrorCode.INVALID_REQUEST


def test_verified_capability_authorizes_and_marks_verified() -> None:
    session = Session(POLICY, registry_with(verified_cap()))
    result = session.authorize("GET", "example.com", 443, capability_id="proxy")
    assert result.authorized
    assert result.transport_verified is True
    assert result.capability_status is CapabilityStatus.VERIFIED


def test_configured_capability_authorizes_but_not_verified() -> None:
    cap = Capability(id="proxy", kind="http-proxy", status=CapabilityStatus.CONFIGURED)
    session = Session(POLICY, registry_with(cap))
    result = session.authorize("GET", "example.com", 443, capability_id="proxy")
    assert result.authorized
    assert result.transport_verified is False
    assert result.capability_status is CapabilityStatus.CONFIGURED


def test_unavailable_capability_denies_route_unavailable() -> None:
    cap = Capability(id="proxy", kind="http-proxy", status=CapabilityStatus.UNAVAILABLE)
    session = Session(POLICY, registry_with(cap))
    result = session.authorize("GET", "example.com", 443, capability_id="proxy")
    assert not result.authorized
    assert result.code is ErrorCode.ROUTE_UNAVAILABLE


def test_unknown_capability_status_denies() -> None:
    cap = Capability(id="proxy", kind="http-proxy", status=CapabilityStatus.UNKNOWN)
    session = Session(POLICY, registry_with(cap))
    result = session.authorize("GET", "example.com", 443, capability_id="proxy")
    assert not result.authorized
    assert result.code is ErrorCode.UNKNOWN


def test_missing_capability_id_denies() -> None:
    session = Session(POLICY, registry_with(verified_cap()))
    result = session.authorize("GET", "example.com", 443, capability_id="nope")
    assert not result.authorized
    assert result.code is ErrorCode.UNKNOWN


def test_no_registry_denies_named_capability() -> None:
    session = Session(POLICY)
    result = session.authorize("GET", "example.com", 443, capability_id="proxy")
    assert not result.authorized
    assert result.code is ErrorCode.UNKNOWN


def test_policy_deny_takes_precedence_over_capability() -> None:
    session = Session(POLICY, registry_with(verified_cap()))
    result = session.authorize("GET", "blocked.example.com", 443, capability_id="proxy")
    assert not result.authorized
    assert result.code is ErrorCode.POLICY_DENIED


def test_authorize_or_raise_returns_result_on_allow() -> None:
    session = Session(POLICY, registry_with(verified_cap()))
    result = session.authorize_or_raise(
        "GET", "example.com", 443, capability_id="proxy"
    )
    assert isinstance(result, AuthorizationResult)
    assert result.authorized


def test_authorize_or_raise_raises_typed_error_on_deny() -> None:
    session = Session(POLICY)
    with pytest.raises(EgressError) as excinfo:
        session.authorize_or_raise("GET", "other.example.com", 443)
    assert excinfo.value.code is ErrorCode.POLICY_DENIED


def test_constructor_rejects_wrong_types() -> None:
    with pytest.raises(TypeError):
        Session("not-a-policy")  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        Session(POLICY, registry="not-a-registry")  # type: ignore[arg-type]


def test_result_is_immutable() -> None:
    session = Session(POLICY)
    result = session.authorize("GET", "example.com", 443)
    with pytest.raises(AttributeError):
        result.authorized = False  # type: ignore[misc]


def test_authorize_never_raises_on_adversarial_inputs() -> None:
    # The gate must deny, never raise, no matter how malformed the input.
    session = Session(POLICY, registry_with(verified_cap()))
    adversarial = [
        ("GET", None, 443, None),
        (None, "example.com", 443, None),
        ("GET", "example.com", "443", None),
        ("GET", "example.com", True, None),
        ("GET", "example.com", 443, []),
        ("GET", "example.com", 443, 123),
        ("", "", 0, ""),
    ]
    for method, host, port, cap_id in adversarial:
        result = session.authorize(  # type: ignore[arg-type]
            method, host, port, capability_id=cap_id
        )
        assert not result.authorized, f"deny expected for {(method, host, port)}"
        assert result.code is not None


def test_authorize_or_raise_never_leaks_unexpected_errors() -> None:
    session = Session(POLICY, registry_with(verified_cap()))
    with pytest.raises(EgressError) as excinfo:
        session.authorize_or_raise("GET", "example.com", 443, capability_id=[])
    # Unhashable capability id -> fail-closed UNKNOWN, not TypeError.
    assert excinfo.value.code is ErrorCode.UNKNOWN
