"""Tests for the v0.1 default-deny egress policy schema."""

from __future__ import annotations

import dataclasses

import pytest

from egressweave.errors import ErrorCode
from egressweave.policy import (
    POLICY_SCHEMA_VERSION,
    EgressPolicy,
    normalize_hostname,
)


def make_policy() -> EgressPolicy:
    return EgressPolicy.from_dict(
        {
            "version": "0.1",
            "rules": [
                {
                    "action": "allow",
                    "hosts": ["api.example.com"],
                    "ports": [443],
                    "methods": ["GET", "POST"],
                },
                {
                    "action": "deny",
                    "hosts": ["internal.example.com"],
                    "ports": [443],
                },
            ],
        }
    )


def test_schema_version_constant() -> None:
    assert POLICY_SCHEMA_VERSION == "0.1"


def test_allow_exact_match() -> None:
    d = make_policy().decide("api.example.com", 443, "GET")
    assert d.allowed is True
    assert d.code is None
    assert d.rule_index == 0


def test_method_case_insensitive() -> None:
    assert make_policy().decide("api.example.com", 443, "get").allowed is True


def test_method_not_listed_is_denied() -> None:
    d = make_policy().decide("api.example.com", 443, "DELETE")
    assert d.allowed is False
    assert d.code is ErrorCode.POLICY_DENIED


def test_port_mismatch_is_denied() -> None:
    d = make_policy().decide("api.example.com", 80, "GET")
    assert d.allowed is False
    assert d.code is ErrorCode.POLICY_DENIED


def test_unknown_host_is_denied_default_deny() -> None:
    d = make_policy().decide("evil.example.com", 443, "GET")
    assert d.allowed is False
    assert d.code is ErrorCode.POLICY_DENIED
    assert d.rule_index is None
    assert "default-deny" in d.reason


def test_deny_rule_beats_allow_rule() -> None:
    policy = EgressPolicy.from_dict(
        {
            "version": "0.1",
            "rules": [
                {"action": "allow", "hosts": ["h.example"], "ports": [443]},
                {"action": "deny", "hosts": ["h.example"], "ports": [443]},
            ],
        }
    )
    d = policy.decide("h.example", 443, "GET")
    assert d.allowed is False
    assert d.code is ErrorCode.POLICY_DENIED
    assert d.rule_index == 1


def test_empty_rules_deny_everything() -> None:
    policy = EgressPolicy.from_dict({"version": "0.1", "rules": []})
    d = policy.decide("api.example.com", 443, "GET")
    assert d.allowed is False
    assert d.code is ErrorCode.POLICY_DENIED


def test_decide_never_raises_on_malformed_input() -> None:
    policy = make_policy()
    for host, port, method in [
        ("", 443, "GET"),
        ("not a host!", 443, "GET"),
        ("10.0.0.1", 443, "GET"),
        ("api.example.com", 0, "GET"),
        ("api.example.com", 99999, "GET"),
        ("api.example.com", 443, ""),
        ("api.example.com", 443, "not a method!!"),
    ]:
        d = policy.decide(host, port, method)
        assert d.allowed is False
        assert d.code is ErrorCode.INVALID_REQUEST


def test_hostname_normalization() -> None:
    assert normalize_hostname("API.Example.COM.") == "api.example.com"
    assert normalize_hostname("  api.example.com  ") == "api.example.com"


@pytest.mark.parametrize(
    "bad",
    [
        "10.0.0.1",
        "127.0.0.1",
        "::1",
        "*.example.com",
        "a/b",
        "a:b",
        "a@b",
        "",
        "münchen.de",  # v0.1 is ASCII-only; use the A-label form
    ],
)
def test_rejected_hostnames(bad: str) -> None:
    with pytest.raises(ValueError):
        normalize_hostname(bad)


def test_punycode_form_accepted() -> None:
    assert normalize_hostname("XN--MNCHEN-3YA.DE.") == "xn--mnchen-3ya.de"


def test_connect_cannot_be_authorized() -> None:
    with pytest.raises(ValueError, match="CONNECT"):
        EgressPolicy.from_dict(
            {
                "version": "0.1",
                "rules": [
                    {
                        "action": "allow",
                        "hosts": ["h.example"],
                        "ports": [443],
                        "methods": ["CONNECT"],
                    }
                ],
            }
        )


@pytest.mark.parametrize(
    "doc",
    [
        {},
        {"version": "0.2", "rules": []},
        {"version": "0.1"},
        {"version": "0.1", "rules": {}, "extra": 1},
        {"version": "0.1", "rules": [{"action": "maybe"}]},
        {
            "version": "0.1",
            "rules": [
                {"action": "allow", "hosts": [], "ports": [443]},
            ],
        },
        {
            "version": "0.1",
            "rules": [
                {"action": "allow", "hosts": ["h.example"], "ports": [0]},
            ],
        },
        {
            "version": "0.1",
            "rules": [
                {"action": "allow", "hosts": ["10.0.0.1"], "ports": [443]},
            ],
        },
    ],
)
def test_malformed_policy_is_fail_closed(doc: object) -> None:
    with pytest.raises(ValueError):
        EgressPolicy.from_dict(doc)  # type: ignore[arg-type]


def test_invalid_json_is_fail_closed() -> None:
    with pytest.raises(ValueError):
        EgressPolicy.from_json("{not json")


def test_json_round_trip() -> None:
    policy = make_policy()
    restored = EgressPolicy.from_dict(policy.to_dict())
    assert restored.to_dict() == policy.to_dict()
    assert restored.decide("api.example.com", 443, "GET").allowed is True
    assert restored.decide("other.example", 443, "GET").allowed is False


def test_policy_is_immutable() -> None:
    policy = make_policy()
    with pytest.raises(dataclasses.FrozenInstanceError):
        policy.version = "9.9"  # type: ignore[misc]
