"""Tests for the capability registry with verification evidence."""

from __future__ import annotations

import dataclasses
from datetime import datetime, timezone

import pytest

from egressweave.capabilities import (
    REGISTRY_SCHEMA_VERSION,
    Capability,
    CapabilityRegistry,
    CapabilityStatus,
)
from egressweave.errors import CapabilityValidationError

NOW = datetime(2026, 10, 18, 12, 0, tzinfo=timezone.utc)


def verified_capability() -> Capability:
    return Capability(
        id="https-proxy",
        kind="http-proxy",
        status=CapabilityStatus.VERIFIED,
        evidence="HTTP 200 from https://example.com via configured proxy",
        verified_at=NOW,
        scope="hostname https only; ip-literal https untested",
        limits=("no direct tcp",),
    )


def test_verified_requires_evidence() -> None:
    with pytest.raises(ValueError, match="evidence"):
        Capability(
            id="x",
            kind="http-proxy",
            status=CapabilityStatus.VERIFIED,
            verified_at=NOW,
        )


def test_verified_requires_timestamp() -> None:
    with pytest.raises(ValueError, match="verified_at"):
        Capability(
            id="x",
            kind="http-proxy",
            status=CapabilityStatus.VERIFIED,
            evidence="some evidence",
        )


def test_non_verified_must_not_carry_timestamp() -> None:
    with pytest.raises(ValueError, match="verified_at"):
        Capability(
            id="x",
            kind="http-proxy",
            status=CapabilityStatus.CONFIGURED,
            verified_at=NOW,
        )


def test_naive_datetime_rejected() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        Capability(
            id="x",
            kind="http-proxy",
            status=CapabilityStatus.VERIFIED,
            evidence="e",
            verified_at=datetime(2026, 10, 18, 12, 0),
        )


def test_configured_without_evidence_is_fine() -> None:
    cap = Capability(id="x", kind="dns", status=CapabilityStatus.CONFIGURED)
    assert cap.status is CapabilityStatus.CONFIGURED
    assert cap.verified_at is None


def test_registry_register_get_list() -> None:
    reg = CapabilityRegistry()
    cap = verified_capability()
    reg.register(cap)
    assert reg.get("https-proxy") == cap
    assert reg.get("missing") is None
    assert reg.list() == [cap]
    assert reg.list(status=CapabilityStatus.VERIFIED) == [cap]
    assert reg.list(status=CapabilityStatus.UNKNOWN) == []
    assert reg.list(kind="http-proxy") == [cap]
    assert reg.list(kind="direct-tcp") == []


def test_registry_rejects_duplicate_id() -> None:
    reg = CapabilityRegistry()
    reg.register(verified_capability())
    with pytest.raises(ValueError, match="already registered"):
        reg.register(verified_capability())


def test_registry_remove() -> None:
    reg = CapabilityRegistry()
    reg.register(verified_capability())
    reg.remove("https-proxy")
    assert reg.get("https-proxy") is None
    with pytest.raises(ValueError, match="unknown capability id"):
        reg.remove("https-proxy")


def test_registry_round_trip() -> None:
    reg = CapabilityRegistry()
    reg.register(verified_capability())
    reg.register(
        Capability(id="direct-tcp", kind="tcp", status=CapabilityStatus.UNKNOWN)
    )
    restored = CapabilityRegistry.from_dict(reg.to_dict())
    assert restored.get("https-proxy") == verified_capability()
    assert restored.get("direct-tcp") is not None
    assert restored.get("direct-tcp").status is CapabilityStatus.UNKNOWN


def test_registry_rejects_bad_version() -> None:
    with pytest.raises(ValueError, match="version"):
        CapabilityRegistry.from_dict({"version": "9.9", "capabilities": []})


def test_registry_rejects_invalid_status() -> None:
    with pytest.raises(ValueError, match="invalid status"):
        Capability.from_dict({"id": "x", "kind": "k", "status": "maybe"})


def test_registry_rejects_unknown_keys() -> None:
    with pytest.raises(ValueError, match="unknown keys"):
        Capability.from_dict({"id": "x", "kind": "k", "status": "unknown", "bogus": 1})


def test_capability_is_immutable() -> None:
    cap = verified_capability()
    with pytest.raises(dataclasses.FrozenInstanceError):
        cap.status = CapabilityStatus.UNKNOWN  # type: ignore[misc]


def test_registry_schema_version() -> None:
    assert REGISTRY_SCHEMA_VERSION == "0.1"


def test_evidence_must_be_str_not_attributeerror() -> None:
    # EW-004: non-string evidence must raise the typed validation error,
    # never a raw AttributeError (fail-closed contract).
    with pytest.raises(CapabilityValidationError, match="evidence must be a string"):
        Capability(
            id="x",
            kind="http-proxy",
            status=CapabilityStatus.VERIFIED,
            evidence=123,  # type: ignore[arg-type]
            verified_at=NOW,
        )


def test_scope_must_be_str() -> None:
    with pytest.raises(CapabilityValidationError, match="scope must be a string"):
        Capability(
            id="x",
            kind="http-proxy",
            status=CapabilityStatus.CONFIGURED,
            scope=["not", "a", "string"],  # type: ignore[arg-type]
        )


def test_from_dict_rejects_non_string_evidence() -> None:
    with pytest.raises(CapabilityValidationError, match="evidence must be a string"):
        Capability.from_dict(
            {
                "id": "x",
                "kind": "http-proxy",
                "status": "verified",
                "evidence": {"nested": "dict"},
                "verified_at": NOW.isoformat(),
            }
        )


def test_from_dict_rejects_non_string_scope() -> None:
    with pytest.raises(CapabilityValidationError, match="scope must be a string"):
        Capability.from_dict(
            {"id": "x", "kind": "http-proxy", "status": "unknown", "scope": 42}
        )
