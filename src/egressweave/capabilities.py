"""Capability registry with verification evidence (v0.1).

A capability record describes one network capability of the current
environment (e.g. "https via platform proxy"). The status taxonomy is
deliberate:

- ``CONFIGURED``: declared in configuration; never successfully exercised.
- ``VERIFIED``: exercised successfully; requires evidence and a timestamp.
- ``UNAVAILABLE``: tested and found not to work, or known-absent.
- ``UNKNOWN``: not yet assessed.

A successful request to one endpoint never implies general reachability;
record the scope that was actually tested.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any

from egressweave.errors import CapabilityValidationError

REGISTRY_SCHEMA_VERSION = "0.1"


class CapabilityStatus(str, Enum):
    CONFIGURED = "configured"
    VERIFIED = "verified"
    UNAVAILABLE = "unavailable"
    UNKNOWN = "unknown"


def _check_timestamp(value: object, *, where: str) -> datetime | None:
    if value is None:
        return None
    if not isinstance(value, datetime):
        raise CapabilityValidationError(where, "verified_at must be datetime or None")
    if value.tzinfo is None:
        raise CapabilityValidationError(where, "verified_at must be timezone-aware")
    return value


@dataclass(frozen=True)
class Capability:
    """One assessed network capability."""

    id: str
    kind: str
    status: CapabilityStatus
    evidence: str = ""
    verified_at: datetime | None = None
    scope: str = ""
    limits: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        where = f"capability {self.id!r}"
        if not isinstance(self.id, str) or not self.id.strip():
            raise CapabilityValidationError(where, "id must be a non-empty string")
        if not isinstance(self.kind, str) or not self.kind.strip():
            raise CapabilityValidationError(where, "kind must be a non-empty string")
        if not isinstance(self.status, CapabilityStatus):
            raise CapabilityValidationError(where, f"invalid status: {self.status!r}")
        verified_at = _check_timestamp(self.verified_at, where=where)
        if self.status is CapabilityStatus.VERIFIED:
            if not self.evidence.strip():
                raise CapabilityValidationError(where, "VERIFIED requires evidence")
            if verified_at is None:
                raise CapabilityValidationError(where, "VERIFIED requires verified_at")
        elif verified_at is not None:
            raise CapabilityValidationError(
                where, "verified_at is only meaningful for VERIFIED capabilities"
            )
        for i, limit in enumerate(self.limits):
            if not isinstance(limit, str) or not limit.strip():
                raise CapabilityValidationError(
                    where, f"limits[{i}] must be a non-empty string"
                )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind,
            "status": self.status.value,
            "evidence": self.evidence,
            "verified_at": (self.verified_at.isoformat() if self.verified_at else None),
            "scope": self.scope,
            "limits": list(self.limits),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> Capability:
        where = "capability"
        if not isinstance(data, Mapping):
            raise CapabilityValidationError(where, "must be a mapping")
        unknown = set(data) - {
            "id",
            "kind",
            "status",
            "evidence",
            "verified_at",
            "scope",
            "limits",
        }
        if unknown:
            raise CapabilityValidationError(where, f"unknown keys: {sorted(unknown)}")
        raw_status = data.get("status")
        try:
            status = CapabilityStatus(raw_status)
        except ValueError as exc:
            raise CapabilityValidationError(
                where, f"invalid status: {raw_status!r}"
            ) from exc
        raw_ts = data.get("verified_at")
        verified_at: datetime | None = None
        if raw_ts is not None:
            if not isinstance(raw_ts, str):
                raise CapabilityValidationError(
                    where, "verified_at must be an ISO-8601 string or null"
                )
            try:
                verified_at = datetime.fromisoformat(raw_ts)
            except ValueError as exc:
                raise CapabilityValidationError(
                    where, f"verified_at is not valid ISO-8601: {raw_ts!r}"
                ) from exc
        raw_limits = data.get("limits", [])
        if not isinstance(raw_limits, list):
            raise CapabilityValidationError(where, "'limits' must be a list")
        return cls(
            id=data.get("id", ""),
            kind=data.get("kind", ""),
            status=status,
            evidence=data.get("evidence", ""),
            verified_at=verified_at,
            scope=data.get("scope", ""),
            limits=tuple(raw_limits),
        )


class CapabilityRegistry:
    """Mutable registry of capability records for one environment."""

    def __init__(self) -> None:
        self._caps: dict[str, Capability] = {}

    def register(self, capability: Capability) -> None:
        """Add a record. Duplicate ids raise instead of overwriting."""
        if capability.id in self._caps:
            raise CapabilityValidationError(
                "registry", f"capability {capability.id!r} already registered"
            )
        self._caps[capability.id] = capability

    def remove(self, capability_id: str) -> None:
        try:
            del self._caps[capability_id]
        except KeyError as exc:
            raise CapabilityValidationError(
                "registry", f"unknown capability id: {capability_id!r}"
            ) from exc

    def get(self, capability_id: str) -> Capability | None:
        return self._caps.get(capability_id)

    def list(
        self,
        *,
        status: CapabilityStatus | None = None,
        kind: str | None = None,
    ) -> list[Capability]:
        return [
            c
            for c in self._caps.values()
            if (status is None or c.status is status)
            and (kind is None or c.kind == kind)
        ]

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": REGISTRY_SCHEMA_VERSION,
            "capabilities": [c.to_dict() for c in self._caps.values()],
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> CapabilityRegistry:
        where = "registry"
        if not isinstance(data, Mapping):
            raise CapabilityValidationError(where, "must be a mapping")
        if data.get("version") != REGISTRY_SCHEMA_VERSION:
            raise CapabilityValidationError(
                where,
                f"unsupported version {data.get('version')!r} "
                f"(expected {REGISTRY_SCHEMA_VERSION!r})",
            )
        raw = data.get("capabilities")
        if not isinstance(raw, list):
            raise CapabilityValidationError(where, "'capabilities' must be a list")
        registry = cls()
        for item in raw:
            registry.register(Capability.from_dict(item))
        return registry
