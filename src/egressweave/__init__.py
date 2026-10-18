"""EgressWeave-py: network capability layer for AI agents.

Milestone M1 provides the portable policy schema (default-deny egress
rules) and the capability registry with verification evidence. A
policy-aware HTTP client, structured diagnostics, and the optional
authorized gateway are later milestones, not this package version.
"""

from egressweave.capabilities import (
    Capability,
    CapabilityRegistry,
    CapabilityStatus,
)
from egressweave.errors import (
    CapabilityValidationError,
    EgressError,
    ErrorCode,
    PolicyValidationError,
)
from egressweave.policy import (
    POLICY_SCHEMA_VERSION,
    EgressPolicy,
    EgressRule,
    PolicyDecision,
    normalize_hostname,
)

__version__ = "0.1.0"

__all__ = [
    "POLICY_SCHEMA_VERSION",
    "Capability",
    "CapabilityRegistry",
    "CapabilityStatus",
    "CapabilityValidationError",
    "EgressError",
    "EgressPolicy",
    "EgressRule",
    "ErrorCode",
    "PolicyDecision",
    "PolicyValidationError",
    "normalize_hostname",
]
