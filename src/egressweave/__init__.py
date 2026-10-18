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
from egressweave.destination import (
    DEFAULT_SCHEMES,
    SCHEME_DEFAULT_PORTS,
    Destination,
    parse_destination,
)
from egressweave.errors import (
    CapabilityValidationError,
    DestinationValidationError,
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
from egressweave.session import AuthorizationResult, Session

__version__ = "0.1.0"

__all__ = [
    "POLICY_SCHEMA_VERSION",
    "AuthorizationResult",
    "Capability",
    "CapabilityRegistry",
    "CapabilityStatus",
    "CapabilityValidationError",
    "DEFAULT_SCHEMES",
    "Destination",
    "DestinationValidationError",
    "EgressError",
    "EgressPolicy",
    "EgressRule",
    "ErrorCode",
    "PolicyDecision",
    "PolicyValidationError",
    "SCHEME_DEFAULT_PORTS",
    "Session",
    "normalize_hostname",
    "parse_destination",
]
