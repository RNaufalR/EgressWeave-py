"""Transport-independent authorization for EgressWeave-py.

A :class:`Session` binds one validated :class:`EgressPolicy` to one
:class:`CapabilityRegistry` and answers a single question: *is this
request permitted to proceed to the transport layer?*

The answer keeps the architecture's five states distinct instead of
collapsing them into one boolean:

1. the policy allows the target (``policy_decision``),
2. a transport capability is known (``capability_status``),
3. the capability was verified with evidence (``transport_verified``),
4. ``authorized`` — this library's gate decision,
5. whether the request actually succeeded — **never** answered here;
   v0.1 ships no transport.

``authorized=True`` means "permitted to attempt", never "will succeed".
Callers must still handle DNS, TLS, timeout, and upstream failures, and
must never treat a configured-but-unverified capability as proof of
reachability.
"""

from __future__ import annotations

from dataclasses import dataclass

from egressweave.capabilities import CapabilityRegistry, CapabilityStatus
from egressweave.errors import EgressError, ErrorCode
from egressweave.policy import EgressPolicy, PolicyDecision


@dataclass(frozen=True)
class AuthorizationResult:
    """Outcome of :meth:`Session.authorize`. Never raises to produce."""

    authorized: bool
    code: ErrorCode | None
    reason: str
    policy_decision: PolicyDecision
    capability_id: str | None
    capability_status: CapabilityStatus | None
    transport_verified: bool


class Session:
    """Policy + capability gate for outbound requests (v0.1).

    The constructor validates its arguments strictly and raises
    ``TypeError`` on misuse. :meth:`authorize` itself never raises:
    unexpected failures deny with ``ErrorCode.UNKNOWN`` (fail-closed).
    """

    def __init__(
        self,
        policy: EgressPolicy,
        registry: CapabilityRegistry | None = None,
    ) -> None:
        # One-off programmer-error guards: short, call-site-specific messages,
        # not reusable error categories (hence noqa, not a new exception type).
        if not isinstance(policy, EgressPolicy):
            raise TypeError("policy must be EgressPolicy")  # noqa: TRY003
        if registry is not None and not isinstance(registry, CapabilityRegistry):
            raise TypeError("registry must be CapabilityRegistry or None")  # noqa: TRY003
        self._policy = policy
        self._registry = registry

    def authorize(
        self,
        method: str,
        host: str,
        port: int,
        *,
        capability_id: str | None = None,
    ) -> AuthorizationResult:
        """Decide whether ``(method, host, port)`` may proceed.

        When ``capability_id`` names a registry entry, the capability must
        be usable (CONFIGURED or VERIFIED); UNAVAILABLE denies with
        ``ROUTE_UNAVAILABLE`` and unknown ids or UNKNOWN status deny with
        ``UNKNOWN``. Without a ``capability_id`` the decision rests on
        policy alone and ``transport_verified`` is ``False``.
        """
        try:
            return self._authorize(method, host, port, capability_id=capability_id)
        except Exception as exc:  # fail-closed: the gate never raises
            # decide() itself never raises, so this is safe even for the
            # inputs that triggered the unexpected failure.
            denied = self._policy.decide(host, port, method)
            return AuthorizationResult(
                authorized=False,
                code=ErrorCode.UNKNOWN,
                reason=f"authorization failed closed ({type(exc).__name__})",
                policy_decision=denied,
                capability_id=capability_id,
                capability_status=None,
                transport_verified=False,
            )

    def _authorize(
        self,
        method: str,
        host: str,
        port: int,
        *,
        capability_id: str | None,
    ) -> AuthorizationResult:
        decision = self._policy.decide(host, port, method)
        if not decision.allowed:
            return AuthorizationResult(
                authorized=False,
                code=decision.code,
                reason=decision.reason,
                policy_decision=decision,
                capability_id=capability_id,
                capability_status=None,
                transport_verified=False,
            )
        if capability_id is None:
            return AuthorizationResult(
                authorized=True,
                code=None,
                reason="policy-authorized; no transport capability assessed",
                policy_decision=decision,
                capability_id=None,
                capability_status=None,
                transport_verified=False,
            )
        capability = (
            self._registry.get(capability_id) if self._registry is not None else None
        )
        if capability is None:
            return AuthorizationResult(
                authorized=False,
                code=ErrorCode.UNKNOWN,
                reason=f"unknown capability {capability_id!r}",
                policy_decision=decision,
                capability_id=capability_id,
                capability_status=None,
                transport_verified=False,
            )
        status = capability.status
        if status is CapabilityStatus.UNAVAILABLE:
            return AuthorizationResult(
                authorized=False,
                code=ErrorCode.ROUTE_UNAVAILABLE,
                reason=f"capability {capability_id!r} is unavailable",
                policy_decision=decision,
                capability_id=capability_id,
                capability_status=status,
                transport_verified=False,
            )
        if status is CapabilityStatus.UNKNOWN:
            return AuthorizationResult(
                authorized=False,
                code=ErrorCode.UNKNOWN,
                reason=f"capability {capability_id!r} has not been assessed",
                policy_decision=decision,
                capability_id=capability_id,
                capability_status=status,
                transport_verified=False,
            )
        # CONFIGURED or VERIFIED: permitted to attempt. Configured alone
        # is not proof of reachability — see transport_verified.
        verified = status is CapabilityStatus.VERIFIED
        return AuthorizationResult(
            authorized=True,
            code=None,
            reason=(
                f"policy-authorized; capability {capability_id!r} "
                f"{'verified' if verified else 'configured (unverified)'}"
            ),
            policy_decision=decision,
            capability_id=capability_id,
            capability_status=status,
            transport_verified=verified,
        )

    def authorize_or_raise(
        self,
        method: str,
        host: str,
        port: int,
        *,
        capability_id: str | None = None,
    ) -> AuthorizationResult:
        """Like :meth:`authorize`, but raises :class:`EgressError` on denial."""
        result = self.authorize(method, host, port, capability_id=capability_id)
        if not result.authorized:
            raise EgressError(
                result.code or ErrorCode.UNKNOWN,
                result.reason,
                detail=(
                    f"capability={result.capability_id!r} "
                    f"status={result.capability_status}"
                ),
            )
        return result
