# ADR-001: In-process policy-aware client library first; independent repository

Date: 2026-10-18
Status: Accepted
Deciders: RNaufalR (project owner), Muse (engineering agent)

## Context

EgressWeave needs a first shippable unit that is useful without running any
new network infrastructure. Two designs were on the table: (A) an in-process,
policy-aware client library, and (B) a local filtering proxy process.

Separately, the name `EgressWeave` on GitHub is held by
`ContextualWisdomLab/EgressWeave`, an independent project implementing an
SSRF-safe HTTP client. The owner chose not to fork or duplicate that name.

## Decision

1. **Library first (A).** Milestone M2 builds an in-process, policy-aware
   client library over the environment's already-authorized connectivity. No
   local proxy process in M1/M2. Rationale: zero new infrastructure, works in
   locked-down sandboxes (no loopback, no raw sockets), directly testable in
   CI, and honest about what it does — it manages capability, it does not
   provide connectivity.
2. **Independent repository named `EgressWeave-py`.** Not a fork of
   `ContextualWisdomLab/EgressWeave`; no code taken from it. The shared name
   root is disclosed in the README to avoid confusion.
3. **Differentiation.** This project owns the layers the name-holder does not
   claim: the evidence-graded capability registry, the portable default-deny
   policy schema, and the agent-facing structured diagnostics taxonomy.

## Consequences

- M1 ships schema + registry only; enforcement arrives in M2 and must consult
  the policy on the request path — the schema alone intercepts nothing.
- The gateway (Mode B) stays deferred to M4 and needs a separate authorization.
- If `ContextualWisdomLab/EgressWeave` later adds a capability registry, the
  differentiation claim must be revisited honestly.
