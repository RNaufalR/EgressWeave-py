# Roadmap

Milestones are sequential. A milestone is done when its tasks are merged with
green CI and the ledger (`TASKS.md`) records the evidence — not when code is
merely written.

## M1 — Foundation (in progress)

Portable building blocks with no network behavior of their own.

- EW-001: repository baseline (docs, ADR, packaging, CI)
- EW-002: versioned default-deny egress policy schema v0.1
- EW-003: capability registry with verification evidence v0.1
- Follow-up: pin GitHub Actions to SHAs (currently version tags)

## M2 — Policy-aware client

An in-process, policy-aware HTTP client library (stdlib + `http.client`, or a
declared dependency) that consults an `EgressPolicy` on the request path:
exact `(host, port)` enforcement, DNS-rebinding resistance, method allowlists,
body budgets, timeout ceilings, fail-closed errors using the `ErrorCode`
taxonomy. No local proxy process in M2.

## M3 — Diagnostics and audit

Structured network-error taxonomy wired end to end (policy_denied,
dns_error, tls_error, timeout, …), credential-safe audit records for every
mediated request, and a `doctor`-style command that re-verifies capability
records against the live environment.

## M4 — Optional authorized gateway (deferred)

Admin-authorized egress gateway for environments where the operator chooses to
provide mediated connectivity. Explicitly out of scope until M1–M3 are stable;
requires a separate authorization decision before any implementation begins.

## Non-goals

- Creating connectivity the environment does not provide.
- Wildcard/suffix host matching (v0.1 is exact-match; any change needs an ADR).
- A local filtering proxy process (deferred; see ADR-001).
