# EgressWeave-py

Network capability layer for AI agents running in sandboxes, containers, and VMs.

EgressWeave-py answers a question most agent runtimes leave vague: *what network
capability does this environment actually provide, and what is this agent allowed
to use?* It provides:

- **Explicit, default-deny egress policies** — a versioned, machine-readable
  schema over exact `(hostname, port, method)` triples. Anything not explicitly
  allowed is denied; deny rules beat allow rules; malformed policies fail closed.
- **Capability discovery with verification evidence** — a registry of what the
  environment offers, graded `configured` / `verified` / `unavailable` /
  `unknown`. A `verified` record requires evidence and a timestamp; a single
  successful request never implies general reachability.
- **Structured diagnostics vocabulary** — stable, machine-readable error codes
  (`policy_denied`, `dns_error`, `tls_error`, …) an agent can branch on,
  instead of scraping free-text tracebacks.

What it is **not**: a proxy, a VPN, a firewall, or a way to create connectivity
the environment does not provide. Capability management is not connectivity
provision. A later milestone adds an optional, admin-authorized egress gateway;
that gateway does not exist yet.

> **Project status (2026-10-18):** early implementation. Milestone M1
> (policy schema + capability registry + CI) is in progress. See
> `docs/engineering/ROADMAP.md` for what exists and what does not.

> **Independence note:** this is an independent implementation. It is not
> affiliated with, forked from, or endorsed by `ContextualWisdomLab/EgressWeave`,
> a separate project that happens to share the name root. The scopes differ:
> EgressWeave-py covers the policy, capability-evidence, and diagnostics layers.

## Install

Requires Python 3.10+.

```bash
pip install egressweave-py
```

From source:

```bash
pip install -e ".[dev]"
```

## Quickstart

```python
from egressweave import EgressPolicy

policy = EgressPolicy.from_json(open("policy.json").read())

decision = policy.decide("api.example.com", 443, "GET")
if decision.allowed:
    print("allowed:", decision.reason)   # "allowed by rule #0"
else:
    print("denied:", decision.code, "-", decision.reason)
```

```python
from datetime import datetime, timezone
from egressweave import Capability, CapabilityRegistry, CapabilityStatus

registry = CapabilityRegistry()
registry.register(Capability(
    id="https-proxy",
    kind="http-proxy",
    status=CapabilityStatus.VERIFIED,
    evidence="HTTP 200 from https://example.com via configured proxy",
    verified_at=datetime.now(timezone.utc),
    scope="hostname https only; ip-literal https untested",
    limits=("no direct tcp",),
))
```

An example policy document lives at `examples/policy.example.json`.

## Design principles

1. **Default-deny.** No allow rule matches → denied. Empty policy → everything denied.
2. **Fail-closed.** Malformed policy documents raise instead of producing a
   permissive policy. `decide()` never raises; bad inputs are denied.
3. **Evidence over claims.** `verified` means "exercised successfully, with a
   timestamp and a description of how" — never "probably works".
4. **Credential-safe.** Error messages and audit records must never contain
   proxy credentials, auth headers, cookies, or secret-bearing URLs.
5. **Small, honest scope.** Each milestone does one thing and documents what it
   does not do.

## Documentation

- `docs/engineering/ROADMAP.md` — milestones and their status
- `docs/engineering/TASKS.md` — task ledger (EW-###)
- `docs/engineering/DECISIONS/` — architecture decision records
- `SECURITY.md` — vulnerability reporting
- `CONTRIBUTING.md` — how to contribute

## License

Apache-2.0. See `LICENSE`.
