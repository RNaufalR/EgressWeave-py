# Task ledger

Format per task: status, scope, evidence. Status values: PLANNED, IN_PROGRESS,
BLOCKED, DONE. DONE requires: merged (or committed, pre-remote), CI green where
applicable, audit recorded.

## EW-001 — Repository baseline

- Status: IN_PROGRESS
- Scope: LICENSE (Apache-2.0), README, SECURITY, CONTRIBUTING, pyproject,
  CI workflow, docs/engineering (ROADMAP, TASKS, DECISIONS), example policy.
- Evidence: local gates (pytest/ruff/mypy) — recorded at merge time.

## EW-002 — Egress policy schema v0.1

- Status: IN_PROGRESS
- Scope: `src/egressweave/policy.py` — `EgressPolicy`, `EgressRule`,
  `PolicyDecision`, `normalize_hostname`; fail-closed parsing; default-deny
  evaluation; deny-beats-allow; CONNECT never authorizable.
- Tests: `tests/test_policy.py` — 27 tests covering allow/deny/default-deny,
  normalization, rejection of IP literals/wildcards/CONNECT, malformed-policy
  fail-closed cases, JSON round-trip, immutability.

## EW-003 — Capability registry v0.1

- Status: IN_PROGRESS
- Scope: `src/egressweave/capabilities.py` — `Capability`,
  `CapabilityRegistry`, `CapabilityStatus`; VERIFIED requires evidence +
  timezone-aware timestamp; duplicate registration raises.
- Tests: `tests/test_capabilities.py` — 17 tests covering status invariants,
  registry CRUD, serialization round-trip, strict parsing.

## Follow-ups (PLANNED)

- Pin GitHub Actions to commit SHAs (currently version tags; SHAs were not
  retrievable without an approval-gated API call — revisit post-remote).
- Remote publication: blocked 2026-10-18 — GitHub App returned
  `403 Resource not accessible by integration` on repository creation.
  Requires the repo to be created manually or the App granted creation
  permission before any push/CI verification can happen.
