# Task ledger

Format per task: status, scope, evidence. Status values: PLANNED, IN_PROGRESS,
BLOCKED, DONE. DONE requires: merged (or committed, pre-remote), CI green where
applicable, audit recorded.

## EW-001 — Repository baseline

- Status: DONE (local; remote pending — see blocker below)
- Scope: LICENSE (Apache-2.0, fetched from apache.org), README, SECURITY,
  CONTRIBUTING, .gitignore, pyproject (hatchling, py>=3.10), CI workflow
  (ruff, ruff format, mypy --strict, pytest, python -m build; matrix
  3.10–3.13), docs/engineering (ROADMAP, TASKS, ADR-001), example policy.
- Evidence: local commit `10712b77`; gates green (see EW-002/EW-003).

## EW-002 — Egress policy schema v0.1

- Status: DONE (local; remote pending)
- Scope: `src/egressweave/policy.py` — `EgressPolicy`, `EgressRule`,
  `PolicyDecision`, `normalize_hostname`, `PolicyValidationError`;
  fail-closed parsing; default-deny evaluation; deny-beats-allow; CONNECT
  never authorizable; ASCII-only hostnames in v0.1 (IDN via A-label).
- Tests: `tests/test_policy.py` — 32 test items, all passing.
- Gates: `ruff check` clean, `ruff format --check` clean, `mypy --strict`
  clean, `pytest` 46/46 green (both test files).
- Audit: full re-read of policy.py before commit; one finding fixed —
  dead IDNA branch removed, ASCII-only rule documented and tested.

## EW-003 — Capability registry v0.1

- Status: DONE (local; remote pending)
- Scope: `src/egressweave/capabilities.py` — `Capability`,
  `CapabilityRegistry`, `CapabilityStatus`, `CapabilityValidationError`;
  VERIFIED requires evidence + timezone-aware timestamp; duplicate
  registration raises; strict `from_dict` with version check.
- Tests: `tests/test_capabilities.py` — 14 test items, all passing.
- Gates: same as EW-002 (shared run).
- Audit: re-read before commit; no findings.

## Blocker — remote publication

- Status: BLOCKED since 2026-10-18 ~22:40 WIB.
- Exact error: `POST https://api.github.com/user/repos` →
  `403 Resource not accessible by integration` (via MCP `create_repository`,
  user-approved). The GitHub App installation lacks repository-creation
  permission.
- Not attempted: raw git push (no remote exists yet); asking the user for a
  token (forbidden by connector policy).
- To unblock, the user must EITHER create the repo manually
  (github.com/new — name `EgressWeave-py`, public, Apache-2.0, no README
  needed) OR grant the Muse GitHub App repository-creation permission.
  After the repo exists: verify MCP `push_files` works (needs Contents
  write on the new repo; may require adding the repo in the App's
  installation settings), push the local commit, open PRs per task, verify
  real GitHub Actions runs, merge on green.
- Nothing was simulated: no remote URL, commit hash, or CI status is
  claimed beyond what was actually produced locally.

## Follow-ups (PLANNED)

- Pin GitHub Actions to commit SHAs (currently version tags; SHAs were not
  retrievable without an approval-gated API call — revisit post-remote).
- M2: policy-aware client library (per ROADMAP).
