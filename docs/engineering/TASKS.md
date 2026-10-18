# Task ledger

Format per task: status, scope, evidence. Status values: PLANNED, IN_PROGRESS,
BLOCKED, DONE. DONE requires: merged (or committed, pre-remote), CI green where
applicable, audit recorded.

## EW-001 — Repository baseline

- Status: DONE — pushed to `RNaufalR/EgressWeave-py`, CI green.
- Scope: LICENSE (Apache-2.0, fetched from apache.org), README, SECURITY,
  CONTRIBUTING, .gitignore, pyproject (hatchling, py>=3.10), CI workflow
  (ruff, ruff format, mypy --strict, pytest, python -m build; matrix
  3.10–3.13), docs/engineering (ROADMAP, TASKS, ADR-001), example policy.
- Evidence: local `10712b77`; remote `4e6cf1a` (merge, hashes verified
  identical); Actions run 39144188155 → success on all 4 matrix jobs.

## EW-002 — Egress policy schema v0.1

- Status: DONE — pushed, CI green (same run as EW-001).
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

- Status: DONE — pushed, CI green (same run as EW-001).
- Scope: `src/egressweave/capabilities.py` — `Capability`,
  `CapabilityRegistry`, `CapabilityStatus`, `CapabilityValidationError`;
  VERIFIED requires evidence + timezone-aware timestamp; duplicate
  registration raises; strict `from_dict` with version check.
- Tests: `tests/test_capabilities.py` — 14 test items, all passing.
- Gates: same as EW-002 (shared run).
- Audit: re-read before commit; no findings.

## Remote publication — RESOLVED 2026-10-18 ~23:16 WIB

- The GitHub App could neither create the repo (403) nor push via
  `push_files` (403 on git/trees — installation lacks Contents write).
- User created `RNaufalR/EgressWeave-py` manually (public) and provided a
  fine-grained PAT via chat (used transiently, never stored; user advised
  to rotate it since it touched chat history).
- Diagnostic note: `Authorization: Bearer` got HTTP 401 from GitHub's git
  endpoints while the same token returned 200 on the API — `Authorization:
  Basic` with `x-access-token:<token>` as the credential worked. The
  `permissions` field on the repo API response reflects the *user's*
  permissions, not the token's; a 401 on git endpoints with a valid token
  points at missing Contents permission on the token, not a bad token.
- Remote had 1 stub commit (`61f9d44`); merged locally with
  `--allow-unrelated-histories`, no force-push; local hashes preserved.
- Push: `61f9d44..4e6cf1a main -> main` (fast-forward). Remote HEAD hash
  verified identical to local (`4e6cf1a`). Fresh clone diff: all 17
  tracked files identical in content and path.

## Follow-ups (PLANNED)

- Pin GitHub Actions to commit SHAs (currently version tags; SHAs were not
  retrievable without an approval-gated API call — revisit post-remote).
- M2: policy-aware client library (per ROADMAP).
