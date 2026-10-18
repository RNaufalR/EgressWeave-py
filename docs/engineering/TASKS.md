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

## EW-004 — Harden Capability validation (P2 defect from baseline audit)

- Status: DONE (local; not pushed — publication credential blocked, see below).
- Root cause: `Capability.__post_init__` called `self.evidence.strip()` without
  a type check, so non-string `evidence`/`scope` raised raw `AttributeError`
  instead of `CapabilityValidationError`, breaking the fail-closed
  typed-validation contract.
- Fix: `src/egressweave/capabilities.py` — isinstance checks for `evidence`
  and `scope` before use.
- Tests: 4 regression tests in `tests/test_capabilities.py` (non-str
  evidence via constructor and `from_dict`; non-str scope via constructor
  and `from_dict`).
- Gates: pytest 50/50 → 65/65 after EW-005; ruff check clean; ruff format
  clean; mypy --strict clean; `python -m build` OK.
- Audit: re-read changed files; no other untyped `.strip()`/attribute uses
  on validated fields found.

## EW-005 — Session authorization contract (transport-independent)

- Status: DONE (local; not pushed — publication credential blocked).
- Scope: `src/egressweave/session.py` — `Session(policy, registry?)` with
  `authorize(method, host, port, *, capability_id?) -> AuthorizationResult`
  and `authorize_or_raise()`. Keeps the five architecture states distinct:
  policy decision, capability status, transport_verified, gate decision,
  and (never claimed) actual completion.
- Semantics: policy evaluated first (deny wins, incl. INVALID_REQUEST);
  named capability must be CONFIGURED or VERIFIED; UNAVAILABLE →
  ROUTE_UNAVAILABLE; unknown id/status → UNKNOWN; `authorize()` never
  raises (unexpected failure → fail-closed UNKNOWN); constructor rejects
  wrong types with TypeError.
- Tests: `tests/test_session.py` — 15 items covering all branches,
  precedence, immutability, and typed errors.
- Gates: pytest 65/65 green; ruff check + format clean (one TRY003
  justified with targeted noqa, documented); mypy --strict clean;
  `python -m build` OK.
- Exports: `Session`, `AuthorizationResult` added to `__init__.__all__`.
- Audit: full re-read of session.py; all allow/deny paths verified;
  reasons secret-free.

## Remote publication (M1) — RESOLVED 2026-10-18 ~23:16 WIB

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

## EW-006 — Destination/URL validation (syntax only)

- Status: DONE (local; not pushed — publication credential blocked).
- Contract: `parse_destination(url, *, allowed_schemes?) -> Destination`
  (frozen: scheme, host, port, is_ip_literal). Threat model documented in
  module docstring: parser-confusion attacks (userinfo, ambiguous IP
  forms, percent-encoded hosts, backslashes, control chars).
- Rules: scheme allowlist (default http/https); userinfo rejected
  outright; ports 1–65535 or scheme default; IP literals strictly parsed
  via `ipaddress` and canonicalized; DNS names via `normalize_hostname`
  (ASCII-only preserved); `%` in host rejected.
- **Gap found by adversarial tests, fixed:** ambiguous IP-like hostnames
  (`0x7f.0.0.1`, `0177.0.0.1`, `2130706433`, `0x7f000001`) were accepted
  as DNS names — a validator/transport parser differential. Now rejected
  via `_IP_LIKE` rule (documented limitation: all-hex DNS names like
  "dead.beef" also rejected; safe default wins).
- Classification (not rejection): `is_loopback`, `is_private`,
  `is_link_local`, `is_multicast`, `is_reserved`, `is_unspecified`,
  `is_global` — policy decides, this module only validates syntax.
- No SSRF protection claimed: no DNS, no transport exists.
- Tests: `tests/test_destination.py` — 54 items, pure parsing, zero
  network connections.
- Gates: pytest 121/121; ruff check + format clean; mypy --strict clean;
  build OK.
- Exports: `Destination`, `parse_destination`, `DestinationValidationError`,
  `DEFAULT_SCHEMES`, `SCHEME_DEFAULT_PORTS` added to `__init__`.

## EW-007 — Prior-art research published in repo

- Status: DONE (local).
- `docs/research/PRIOR_ART_AND_DIFFERENTIATION.md`: ported from workspace
  research (11 projects, 2026-10-18), with per-project URL, license,
  features, overlap, limitations, and evidence-graded differentiator
  verdicts. No unsupported novelty claims.

## EW-008 — Dependency and packaging audit

- Status: DONE (local).
- Runtime dependencies: zero (stdlib-only). Dev deps: pytest, ruff, mypy,
  build — `pip-audit` clean (upgraded venv pip 24.0 → 26.2.1 to clear
  pip's own CVEs; none in project deps).
- Wheel: 6 modules + LICENSE + accurate METADATA (Apache-2.0).
- sdist: complete (docs, examples, source). Build content reproducible
  (verified via content hash).

## Publication status

- Remote `main` remains at `bee1233` (M1). EW-004 through EW-008 are
  committed locally only (`1a4d5a1`, `e1abe06`, `d8d772a`).
- 2026-10-18 ~23:58 WIB: user stated access had been granted; retried the
  legitimate App path (`push_files`, user-approved). Result: **403
  "Resource not accessible by integration"** on `POST .../git/trees` —
  the installation still lacks Contents write on EgressWeave-py. Nothing
  was written; no sync record created.
- BLOCKED: no usable push credential. Per orchestrator §12.1 the
  chat-exposed PAT is treated as compromised and is not reused. To
  unblock: (a) user fixes the App's repository access (GitHub → Settings
  → Applications → Muse → Configure → add `EgressWeave-py`, Contents =
  Read and write), or (b) user provides a fresh credential via Secure
  Vault (never in chat).

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
