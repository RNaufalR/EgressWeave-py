# Baseline Audit — EgressWeave-py

Verification date: 2026-10-18 (Asia/Jakarta, ISO 8601).

## Repository identity

- URL: `https://github.com/RNaufalR/EgressWeave-py`
- Owner/name: `RNaufalR` / `EgressWeave-py` (owner verified via API `get_me`
  id 146347500 on 2026-10-18; repo URL provided by user and confirmed).
- Visibility: public. License: Apache-2.0 (`LICENSE`, 11358 bytes, fetched
  from apache.org; byte-identical to GitHub's stock text modulo leading
  blank line).
- Default branch: `main`.

## Commit history (local == remote)

| Hash | Subject |
|------|---------|
| `bee1233` | docs: record remote publication evidence (push + CI green) |
| `4e6cf1a` | Merge remote initial commit (README stub + Apache-2.0 LICENSE) |
| `61f9d44` | Initial commit (user-created stub: 1-line README + LICENSE) |
| `1563d61` | EW-001/EW-002/EW-003: record task ledger with evidence |
| `10712b7` | EW-001/EW-002/EW-003: M1 foundation — policy schema, capability registry, CI, docs |

- Remote HEAD (`git ls-remote`): `bee1233` — matches local `HEAD`.
- Working tree: clean. No staged/unstaged changes. No untracked files
  (excluding ignored caches).
- Merge `4e6cf1a` resolved unrelated histories (`--allow-unrelated-histories`);
  no force-push used at any point.

## Remote file verification

Fresh anonymous clone to `/tmp` diffed against local tree: all 17 tracked
files identical in content and path. Only ignored caches
(`.mypy_cache`, `.pytest_cache`, `.ruff_cache`) differ locally.

## CI status

- Run 39144188155 (head `4e6cf1a`): completed, success — 4/4 matrix jobs
  (`quality (3.10)`, `(3.11)`, `(3.12)`, `(3.13)`).
- Run 39144379153 (head `bee1233`): completed, success.
- Workflow `.github/workflows/ci.yml`: ruff check, ruff format --check,
  mypy --strict, pytest, `python -m build`.

## Local quality gates (re-run 2026-10-18 ~23:30 WIB)

- `pytest`: 46/46 passed.
- `ruff check src tests`: clean. `ruff format --check`: clean.
- `mypy --strict src`: clean (4 files).
- Package build: verified earlier (wheel + sdist); re-verified on demand.

### Environment incident (resolved)

At ~23:28 WIB `pytest` failed at collection with
`ModuleNotFoundError: No module named 'egressweave'` — the venv had lost
its editable install (likely VM redeployment), not a code defect.
Reinstalled via `pip install -e ".[dev]"` (mirroring CI); 46/46 green
again. Lesson recorded: local gate runs must ensure the package is
installed before interpreting failures.

## M1 verification (EW-001/002/003)

- EW-001: all artifacts present (LICENSE, README, SECURITY.md,
  CONTRIBUTING.md, `.gitignore`, `pyproject.toml`, CI workflow,
  `docs/engineering/` incl. ADR-001, `examples/policy.example.json`).
  README is honest about status and independence from
  `ContextualWisdomLab/EgressWeave`.
- EW-002: `src/egressweave/policy.py` — default-deny, deny-beats-allow,
  fail-closed parsing, CONNECT rejected, ASCII-only hostnames, `decide()`
  never raises. 32 test items green.
- EW-003: `src/egressweave/capabilities.py` — four statuses, VERIFIED
  requires evidence + tz-aware timestamp, strict serialization. 14 test
  items green.
- **Defect found this audit (P2):** non-string `evidence`/`scope` on
  `Capability` bypasses typed validation and raises raw `AttributeError`
  instead of `CapabilityValidationError` (fail-closed contract violation).
  Tracked as EW-004; fix before further feature work.

## Security posture

- Secret scan: clean (no tokens, keys, `.env`, or credentials in tree).
- No network code exists yet; SSRF/DNS-rebinding review deferred until a
  transport is introduced (documented, not ignored).
- Publication credential: the chat-exposed PAT is treated as compromised
  per orchestrator §12.1 and will not be reused. Remote pushes are
  **blocked** until the user either fixes the GitHub App installation's
  repository access (Contents: write on `EgressWeave-py`) or provides a
  fresh credential via Secure Vault. All engineering continues locally.

## Next executable tasks (updated 2026-10-18 ~23:55 WIB)

Completed this round:
1. EW-004 — done (Capability validation hardening).
2. EW-005 — done (Session authorization contract).
3. EW-006 — done (destination/URL validation, syntax-only).
4. EW-007 — done (prior-art doc in repo).
5. EW-008 — done (dependency/packaging audit).
6. Prioritas 1 audit: EW-004/EW-005 re-audited; 2 adversarial "never
   raises" tests added; all gates green (121/121).

Remaining:
1. URL → Session integration (`authorize_url` convenience) — optional.
2. Property-based tests for policy evaluation invariants — deferred
   (benefit vs. new dependency `hypothesis` not yet justified).
3. Publication: BLOCKED until legitimate credential path available
   (App Contents write or fresh Secure Vault credential). Local HEAD is
   4 commits ahead of remote (`bee1233`).

## Local quality gates (re-run 2026-10-18 ~23:55 WIB)

- `pytest`: 121/121 passed.
- `ruff check src tests`: clean. `ruff format --check`: clean.
- `mypy --strict src`: clean (6 files).
- `python -m build`: OK (wheel + sdist).
- `pip-audit`: clean (after pip upgrade).
- Secret scan: clean.
