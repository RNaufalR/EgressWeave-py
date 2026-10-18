# Requirements Traceability Matrix — EgressWeave-py

Recovered 2026-10-18 from: V1/V2 consultation prompts, V3 autonomous
directive, user decisions (naming, push protocol, credential policy), the
consultation findings (A–G, B-1…B-9, AT-01…AT-10, D-1…D-8, T-01…T-12),
and the Autonomous Engineering Orchestrator prompt (§§0–22).

Status values: `verified` · `in-progress` · `blocked` · `deferred` ·
`not-applicable`. A requirement is `verified` only when acceptance
criteria are met **and** evidence exists. Nothing is marked complete
from documentation alone.

## A. Governance and safety (P0)

| ID | Source | Requirement | Type | Status | Evidence / Remaining work |
|----|--------|-------------|------|--------|---------------------------|
| REQ-GOV-001 | V3 | Never bypass auth, org policy, or branch protections | Security | in-progress (standing) | Ongoing invariant; no bypass attempted. |
| REQ-GOV-002 | V3 | Never fabricate GitHub access, operations, test results, CI status, or absence of bugs | Security | in-progress (standing) | All claims cite tool output. |
| REQ-GOV-003 | V3 | Pause for user authorization on destructive, public, irreversible, cost-incurring, or scope-changing ops | Operations | in-progress (standing) | Push path chosen by user; no destructive op taken. |
| REQ-GOV-004 | V3 §17.2 | Naming-conflict rule: never modify another party's repo | Security | verified | `ContextualWisdomLab/EgressWeave` untouched; chose `EgressWeave-py`. |
| REQ-GOV-005 | User 2026-10-18 | Never ask user to paste PAT/token/secret in chat | Security | in-progress (standing) | Never requested; one user-supplied token used transiently, never stored. |
| REQ-GOV-006 | Orch §12.1 | Treat the chat-exposed PAT as compromised; do not reuse, print, or store it | Security | verified | Not reused after publication; rotation advised to user 2026-10-18. |
| REQ-GOV-007 | Orch §12.4 | No force-push, history rewrite, or branch deletion | Operations | in-progress (standing) | All pushes fast-forward (`61f9d44..4e6cf1a`, `4e6cf1a..bee1233`). |
| REQ-GOV-008 | Orch §17.1 | Do not publish with known unresolved P0/P1 defects | Security | in-progress (standing) | Gate on every push. |

## B. Repository and delivery

| ID | Source | Requirement | Type | Status | Evidence / Remaining work |
|----|--------|-------------|------|--------|---------------------------|
| REQ-REP-001 | V3 + User | Real public GitHub repo `RNaufalR/EgressWeave-py`, Apache-2.0, branch `main` | Operations | verified | Repo exists, public, Apache-2.0; remote HEAD `bee1233` matches local. |
| REQ-REP-002 | User 2026-10-18 | Deliverable is a real software repo, not an HTML artifact/mockup | Architecture | verified | No artifact mode used since correction. |
| REQ-REP-003 | User 2026-10-18 | 8-step push protocol (verify URL/owner, inspect local, no credential exposure, no force-push, hash verification, real CI check, per-milestone commits, no unverified claims) | Operations | verified | Followed for both pushes; hashes verified; CI runs 39144188155, 39144379153. |
| REQ-REP-004 | Orch §12.6 | Verify actual GitHub Actions run per pushed revision (all jobs) | CI | verified | Both M1 pushes: 4/4 matrix jobs success. |
| REQ-REP-005 | Orch §19 | Task ledger in repo, consistent with real history | Docs | in-progress | `TASKS.md` current through `bee1233`. |
| REQ-REP-006 | Orch §13 | Python 3.10–3.13 CI matrix stays green | CI | verified | 4/4 jobs success on latest push. |

## C. Architecture (from consultation D-1…D-8, ADR-001)

| ID | Source | Requirement | Type | Status | Evidence / Remaining work |
|----|--------|-------------|------|--------|---------------------------|
| REQ-ARCH-001 | D-1 / ADR-001 | Library-first: in-process policy-aware Python client library, not a local proxy | Architecture | verified | `ADR-001-library-first.md`; package ships policy+capabilities+errors. |
| REQ-ARCH-002 | V1/V2 | Mode A (policy/capability layer over authorized connectivity); Mode B gateway deferred | Architecture | verified | Mode A implemented; Mode B deferred with rationale in ADR-001. |
| REQ-ARCH-003 | Orch §4 | Five states never collapsed: policy-allowed ≠ transport-available ≠ reachable ≠ verified ≠ completed | Architecture | in-progress | Policy and capability modules separate; unified `Session` API pending (EW-005). |
| REQ-ARCH-004 | Orch §7 | Responsibility boundaries (policy, normalization, evaluation, registry, errors, audit interfaces) | Architecture | in-progress | `policy.py`, `capabilities.py`, `errors.py` separated; session module pending. |
| REQ-ARCH-005 | Orch §7 | Stdlib-first; justify each new dependency | Architecture | verified | Zero runtime dependencies (`pyproject.toml`). |

## D. Policy engine (EW-002)

| ID | Source | Requirement | Type | Status | Evidence / Remaining work |
|----|--------|-------------|------|--------|---------------------------|
| REQ-POL-001 | V2 | Default-deny evaluation | Security | verified | `tests/test_policy.py` (32 items); `decide()` default-deny branch. |
| REQ-POL-002 | V2 | Deny-beats-allow precedence | Security | verified | Two-pass evaluation; deny checked first. Tests cover conflict. |
| REQ-POL-003 | V2 | Fail-closed parsing (`PolicyValidationError`, never permissive) | Security | verified | Strict `from_dict`; unknown keys rejected; version pinned. |
| REQ-POL-004 | V2 | `CONNECT` never authorizable | Security | verified | `_check_method` rejects; tested. |
| REQ-POL-005 | V2 | ASCII-only hostnames in v0.1; IDN via A-label only | Security | verified | `normalize_hostname`; dead IDNA branch removed; tested. |
| REQ-POL-006 | Orch §6.2 | Hostname/address validation incl. IP literals, userinfo, ports, trailing dots, case | Security | verified | Covered in `normalize_hostname` + tests. IPv6/SSRF transport review deferred to gateway phase. |
| REQ-POL-007 | Orch §6.1 | `decide()` never raises; malformed input → deny with `INVALID_REQUEST` | Security | verified | Try/except → deny; tested. |

## E. Capability registry (EW-003)

| ID | Source | Requirement | Type | Status | Evidence / Remaining work |
|----|--------|-------------|------|--------|---------------------------|
| REQ-CAP-001 | V2 | Statuses configured/verified/unavailable/unknown | Feature | verified | `CapabilityStatus`; `tests/test_capabilities.py` (14 items). |
| REQ-CAP-002 | V2 | VERIFIED requires evidence + timezone-aware timestamp | Security | verified | `__post_init__` enforcement; tested. |
| REQ-CAP-003 | V2 | Invalid states / incomplete evidence rejected; naive timestamps rejected | Security | verified | `_check_timestamp` requires tzinfo; tested. |
| REQ-CAP-004 | V2 | Strict serialization round-trip | Feature | verified | `to_dict`/`from_dict` with version check; tested. |
| REQ-CAP-005 | Orch §6.6 | Validation failures raise typed errors, never raw `AttributeError`/`TypeError` (fail-closed contract) | Security | verified | Fixed in EW-004 (`1a4d5a1`); 4 regression tests. |

## F. Authorization contract (EW-005, Phase E)
| ID | Source | Requirement | Type | Status | Evidence / Remaining work |
|----|--------|-------------|------|--------|---------------------------|
| REQ-AUTH-001 | Orch §4, §9-E | Transport-independent authorization combining policy + capability state, without collapsing the five states | Feature | verified | `src/egressweave/session.py` (EW-005, `1a4d5a1`); 15 tests. |
| REQ-AUTH-002 | Orch §6.7 | Structured errors: policy_denied vs route_unavailable vs unknown capability vs invalid_request | Feature | verified | Mapped in `Session._authorize` (EW-005); tested. |
| REQ-AUTH-003 | Orch §6.5 | No secrets in errors, logs, or audit output | Security | in-progress | `EgressError` secret-free by construction; audit logging not yet implemented (deferred). |

## F2. Destination validation (EW-006, Phase C)

| ID | Source | Requirement | Type | Status | Evidence / Remaining work |
|----|--------|-------------|------|--------|---------------------------|
| REQ-DEST-001 | User P2-2026-10-18 | Strict destination URL validation: contract, threat model, syntax-only (no DNS, no transport claims) | Security | verified | `src/egressweave/destination.py` (`1a4d5a1`+); 54 tests. |
| REQ-DEST-002 | User P2-2026-10-18 | ASCII-only hostname rule preserved, not implicitly changed | Security | verified | Reuses `normalize_hostname`; IDN-as-A-label tested. |
| REQ-DEST-003 | User P2-2026-10-18 | Ambiguous IP-like hostnames (`0x7f.0.0.1`, octal, integer forms) rejected, never treated as DNS | Security | verified | Gap found by adversarial tests, fixed (`_IP_LIKE` rule); tested. |
| REQ-DEST-004 | User P2-2026-10-18 | Special-use addresses classified (loopback/private/link-local/reserved), not rejected — policy decides | Security | verified | `is_loopback`/`is_private`/… properties; tested. |
| REQ-DEST-005 | User P2-2026-10-18 | No complete-SSRF-protection claim without transport + address validation | Security | verified | Documented in module + SECURITY_REVIEW.md; no such claim made. |
| REQ-DEST-006 | User P2-2026-10-18 | No connections to sensitive/external targets in validation tests | Security | verified | All tests pure parsing; none open sockets. |

## G. Research and differentiation

| ID | Source | Requirement | Type | Status | Evidence / Remaining work |
|----|--------|-------------|------|--------|---------------------------|
| REQ-RES-001 | V2 | Prior-art research on 6 leads with citations | Research | verified | `~/workspace/research_notes/egressweave-prior-art-20261018-1448/` (11 projects). |
| REQ-RES-002 | Orch §8 | Publish `docs/research/PRIOR_ART_AND_DIFFERENTIATION.md` in repo | Research | verified | Ported 2026-10-18 with provenance, dates, licenses; no unsupported novelty claims. |
| REQ-RES-003 | V2 | Do not claim novelty without evidence | Research | in-progress (standing) | README states independent implementation, no novelty claims. |

## H. Quality, docs, supply chain

| ID | Source | Requirement | Type | Status | Evidence / Remaining work |
|----|--------|-------------|------|--------|---------------------------|
| REQ-QA-001 | Orch §11 | Layered tests: unit, adversarial, integration | Testing | in-progress | Unit 121/121; adversarial strong (session + destination); integration via Session composition tested. |
| REQ-QA-002 | Orch §14 | Docs describe implemented behavior only; examples execute | Docs | in-progress | README/SECURITY/CONTRIBUTING current; `policy.example.json` exercised. |
| REQ-QA-003 | Orch §15 | Dependency & license audit | Security | verified | 2026-10-18: zero runtime deps; pip-audit clean after pip upgrade; wheel/sdist contents verified; build reproducible. |
| REQ-QA-004 | Orch §6.5 | Secret scan on every change; no committed secrets | Security | verified | Scans clean; `.gitignore` covers `.env`/keys. |

## Disposition summary

- Verified: 36 · In-progress (incl. standing invariants): 10 · Blocked: 0 ·
  Deferred with rationale: 2 (Mode B gateway; SSRF transport review) ·
  Not-applicable: 0.
- Blocked items: none currently — publication credential is the only
  external dependency (see BASELINE_AUDIT.md); all engineering work
  proceeds locally.
