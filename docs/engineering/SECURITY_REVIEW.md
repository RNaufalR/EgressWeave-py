# Security Review — EgressWeave-py

Date: 2026-10-18. Scope: v0.1 library (policy schema, capability registry,
error taxonomy). No transport code exists; network-facing reviews are
scheduled, not skipped.

## Invariants (from orchestrator §6, encoded as requirements)

### §6.1 Default-deny and fail-closed evaluation — ENFORCED
- `decide()` denies unless an allow rule matches; deny rules evaluated
  first. Tested: `test_policy.py` (conflict, default-deny, malformed).
- `from_dict`/`from_json` raise `PolicyValidationError` on any malformed
  input, including unknown keys and version mismatch. No permissive
  fallback exists in the code path.

### §6.2 Hostname and address validation — ENFORCED (v0.1 scope)
- `normalize_hostname` rejects: non-strings, empty, non-ASCII, IP
  literals, wildcards, userinfo, ports, paths, backslashes, >253 chars;
  lowercases and strips one trailing dot.
- IDN must be supplied as A-label (punycode); no implicit IDNA mapping.
- **Limitation:** no transport exists, so DNS-rebinding/SSRF controls are
  not yet applicable. Any future transport requires the dedicated review
  in §6.3 before implementation. This is a scheduled gate, not a waiver.

### §6.3 SSRF, DNS rebinding, redirects — SCHEDULED
No URL fetching, redirect following, or DNS resolution code exists in
v0.1. When a transport or destination resolver is introduced, the review
checklist (§6.3: SSRF, metadata services, rebinding, redirect chains,
scheme/port changes, credential propagation, validate-every-destination)
is mandatory before merge.

### §6.4 Protocol, method, port controls — ENFORCED
- `CONNECT` can never appear in a method allowlist (`_check_method`
  rejects; tested).
- Ports must be ints in 1–65535; bools rejected explicitly.
- No tunneling, proxying, or socket access exists in v0.1.

### §6.5 Credentials and request metadata — ENFORCED
- `EgressError` messages must be secret-free by construction; no header,
  cookie, userinfo, or token values are accepted into error paths.
- Repo secret scans clean. `.gitignore` covers `.env`, keys, tokens.
- Operational: never request secrets in chat; the one chat-exposed PAT
  is treated as compromised and never reused.

### §6.6 Capability evidence — ENFORCED, one defect found
- VERIFIED requires non-empty evidence **and** a timezone-aware
  `verified_at`; naive timestamps rejected; `verified_at` on non-VERIFIED
  statuses rejected; duplicate registration raises.
- **Defect (P2, EW-004):** non-string `evidence`/`scope` raise raw
  `AttributeError` instead of `CapabilityValidationError`, breaking the
  fail-closed typed-validation contract. Fix in progress.

### §6.7 Error handling and observability — ENFORCED (v0.1 scope)
- Distinct codes: `policy_denied`, `invalid_request`, `route_unavailable`,
  `unknown`, plus transport codes reserved for future use.
- Errors never become allow decisions: every failure path returns a
  deny/failure value or raises a typed validation error.
- Audit logging not yet implemented; when added, log policy decisions and
  capability transitions without secrets (deferred, tracked).

## Threat model (v0.1)

- **Adversary:** a caller (possibly compromised agent code) attempting to
  widen its own egress by supplying crafted policies, hostnames, methods,
  or capability records.
- **Trust boundary:** the validated `EgressPolicy`/`CapabilityRegistry`
  objects. Everything crossing it (dicts, JSON, host strings) is
  validated fail-closed.
- **Out of scope (explicit):** actual network enforcement (no transport),
  OS/sandbox bypass resistance, supply-chain attacks on dev tooling
  (audit pending per REQ-QA-003).

## Findings

| Severity | Finding | Status |
|----------|---------|--------|
| P2 | `Capability` non-string `evidence`/`scope` → raw `AttributeError` | Fixed (EW-004), verified |
| P3 | `scope` field had no validation at all | Fixed (EW-004), verified |
| P2 | Ambiguous IP-like hostnames accepted as DNS names (validator/transport parser differential) | Found by adversarial tests, fixed (EW-006 `_IP_LIKE` rule), verified |
| — | No P0/P1 findings in v0.1 scope | — |

## Destination validation (EW-006, 2026-10-18)

`parse_destination` implements syntax-only validation with a documented
threat model. Userinfo rejected outright; IP literals strictly parsed
and canonicalized; ambiguous forms rejected; special-use addresses
classified (not rejected — policy decides). No DNS resolution, no
transport, no SSRF-protection claim. 54 adversarial tests, all pure
parsing.
| — | No P0/P1 findings in v0.1 scope | — |

No change will be published with an unresolved P0/P1.
