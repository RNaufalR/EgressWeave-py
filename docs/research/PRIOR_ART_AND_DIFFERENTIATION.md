# Prior Art and Differentiation — EgressWeave-py

Research date: 2026-10-18. Method: official documentation and repository
READMEs (no live runs; internals beyond docs are marked as unverified).
Full per-project notes: `~/workspace/research_notes/egressweave-prior-art-20261018-1448/`
(kept outside the repo; this document is the repo's canonical summary).

Eleven projects assessed. Verdicts below are evidence-graded: a claim is
only made where the cited source was actually read.

## Candidate differentiators — honest verdicts

**(a) Capability registry with verification evidence and configured /
verified / unavailable / unknown statuses: NOT FOUND** in any assessed
project. Nearest mechanisms, all weaker:
- agentcage: workload-queryable `GET /v1/allowlist` (configured domains
  only; no statuses, no evidence).
- mattolson/agent-sandbox: read-only sanitized live allowlist file
  (configured policy only).
- strands-agents/box: startup grant report ("read that output — it is
  your blast radius"; configured only).
- Docker sandboxes: approval workflow records the actual destination the
  sandbox requested (real-request evidence, but an approval flow, not a
  registry).
- Agent-Reach: `doctor` verifies which content-channel backends work
  (verification evidence — but for web-reading channels, not network
  routes).

**(b) Portable, runtime-agnostic default-deny egress policy schema: NOT
FOUND.** Every policy format is platform-bound: agent-sandbox layered
YAML, agentcage `cage.yaml`, Box Dogwood `policy.dw`, Docker platform
rules, openshell OPA/Rego, E2B/Daytona/Modal API parameters.

**(c) Structured network-error taxonomy for agents (policy_denied,
route_unavailable, dns_error, …): NOT FOUND.** Partial pieces only:
openshell structured OCSF deny logs (operator-facing), agentcage JSON
502s, agent-sandbox proxy 403s, E2B's documented caveat that blocked TCP
can *appear* successful.

## Project summaries

| Project | URL | License | What it is | Overlap | Key limitation for our purposes |
|---------|-----|---------|------------|---------|---------------------------------|
| mattolson/agent-sandbox | github.com/mattolson/agent-sandbox | (see repo) | Local Docker sandbox for coding agents; mitmproxy egress enforcement, default-deny | Mode A policy + credential-safe proxy injection | Single-machine; project-specific YAML policy |
| E2B | docs.e2b.dev | proprietary | Hosted Firecracker microVMs; firewall allow/deny lists | Allow/deny primitives as API params | Hosted platform; ambiguous failure signals by design |
| agentgateway | github.com/agentgateway/agentgateway | Apache-2.0 | Rust gateway for agent protocols (MCP/A2A/LLM) | Mode B *shape* only (deployed gateway) | Not sandbox egress; no workload confinement |
| agentcage | github.com/agentcage/agentcage | MIT | Defense-in-depth proxy sandbox; default-deny, DNS sinkholing, audit logs | Strongest overall overlap (Modes A+B, diagnostics, redaction) | `cage.yaml` tied to the tool; no status taxonomy |
| strands-agents/box | github.com/strands-agents/box | Apache-2.0 | macOS sandbox engine; Dogwood semantic policies, egress gateway | Default-deny egress, decision records | macOS-only preview; Dogwood is general policy language |
| Agent-Reach | github.com/Panniantong/Agent-Reach | MIT | Ingress toolkit: routes agents to public web data sources | Concept of "capability layer" + `doctor` health checks only | Inverse direction (adds routes, no egress control) |
| Docker sandboxes | docs.docker.com | proprietary | Sandbox governance: network allowlists, approvals | Allowlist policy model, deny-precedence | Platform-bound; proprietary |
| Modal | modal.com/docs | proprietary | Sandbox network params (block-all, CIDR/domain allowlists) | Policy primitives | Platform-bound |
| Daytona | daytona.io/docs | proprietary | Sandbox network limits + BYO outbound proxy | Mode B analog (operator proxy) | Platform-bound |
| NVIDIA openshell | docs.nvidia.com | proprietary | Sandbox product; default-deny, OPA at egress proxy | Default-deny, structured deny logs | OPA/Rego is general policy language |
| Strands Shell | strandsagents.com | (docs only) | In-process agent shell; SSRF guard, credential binding | Library-layer mediation, SSRF-safe defaults | Default-open for public egress; in-process only |

**Category corrections** (from research): agentgateway is an
agent-protocol gateway, not sandbox egress. Agent-Reach is an
ingress/content tool with no egress control.

## What EgressWeave-py claims — and does not claim

Supported by the evidence above, EgressWeave-py differentiates on:

1. A portable, versioned, default-deny egress policy schema
   (`EgressPolicy`, schema v0.1) decoupled from any runtime.
2. A capability registry with verification evidence and explicit
   configured/verified/unavailable/unknown statuses.
3. A structured, agent-facing network-error taxonomy (`ErrorCode`).
4. An explicit honesty contract: policy approval ≠ connectivity, and the
   library never claims a blocked request is reachable.

Not claimed: that no one has built egress filtering (many have, mostly
better-funded and platform-bound); that the schema is complete (v0.1 is
exact-match only); SSRF protection (no transport exists yet — see
`SECURITY_REVIEW.md`).

## Unresolved research questions

- Exact maintenance state/dates for agent-sandbox, agentcage, Agent-Reach
  (observed active Oct 2026; commit dates not verified).
- agentcage inspector-chain internals and 502 body schemas (README-level only).
- Daytona Secrets-API placeholder swapping (third-party source only).
- Whether any project has since added a formal error taxonomy (recheck
  before any novelty claim in release notes).
