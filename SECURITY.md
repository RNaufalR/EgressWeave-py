# Security Policy

## Supported versions

Only the latest released minor version receives security fixes. Pre-release
(`0.x`) versions are supported on a best-effort basis.

## Reporting a vulnerability

**Do not open a public issue for a suspected vulnerability.** Use GitHub's
private vulnerability reporting ("Report a vulnerability" on the Security tab),
or open a draft security advisory. Include:

- What you did, step by step, to trigger the issue.
- What you expected vs. what happened.
- The smallest policy document / code snippet that reproduces it.

We aim to acknowledge within 7 days. Please do not disclose the issue publicly
until a fix is released and we have agreed on a disclosure timeline.

## Scope

In scope: bypasses of the default-deny policy evaluation, fail-open parsing
bugs, hostname-validation bypasses (SSRF-relevant), credential leakage through
error messages or logs, dependency supply-chain issues in this repository's
declared dependencies.

Out of scope: the absence of features (e.g. "no gateway yet" is the roadmap,
not a vulnerability), social engineering, and vulnerabilities in third-party
services the policy merely references.

## Guarantees

We do not claim this software is bug-free or that any audit found "no issues".
Security properties are stated per-module in docstrings and ADRs, with their
limitations. Audit findings are recorded in `docs/engineering/TASKS.md`.
