# Contributing

## Workflow

1. Pick up or file a task in `docs/engineering/TASKS.md` (`EW-###`).
2. Work on a branch named `ew-###-short-description`, never directly on `main`.
3. Keep changes small and focused; one task, one branch.
4. Before pushing, run the full local gate:
   ```bash
   PYTHONPATH=src python -m pytest tests/ -q
   ruff check src tests
   ruff format --check src tests
   mypy src
   ```
   (With the dev extras installed: `pip install -e ".[dev]"`, drop `PYTHONPATH`.)
5. Audit your own diff: re-read every changed file, check for accidental
   changes, secrets, debug leftovers, and scope creep.
6. Open a pull request. Merge only when CI is green on the PR.

## Code standards

- Python 3.10+ compatible; stdlib preferred, new dependencies justified in the PR.
- `ruff` (lint + format) and `mypy --strict` must pass.
- Every behavior change needs a test that checks behavior, not file existence.
- Docstrings state security properties *and* limitations. Never claim a module
  does something it does not.
- Error messages must never contain secrets (proxy credentials, auth headers,
  cookies, secret-bearing URLs).

## What not to do

- Do not weaken a check to make a test pass.
- Do not delete or narrow a test because the implementation is inconvenient.
- Do not claim "no bugs", "fully secure", or "complete" in code, docs, or PRs.
  Report what was checked and what was not.
