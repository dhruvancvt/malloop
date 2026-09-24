# Contributing

Thanks for helping. A few rules keep this project safe to work on in public.

## Workflow

1. Fork the repo (or create a branch if you have write access). Nobody pushes to `main` directly.
2. Branch names: `feat/...`, `fix/...`, `docs/...`, `chore/...`.
3. Open a pull request against `main` and fill in the template, including the safety checklist.
4. CI must pass: `lint` (ruff), `test` (pytest) and `sample-guard` (no binaries or archives).
5. A code owner reviews and approves. All review threads must be resolved.
6. PRs are squash-merged, so keep the PR title meaningful: it becomes the commit message.

## Local setup

```bash
python -m venv .venv
.venv/Scripts/activate          # Windows; use .venv/bin/activate elsewhere
pip install -r requirements.txt pytest ruff
ruff check .
python -m pytest
```

## Ground rules

- **No samples in the repo, ever.** Generate test fixtures in code (see `tests/test_unpack.py`).
- **The agent gets no shell.** New capabilities are new typed tools in `malloop/tools.py`, executed deterministically.
- **Sample-derived data is untrusted.** Keep it inside the `<untrusted>` wrapping when it reaches the model.
- **Bound everything** that parses or extracts attacker-controlled input: size, count, depth and time.

See [AGENTS.md](AGENTS.md) for architecture invariants and conventions.
