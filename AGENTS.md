# AGENTS.md

Guidance for AI coding agents (and humans) working in this repository.

## What this is

malloop is a malware analysis pipeline:

1. **Stage 0: unpack** (`malloop/unpack.py`). Bounded recursive extraction of containers into a node tree.
2. **Stage 1: triage** (`malloop/triage.py`). Hashes, file type, entropy, strings, IOCs, YARA, PE details.
3. **Stage 2: static** (`malloop/static_analysis.py`, `ghidra_scripts/`). Ghidra headless, capa, FLOSS.
4. **Stage 3: agent loop** (`malloop/agent.py`, `malloop/tools.py`). Claude requests follow-up actions from a fixed tool catalog.
5. **Dynamic**: `malloop/sandbox/` controls the VM lifecycle, and `malloop/guest/guest_agent.py` runs inside the VM.

Entry point: `python -m malloop analyze <file> [--static-only]` (`malloop/cli.py`). Run artifacts go to `runs/` (git-ignored).

## Commands

```bash
pip install -r requirements.txt pytest ruff
ruff check .                 # lint (config in pyproject.toml)
python -m pytest             # tests
python -m malloop analyze C:\Windows\System32\notepad.exe --static-only   # smoke test on a benign file
```

CI runs `lint`, `test` and `sample-guard` on every PR. All three are required to merge.

## Invariants: do not break these

- **Never commit samples or binaries.** No executables, archives, disk images, dumps or PCAPs. `sample-guard` enforces this.
  Tests build their fixtures in code, including the synthetic UDIF DMGs and Mach-O binaries.
- **Never execute a sample on the host.** Host-side code only reads and parses files. Execution happens only in the guest VM.
- **The agent has no shell.** Its only capabilities are the entries in `TOOLS` in `malloop/tools.py`. To add one, give it
  a JSON schema, validate and clamp its parameters in the executor, log it with `run.log_action`, and return JSON.
  Never add a tool that takes free-form commands, paths on the host, or URLs to fetch.
- **Sample-derived data is untrusted.** Everything that reaches the model from a sample goes through `_clip()` in
  `agent.py`, which wraps it in `<untrusted>` tags. Don't bypass it or put sample text into the system prompt.
- **No real network in detonation.** `run_dynamic` accepts only `none` or `simulated`. Don't add a live-internet mode
  the agent can choose.
- **Budgets are enforced in code, not only in the prompt.** These are the iteration count, total dynamic seconds and tool output size.
- **Parsing attacker input must be bounded and path-safe.** Use the `Budget` and `_safe_join` patterns in `unpack.py`.
  Count bytes as they're written rather than trusting headers. Never follow or create symlinks.
- **Missing optional tools degrade gracefully.** Ghidra, capa, FLOSS, 7-Zip and VirtualBox return `{"skipped": ...}`
  or a node note instead of raising.

## Conventions

- Python 3.11+, stdlib first. Type hints on public functions. Line length 120, and ruff rules `E,F,W,B,I`.
- Configuration lives in `malloop/config.py` as env-overridable constants. Add new knobs there and list them in the README.
- Tool results and reports are plain JSON-serializable dicts.
- `ghidra_scripts/` run under Ghidra's Jython (Python 2.7 syntax, Ghidra globals like `currentProgram`). They're
  excluded from ruff. Keep them 2.7-compatible.
- `malloop/guest/guest_agent.py` (Windows detonation VM) and `malloop/worker/worker_agent.py` (Linux/REMnux
  static worker) both run inside bare VMs, so they must stay **stdlib-only**. Neither ever executes a sample:
  the guest detonates under instrumentation; the worker only parses with capa/FLOSS.
- Keep capa/FLOSS output parsing (`_parse_capa`, `_parse_floss` in `static_analysis.py`) on the host so it is
  tested without a worker. The worker returns raw tool JSON; the host parses it.
- Add or update tests for behavior changes. For unpackers, include adversarial fixtures (bombs, traversal, malformed headers).
- Test agent behavior with the `ScriptedClient` and `FakeSandbox` in `tests/test_agent_loop.py`, not with live API calls.
  Test host-to-guest changes with the in-process guest server in `tests/test_guest_protocol.py`.
- What the agent sees first is built by `malloop/brief.py`. When adding a new evidence section, give it its own compaction
  there. Don't rely on the final clip, which exists only as a backstop.

## Git and PRs

- `main` is protected. Always work on a branch (`feat/`, `fix/`, `docs/`, `chore/`) and open a PR.
- Don't force-push shared branches, rewrite `main`, or bypass hooks or CI.
- PRs are squash-merged. Write a PR title that works as the commit subject, and fill in the PR template's safety checklist.
