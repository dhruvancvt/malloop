@AGENTS.md

## Claude Code notes

- The primary dev machine is Windows 10 Home (no Hyper-V; VirtualBox is the sandbox backend). Use the project venv:
  `.venv/Scripts/python -m pytest`, `.venv/Scripts/ruff check .`
- `gh` may not be on PATH in agent shells. If so, use `"C:\Program Files\GitHub CLI\gh.exe"`.
- Never create, download or unzip real malware while working in this repo, even to test something. Use the
  fixture builders in `tests/test_unpack.py` or benign system binaries such as `notepad.exe`.
- When adding an agent tool, update `TOOLS` and the `ToolExecutor` method in `malloop/tools.py`, update the system
  prompt in `malloop/agent.py` if the method guidance changes, and add a test.
