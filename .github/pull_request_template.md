## What and why

<!-- What does this change, and what problem does it solve? Link issues with "Closes #123". -->

## How it was tested

<!-- Commands run, new tests, and any manual checks (e.g. a --static-only run on a benign file). -->

## Safety checklist

- [ ] No samples, binaries, archives, dumps or PCAPs are committed (fixtures are generated in code)
- [ ] The agent still can't run arbitrary commands: any new capability is a typed tool in `malloop/tools.py` with validated parameters
- [ ] Sample-derived text reaching the model stays inside `<untrusted>` wrapping
- [ ] Nothing gives the sandbox guest real network access or a writable channel back to the host
- [ ] New extraction/parsing code is bounded (size, count, depth, time) and path-safe
- [ ] Docs updated (`README.md` / `AGENTS.md`) if behavior or setup changed
