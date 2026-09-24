# Security policy

## Reporting a vulnerability

Please report vulnerabilities **privately** via
[GitHub security advisories](https://github.com/dhruvancvt/malloop/security/advisories/new).
Don't open a public issue.

In scope, for example:

- Anything that lets a sample, or a guest VM, affect the host (sandbox escape paths in our code or setup guidance)
- Ways for sample content to make the agent act outside its tool catalog or budgets (prompt injection that works)
- Unpacker/parser bugs: path traversal, symlink writes, unbounded resource use, crashes on crafted input
- Guest agent authentication or request-handling flaws

## Handling samples

- Never attach live malware, or links to it, to issues, PRs or discussions. Refer to samples by SHA256.
- The repository rejects executables, archives and disk images in CI (`sample-guard`).
- Run dynamic analysis only in an isolated VM on a host-only network, as described in the README.
