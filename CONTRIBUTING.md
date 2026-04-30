# Contributing to mcp-gate

🇺🇸 English · [🇰🇷 한국어](./CONTRIBUTING.ko.md)

Thank you for considering a contribution. mcp-gate handles credentials, so changes should preserve the security boundary described in [ARCHITECTURE.md](./ARCHITECTURE.md) and should be easy to review.

## Before Opening a PR

Please open an issue first for non-trivial changes, including new features, security model changes, storage format changes, and new dependencies. Small fixes such as typos, documentation improvements, focused tests, and clear bug fixes can be sent directly as pull requests.

## Development Setup

Requirements:

- Go 1.23+
- macOS or Linux
- Node.js 18+ for npm packaging and Node compatibility smoke tests

```bash
git clone https://github.com/seoo2001/mcp-gate
cd mcp-gate
make build
make test
make cover
make e2e
```

CI runs `go vet`, `go test -race`, and a build on macOS and Linux for every push and pull request.

## Useful Commands

```bash
make build   # build ./bin/mcp-gate
make test    # run go test -race -count=1 ./...
make vet     # run go vet ./...
make fmt     # run go fmt ./...
make e2e     # run subprocess E2E tests for credential isolation
```

Node proxy compatibility can be checked with:

```bash
./scripts/smoke-node.sh
```

## Contributions We Welcome

- Bug fixes with regression tests.
- Documentation improvements, including translations.
- Compatibility improvements for MCP server runtimes.
- New built-in service mappings in `internal/services/services.go`, with tests where practical.
- Audit log or approval-flow improvements that do not weaken credential isolation.

## Changes That Need Design Discussion

- Vault format, encryption, signing, or key-derivation changes.
- Trust-store or local CA behavior.
- Proxy token format or validation semantics.
- New dependencies in credential-handling paths.
- Multi-user, team, or remote-vault behavior.
- Changes that affect the threat-model boundary.

## Code Guidelines

- Run `go fmt ./...` and `go vet ./...` before sending a PR.
- Add tests for behavior changes.
- Keep PRs focused on one logical change.
- Prefer the Go standard library unless a dependency has a clear benefit and a bounded security impact.
- Wrap errors with `%w` and include useful context.
- Do not log plaintext credentials, proxy tokens, personal data, or full authorization header values.
- Comments should explain non-obvious reasoning or security-sensitive decisions.

## Commit and PR Style

Conventional Commit-style prefixes are preferred but not required:

- `feat(scope): ...`
- `fix(scope): ...`
- `docs(scope): ...`
- `test(scope): ...`
- `chore: ...`

In the PR body, include a short motivation, the user-visible behavior change, and the tests you ran.

## Security Disclosures

Please do not report vulnerabilities through public issues. Contact the maintainer through the email listed on the GitHub profile and include reproduction steps, impact, affected versions or commits, and a suggested fix if available.

## Code of Conduct

Please be respectful, specific, and focused on the technical merits of the discussion.
