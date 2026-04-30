# mcp-gate

[![CI](https://github.com/seoo2001/mcp-gate/actions/workflows/ci.yml/badge.svg)](https://github.com/seoo2001/mcp-gate/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)

🇺🇸 English · [🇰🇷 한국어](./README.ko.md)

mcp-gate is a local credential vault and HTTPS proxy for MCP servers. It keeps long-lived API credentials out of MCP server processes: wrapped servers receive short-lived proxy tokens, and mcp-gate swaps those tokens for real credentials only when forwarding upstream API requests.

> **Status:** Alpha. mcp-gate is ready for evaluation and local development workflows, but CLI details and storage formats may still change.

## Threat model

mcp-gate is built for the case where an MCP server, dependency, or tool runtime is compromised. April 2026 MCP security reports described STDIO/config paths that can lead to remote code execution, while ecosystem audits show that many public MCP servers are lightly maintained or abandoned. In that environment, plaintext tokens in `mcp.json` and `.env` files are a high-value target.

For context, see reporting from [The Register](https://www.theregister.com/2026/04/16/anthropic_mcp_design_flaw/), [The Hacker News](https://thehackernews.com/2026/04/anthropic-mcp-design-vulnerability.html), and the [Rapid Claw MCP reliability report](https://rapidclaw.dev/blog/mcp-servers-dead-what-it-means-2026).

mcp-gate reduces credential exposure by:

- storing real credentials in an encrypted local vault;
- giving child MCP servers only HMAC-signed proxy tokens with a default 5-minute TTL;
- enforcing token expiry at the proxy before upstream requests are forwarded;
- recording intercepted calls in a local JSONL audit log.

mcp-gate does not protect against compromise of the local OS account, debugger access to the mcp-gate process, or a malicious upstream API provider.

## How it works

```text
[MCP server] -- proxy token --> mcp-gate proxy -- real credential --> api.github.com
                                         |
                                         v
                              encrypted local vault
```

The MCP server never receives the real credential. mcp-gate starts the server as a child process, injects a service-specific proxy token into the environment, routes the child process through a local HTTPS proxy, validates each proxy token, and swaps it for the real credential only for matching upstream API hosts.

## Install

```bash
# npm package (scoped to avoid a name collision with an unrelated `mcpgate` package)
npm install -g @seoo2001/mcp-gate

# or run on demand without installing globally
npx -y @seoo2001/mcp-gate --help

# from source
git clone https://github.com/seoo2001/mcp-gate
cd mcp-gate
make build
```

The npm package requires Node.js 18+ and ships prebuilt binaries for macOS (arm64/x64) and Linux (x64/arm64). Native Windows binaries are not published yet; Windows users should run mcp-gate through WSL2 for now.

## Quick start

Store a real credential in the vault:

```bash
mcp-gate add github --stdin
# paste the GitHub token, then press Enter
```

Wrap an MCP server:

```bash
mcp-gate wrap --service=github --node-shim npx -y @modelcontextprotocol/server-github
```

`--node-shim` is recommended for Node.js MCP servers because many Node HTTP clients do not honor `HTTPS_PROXY` by default. Omit it for non-Node servers when the runtime already respects proxy environment variables.

For `mcp.json`, either use the globally installed `mcp-gate` binary:

```json
{
  "mcpServers": {
    "github": {
      "command": "mcp-gate",
      "args": [
        "wrap",
        "--service=github",
        "--node-shim",
        "npx",
        "-y",
        "@modelcontextprotocol/server-github"
      ]
    }
  }
}
```

Or run mcp-gate itself through `npx`:

```json
{
  "mcpServers": {
    "github": {
      "command": "npx",
      "args": [
        "-y",
        "@seoo2001/mcp-gate",
        "wrap",
        "--service=github",
        "--node-shim",
        "npx",
        "-y",
        "@modelcontextprotocol/server-github"
      ]
    }
  }
}
```

## Common commands

| Command | Purpose |
|---|---|
| `mcp-gate add <service> --stdin` | Store a credential without putting it in shell history. |
| `mcp-gate import --dry-run` | Scan known MCP config and `.env` locations without changing the vault. |
| `mcp-gate services` | List built-in service mappings and upstream host patterns. |
| `mcp-gate logs --since=24h` | Show intercepted calls from the last 24 hours. |
| `mcp-gate info` | Print state paths for the vault, audit log, CA certificate, and service overrides. |

Built-in service mappings cover common developer, productivity, infrastructure, observability, and AI APIs. Add or override mappings with `$MCP_GATE_HOME/services.json` and run `mcp-gate services` to verify the active registry.

## Project status

Current scope is single-user local development on macOS and Linux. The core credential-isolation claim is covered by end-to-end tests:

> The real credential does not appear in the wrapped child process environment, audit log, vault file, or other on-disk state. It is only materialized inside mcp-gate when forwarding a matching upstream request.

| Area | Status |
|---|---|
| Encrypted local vault | Implemented |
| Process wrapper and proxy token format | Implemented |
| HTTPS proxy with Authorization header swap | Implemented |
| Token TTL enforcement and audit log | Implemented |
| Node.js proxy compatibility shim | Implemented |
| Slack approval webhook for sensitive paths | Implemented |
| Native Windows release | Planned |

## Build and test

```bash
make build   # ./bin/mcp-gate
make test    # go test -race -count=1 ./...
make cover   # coverage report
make e2e     # subprocess E2E for credential isolation
```

CI runs `go vet`, `go test -race`, and a build on macOS and Linux for every push and pull request.

## Documentation

| File | Contents |
|---|---|
| [ARCHITECTURE.md](./ARCHITECTURE.md) | Token flow, proxy behavior, and security boundaries. |
| [docs/NODE_COMPAT.md](./docs/NODE_COMPAT.md) | Node.js MCP server proxy compatibility and `--node-shim`. |
| [CONTRIBUTING.md](./CONTRIBUTING.md) | Development setup, contribution guidelines, and PR conventions. |

## Contributing

Issues and pull requests are welcome. Please open an issue before starting non-trivial feature work, security model changes, or dependency additions so the design can be discussed first. Small fixes such as typos, documentation improvements, and focused tests can be sent directly as PRs.

## Security disclosures

Please do not open a public issue for vulnerabilities. Contact the maintainer through the email listed on the GitHub profile and include reproduction details, impact, and a suggested fix if you have one.

## License

mcp-gate is released under the [MIT License](./LICENSE).
