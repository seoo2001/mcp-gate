# mcp-gate

mcp-gate is a local credential vault and HTTPS proxy for MCP servers. It keeps long-lived API credentials out of MCP server processes by giving wrapped servers short-lived proxy tokens and swapping them for real credentials only at the local proxy.

## Install

```bash
npm install -g mcp-gate

# or run on demand without installing globally
npx -y mcp-gate --help
```

This package ships a small JavaScript shim that loads the prebuilt binary for your platform from one of:

- `mcp-gate-darwin-arm64`
- `mcp-gate-darwin-x64`
- `mcp-gate-linux-arm64`
- `mcp-gate-linux-x64`

Node.js 18+ is required for the npm shim. Native Windows binaries are not published yet; use WSL2 on Windows for now.

## Usage

Store a credential:

```bash
mcp-gate add github --stdin
```

Wrap a Node.js MCP server:

```bash
mcp-gate wrap --service=github --node-shim npx -y @modelcontextprotocol/server-github
```

Use the same shape in `mcp.json`:

```json
{
  "mcpServers": {
    "github": {
      "command": "npx",
      "args": [
        "-y",
        "mcp-gate",
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

See the [project README](https://github.com/seoo2001/mcp-gate#readme) for the threat model, architecture, supported commands, and contribution guidelines.

## License

MIT
