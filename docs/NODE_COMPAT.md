# Node.js MCP Server Compatibility

🇺🇸 English · [🇰🇷 한국어](./NODE_COMPAT.ko.md)

## Summary

Many Node.js HTTP clients do not use `HTTPS_PROXY` automatically. That matters for mcp-gate because wrapped MCP servers must send upstream API calls through the local mcp-gate proxy for credential swapping to happen.

For Node-based MCP servers, use:

```bash
mcp-gate wrap --service=github --node-shim npx -y @modelcontextprotocol/server-github
```

`--node-shim` loads a small dependency-free CommonJS shim into the child process so common Node HTTP paths use the proxy configured by mcp-gate.

## Compatibility Matrix

The smoke test in `./scripts/smoke-node.sh` exercises the following paths:

| HTTP stack | Without `--node-shim` | With `--node-shim` |
|---|---|---|
| `node:https.request` | Connects directly and ignores `HTTPS_PROXY` | Uses the mcp-gate proxy |
| `globalThis.fetch` / undici | Connects directly unless a dispatcher is configured | Uses the mcp-gate proxy through the shimmed fetch wrapper |
| `undici.fetch({ dispatcher })` | Works only when the application provides its own proxy dispatcher | Still works when routed through the shimmed path tested by mcp-gate |

This is why `--node-shim` is recommended for Node MCP servers.

## What the Shim Does

When `--node-shim` is set, the wrapper writes a temporary CommonJS file and starts the child with:

```text
NODE_OPTIONS=--require=<shim>
```

The shim:

1. Replaces `https.globalAgent` with a custom agent that tunnels requests through `HTTPS_PROXY` using HTTP `CONNECT`.
2. Replaces `http.globalAgent` for non-TLS HTTP targets.
3. Wraps `globalThis.fetch` so native fetch uses the same proxy path.

The shim uses only Node built-ins such as `tls`, `net`, `http`, and `https`. It does not require an npm dependency.

## Covered Paths

`--node-shim` is intended to cover:

- raw `node:https` and `node:http`;
- `globalThis.fetch`;
- libraries that use Node's global HTTP(S) agents, such as many `axios`, `node-fetch`, and Octokit call paths;
- common `@modelcontextprotocol/server-*` packages that use those HTTP paths internally.

It does not cover every possible Node network path. In particular:

- code that creates and uses its own `undici.Dispatcher` can bypass `globalThis.fetch`;
- HTTP/2-specific clients can bypass `https.Agent`;
- WebSocket and EventSource streams are outside the current credential-swap model.

If a server uses one of those paths, it may need explicit proxy integration in that server.

## Verifying Locally

Run:

```bash
./scripts/smoke-node.sh
```

The script builds mcp-gate, creates a temporary vault, wraps the Node smoke helper with and without `--node-shim`, and reports which HTTP paths used the proxy.

With Node.js 18 or later and `--node-shim` enabled, the expected successful indicators include:

- `fetch_default_used_proxy`
- `raw_https_used_proxy`

## Why mcp-gate Ships Its Own Shim

`https-proxy-agent` is a common npm solution, but mcp-gate does not require users to install it globally or make it available inside an `npx` package's isolated dependency tree. Shipping the shim inside the mcp-gate binary also avoids adding another runtime dependency to the credential-handling path.

The shim is written to a temporary file for the wrap session and removed when the wrapper exits.

## Keep-Alive Behavior

The shim uses one connection per request. Earlier keep-alive behavior caused some CONNECT-tunneled responses to remain open after the response body ended, which could leave awaiting user code unresolved.

The local proxy is in-process and loopback-only, so the extra local handshake is small. The mcp-gate proxy can still use normal upstream connection reuse separately.

## When to Skip `--node-shim`

Do not set `--node-shim` when:

- the wrapped child is not a Node.js process;
- the server already configures its own proxy-aware undici dispatcher or HTTP agent;
- you are intentionally testing direct-network behavior.

For typical Node MCP servers, `--node-shim` is the recommended default.
