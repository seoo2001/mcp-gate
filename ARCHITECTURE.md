# Architecture

🇺🇸 English · [🇰🇷 한국어](./ARCHITECTURE.ko.md)

## Overview

mcp-gate is a local credential vault and HTTPS proxy for MCP servers. Its current architecture focuses on single-user local development on macOS and Linux:

1. Store real credentials in an encrypted local vault.
2. Start an MCP server as a child process.
3. Give the child process only a short-lived proxy token.
4. Route the child process through a local proxy.
5. Swap the proxy token for the real credential only when forwarding matching upstream API requests.

The design assumes that an MCP server or one of its dependencies may be compromised. It does not assume that the local OS account or the mcp-gate process itself is compromised.

## Request Flow

```text
MCP client
   |
   | stdio
   v
wrapped MCP server
   env: GITHUB_TOKEN=mcpgate_github.<random>.<exp>.<sig>
   env: HTTPS_PROXY=http://127.0.0.1:<port>
   env: SSL_CERT_FILE=$MCP_GATE_HOME/ca.pem
   |
   | HTTPS through local proxy
   v
mcp-gate proxy
   validate proxy token
   load real credential from vault
   swap matching header value
   write audit event
   |
   | HTTPS with real credential
   v
upstream API
```

The wrapped MCP server receives a service-specific proxy token in the environment variable expected by that service, for example `GITHUB_TOKEN`. The real credential remains in the vault until the proxy handles a matching upstream request.

## Components

| Component | Responsibility |
|---|---|
| CLI | Dispatches commands such as `add`, `wrap`, `import`, `setup`, `logs`, and `services`. |
| Wrapper | Starts the MCP server as a child process and injects proxy, trust-store, and service-token environment variables. |
| Proxy | Handles HTTP proxy traffic, performs local TLS interception for CONNECT requests, validates proxy tokens, swaps credentials, and forwards requests upstream. |
| Vault | Stores service credentials in `$MCP_GATE_HOME/vault.json` using envelope encryption. |
| Keystore | Stores or loads the vault master key from macOS Keychain or the file fallback. |
| Service registry | Maps service names to environment variables, token prefixes, and upstream host patterns. |
| Audit log | Writes one JSONL event per proxied request to `$MCP_GATE_HOME/audit.jsonl`. |
| Approval gate | Optionally blocks matching sensitive requests until a Slack approval callback allows them. |

## Wrapper Environment

For each wrapped process, mcp-gate sets:

- `HTTP_PROXY`, `HTTPS_PROXY`, `http_proxy`, and `https_proxy` to the local proxy URL.
- `NO_PROXY` and `no_proxy` for loopback hosts.
- `SSL_CERT_FILE`, `NODE_EXTRA_CA_CERTS`, `REQUESTS_CA_BUNDLE`, and `GIT_SSL_CAINFO` to the generated local CA certificate.
- The service credential environment variable, such as `GITHUB_TOKEN`, to the short-lived proxy token.
- `NODE_OPTIONS=--require=<shim>` when `--node-shim` is enabled.

mcp-gate does not install a CA into the system trust store. Trust is scoped to the wrapped child process through environment variables.

## Proxy Behavior

The proxy listens on `127.0.0.1` and usually binds an OS-assigned port. For HTTPS requests, it accepts `CONNECT`, issues a per-host leaf certificate signed by the local mcp-gate CA, reads the inner HTTP request, and scans all request headers for `mcpgate_` proxy tokens.

Credential swap rules:

- If no proxy token is present, the request is forwarded as passthrough traffic and still audited.
- If a proxy token is present for an unknown upstream host, the request is rejected.
- If a token is invalid, expired, signed by another wrap session, or for a different service, the request is rejected.
- If multiple proxy tokens are present in one request, they must be identical.
- If validation succeeds, every occurrence of that proxy token in request headers is replaced with the real credential from the vault.

The proxy implementation uses Go standard-library networking and TLS primitives. It is intentionally small so the credential-handling path is easy to audit.

## Vault Format

The vault is a line-stable JSON file at `$MCP_GATE_HOME/vault.json`. Each record uses envelope encryption:

```text
real credential
   |
   v
AES-256-GCM with random per-record DEK
   |
   v
encrypted value

DEK
   |
   v
AES-256-GCM with master key
   |
   v
encrypted DEK
```

The service name is used as additional authenticated data, so changing the service key in the JSON file causes authentication to fail when the record is opened.

Persistent state is written with restrictive permissions:

- `$MCP_GATE_HOME` is created with mode `0700`.
- `vault.json`, `audit.jsonl`, `ca.key`, and the file-keystore fallback are written with mode `0600`.

## Keystore Backends

| Backend | When used | Notes |
|---|---|---|
| macOS Keychain | Default on macOS when available | Stores the vault master key through the `security` CLI. |
| File keystore | Default on non-macOS and fallback on macOS | Stores the master key in `$MCP_GATE_HOME/master.key` with mode `0600`. |

The backend can be forced with `MCP_GATE_KEYSTORE=file` or `MCP_GATE_KEYSTORE=keychain`.

## Proxy Token Format

Proxy tokens are HMAC-signed and valid only for the current `mcp-gate wrap` process:

```text
mcpgate_<service>.<rand24>.<exp_unix>.<sig>
```

Fields:

- `service`: canonical service name, such as `github`.
- `rand24`: 24 random bytes encoded as base64url without padding.
- `exp_unix`: Unix expiry timestamp.
- `sig`: `HMAC-SHA256(signingKey, "<service>|<rand24>|<exp_unix>")`, base64url without padding.

The signing key is generated in memory for each wrap session and is not persisted. The default TTL is 5 minutes, and the maximum accepted TTL is 60 minutes.

## Service Registry

The built-in registry lives in `internal/services/services.go`. Each service entry defines:

- the canonical service name;
- the environment variable set in the wrapped child process;
- optional environment-variable aliases used by import/setup discovery;
- optional token prefixes used for safer credential classification;
- upstream host patterns intercepted for that service.

Users can add or override service definitions with `$MCP_GATE_HOME/services.json`.

## Audit Log

The audit log is append-only JSONL at `$MCP_GATE_HOME/audit.jsonl`. Events include timestamp, service, method, host, path, outcome, status, duration, approval status, and a non-secret proxy-token identifier.

Audit events must not contain plaintext credentials. The proxy records token IDs derived from the random token field and does not log full authorization header values.

## Node.js Compatibility

Many Node.js HTTP stacks do not honor `HTTPS_PROXY` by default. For Node-based MCP servers, `mcp-gate wrap --node-shim` writes a temporary dependency-free CommonJS shim and loads it through `NODE_OPTIONS=--require=<shim>`.

See [docs/NODE_COMPAT.md](./docs/NODE_COMPAT.md) for the compatibility matrix and verification steps.

## Current Limitations

- Native Windows binaries are not published yet; Windows users should use WSL2.
- The vault is single-user local state, not a team or multi-user credential service.
- The file keystore fallback protects against accidental plaintext exposure, but it is not equivalent to OS-backed key storage.
- Long-running server token refresh depends on the wrapped server's ability to reload credentials; this is not a portable contract across runtimes.
- WebSocket and EventSource streams are outside the current credential-swap model.
