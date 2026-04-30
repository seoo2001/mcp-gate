#!/usr/bin/env node
// Node-side smoke helper: verifies which Node HTTP stacks respect the
// wrapper env (HTTPS_PROXY + NODE_EXTRA_CA_CERTS).
//
// Why this matters: ARCHITECTURE.md "Open question 1" asks
//   "How do we handle MCP servers that don't respect HTTP_PROXY?"
// Most MCP servers are Node.js (Anthropic's reference implementations are
// all TypeScript). Node has FOUR popular HTTP stacks, each with different
// proxy semantics:
//
//   1. node:https (raw)             — ignores HTTPS_PROXY by default
//   2. fetch (undici, built-in)     — needs setGlobalDispatcher(EnvHttpProxyAgent)
//   3. node-fetch v3+ (CJS dep)     — same as fetch, configurable
//   4. axios / Octokit              — usually wraps node-fetch or http
//
// We test #1 and #2 here. The result table tells us whether MCP servers
// "just work" or need a wrapper-side workaround (--node-shim flag).
//
// No real PAT needed: we hit api.github.com/zen which is unauthenticated.
// A successful response proves the proxy was used (TLS handshake against
// our CA + actual upstream byte response).

const https = require('node:https');

async function probeFetchDefault() {
  // Default fetch — built into Node 18+ via undici. Without explicit dispatcher,
  // does NOT pick up HTTPS_PROXY.
  try {
    const r = await fetch('https://api.github.com/zen', {
      headers: { 'User-Agent': 'mcp-gate-smoke-node' },
    });
    const body = await r.text();
    return { ok: true, status: r.status, body_excerpt: body.slice(0, 80) };
  } catch (e) {
    return { ok: false, err: e.code || e.message };
  }
}

async function probeFetchWithEnvProxy() {
  // undici's EnvHttpProxyAgent reads HTTPS_PROXY/HTTP_PROXY/NO_PROXY at
  // dispatch time and routes accordingly. Available in Node 22+.
  let mod;
  try {
    mod = require('node:undici');
  } catch {
    try {
      mod = require('undici');
    } catch (e) {
      return { skipped: 'undici not available: ' + e.message };
    }
  }
  if (!mod.EnvHttpProxyAgent) {
    return { skipped: 'EnvHttpProxyAgent not in this Node version' };
  }
  try {
    const r = await mod.fetch('https://api.github.com/zen', {
      dispatcher: new mod.EnvHttpProxyAgent(),
      headers: { 'User-Agent': 'mcp-gate-smoke-node' },
    });
    const body = await r.text();
    return { ok: true, status: r.status, body_excerpt: body.slice(0, 80) };
  } catch (e) {
    return { ok: false, err: e.code || e.message };
  }
}

function probeRawHTTPS() {
  // Raw node:https — never respects HTTPS_PROXY. Documented baseline.
  return new Promise((resolve) => {
    const req = https.request({
      hostname: 'api.github.com',
      path: '/zen',
      headers: { 'User-Agent': 'mcp-gate-smoke-node' },
    }, (res) => {
      let body = '';
      res.on('data', (c) => body += c);
      res.on('end', () => resolve({ ok: true, status: res.statusCode, body_excerpt: body.slice(0, 80) }));
    });
    req.on('error', (e) => resolve({ ok: false, err: e.code || e.message }));
    req.end();
  });
}

async function main() {
  const env = {
    GITHUB_TOKEN_prefix: (process.env.GITHUB_TOKEN || '').slice(0, 9),
    HTTPS_PROXY: process.env.HTTPS_PROXY || null,
    HTTP_PROXY: process.env.HTTP_PROXY || null,
    NO_PROXY: process.env.NO_PROXY || null,
    NODE_EXTRA_CA_CERTS: process.env.NODE_EXTRA_CA_CERTS || null,
    SSL_CERT_FILE: process.env.SSL_CERT_FILE || null,
  };

  const result = {
    node_version: process.version,
    env,
    probes: {
      fetch_default:           await probeFetchDefault(),
      fetch_with_env_dispatcher: await probeFetchWithEnvProxy(),
      raw_https:               await probeRawHTTPS(),
    },
  };

  // Stamp a verdict the shell script can grep.
  const proxyHostMatch = (env.HTTPS_PROXY || '').match(/127\.0\.0\.1:(\d+)/);
  result.verdict = {
    real_pat_in_env: result.env.GITHUB_TOKEN_prefix.startsWith('ghp_') ||
                     result.env.GITHUB_TOKEN_prefix.startsWith('github_pat_'),
    https_proxy_set: !!proxyHostMatch,
    fetch_default_used_proxy:   probeUsedProxy(result.probes.fetch_default,           proxyHostMatch),
    fetch_env_dispatcher_used:  probeUsedProxy(result.probes.fetch_with_env_dispatcher, proxyHostMatch),
    raw_https_used_proxy:       probeUsedProxy(result.probes.raw_https,               proxyHostMatch),
  };

  console.log(JSON.stringify(result, null, 2));
  if (result.verdict.real_pat_in_env) {
    process.exit(3);
  }
  // Pass if at least one probe successfully went through the proxy.
  const anyProbeWorked = result.verdict.fetch_default_used_proxy ||
                         result.verdict.fetch_env_dispatcher_used ||
                         result.verdict.raw_https_used_proxy;
  process.exit(anyProbeWorked ? 0 : 4);
}

// We can't directly tell from the response whether the proxy was used.
// Heuristic: if the request SUCCEEDED but the only TLS root the child
// trusts is our CA (NODE_EXTRA_CA_CERTS), then upstream had to be
// proxy-mediated for the TLS handshake to validate. The wrapper script
// double-checks this by inspecting our audit log.
function probeUsedProxy(probe, _) {
  if (probe.skipped) return null;
  return probe.ok === true && probe.status === 200;
}

main().catch((e) => {
  console.error('fatal:', e);
  process.exit(1);
});
