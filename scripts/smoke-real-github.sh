#!/bin/bash
# Real-API smoke test: wraps a tiny Go helper with mcp-gate and calls the
# live https://api.github.com/user endpoint.
#
# Validates that the architecture's promises hold against a *real* upstream:
#
#   - Wrapped child receives only mcpgate_... in $GITHUB_TOKEN
#   - api.github.com returns 200 + the right user login
#   - Audit log records outcome=swap with no plaintext PAT bytes
#   - Vault file on disk contains zero plaintext PAT bytes
#
# Required:
#
#   MCP_GATE_SMOKE_PAT=<real github PAT, read:user scope is enough>
#
# We READ from env, never argv, so the token never lands in shell history.
set -euo pipefail

PAT="${MCP_GATE_SMOKE_PAT:-}"
if [ -z "$PAT" ]; then
  echo "FAIL: set MCP_GATE_SMOKE_PAT to a real GitHub PAT first" >&2
  echo "      (read:user scope is sufficient; will be removed at end of test)" >&2
  exit 1
fi

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

# Isolated home so we never touch the user's real vault.
TEST_HOME="$(mktemp -d -t mcp-gate-smoke-XXXXXX)"
export MCP_GATE_HOME="$TEST_HOME"
export MCP_GATE_KEYSTORE=file
trap 'rm -rf "$TEST_HOME"' EXIT

cleanup_step() {
  local label="$1"; shift
  echo
  echo "── $label"
  echo "──────────────────────────────────────────"
}

cleanup_step "1. build mcp-gate + smoke-helper"
make build >/dev/null
go build -trimpath -o bin/smoke-helper ./cmd/smoke-helper
ls -la bin/mcp-gate bin/smoke-helper

cleanup_step "2. add real PAT to isolated vault"
bin/mcp-gate add github --token-env=MCP_GATE_SMOKE_PAT
bin/mcp-gate list

cleanup_step "3. confirm vault has zero plaintext PAT"
if grep -q "$PAT" "$TEST_HOME/vault.json"; then
  echo "FAIL: real PAT visible in vault.json (envelope crypto broken)"
  exit 2
fi
echo "ok: vault.json contains zero bytes of the plaintext PAT"

cleanup_step "4. wrap smoke-helper → call api.github.com/user"
# Capture stdout of the helper for parsing.
HELPER_OUT="$(bin/mcp-gate wrap --service=github --ttl=2m bin/smoke-helper)"
echo "$HELPER_OUT"

cleanup_step "5. parse helper output"
TOKEN_PREFIX="$(echo "$HELPER_OUT" | python3 -c 'import json,sys; print(json.load(sys.stdin)["github_token_prefix"])')"
STATUS="$(echo "$HELPER_OUT" | python3 -c 'import json,sys; print(json.load(sys.stdin)["upstream_status"])')"
LOGIN="$(echo "$HELPER_OUT" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("upstream_login","") or "")')"
LEAK="$(echo "$HELPER_OUT" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("real_pat_seen_in_env",False))')"

if [ "$LEAK" != "False" ]; then
  echo "FAIL: real PAT visible in wrapped child env (CRITICAL)"
  exit 3
fi
if [ "$TOKEN_PREFIX" != "mcpgate_" ]; then
  echo "FAIL: child saw token with prefix '$TOKEN_PREFIX', expected mcpgate_"
  exit 3
fi
if [ "$STATUS" != "200" ]; then
  echo "FAIL: upstream status was $STATUS, expected 200"
  exit 4
fi
if [ -z "$LOGIN" ]; then
  echo "FAIL: api.github.com/user response had no login field"
  exit 4
fi
echo "ok: child saw mcpgate_ token, upstream returned 200, login=$LOGIN"

cleanup_step "6. confirm audit log recorded the swap"
bin/mcp-gate logs
if ! bin/mcp-gate logs --json | grep -q '"outcome":"swap"'; then
  echo "FAIL: audit log missing swap event"
  exit 5
fi
if grep -q "$PAT" "$TEST_HOME/audit.jsonl"; then
  echo "FAIL: real PAT visible in audit.jsonl"
  exit 5
fi
echo "ok: audit.jsonl recorded swap event with no plaintext PAT"

cleanup_step "PASS"
echo "Real GitHub API smoke test passed."
echo "  vault.json size:    $(wc -c < "$TEST_HOME/vault.json") bytes"
echo "  audit.jsonl events: $(wc -l < "$TEST_HOME/audit.jsonl")"
echo "  CA cert path:       $TEST_HOME/ca.pem"
echo "  github user:        $LOGIN"
echo "  test home (cleaned on exit): $TEST_HOME"
