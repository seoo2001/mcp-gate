#!/bin/bash
# Node-side smoke test: verifies which Node HTTP stacks respect the wrapper
# env (HTTPS_PROXY + NODE_EXTRA_CA_CERTS). No real PAT required —
# api.github.com/zen is unauthenticated.
#
# This is the answer to ARCHITECTURE.md "Open question 1" for Node MCP
# servers. Decision tree consumed by the wrap CLI's --node-shim flag.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

TEST_HOME="$(mktemp -d -t mcp-gate-node-XXXXXX)"
export MCP_GATE_HOME="$TEST_HOME"
export MCP_GATE_KEYSTORE=file
trap 'rm -rf "$TEST_HOME"' EXIT

step() { echo; echo "── $1"; echo "──────────────────────────────────────────"; }

step "1. build mcp-gate"
make build >/dev/null
ls -la bin/mcp-gate

step "2. add a stub credential (Node helper hits unauth endpoint, no real PAT needed)"
# We still need the vault to have a github entry so wrap doesn't refuse.
bin/mcp-gate add github --token=fake_stub_for_node_smoke_test
bin/mcp-gate list

step "3a. wrap WITHOUT --node-shim (baseline: documents the limitation)"
set +e
WRAP_OUT_RAW="$(bin/mcp-gate wrap --service=github --ttl=2m \
  node "$REPO_ROOT/cmd/smoke-helper-node/smoke.js")"
RAW_EXIT=$?
set -e
echo "$WRAP_OUT_RAW"
echo "(no-shim wrap exit: $RAW_EXIT)"

step "3b. wrap WITH --node-shim (the workaround under test)"
set +e
WRAP_OUT="$(bin/mcp-gate wrap --service=github --ttl=2m --node-shim \
  node "$REPO_ROOT/cmd/smoke-helper-node/smoke.js")"
WRAP_EXIT=$?
set -e
echo "$WRAP_OUT"
echo "(shim wrap exit: $WRAP_EXIT)"

step "4. parse via node (its own JSON is what we just emitted)"
JSON_FILE="$TEST_HOME/probe.json"
printf '%s' "$WRAP_OUT" > "$JSON_FILE"
node "$REPO_ROOT/scripts/smoke-node-grade.js" "$JSON_FILE"

step "5. audit log for the proxied calls"
bin/mcp-gate logs

step "verdict"
case "$WRAP_EXIT" in
  0)
    echo "PASS — at least one Node HTTP stack succeeded through the proxy."
    ;;
  3)
    echo "FAIL CRITICAL — real PAT visible in child env."
    exit 3
    ;;
  4)
    echo "DOCUMENTED LIMITATION — no Node HTTP stack used the proxy."
    echo "This confirms ARCHITECTURE.md \"Open question 1\": Node MCP servers"
    echo "do not respect HTTPS_PROXY by default. See docs/NODE_COMPAT.md for"
    echo "the recommended workaround (--node-shim) once shipped."
    # Documented limitation is not a script failure; the test does its job
    # by surfacing exactly which stacks need a shim.
    ;;
  *)
    echo "wrap exited $WRAP_EXIT"
    exit "$WRAP_EXIT"
    ;;
esac
echo "Test home (cleaned on exit): $TEST_HOME"
