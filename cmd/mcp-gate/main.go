// Command mcp-gate is the credential gate for MCP servers.
//
// The CLI surface follows the README quickstart:
//
//	mcp-gate add <service> --token=<value>
//	mcp-gate list
//	mcp-gate remove <service>
//	mcp-gate wrap <command> [args...]
//	mcp-gate logs [--service=name] [--since=24h]
//	mcp-gate services [list|info <name>]
//	mcp-gate version
//
// All persistent state lives under $MCP_GATE_HOME or ~/.mcp-gate by default:
//
//	~/.mcp-gate/
//	  ├── vault.json     # envelope-encrypted credential store (mode 0600)
//	  ├── audit.jsonl    # one JSON event per proxy call (append-only)
//	  ├── ca.pem         # local root CA cert (public)
//	  ├── ca.key         # local root CA key (mode 0600, master-key-encrypted)
//	  └── services.json  # optional user overrides for the service registry
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/seoo2001/mcp-gate/internal/cli"
)

// version is set at build time via -ldflags="-X main.version=...".
var version = "dev"

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	app := cli.New(version, os.Stdout, os.Stderr)
	code := app.Run(ctx, os.Args[1:])
	if code != 0 {
		fmt.Fprintln(os.Stderr, "mcp-gate exited with code", code)
		os.Exit(code)
	}
}
