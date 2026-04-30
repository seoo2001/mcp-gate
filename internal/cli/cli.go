// Package cli is the mcp-gate command-line dispatcher.
//
// The shape mirrors README quickstart:
//
//	mcp-gate add <service> --token=<value>
//	mcp-gate list
//	mcp-gate remove <service>
//	mcp-gate wrap [flags] <command> [args...]
//	mcp-gate logs [flags]
//	mcp-gate services
//	mcp-gate version
//	mcp-gate info
//
// We hand-roll dispatch on top of stdlib `flag` rather than pulling cobra:
// the surface is small, and a single binary with zero deps is the product.
package cli

import (
	"context"
	"fmt"
	"io"
	"os"
)

// App is the CLI runtime.
type App struct {
	Version string
	Out     io.Writer
	Err     io.Writer
}

// New returns an App. Stdout/Stderr are captured so tests can inspect output.
func New(version string, out, err io.Writer) *App {
	if out == nil {
		out = os.Stdout
	}
	if err == nil {
		err = os.Stderr
	}
	return &App{Version: version, Out: out, Err: err}
}

// Run dispatches one CLI invocation.
func (a *App) Run(ctx context.Context, argv []string) int {
	if len(argv) == 0 {
		a.printUsage()
		return 2
	}
	cmd := argv[0]
	rest := argv[1:]
	switch cmd {
	case "version", "--version", "-v":
		fmt.Fprintln(a.Out, "mcp-gate", a.Version)
		return 0
	case "help", "--help", "-h":
		a.printUsage()
		return 0
	case "info":
		return a.runInfo(ctx, rest)
	case "add":
		return a.runAdd(ctx, rest)
	case "list", "ls":
		return a.runList(ctx, rest)
	case "remove", "rm":
		return a.runRemove(ctx, rest)
	case "services":
		return a.runServices(ctx, rest)
	case "wrap":
		return a.runWrap(ctx, rest)
	case "logs":
		return a.runLogs(ctx, rest)
	case "import":
		return a.runImport(ctx, rest)
	case "setup":
		return a.runSetup(ctx, rest)
	default:
		fmt.Fprintf(a.Err, "mcp-gate: unknown subcommand %q\n", cmd)
		a.printUsage()
		return 2
	}
}

func (a *App) printUsage() {
	fmt.Fprint(a.Out, `mcp-gate — credential gate for MCP servers.

Usage:
  mcp-gate setup  [--config=PATH]... [--dry-run] [--yes] [--ttl=5m] [--no-node-shim]
  mcp-gate import [--source=PATH]... [--dry-run] [--yes]
  mcp-gate add <service> [--token=<value>] [--token-env=VAR] [--stdin]
  mcp-gate list
  mcp-gate remove <service>
  mcp-gate services
  mcp-gate wrap [--service=<name>] [--ttl=5m] [--port=0] \
                [--rotate=<dur>] [--require-approval-for=<rule>]... \
                [--slack-webhook=<url>] [--callback=<host:port>] \
                <command> [args...]
  mcp-gate logs [--service=<name>] [--since=24h] [--limit=100] [--json]
  mcp-gate info
  mcp-gate version

State lives under $MCP_GATE_HOME (default ~/.mcp-gate).
`)
}
