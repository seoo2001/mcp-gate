package cli

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/seoo2001/mcp-gate/internal/discovery"
	"github.com/seoo2001/mcp-gate/internal/rewriter"
)

// runSetup is the one-shot magic: scan known MCP config locations, import
// every recognised credential into the vault, then rewrite each config so
// the MCP server runs through `mcp-gate wrap` instead of with its plaintext
// token in env. Backups are made on every rewrite.
//
// Trade-off vs `import` + manual edit: setup writes user files. We mitigate
// with three layers: backup-on-write, --dry-run preview, and an explicit
// --yes flag that's required when stdin isn't a TTY (so a CI run can't
// silently rewrite a developer's Claude Desktop config).
func (a *App) runSetup(ctx context.Context, argv []string) int {
	flags, _ := reorderArgs(argv)
	fs := flag.NewFlagSet("setup", flag.ContinueOnError)
	fs.SetOutput(a.Err)
	dryRun := fs.Bool("dry-run", false, "preview discoveries + rewrites without modifying vault or files")
	yes := fs.Bool("yes", false, "skip confirmation prompts (required outside a TTY)")
	ttl := fs.String("ttl", "5m", "proxy-token TTL for the wrap invocations we write")
	noNodeShim := fs.Bool("no-node-shim", false, "disable the Node.js HTTPS_PROXY shim heuristic")
	mcpGatePath := fs.String("mcp-gate-path", "", "absolute path to write into the rewritten command field (defaults to running binary)")
	var configs stringList
	fs.Var(&configs, "config", "additional mcp.json config to scan and rewrite (repeatable)")
	if err := fs.Parse(flags); err != nil {
		return 2
	}

	st, err := loadState(ctx)
	if err != nil {
		fmt.Fprintln(a.Err, "mcp-gate:", err)
		return 1
	}

	gatePath, err := resolveBinaryPath(*mcpGatePath)
	if err != nil {
		fmt.Fprintln(a.Err, "mcp-gate setup:", err)
		return 1
	}

	// Phase 1: discovery — same code path as `mcp-gate import`.
	srcs := discovery.DefaultSources()
	for _, raw := range configs {
		srcs = append(srcs, discovery.Source{
			Path:  raw,
			Kind:  discovery.KindMCPJSON,
			Label: "user --config",
		})
	}
	hits, errs := discovery.Scan(srcs, st.registry)

	if len(errs) > 0 {
		fmt.Fprintln(a.Out, "scan warnings (non-fatal):")
		for _, e := range errs {
			fmt.Fprintf(a.Out, "  %s: %v\n", e.Source.Path, e.Err)
		}
		fmt.Fprintln(a.Out)
	}

	if len(hits) == 0 {
		fmt.Fprintln(a.Out, "Nothing to set up — no recognised credentials in:")
		printSourceList(a.Out, srcs)
		return 0
	}

	// Phase 2: vault import.
	a.printDiscoveryTable(hits)

	if *dryRun {
		fmt.Fprintln(a.Out, "── dry run summary ──")
	}

	v, err := st.openVault(ctx)
	if err != nil {
		fmt.Fprintln(a.Err, "mcp-gate:", err)
		return 1
	}
	defer v.Close()

	importedFor := map[string]bool{} // service → did we just import it?
	for _, h := range hits {
		if !*dryRun {
			if err := v.Add(ctx, h.Service, h.Token); err != nil {
				fmt.Fprintf(a.Err, "  ERROR storing %s: %v\n", h.Service, err)
				continue
			}
		}
		importedFor[h.Service] = true
		fmt.Fprintf(a.Out, "  ✓ vault: %-12s %s\n", h.Service, h.Redacted())
	}
	fmt.Fprintln(a.Out)

	// Phase 3: rewrite every config file we found at least one of those
	// credentials in. We only rewrite files that we *can* read+write, and
	// we always make a backup. Files that didn't show up in discovery are
	// not touched (we don't speculate).
	rewriteTargets := map[string]struct{}{}
	for _, h := range hits {
		for _, s := range h.Sources {
			if strings.HasSuffix(strings.ToLower(s.Path), ".json") {
				rewriteTargets[s.Path] = struct{}{}
			}
		}
	}
	if len(rewriteTargets) == 0 {
		fmt.Fprintln(a.Out, "No mcp.json files to rewrite — credentials live only in .env files.")
		fmt.Fprintln(a.Out, "Wrap your servers manually: mcp-gate wrap --service=<name> [--node-shim] <command> [args...]")
		return 0
	}

	if !*dryRun && !*yes && !confirm(*yes, a.Out) {
		// confirm() with yesFlag=false prompts; when --yes was set we
		// short-circuit above without re-prompting.
	}

	for path := range rewriteTargets {
		fmt.Fprintf(a.Out, "── rewriting %s\n", path)
		results, err := rewriter.Rewrite(path, st.registry, rewriter.Options{
			MCPGatePath: gatePath,
			NodeShim:    !*noNodeShim,
			TTL:         *ttl,
			DryRun:      *dryRun,
		}, func(service string) bool {
			// Now that import has run, the vault has every importable
			// credential. We still gate on the actual vault state in case
			// some service was already there or import was --dry-run.
			if v.Has(service) {
				return true
			}
			return importedFor[service]
		})
		if err != nil {
			fmt.Fprintf(a.Err, "  ERROR: %v\n", err)
			continue
		}
		for _, r := range results {
			marker := "  ·"
			switch r.Action {
			case rewriter.ActionWrapped:
				marker = "  ✓"
			case rewriter.ActionRewrap:
				marker = "  ↻"
			}
			fmt.Fprintf(a.Out, "%s %s [%s] %s\n", marker, r.ServerName, actionLabel(r.Action), r.Reason)
		}
	}

	if *dryRun {
		fmt.Fprintln(a.Out, "\n(--dry-run: no files were modified)")
		return 0
	}

	fmt.Fprintln(a.Out)
	fmt.Fprintln(a.Out, "Done. Restart Claude Desktop / Code / Cursor / Windsurf to pick up changes.")
	if runtime.GOOS == "darwin" {
		fmt.Fprintln(a.Out, "  killall \"Claude\" 2>/dev/null  # macOS Claude Desktop")
	}
	return 0
}

// resolveBinaryPath returns userPath if non-empty, otherwise the absolute
// path of the currently running binary. mcp.json files reference the
// command verbatim — relative or bare names break Claude Desktop because
// it spawns from a constant working dir.
func resolveBinaryPath(userPath string) (string, error) {
	if userPath != "" {
		abs, err := filepath.Abs(userPath)
		if err != nil {
			return "", fmt.Errorf("resolve --mcp-gate-path: %w", err)
		}
		return abs, nil
	}
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("os.Executable: %w (pass --mcp-gate-path)", err)
	}
	resolved, err := filepath.EvalSymlinks(exe)
	if err != nil {
		// Symlink resolution is best-effort; fall back to raw exe path.
		return exe, nil
	}
	return resolved, nil
}

func actionLabel(a rewriter.Action) string {
	switch a {
	case rewriter.ActionWrapped:
		return "wrapped"
	case rewriter.ActionRewrap:
		return "rewrapped"
	default:
		return "skipped"
	}
}

func printSourceList(w interface{ Write([]byte) (int, error) }, srcs []discovery.Source) {
	for _, s := range srcs {
		marker := " "
		if s.Exists() {
			marker = "✓"
		}
		fmt.Fprintf(w, "  %s %-30s %s\n", marker, s.Label, s.Path)
	}
}
