package cli

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"strings"

	"github.com/seoo2001/mcp-gate/internal/discovery"
)

// runImport implements `mcp-gate import` — the credential-archaeology entry
// point. Default behaviour:
//
//	1. Walk known config locations (Claude Desktop / Code, Cursor, Windsurf,
//	   project .env / .mcp.json).
//	2. For each recognised credential, show what we found (redacted) and
//	   where it came from.
//	3. Ask y/n before storing in the vault. Existing vault entries are
//	   replaced atomically — we tell the user when this will happen.
//
// The whole point is that users who've been running plaintext-token MCP
// configs for months can move to mcp-gate in 60 seconds without typing
// any secrets manually.
func (a *App) runImport(ctx context.Context, argv []string) int {
	flags, _ := reorderArgs(argv)
	fs := flag.NewFlagSet("import", flag.ContinueOnError)
	fs.SetOutput(a.Err)
	dryRun := fs.Bool("dry-run", false, "list discoveries; do not modify the vault")
	yes := fs.Bool("yes", false, "skip y/n prompts (required when stdin isn't a TTY)")
	var sources stringList
	fs.Var(&sources, "source", "additional config file path to scan (repeatable)")
	if err := fs.Parse(flags); err != nil {
		return 2
	}

	st, err := loadState(ctx)
	if err != nil {
		fmt.Fprintln(a.Err, "mcp-gate:", err)
		return 1
	}

	// Compose the source list: defaults plus any --source overrides. The
	// user-supplied sources are best-effort: we guess the format from the
	// extension (.json → MCP JSON, anything else → .env).
	srcs := discovery.DefaultSources()
	for _, raw := range sources {
		kind := discovery.KindDotenv
		if strings.HasSuffix(strings.ToLower(raw), ".json") {
			kind = discovery.KindMCPJSON
		}
		srcs = append(srcs, discovery.Source{Path: raw, Kind: kind, Label: "user --source"})
	}

	hits, errs := discovery.Scan(srcs, st.registry)

	if len(errs) > 0 {
		fmt.Fprintln(a.Out, "warnings (non-fatal):")
		for _, e := range errs {
			fmt.Fprintf(a.Out, "  %s: %v\n", e.Source.Path, e.Err)
		}
		fmt.Fprintln(a.Out)
	}

	if len(hits) == 0 {
		fmt.Fprintln(a.Out, "No recognised credentials found in:")
		for _, s := range srcs {
			marker := " "
			if s.Exists() {
				marker = "✓"
			}
			fmt.Fprintf(a.Out, "  %s %-30s %s\n", marker, s.Label, s.Path)
		}
		fmt.Fprintln(a.Out)
		fmt.Fprintln(a.Out, "Tip: pass --source=PATH to add another file.")
		return 0
	}

	a.printDiscoveryTable(hits)

	if *dryRun {
		fmt.Fprintln(a.Out, "(--dry-run: nothing imported)")
		return 0
	}

	v, err := st.openVault(ctx)
	if err != nil {
		fmt.Fprintln(a.Err, "mcp-gate:", err)
		return 1
	}
	defer v.Close()

	imported := 0
	skipped := 0
	for _, h := range hits {
		// If the vault already has this service, the import overwrites.
		// Tell the user up front so it's never a surprise.
		action := "import"
		if v.Has(h.Service) {
			action = "OVERWRITE existing"
		}
		fmt.Fprintf(a.Out, "%s %s (%s) from %s? ",
			action, h.Service, h.Redacted(), summariseSources(h.Sources))
		if !confirm(*yes, a.Out) {
			fmt.Fprintln(a.Out, "skipped.")
			skipped++
			continue
		}
		if err := v.Add(ctx, h.Service, h.Token); err != nil {
			fmt.Fprintf(a.Err, "  ERROR storing %s: %v\n", h.Service, err)
			skipped++
			continue
		}
		imported++
	}

	fmt.Fprintln(a.Out)
	fmt.Fprintf(a.Out, "Done: %d imported, %d skipped.\n", imported, skipped)
	if imported > 0 {
		fmt.Fprintln(a.Out, "Next: wrap your MCP servers with mcp-gate, e.g.")
		fmt.Fprintln(a.Out, "  mcp-gate wrap --service=github --node-shim node /path/to/server.js")
	}
	return 0
}

func (a *App) printDiscoveryTable(hits []discovery.Aggregated) {
	fmt.Fprintln(a.Out, "Discovered credentials:")
	fmt.Fprintln(a.Out)
	fmt.Fprintf(a.Out, "  %-14s  %-22s  %s\n", "service", "token (redacted)", "sources")
	fmt.Fprintf(a.Out, "  %-14s  %-22s  %s\n", strings.Repeat("-", 14), strings.Repeat("-", 22), strings.Repeat("-", 40))
	for _, h := range hits {
		fmt.Fprintf(a.Out, "  %-14s  %-22s  %s\n", h.Service, h.Redacted(), summariseSources(h.Sources))
		for _, n := range h.Notes {
			fmt.Fprintf(a.Out, "    note: %s\n", n)
		}
	}
	fmt.Fprintln(a.Out)
}

// summariseSources renders the list of paths a credential was found in
// using basenames + a server-name suffix, e.g.
//
//	"claude_desktop_config.json[github] + .env"
//
// to keep the table compact.
func summariseSources(srcs []discovery.DiscoverySource) string {
	if len(srcs) == 0 {
		return ""
	}
	out := make([]string, 0, len(srcs))
	for _, s := range srcs {
		base := s.Path
		if i := strings.LastIndexByte(base, '/'); i >= 0 {
			base = base[i+1:]
		}
		if s.ServerName != "" {
			base = base + "[" + s.ServerName + "]"
		}
		out = append(out, base)
	}
	return strings.Join(out, " + ")
}

// confirm reads one line from stdin and returns true on yes/y. When `yes`
// is true (--yes flag), or when stdin isn't a TTY (no input available),
// returns whatever the flag says.
func confirm(yesFlag bool, w interface{ Write([]byte) (int, error) }) bool {
	if yesFlag {
		w.Write([]byte("(--yes)\n"))
		return true
	}
	w.Write([]byte("[y/N] "))
	r := bufio.NewReader(stdin)
	line, err := r.ReadString('\n')
	if err != nil {
		return false
	}
	line = strings.TrimSpace(strings.ToLower(line))
	return line == "y" || line == "yes"
}
