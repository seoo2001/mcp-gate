package cli

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/seoo2001/mcp-gate/internal/vault"
)

// runAdd handles `mcp-gate add <service> [--token=...|--token-env=...|--stdin]`.
//
// Three input modes by design:
//   - --token       fast for scripts; risk: leaks via shell history
//   - --token-env   safer in CI; the secret never lands in argv
//   - --stdin       safest at the keyboard; no echo, no scrollback
//
// We never prompt with hidden tty input here — that's a separate UX problem
// (term/tty libs are platform-specific). --stdin reads one line.
func (a *App) runAdd(ctx context.Context, argv []string) int {
	flags, positional := reorderArgs(argv)
	fs := flag.NewFlagSet("add", flag.ContinueOnError)
	fs.SetOutput(a.Err)
	tokenFlag := fs.String("token", "", "credential value (avoid in shared shells)")
	tokenEnv := fs.String("token-env", "", "read credential from this env var")
	stdin := fs.Bool("stdin", false, "read one line of credential from stdin")
	if err := fs.Parse(flags); err != nil {
		return 2
	}
	if len(positional) != 1 {
		fmt.Fprintln(a.Err, "usage: mcp-gate add <service> [--token=...|--token-env=VAR|--stdin]")
		return 2
	}
	service := strings.ToLower(strings.TrimSpace(positional[0]))

	token, err := pickToken(*tokenFlag, *tokenEnv, *stdin, os.Stdin)
	if err != nil {
		fmt.Fprintln(a.Err, "mcp-gate add:", err)
		return 1
	}

	st, err := loadState(ctx)
	if err != nil {
		fmt.Fprintln(a.Err, "mcp-gate:", err)
		return 1
	}
	v, err := st.openVault(ctx)
	if err != nil {
		fmt.Fprintln(a.Err, "mcp-gate:", err)
		return 1
	}
	defer v.Close()
	if err := v.Add(ctx, service, token); err != nil {
		fmt.Fprintln(a.Err, "mcp-gate add:", err)
		return 1
	}
	fmt.Fprintf(a.Out, "stored credential for %q (vault: %s, keystore: %s)\n",
		service, st.layout.Vault, st.ks.Backend())
	return 0
}

func pickToken(tokenFlag, tokenEnv string, stdin bool, in io.Reader) (string, error) {
	switch {
	case tokenFlag != "":
		return tokenFlag, nil
	case tokenEnv != "":
		v := os.Getenv(tokenEnv)
		if v == "" {
			return "", fmt.Errorf("env var %q is empty", tokenEnv)
		}
		return v, nil
	case stdin:
		r := bufio.NewReader(in)
		line, err := r.ReadString('\n')
		if err != nil && err != io.EOF {
			return "", fmt.Errorf("read stdin: %w", err)
		}
		line = strings.TrimRight(line, "\n\r")
		if line == "" {
			return "", errors.New("stdin produced empty token")
		}
		return line, nil
	default:
		return "", errors.New("supply --token, --token-env=VAR, or --stdin")
	}
}

// runList prints all stored services (sorted).
func (a *App) runList(ctx context.Context, argv []string) int {
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	fs.SetOutput(a.Err)
	if err := fs.Parse(argv); err != nil {
		return 2
	}
	st, err := loadState(ctx)
	if err != nil {
		fmt.Fprintln(a.Err, "mcp-gate:", err)
		return 1
	}
	v, err := st.openVault(ctx)
	if err != nil {
		fmt.Fprintln(a.Err, "mcp-gate:", err)
		return 1
	}
	defer v.Close()
	names, err := v.List(ctx)
	if err != nil {
		fmt.Fprintln(a.Err, "mcp-gate list:", err)
		return 1
	}
	if len(names) == 0 {
		fmt.Fprintln(a.Out, "(empty — `mcp-gate add <service> --token=...` to start)")
		return 0
	}
	for _, n := range names {
		fmt.Fprintln(a.Out, n)
	}
	return 0
}

// runRemove deletes a service.
func (a *App) runRemove(ctx context.Context, argv []string) int {
	flags, positional := reorderArgs(argv)
	fs := flag.NewFlagSet("remove", flag.ContinueOnError)
	fs.SetOutput(a.Err)
	if err := fs.Parse(flags); err != nil {
		return 2
	}
	if len(positional) != 1 {
		fmt.Fprintln(a.Err, "usage: mcp-gate remove <service>")
		return 2
	}
	args := positional
	st, err := loadState(ctx)
	if err != nil {
		fmt.Fprintln(a.Err, "mcp-gate:", err)
		return 1
	}
	v, err := st.openVault(ctx)
	if err != nil {
		fmt.Fprintln(a.Err, "mcp-gate:", err)
		return 1
	}
	defer v.Close()
	if err := v.Remove(ctx, args[0]); err != nil {
		if errors.Is(err, vault.ErrNotFound) {
			fmt.Fprintln(a.Err, "no such service:", args[0])
			return 1
		}
		fmt.Fprintln(a.Err, "mcp-gate remove:", err)
		return 1
	}
	fmt.Fprintln(a.Out, "removed", args[0])
	return 0
}

// runServices lists the built-in service registry plus any overrides.
func (a *App) runServices(ctx context.Context, argv []string) int {
	fs := flag.NewFlagSet("services", flag.ContinueOnError)
	fs.SetOutput(a.Err)
	if err := fs.Parse(argv); err != nil {
		return 2
	}
	st, err := loadState(ctx)
	if err != nil {
		fmt.Fprintln(a.Err, "mcp-gate:", err)
		return 1
	}
	for _, s := range st.registry.All() {
		fmt.Fprintf(a.Out, "%-8s  %-18s  hosts=%s\n", s.Name, s.EnvVar, strings.Join(s.Hosts, ","))
		if s.Description != "" {
			fmt.Fprintf(a.Out, "          %s\n", s.Description)
		}
	}
	return 0
}

// runInfo prints layout + keystore backend (useful when filing bugs).
func (a *App) runInfo(ctx context.Context, _ []string) int {
	st, err := loadState(ctx)
	if err != nil {
		fmt.Fprintln(a.Err, "mcp-gate:", err)
		return 1
	}
	fmt.Fprintf(a.Out, "home:     %s\n", st.layout.Home)
	fmt.Fprintf(a.Out, "vault:    %s\n", st.layout.Vault)
	fmt.Fprintf(a.Out, "audit:    %s\n", st.layout.Audit)
	fmt.Fprintf(a.Out, "ca cert:  %s\n", st.layout.CACert)
	fmt.Fprintf(a.Out, "ca key:   %s (encrypted)\n", st.layout.CAKey)
	fmt.Fprintf(a.Out, "services: %s\n", st.layout.Services)
	fmt.Fprintf(a.Out, "keystore: %s\n", st.ks.Backend())
	return 0
}
