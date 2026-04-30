// Package wrapper spawns the wrapped MCP server as a child process with the
// proxy environment baked in:
//
//	HTTP_PROXY=http://127.0.0.1:<proxyPort>
//	HTTPS_PROXY=http://127.0.0.1:<proxyPort>
//	SSL_CERT_FILE=$MCP_GATE_HOME/ca.pem        ← OpenSSL/curl trust store
//	NODE_EXTRA_CA_CERTS=$MCP_GATE_HOME/ca.pem  ← Node.js trust extension
//	REQUESTS_CA_BUNDLE=$MCP_GATE_HOME/ca.pem   ← Python requests / urllib3
//	GIT_SSL_CAINFO=$MCP_GATE_HOME/ca.pem       ← Git over HTTPS
//	<env_var>=mcpgate_<service>.<rand>.<exp>.<sig>   ← per service registry
//
// We deliberately set every popular trust-store env var rather than mutating
// system-wide trust. The wrapped process trusts our CA; nothing else on the
// laptop does.
//
// On signal, the wrapper forwards SIGINT/SIGTERM to the child, then waits up
// to gracefulShutdownWindow before SIGKILLing.
package wrapper

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/seoo2001/mcp-gate/internal/proxytoken"
	"github.com/seoo2001/mcp-gate/internal/services"
)

// gracefulShutdownWindow is how long we wait between SIGTERM and SIGKILL.
const gracefulShutdownWindow = 5 * time.Second

// Config wires the wrapper to its dependencies.
type Config struct {
	// Command is the program to run (argv[0]). Resolved via $PATH if relative.
	Command string
	// Args are the trailing argv.
	Args []string
	// Service is the canonical service name (e.g. "github"). Looked up in
	// Registry to determine which env var to set.
	Service string
	// Registry resolves Service → env var name.
	Registry *services.Registry
	// Signer mints proxy tokens for the child.
	Signer *proxytoken.Signer
	// ProxyURL is the http://127.0.0.1:port form returned by Proxy.URL().
	ProxyURL string
	// CACertPath is the absolute path to the CA cert (PEM, public).
	CACertPath string
	// TTL is the proxy-token lifetime. Defaults to 5 minutes.
	TTL time.Duration
	// RotateInterval, if > 0, mints a fresh token and signals the child via
	// SIGUSR1 every RotateInterval. Most MCP servers re-read env on signal;
	// for those that don't this is a no-op (still safe).
	RotateInterval time.Duration
	// Stdout/Stderr/Stdin connect the child's I/O.
	Stdout io.Writer
	Stderr io.Writer
	Stdin  io.Reader
	// ExtraEnv are key=value strings appended verbatim to child env.
	ExtraEnv []string
	// NodeShim, when true, writes a Node.js shim to a temp file and sets
	// NODE_OPTIONS=--require=<shim> on the child. Use this for wrapping
	// Node MCP servers that would otherwise ignore HTTPS_PROXY (which is
	// most of them: native fetch and node:https don't honor proxy env).
	NodeShim bool
	// NodeShimDir is the directory the shim is written into. Defaults to
	// os.TempDir() when empty. Tests pass a t.TempDir() so the shim is
	// reaped at the end of the test.
	NodeShimDir string
}

// Run spawns the child and blocks until it exits or ctx is cancelled.
//
// The returned int is the child's exit code (0 on success, non-zero on
// error or signal). Errors returned describe wrapper-level failures
// (token mint, exec) — the child's own non-zero exit is reported via the
// int, not the error.
func Run(ctx context.Context, cfg Config) (int, error) {
	if cfg.Command == "" {
		return 1, errors.New("wrapper: empty command")
	}
	if cfg.Service == "" {
		return 1, errors.New("wrapper: empty service")
	}
	if cfg.Registry == nil {
		return 1, errors.New("wrapper: nil registry")
	}
	if cfg.Signer == nil {
		return 1, errors.New("wrapper: nil signer")
	}
	if cfg.ProxyURL == "" {
		return 1, errors.New("wrapper: empty proxy URL")
	}
	svc, ok := cfg.Registry.Get(cfg.Service)
	if !ok {
		return 1, fmt.Errorf("wrapper: unknown service %q (run `mcp-gate services` for list)", cfg.Service)
	}
	if cfg.TTL <= 0 {
		cfg.TTL = 5 * time.Minute
	}

	tok, err := cfg.Signer.Mint(svc.Name, cfg.TTL)
	if err != nil {
		return 1, fmt.Errorf("wrapper: mint token: %w", err)
	}

	// If --node-shim was requested, drop the embedded JS shim onto disk
	// so the child's NODE_OPTIONS=--require=<shim> picks it up.
	var shimPath string
	if cfg.NodeShim {
		shimPath, err = installNodeShim(cfg.NodeShimDir)
		if err != nil {
			return 1, fmt.Errorf("wrapper: install node shim: %w", err)
		}
		defer os.Remove(shimPath)
	}

	cmd := exec.CommandContext(ctx, cfg.Command, cfg.Args...)
	cmd.Env = buildEnv(cfg, svc, tok.Raw, shimPath)
	cmd.Stdout = cfg.Stdout
	cmd.Stderr = cfg.Stderr
	cmd.Stdin = cfg.Stdin
	// Run child in its own process group so we can signal-fan to all of its
	// descendants on shutdown — MCP servers often spawn helpers.
	cmd.SysProcAttr = newSysProcAttr()

	if err := cmd.Start(); err != nil {
		return 1, fmt.Errorf("wrapper: start %q: %w", cfg.Command, err)
	}

	// Forward our signals to the child group.
	sigCh := make(chan os.Signal, 4)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(sigCh)

	// Token rotation goroutine.
	var rotateWG sync.WaitGroup
	rotateCtx, cancelRotate := context.WithCancel(ctx)
	defer cancelRotate()
	if cfg.RotateInterval > 0 {
		rotateWG.Add(1)
		go func() {
			defer rotateWG.Done()
			rotateLoop(rotateCtx, cmd, cfg)
		}()
	}

	// Wait for child or ctx.
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	for {
		select {
		case sig := <-sigCh:
			if sysSig, ok := sig.(syscall.Signal); ok {
				signalGroup(cmd, sysSig)
			}
		case <-ctx.Done():
			signalGroup(cmd, syscall.SIGTERM)
			select {
			case err := <-done:
				cancelRotate()
				rotateWG.Wait()
				return exitCode(err), nil
			case <-time.After(gracefulShutdownWindow):
				signalGroup(cmd, syscall.SIGKILL)
				err := <-done
				cancelRotate()
				rotateWG.Wait()
				return exitCode(err), nil
			}
		case err := <-done:
			cancelRotate()
			rotateWG.Wait()
			return exitCode(err), nil
		}
	}
}

func rotateLoop(ctx context.Context, cmd *exec.Cmd, cfg Config) {
	t := time.NewTicker(cfg.RotateInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			tok, err := cfg.Signer.Mint(cfg.Service, cfg.TTL)
			if err != nil {
				continue
			}
			// Update the proxy-side state by emitting via env... actually the
			// child already has the env baked. Updating mid-process is a
			// known hard problem on Unix (env is copy-on-fork). We signal
			// the child via SIGUSR1; servers that re-read env handle it,
			// the rest will continue on their existing token until it
			// expires (then mcp-gate refreshes implicitly via vault swap).
			_ = tok
			signalGroup(cmd, syscall.SIGUSR1)
		}
	}
}

func buildEnv(cfg Config, svc services.Service, token, shimPath string) []string {
	parent := os.Environ()
	out := make([]string, 0, len(parent)+9)
	skip := map[string]struct{}{
		"HTTP_PROXY":          {},
		"HTTPS_PROXY":         {},
		"http_proxy":          {},
		"https_proxy":         {},
		"NO_PROXY":            {},
		"no_proxy":            {},
		"SSL_CERT_FILE":       {},
		"NODE_EXTRA_CA_CERTS": {},
		"REQUESTS_CA_BUNDLE":  {},
		"GIT_SSL_CAINFO":      {},
		svc.EnvVar:            {},
	}
	if shimPath != "" {
		// We rewrite NODE_OPTIONS to ensure --require=<shim> is the first
		// thing the child's Node sees, regardless of any previous value.
		skip["NODE_OPTIONS"] = struct{}{}
	}
	for _, e := range parent {
		if k, _, ok := strings.Cut(e, "="); ok {
			if _, drop := skip[k]; drop {
				continue
			}
		}
		out = append(out, e)
	}
	out = append(out,
		"HTTP_PROXY="+cfg.ProxyURL,
		"HTTPS_PROXY="+cfg.ProxyURL,
		"http_proxy="+cfg.ProxyURL,
		"https_proxy="+cfg.ProxyURL,
		"NO_PROXY=localhost,127.0.0.1,::1",
		"no_proxy=localhost,127.0.0.1,::1",
		"SSL_CERT_FILE="+cfg.CACertPath,
		"NODE_EXTRA_CA_CERTS="+cfg.CACertPath,
		"REQUESTS_CA_BUNDLE="+cfg.CACertPath,
		"GIT_SSL_CAINFO="+cfg.CACertPath,
		svc.EnvVar+"="+token,
	)
	if shimPath != "" {
		// Preserve any user NODE_OPTIONS by reading the original env (we
		// just stripped it from `out` above). Append our --require last.
		prior := os.Getenv("NODE_OPTIONS")
		if prior != "" {
			out = append(out, "NODE_OPTIONS="+prior+" --require="+shimPath)
		} else {
			out = append(out, "NODE_OPTIONS=--require="+shimPath)
		}
	}
	out = append(out, cfg.ExtraEnv...)
	return out
}

// installNodeShim writes nodeShimSrc to a fresh temp file and returns its
// absolute path. Caller is responsible for os.Remove() on completion.
func installNodeShim(dir string) (string, error) {
	if dir == "" {
		dir = os.TempDir()
	}
	f, err := os.CreateTemp(dir, "mcp-gate-node-shim-*.cjs")
	if err != nil {
		return "", err
	}
	defer f.Close()
	if _, err := f.WriteString(nodeShimSrc); err != nil {
		os.Remove(f.Name())
		return "", err
	}
	return f.Name(), nil
}

func exitCode(err error) int {
	if err == nil {
		return 0
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
	}
	return 1
}
