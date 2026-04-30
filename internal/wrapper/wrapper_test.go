package wrapper

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/seoo2001/mcp-gate/internal/proxytoken"
	"github.com/seoo2001/mcp-gate/internal/services"
)

// TestRun_PassesProxyTokenViaEnvVar: child sees mcpgate_... in $GITHUB_TOKEN
// and HTTP_PROXY pointing at our proxy URL. Use /bin/sh -c env to dump.
func TestRun_PassesProxyTokenViaEnvVar(t *testing.T) {
	signer, _ := proxytoken.NewSigner()
	out := &bytes.Buffer{}
	exit, err := Run(context.Background(), Config{
		Command:    "/bin/sh",
		Args:       []string{"-c", "env"},
		Service:    "github",
		Registry:   services.NewRegistry(),
		Signer:     signer,
		ProxyURL:   "http://127.0.0.1:9999",
		CACertPath: "/tmp/test-ca.pem",
		TTL:        time.Minute,
		Stdout:     out,
		Stderr:     out,
	})
	if err != nil {
		t.Fatal(err)
	}
	if exit != 0 {
		t.Fatalf("exit = %d", exit)
	}
	got := out.String()
	if !strings.Contains(got, "GITHUB_TOKEN=mcpgate_github.") {
		t.Fatalf("GITHUB_TOKEN missing or wrong shape; got:\n%s", excerpt(got))
	}
	if !strings.Contains(got, "HTTP_PROXY=http://127.0.0.1:9999") {
		t.Fatalf("HTTP_PROXY missing; got:\n%s", excerpt(got))
	}
	if !strings.Contains(got, "HTTPS_PROXY=http://127.0.0.1:9999") {
		t.Fatalf("HTTPS_PROXY missing; got:\n%s", excerpt(got))
	}
	if !strings.Contains(got, "SSL_CERT_FILE=/tmp/test-ca.pem") {
		t.Fatalf("SSL_CERT_FILE missing; got:\n%s", excerpt(got))
	}
	if !strings.Contains(got, "NODE_EXTRA_CA_CERTS=/tmp/test-ca.pem") {
		t.Fatalf("NODE_EXTRA_CA_CERTS missing; got:\n%s", excerpt(got))
	}
	// Critical: parent's real $GITHUB_TOKEN (if set) must NOT appear.
	if strings.Contains(got, "GITHUB_TOKEN=ghp_") {
		t.Fatalf("CRITICAL: real ghp_ token leaked into child env:\n%s", excerpt(got))
	}
}

// TestRun_PreservesChildExitCode: a non-zero child exit propagates.
func TestRun_PreservesChildExitCode(t *testing.T) {
	signer, _ := proxytoken.NewSigner()
	exit, err := Run(context.Background(), Config{
		Command:  "/bin/sh",
		Args:     []string{"-c", "exit 42"},
		Service:  "github",
		Registry: services.NewRegistry(),
		Signer:   signer,
		ProxyURL: "http://127.0.0.1:9999",
	})
	if err != nil {
		t.Fatal(err)
	}
	if exit != 42 {
		t.Fatalf("exit = %d, want 42", exit)
	}
}

// TestRun_RejectsUnknownService: catches typos at the wrapper boundary
// before we even touch the child.
func TestRun_RejectsUnknownService(t *testing.T) {
	signer, _ := proxytoken.NewSigner()
	if _, err := Run(context.Background(), Config{
		Command:  "/bin/true",
		Service:  "nope",
		Registry: services.NewRegistry(),
		Signer:   signer,
		ProxyURL: "http://x",
	}); err == nil {
		t.Fatal("expected unknown-service error")
	}
}

// TestRun_DefaultsTTL: zero TTL gets defaulted to 5m so callers can leave it
// unset.
func TestRun_DefaultsTTL(t *testing.T) {
	signer, _ := proxytoken.NewSigner()
	out := &bytes.Buffer{}
	exit, err := Run(context.Background(), Config{
		Command:  "/bin/sh",
		Args:     []string{"-c", "env"},
		Service:  "github",
		Registry: services.NewRegistry(),
		Signer:   signer,
		ProxyURL: "http://127.0.0.1:0",
		Stdout:   out,
	})
	if err != nil || exit != 0 {
		t.Fatalf("exit=%d err=%v", exit, err)
	}
	// We can't introspect TTL from env directly, but the token format includes
	// the expiry — sanity: non-empty.
	if !strings.Contains(out.String(), "GITHUB_TOKEN=mcpgate_") {
		t.Fatalf("expected token in env")
	}
}

func excerpt(s string) string {
	const max = 800
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}
