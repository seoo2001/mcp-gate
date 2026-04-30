// Package e2e exercises the full wrap path with a real subprocess so we can
// verify the central architectural claim:
//
//	"The MCP server never sees your real PAT."
//
// The test re-execs itself as the wrapped child via the standard Go
// test-self-exec trick (TestMain + an env switch). Inside the child we
// inspect $GITHUB_TOKEN, dial the (fake) upstream over HTTPS through
// $HTTPS_PROXY trusting $SSL_CERT_FILE, and write a witness file recording
// what env vars we actually saw.
//
// Parent-side assertions:
//
//   - upstream Authorization header contained the REAL PAT (proxy did the swap)
//   - upstream Authorization header did NOT contain "mcpgate_" (no leak)
//   - the witness file shows the child's $GITHUB_TOKEN started with "mcpgate_"
//     and did NOT contain the real PAT (process boundary held)
//   - the audit log has one event with outcome=swap, no real PAT bytes anywhere
//   - the on-disk vault.json never contains the plaintext PAT (envelope crypto holds)
package e2e

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/seoo2001/mcp-gate/internal/audit"
	"github.com/seoo2001/mcp-gate/internal/keystore"
	"github.com/seoo2001/mcp-gate/internal/proxy"
	"github.com/seoo2001/mcp-gate/internal/proxyca"
	"github.com/seoo2001/mcp-gate/internal/proxytoken"
	"github.com/seoo2001/mcp-gate/internal/services"
	"github.com/seoo2001/mcp-gate/internal/vault"
	"github.com/seoo2001/mcp-gate/internal/wrapper"
)

const (
	envChildSwitch = "MCP_GATE_E2E_CHILD"
	envChildTarget = "MCP_GATE_E2E_TARGET"
	envChildOutput = "MCP_GATE_E2E_OUTPUT"
	envChildExtra  = "MCP_GATE_E2E_EXTRA_CA"
)

type childWitness struct {
	GitHubTokenEnv string `json:"github_token_env"`
	HTTPProxyEnv   string `json:"http_proxy_env"`
	HTTPSProxyEnv  string `json:"https_proxy_env"`
	SSLCertEnv     string `json:"ssl_cert_env"`
	UpstreamStatus int    `json:"upstream_status"`
	UpstreamBody   string `json:"upstream_body"`
	UpstreamError  string `json:"upstream_error,omitempty"`
}

// TestMain dispatches to childMain when the env switch is set, otherwise runs
// the normal test suite.
func TestMain(m *testing.M) {
	if os.Getenv(envChildSwitch) == "1" {
		childMain()
		return
	}
	os.Exit(m.Run())
}

// childMain is the body of the wrapped MCP-server stand-in. It runs entirely
// from env vars: nothing is hard-coded.
func childMain() {
	target := os.Getenv(envChildTarget)
	output := os.Getenv(envChildOutput)
	wit := childWitness{
		GitHubTokenEnv: os.Getenv("GITHUB_TOKEN"),
		HTTPProxyEnv:   os.Getenv("HTTP_PROXY"),
		HTTPSProxyEnv:  os.Getenv("HTTPS_PROXY"),
		SSLCertEnv:     os.Getenv("SSL_CERT_FILE"),
	}

	pool := x509.NewCertPool()
	if wit.SSLCertEnv != "" {
		if pem, err := os.ReadFile(wit.SSLCertEnv); err == nil {
			pool.AppendCertsFromPEM(pem)
		}
	}
	if extra := os.Getenv(envChildExtra); extra != "" {
		if pem, err := os.ReadFile(extra); err == nil {
			pool.AppendCertsFromPEM(pem)
		}
	}

	// Important: Go's http.ProxyFromEnvironment hard-codes a bypass for
	// loopback addresses (httpproxy.useProxy). In our test the upstream
	// lives on 127.0.0.1, so the default helper would skip the proxy and
	// short-circuit our whole intercept. Pass the proxy URL explicitly.
	var proxyFn func(*http.Request) (*url.URL, error)
	if wit.HTTPSProxyEnv != "" {
		if pu, err := url.Parse(wit.HTTPSProxyEnv); err == nil {
			proxyFn = http.ProxyURL(pu)
		}
	}
	tr := &http.Transport{
		Proxy:           proxyFn,
		TLSClientConfig: &tls.Config{RootCAs: pool},
	}
	client := &http.Client{Transport: tr, Timeout: 10 * time.Second}

	req, _ := http.NewRequest(http.MethodGet, target, nil)
	req.Header.Set("Authorization", "Bearer "+wit.GitHubTokenEnv)
	resp, err := client.Do(req)
	if err != nil {
		wit.UpstreamError = err.Error()
	} else {
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		wit.UpstreamStatus = resp.StatusCode
		wit.UpstreamBody = string(body)
	}
	if output != "" {
		b, _ := json.MarshalIndent(wit, "", "  ")
		_ = os.WriteFile(output, b, 0o600)
	}
}

// TestE2E_RealPATNeverSeenByChild is the headline test of the project.
func TestE2E_RealPATNeverSeenByChild(t *testing.T) {
	const realPAT = "ghp_REAL_PRODUCTION_TOKEN_xyz_THIS_MUST_NEVER_LEAK"

	// Capture upstream Authorization in a thread-safe way.
	var mu sync.Mutex
	var seenAuth string
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seenAuth = r.Header.Get("Authorization")
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "upstream-ok")
	}))
	defer upstream.Close()

	host := strings.TrimPrefix(upstream.URL, "https://")
	bareHost, _, _ := strings.Cut(host, ":")

	dir := t.TempDir()
	homeDir := filepath.Join(dir, "home")
	if err := os.MkdirAll(homeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("MCP_GATE_HOME", homeDir)
	t.Setenv("MCP_GATE_KEYSTORE", "file")

	// 1. Vault with the real PAT.
	ks, err := keystore.Auto(context.Background(), filepath.Join(homeDir, "master.key"))
	if err != nil {
		t.Fatal(err)
	}
	v, err := vault.Open(context.Background(), filepath.Join(homeDir, "vault.json"), ks)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	if err := v.Add(context.Background(), "github", realPAT); err != nil {
		t.Fatal(err)
	}

	// 2. CA + signer.
	kek, _ := ks.Load(context.Background())
	ca, err := proxyca.LoadOrCreate(filepath.Join(homeDir, "ca.pem"), filepath.Join(homeDir, "ca.key"), kek)
	if err != nil {
		t.Fatal(err)
	}
	signer, _ := proxytoken.NewSigner()

	// 3. Service registry mapping the upstream host → "github" service.
	regPath := filepath.Join(dir, "services.json")
	if err := os.WriteFile(regPath, []byte(fmt.Sprintf(
		`[{"name":"github","env_var":"GITHUB_TOKEN","hosts":[%q]}]`, bareHost)), 0o600); err != nil {
		t.Fatal(err)
	}
	reg := services.NewRegistry()
	if err := reg.LoadOverrides(regPath); err != nil {
		t.Fatal(err)
	}

	// 4. Audit log.
	auditPath := filepath.Join(dir, "audit.jsonl")
	auditLog, err := audit.Open(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	defer auditLog.Close()

	// 5. Proxy with upstream cert pinned.
	upstreamPool := x509.NewCertPool()
	upstreamPool.AddCert(upstream.Certificate())
	pr, err := proxy.New(proxy.Config{
		Listen:            "127.0.0.1:0",
		CA:                ca,
		Vault:             v,
		Signer:            signer,
		Registry:          reg,
		Audit:             auditLog,
		UpstreamTLSConfig: &tls.Config{RootCAs: upstreamPool},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := pr.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer pr.Stop(context.Background())

	// 6. Wrap a self-re-exec child making the real HTTPS call.
	witnessPath := filepath.Join(dir, "witness.json")
	extraCA := filepath.Join(dir, "extra-ca.pem")
	upstreamPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: upstream.Certificate().Raw})
	if err := os.WriteFile(extraCA, upstreamPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	exit, err := wrapper.Run(context.Background(), wrapper.Config{
		Command:    self,
		Args:       []string{"-test.run", "TestMain"},
		Service:    "github",
		Registry:   reg,
		Signer:     signer,
		ProxyURL:   pr.URL(),
		CACertPath: filepath.Join(homeDir, "ca.pem"),
		TTL:        time.Minute,
		Stdout:     stdout,
		Stderr:     stderr,
		ExtraEnv: []string{
			envChildSwitch + "=1",
			envChildTarget + "=https://" + host + "/v1/user",
			envChildOutput + "=" + witnessPath,
			envChildExtra + "=" + extraCA,
			// In production we exclude 127.0.0.1 from proxying so localhost
			// services aren't intercepted; in this test the upstream itself
			// lives on 127.0.0.1, so we override NO_PROXY to force the
			// child to dial through our proxy.
			"NO_PROXY=",
			"no_proxy=",
		},
	})
	if err != nil {
		t.Fatalf("wrapper.Run: %v\nstdout: %s\nstderr: %s", err, stdout, stderr)
	}
	if exit != 0 {
		t.Fatalf("child exit = %d\nstdout: %s\nstderr: %s", exit, stdout, stderr)
	}

	// 7. Assertions.
	witBytes, err := os.ReadFile(witnessPath)
	if err != nil {
		t.Fatalf("read witness: %v\nstdout: %s\nstderr: %s", err, stdout, stderr)
	}
	var wit childWitness
	if err := json.Unmarshal(witBytes, &wit); err != nil {
		t.Fatalf("parse witness: %v", err)
	}

	// — The child's GITHUB_TOKEN must be the proxy token.
	if !strings.HasPrefix(wit.GitHubTokenEnv, "mcpgate_") {
		t.Fatalf("child GITHUB_TOKEN didn't start with mcpgate_: %q", wit.GitHubTokenEnv)
	}
	// — The child must NEVER have seen the real PAT.
	if strings.Contains(wit.GitHubTokenEnv, realPAT) {
		t.Fatalf("CRITICAL: real PAT visible in child env")
	}
	// — Proxy env was injected.
	if !strings.HasPrefix(wit.HTTPSProxyEnv, "http://127.0.0.1:") {
		t.Fatalf("HTTPS_PROXY not injected: %q", wit.HTTPSProxyEnv)
	}
	if wit.SSLCertEnv == "" {
		t.Fatalf("SSL_CERT_FILE not injected")
	}
	// — Child got 200 from upstream → swap actually worked end-to-end.
	if wit.UpstreamStatus != 200 {
		t.Fatalf("upstream status = %d, err=%q, body=%q", wit.UpstreamStatus, wit.UpstreamError, wit.UpstreamBody)
	}

	// — Upstream saw the real PAT (and not the proxy token).
	mu.Lock()
	auth := seenAuth
	mu.Unlock()
	wantAuth := "Bearer " + realPAT
	if auth != wantAuth {
		t.Fatalf("upstream Authorization = %q, want %q", auth, wantAuth)
	}
	if strings.Contains(auth, "mcpgate_") {
		t.Fatalf("CRITICAL: proxy token leaked to upstream: %q", auth)
	}

	// — Audit log has the swap event and no plaintext PAT.
	auditBytes := mustRead(t, auditPath)
	if !bytes.Contains(auditBytes, []byte(`"outcome":"swap"`)) {
		t.Fatalf("audit log missing swap outcome:\n%s", auditBytes)
	}
	if bytes.Contains(auditBytes, []byte(realPAT)) {
		t.Fatalf("CRITICAL: real PAT in audit log")
	}
	// — Vault file does not contain plaintext PAT (envelope crypto holds).
	vaultBytes := mustRead(t, filepath.Join(homeDir, "vault.json"))
	if bytes.Contains(vaultBytes, []byte(realPAT)) {
		t.Fatalf("CRITICAL: real PAT plaintext on disk in vault.json")
	}
}

func mustRead(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
