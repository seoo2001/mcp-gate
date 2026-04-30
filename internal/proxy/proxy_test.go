package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
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
	"github.com/seoo2001/mcp-gate/internal/cryptox"
	"github.com/seoo2001/mcp-gate/internal/proxyca"
	"github.com/seoo2001/mcp-gate/internal/proxytoken"
	"github.com/seoo2001/mcp-gate/internal/services"
)

// fakeVault is the test stand-in for *vault.Vault.
type fakeVault struct {
	tokens map[string]string
}

func (f *fakeVault) Get(_ context.Context, svc string) (string, error) {
	v, ok := f.tokens[svc]
	if !ok {
		return "", errors.New("not found")
	}
	return v, nil
}

type seenRequest struct {
	auth   string
	method string
	path   string
}

type seenSink struct {
	mu   sync.Mutex
	rows []seenRequest
}

func (s *seenSink) record(r seenRequest) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rows = append(s.rows, r)
}

func (s *seenSink) only() seenRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.rows) != 1 {
		return seenRequest{}
	}
	return s.rows[0]
}

func (s *seenSink) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.rows)
}

func startFakeUpstream(t *testing.T) (*httptest.Server, *seenSink) {
	t.Helper()
	sink := &seenSink{}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		sink.record(seenRequest{auth: r.Header.Get("Authorization"), method: r.Method, path: r.URL.Path})
		w.Header().Set("X-From-Upstream", "yes")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "upstream-ok")
	})
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	return srv, sink
}

// registryWithService returns a fresh registry containing exactly one service
// pointing at hosts. Used to scope tests to a single intercepted endpoint.
func registryWithService(t *testing.T, name, env string, hosts []string) *services.Registry {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "services.json")
	hostsJSON := make([]string, len(hosts))
	for i, h := range hosts {
		hostsJSON[i] = fmt.Sprintf("%q", h)
	}
	body := fmt.Sprintf(`[{"name":%q,"env_var":%q,"hosts":[%s]}]`,
		name, env, strings.Join(hostsJSON, ","))
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	r := services.NewRegistry()
	// Wipe built-ins by overriding all of them with empty hosts is wrong; instead
	// we accept that built-ins remain — the test host won't match any of them.
	if err := r.LoadOverrides(path); err != nil {
		t.Fatal(err)
	}
	return r
}

type denyAll struct{}

func (denyAll) Approve(context.Context, ApprovalRequest) error { return errors.New("denied") }

type allowAll struct{}

func (allowAll) Approve(context.Context, ApprovalRequest) error { return nil }

type harness struct {
	proxy    *Proxy
	url      string
	signer   *proxytoken.Signer
	ca       *proxyca.CA
	upstream *httptest.Server
	upstreamHost string
	auditPath string
}

// newHarness wires together a proxy + fake upstream + fake vault. The fake
// upstream is reachable at upstreamHost (the httptest URL host:port). The
// registry routes all calls for that host to "github".
func newHarness(t *testing.T, tokens map[string]string, patterns []string, approver Approver) *harness {
	t.Helper()
	upstream, sink := startFakeUpstream(t)
	_ = sink

	host := strings.TrimPrefix(upstream.URL, "https://")
	bareHost, _, _ := strings.Cut(host, ":")
	if bareHost == "" {
		bareHost = host
	}

	dir := t.TempDir()
	kek, _ := cryptox.RandomBytes(cryptox.AESKeyLen)
	ca, err := proxyca.LoadOrCreate(filepath.Join(dir, "ca.pem"), filepath.Join(dir, "ca.key"), kek)
	if err != nil {
		t.Fatal(err)
	}
	signer, _ := proxytoken.NewSigner()
	reg := registryWithService(t, "github", "GITHUB_TOKEN", []string{bareHost})

	auditPath := filepath.Join(dir, "audit.jsonl")
	auditLog, err := audit.Open(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { auditLog.Close() })

	upstreamPool := x509.NewCertPool()
	upstreamPool.AddCert(upstream.Certificate())

	if approver == nil {
		approver = denyAll{}
	}

	p, err := New(Config{
		Listen:           "127.0.0.1:0",
		CA:               ca,
		Vault:            &fakeVault{tokens: tokens},
		Signer:           signer,
		Registry:         reg,
		Audit:            auditLog,
		Approver:         approver,
		ApprovalPatterns: patterns,
		UpstreamTLSConfig: &tls.Config{RootCAs: upstreamPool},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { p.Stop(context.Background()) })

	return &harness{
		proxy:        p,
		url:          p.URL(),
		signer:       signer,
		ca:           ca,
		upstream:     upstream,
		upstreamHost: host,
		auditPath:    auditPath,
	}
}

func (h *harness) client() *http.Client {
	pool := x509.NewCertPool()
	pool.AddCert(h.ca.Cert)
	pool.AddCert(h.upstream.Certificate())
	pu, _ := url.Parse(h.url)
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			Proxy: http.ProxyURL(pu),
			DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
			TLSClientConfig: &tls.Config{
				RootCAs: pool,
			},
		},
	}
}

// requestURL returns https://<httptestHost>/p — the host comes from the
// httptest server itself so DNS just works.
func (h *harness) requestURL(p string) string {
	return "https://" + h.upstreamHost + p
}

func TestProxy_TokenSwap_RealCredentialReachesUpstream(t *testing.T) {
	const realPAT = "ghp_REAL_PRODUCTION_PAT_neverleak"
	h := newHarness(t, map[string]string{"github": realPAT}, nil, nil)

	// We need access to the sink. Re-fetch from upstream's handler isn't
	// possible directly; harness.upstream is the same server, so we extend
	// newHarness to expose the sink.
	// Workaround: use a fresh wired test for this assertion.
	upstream := h.upstream
	_ = upstream

	tok, err := h.signer.Mint("github", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodGet, h.requestURL("/user"), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+tok.Raw)
	resp, err := h.client().Do(req)
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body=%s", resp.StatusCode, body)
	}

	// Validate via audit log: it records token id of the swap and the path,
	// without the real PAT.
	rawAudit := mustRead(t, h.auditPath)
	if !bytes.Contains(rawAudit, []byte(`"outcome":"swap"`)) {
		t.Fatalf("expected swap outcome in audit, got: %s", rawAudit)
	}
	if bytes.Contains(rawAudit, []byte(realPAT)) {
		t.Fatalf("CRITICAL: real PAT found in audit log")
	}
	if !bytes.Contains(rawAudit, []byte(`"path":"/user"`)) {
		t.Fatalf("expected /user path in audit, got: %s", rawAudit)
	}
}

// To validate that the real PAT actually reaches upstream we need the sink.
// Easiest is to expose it from a dedicated test that builds its own server.
func TestProxy_RealPATReachesUpstreamAuthHeader(t *testing.T) {
	const realPAT = "ghp_REAL_PAT_for_upstream"
	got := make(chan string, 1)
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got <- r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	host := strings.TrimPrefix(upstream.URL, "https://")
	bareHost, _, _ := strings.Cut(host, ":")
	if bareHost == "" {
		bareHost = host
	}

	dir := t.TempDir()
	kek, _ := cryptox.RandomBytes(cryptox.AESKeyLen)
	ca, _ := proxyca.LoadOrCreate(filepath.Join(dir, "ca.pem"), filepath.Join(dir, "ca.key"), kek)
	signer, _ := proxytoken.NewSigner()
	reg := registryWithService(t, "github", "GITHUB_TOKEN", []string{bareHost})

	pool := x509.NewCertPool()
	pool.AddCert(upstream.Certificate())

	p, err := New(Config{
		Listen:            "127.0.0.1:0",
		CA:                ca,
		Vault:             &fakeVault{tokens: map[string]string{"github": realPAT}},
		Signer:            signer,
		Registry:          reg,
		UpstreamTLSConfig: &tls.Config{RootCAs: pool},
	})
	if err != nil {
		t.Fatal(err)
	}
	p.Start(context.Background())
	defer p.Stop(context.Background())

	tok, _ := signer.Mint("github", time.Minute)
	clientPool := x509.NewCertPool()
	clientPool.AddCert(ca.Cert)
	clientPool.AddCert(upstream.Certificate())
	pu, _ := url.Parse(p.URL())
	client := &http.Client{Transport: &http.Transport{
		Proxy: http.ProxyURL(pu),
		TLSClientConfig: &tls.Config{RootCAs: clientPool},
	}, Timeout: 5 * time.Second}

	req, _ := http.NewRequest("GET", "https://"+host+"/x", nil)
	req.Header.Set("Authorization", "Bearer "+tok.Raw)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	select {
	case auth := <-got:
		want := "Bearer " + realPAT
		if auth != want {
			t.Fatalf("upstream Authorization = %q, want %q", auth, want)
		}
		if strings.Contains(auth, "mcpgate_") {
			t.Fatalf("CRITICAL: proxy token leaked to upstream: %q", auth)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("upstream did not receive request in time")
	}
}

func TestProxy_RejectsExpiredToken(t *testing.T) {
	h := newHarness(t, map[string]string{"github": "real"}, nil, nil)
	tok, _ := h.signer.Mint("github", time.Second)
	time.Sleep(1100 * time.Millisecond)

	req, _ := http.NewRequest("GET", h.requestURL("/x"), nil)
	req.Header.Set("Authorization", "Bearer "+tok.Raw)
	resp, err := h.client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
}

func TestProxy_RejectsForgedToken(t *testing.T) {
	h := newHarness(t, map[string]string{"github": "real"}, nil, nil)
	other, _ := proxytoken.NewSigner()
	tok, _ := other.Mint("github", time.Minute)
	req, _ := http.NewRequest("GET", h.requestURL("/x"), nil)
	req.Header.Set("Authorization", "Bearer "+tok.Raw)
	resp, err := h.client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d", resp.StatusCode)
	}
}

func TestProxy_RejectsServiceMismatch(t *testing.T) {
	h := newHarness(t, map[string]string{"github": "real", "slack": "x"}, nil, nil)
	tok, _ := h.signer.Mint("slack", time.Minute) // wrong service for this host
	req, _ := http.NewRequest("GET", h.requestURL("/x"), nil)
	req.Header.Set("Authorization", "Bearer "+tok.Raw)
	resp, err := h.client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d", resp.StatusCode)
	}
}

func TestProxy_PassthroughWithoutToken(t *testing.T) {
	h := newHarness(t, map[string]string{"github": "real"}, nil, nil)
	req, _ := http.NewRequest("GET", h.requestURL("/public"), nil)
	resp, err := h.client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (no token = passthrough)", resp.StatusCode)
	}
}

func TestProxy_ApprovalGate_Allow(t *testing.T) {
	h := newHarness(t, map[string]string{"github": "real"}, []string{"DELETE /repos/"}, allowAll{})
	tok, _ := h.signer.Mint("github", time.Minute)
	req, _ := http.NewRequest("DELETE", h.requestURL("/repos/owner/repo"), nil)
	req.Header.Set("Authorization", "Bearer "+tok.Raw)
	resp, err := h.client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
}

func TestProxy_ApprovalGate_Deny(t *testing.T) {
	h := newHarness(t, map[string]string{"github": "real"}, []string{"DELETE /repos/"}, denyAll{})
	tok, _ := h.signer.Mint("github", time.Minute)
	req, _ := http.NewRequest("DELETE", h.requestURL("/repos/owner/repo"), nil)
	req.Header.Set("Authorization", "Bearer "+tok.Raw)
	resp, err := h.client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
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
