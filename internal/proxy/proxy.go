// Package proxy is the credential-swapping HTTPS MITM proxy.
//
// Flow for an HTTPS request from a wrapped MCP server:
//
//	┌─────────────┐   CONNECT api.github.com:443     ┌────────────────────────┐
//	│ MCP server  │ ─────────────────────────────▶  │ proxy listener (HTTP)  │
//	└─────────────┘                                  └─────────┬──────────────┘
//	                                                           │ hijack TCP
//	                                                           ▼
//	                                          generate leaf for api.github.com
//	                                          (signed by local CA)
//	                                          tls.Server handshake with MCP
//	                                                           │
//	                                          inner HTTPS request decrypted
//	                                                           │
//	                                          scan headers for mcpgate_ prefix
//	                                                           │
//	                                          ╭───────────────┴───────────────╮
//	                                          │ valid token → swap            │
//	                                          │ bogus token → 401             │
//	                                          │ no token    → pass-through    │
//	                                          ╰───────────────┬───────────────╯
//	                                                           ▼
//	                                          http.Transport.RoundTrip(real PAT)
//	                                          → api.github.com (system trust store)
//	                                                           │
//	                                          response streamed back to MCP server
//
// Why we wrote this rather than using goproxy: surgical header rewriting and a
// minimal audit surface. Every byte that touches a credential is in this file.
package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/seoo2001/mcp-gate/internal/audit"
	"github.com/seoo2001/mcp-gate/internal/proxyca"
	"github.com/seoo2001/mcp-gate/internal/proxytoken"
	"github.com/seoo2001/mcp-gate/internal/services"
)

// VaultGetter abstracts the credential lookup. Production wires this to a
// real *vault.Vault; tests pass an in-memory map.
type VaultGetter interface {
	Get(ctx context.Context, service string) (string, error)
}

// Approver decides whether a sensitive call (matched by an approval pattern)
// should proceed. Returns nil to allow, non-nil to deny.
//
// Synchronous on purpose: the proxy holds the request open until decision.
type Approver interface {
	Approve(ctx context.Context, req ApprovalRequest) error
}

// ApprovalRequest describes a call awaiting human decision.
type ApprovalRequest struct {
	Service string
	Method  string
	Host    string
	Path    string
	Now     time.Time
}

// Config bundles dependencies for a Proxy.
type Config struct {
	// Listen address — typically "127.0.0.1:0" so the OS picks a free port
	// and the wrapper reads it from Proxy.URL().
	Listen string
	// CA used to mint per-host leaf certs. Must be the same CA the wrapped
	// child trusts (we install ours into the child's process trust store).
	CA *proxyca.CA
	// Vault returns the real PAT for a given service.
	Vault VaultGetter
	// Signer validates inbound proxy tokens.
	Signer *proxytoken.Signer
	// Registry resolves upstream host → service.
	Registry *services.Registry
	// Audit, if non-nil, gets one event per intercepted call.
	Audit *audit.Logger
	// Approver, if non-nil, is consulted when ApprovalPatterns matches.
	Approver Approver
	// ApprovalPatterns is a list of "<METHOD> <path-prefix>" rules. Empty list
	// = no approvals required. Example: []string{"DELETE /repos/"}.
	ApprovalPatterns []string
	// Logger, if non-nil, gets debug-level traces of intercepted hosts.
	Logger *slog.Logger
	// UpstreamTLSConfig overrides the TLS config the proxy uses to dial real
	// upstream APIs. Production leaves this nil (system trust store);
	// tests inject a fixture CA to accept httptest TLS certs.
	UpstreamTLSConfig *tls.Config
	// UpstreamDialContext overrides the proxy's outbound dialer. Production
	// leaves this nil (default Go net dialer); tests redirect synthetic
	// hostnames to the loopback port of httptest.
	UpstreamDialContext func(ctx context.Context, network, addr string) (net.Conn, error)
}

// Proxy is the running MITM proxy.
type Proxy struct {
	cfg Config

	listener net.Listener
	server   *http.Server

	leafMu sync.Mutex
	leaves map[string]*tls.Certificate

	upstream *http.Transport
	rules    []approvalRule
}

type approvalRule struct {
	method string
	prefix string
}

// New returns a configured but not-yet-listening Proxy.
func New(cfg Config) (*Proxy, error) {
	if cfg.CA == nil {
		return nil, errors.New("proxy: CA required")
	}
	if cfg.Vault == nil {
		return nil, errors.New("proxy: Vault required")
	}
	if cfg.Signer == nil {
		return nil, errors.New("proxy: Signer required")
	}
	if cfg.Registry == nil {
		return nil, errors.New("proxy: Registry required")
	}
	rules, err := parseApprovalPatterns(cfg.ApprovalPatterns)
	if err != nil {
		return nil, err
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	dial := cfg.UpstreamDialContext
	if dial == nil {
		dial = (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext
	}
	return &Proxy{
		cfg:    cfg,
		leaves: map[string]*tls.Certificate{},
		upstream: &http.Transport{
			Proxy:                 nil, // we ARE the proxy; don't recurse via env
			DialContext:           dial,
			TLSClientConfig:       cfg.UpstreamTLSConfig,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          50,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
		rules: rules,
	}, nil
}

// Start binds the listener and serves in a background goroutine. The returned
// channel emits the bind error (or nil at clean Stop).
func (p *Proxy) Start(ctx context.Context) error {
	addr := p.cfg.Listen
	if addr == "" {
		addr = "127.0.0.1:0"
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("proxy: listen %s: %w", addr, err)
	}
	p.listener = ln
	p.server = &http.Server{
		Handler:           http.HandlerFunc(p.handle),
		ReadHeaderTimeout: 15 * time.Second,
		BaseContext:       func(_ net.Listener) context.Context { return ctx },
	}
	go func() {
		if err := p.server.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			p.cfg.Logger.Error("proxy serve exited", "err", err)
		}
	}()
	return nil
}

// URL returns the http://127.0.0.1:port form for $HTTP_PROXY / $HTTPS_PROXY.
func (p *Proxy) URL() string {
	if p.listener == nil {
		return ""
	}
	return "http://" + p.listener.Addr().String()
}

// Addr returns the listener address (host:port).
func (p *Proxy) Addr() string {
	if p.listener == nil {
		return ""
	}
	return p.listener.Addr().String()
}

// Stop drains in-flight requests up to ctx deadline.
func (p *Proxy) Stop(ctx context.Context) error {
	if p.server == nil {
		return nil
	}
	err := p.server.Shutdown(ctx)
	p.upstream.CloseIdleConnections()
	return err
}

// handle dispatches between CONNECT (HTTPS) and direct HTTP requests.
func (p *Proxy) handle(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
		return
	}
	// Plain HTTP through the proxy. Rare for our target services (which are
	// all HTTPS) but supported for completeness.
	p.handlePlainHTTP(w, r)
}

// handleConnect runs the MITM TLS dance.
func (p *Proxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	host, _, err := net.SplitHostPort(r.Host)
	if err != nil {
		host = r.Host
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijack not supported", http.StatusInternalServerError)
		return
	}
	clientConn, bufrw, err := hj.Hijack()
	if err != nil {
		http.Error(w, "hijack failed", http.StatusInternalServerError)
		return
	}
	defer clientConn.Close()

	// Tell the client the tunnel is ready.
	if _, err := bufrw.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return
	}
	if err := bufrw.Flush(); err != nil {
		return
	}

	tlsConfig := &tls.Config{
		GetCertificate: func(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
			return p.leafFor(host)
		},
		MinVersion: tls.VersionTLS12,
	}
	tlsConn := tls.Server(clientConn, tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		p.cfg.Logger.Debug("tls handshake failed", "host", host, "err", err)
		return
	}
	defer tlsConn.Close()

	reader := bufio.NewReader(tlsConn)
	for {
		innerReq, err := http.ReadRequest(reader)
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
				p.cfg.Logger.Debug("read inner request", "host", host, "err", err)
			}
			return
		}
		innerReq.URL.Scheme = "https"
		innerReq.URL.Host = r.Host
		innerReq.RequestURI = ""
		// Drop hop-by-hop. Most importantly, don't propagate Connection: close
		// from CONNECT into upstream RoundTrip.
		stripHopByHop(innerReq.Header)

		resp, status := p.proxyOne(innerReq.Context(), innerReq, host)
		if err := writeResponse(tlsConn, innerReq, resp, status); err != nil {
			p.cfg.Logger.Debug("write inner response", "host", host, "err", err)
			return
		}
		// http.ReadRequest doesn't drain the body for next request unless we do.
		if innerReq.Body != nil {
			io.Copy(io.Discard, innerReq.Body)
			innerReq.Body.Close()
		}
		// HTTP/1.1 keep-alive: loop until client closes.
	}
}

// handlePlainHTTP serves HTTP-over-HTTP-proxy (no TLS).
func (p *Proxy) handlePlainHTTP(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Host
	if host == "" {
		host = r.Host
	}
	if !strings.HasPrefix(strings.ToLower(r.URL.Scheme), "http") {
		http.Error(w, "scheme not supported", http.StatusBadRequest)
		return
	}
	r.RequestURI = ""
	stripHopByHop(r.Header)

	resp, status := p.proxyOne(r.Context(), r, hostOnly(host))
	if resp == nil {
		http.Error(w, http.StatusText(status), status)
		return
	}
	defer resp.Body.Close()
	for k, vs := range resp.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

// proxyOne handles credential swap, approval, forward, and audit for a single
// inner request. Returns the upstream response (or nil on rejection) and the
// HTTP status the caller should emit.
func (p *Proxy) proxyOne(ctx context.Context, req *http.Request, host string) (*http.Response, int) {
	start := time.Now()
	svc, knownHost := p.cfg.Registry.MatchHost(host)
	ev := audit.Event{
		Service: svc.Name,
		Method:  req.Method,
		Host:    host,
		Path:    req.URL.Path,
	}

	// 1. Token swap.
	tokens := scanForTokens(req.Header)
	if len(tokens) > 0 {
		if !knownHost {
			ev.Outcome = "rejected:unknown-host"
			p.recordAudit(ctx, ev, http.StatusForbidden, time.Since(start))
			return nil, http.StatusForbidden
		}
		realToken, parsed, err := p.resolveToken(ctx, tokens, svc.Name)
		if err != nil {
			ev.Outcome = "rejected:" + err.Error()
			p.recordAudit(ctx, ev, http.StatusUnauthorized, time.Since(start))
			return nil, http.StatusUnauthorized
		}
		ev.TokenID = shortID(parsed.Random)
		swapTokens(req.Header, tokens, realToken)
		ev.Outcome = "swap"
	} else {
		ev.Outcome = "passthrough"
	}

	// 2. Approval gate.
	if p.matchesApproval(req) {
		if p.cfg.Approver == nil {
			ev.Approval = "denied"
			ev.Outcome = "rejected:no-approver"
			p.recordAudit(ctx, ev, http.StatusForbidden, time.Since(start))
			return nil, http.StatusForbidden
		}
		err := p.cfg.Approver.Approve(ctx, ApprovalRequest{
			Service: svc.Name, Method: req.Method, Host: host, Path: req.URL.Path, Now: time.Now(),
		})
		if err != nil {
			ev.Approval = "denied"
			ev.Outcome = "rejected:approval-denied"
			ev.Err = err.Error()
			p.recordAudit(ctx, ev, http.StatusForbidden, time.Since(start))
			return nil, http.StatusForbidden
		}
		ev.Approval = "approved"
	} else {
		ev.Approval = "auto"
	}

	// 3. Forward.
	resp, err := p.upstream.RoundTrip(req)
	if err != nil {
		ev.Outcome = "upstream-error"
		ev.Err = err.Error()
		p.recordAudit(ctx, ev, http.StatusBadGateway, time.Since(start))
		return nil, http.StatusBadGateway
	}
	ev.Status = resp.StatusCode
	p.recordAudit(ctx, ev, resp.StatusCode, time.Since(start))
	return resp, resp.StatusCode
}

func (p *Proxy) recordAudit(ctx context.Context, ev audit.Event, status int, dur time.Duration) {
	ev.Status = status
	ev.DurationMS = dur.Milliseconds()
	if p.cfg.Audit == nil {
		return
	}
	if err := p.cfg.Audit.Log(ctx, ev); err != nil {
		p.cfg.Logger.Warn("audit log failed", "err", err)
	}
}

// resolveToken validates the first proxy token in tokens and returns the real
// upstream credential. All tokens after must be the same — different tokens
// in one request signal tampering.
func (p *Proxy) resolveToken(ctx context.Context, tokens []tokenHit, expectedService string) (string, proxytoken.Token, error) {
	first := tokens[0]
	parsed, err := p.cfg.Signer.Parse(first.token, time.Now())
	if err != nil {
		return "", proxytoken.Token{}, errors.New("invalid")
	}
	if parsed.Service != expectedService {
		return "", proxytoken.Token{}, errors.New("service-mismatch")
	}
	for _, t := range tokens[1:] {
		if t.token != first.token {
			return "", proxytoken.Token{}, errors.New("token-mismatch")
		}
	}
	real, err := p.cfg.Vault.Get(ctx, parsed.Service)
	if err != nil {
		return "", proxytoken.Token{}, errors.New("no-record")
	}
	return real, parsed, nil
}

// leafFor returns a cached leaf cert for host or issues a new one.
func (p *Proxy) leafFor(host string) (*tls.Certificate, error) {
	host = strings.ToLower(host)
	p.leafMu.Lock()
	defer p.leafMu.Unlock()
	if c, ok := p.leaves[host]; ok {
		return c, nil
	}
	leaf, key, err := p.cfg.CA.IssueLeaf(host)
	if err != nil {
		return nil, err
	}
	cert := &tls.Certificate{
		Certificate: [][]byte{leaf.Raw, p.cfg.CA.Cert.Raw},
		PrivateKey:  key,
		Leaf:        leaf,
	}
	p.leaves[host] = cert
	return cert, nil
}

func (p *Proxy) matchesApproval(req *http.Request) bool {
	for _, r := range p.rules {
		if r.method != "*" && r.method != req.Method {
			continue
		}
		if strings.HasPrefix(req.URL.Path, r.prefix) {
			return true
		}
	}
	return false
}

// parseApprovalPatterns parses entries like "DELETE /repos/" or "* /admin".
func parseApprovalPatterns(in []string) ([]approvalRule, error) {
	out := make([]approvalRule, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		fields := strings.Fields(s)
		if len(fields) != 2 {
			return nil, fmt.Errorf("proxy: approval pattern %q must be \"<METHOD> <path-prefix>\"", s)
		}
		out = append(out, approvalRule{method: strings.ToUpper(fields[0]), prefix: fields[1]})
	}
	return out, nil
}

// shortID returns a non-secret identifier for a proxy token's random part.
// Used in audit logs to correlate calls in one wrap session without leaking
// the full token.
func shortID(rand string) string {
	if len(rand) <= 12 {
		return rand
	}
	return rand[:12]
}

func hostOnly(hostport string) string {
	if i := strings.IndexByte(hostport, ':'); i > 0 {
		return hostport[:i]
	}
	return hostport
}
