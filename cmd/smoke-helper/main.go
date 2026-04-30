// Command smoke-helper is the wrapped child for live-API smoke tests.
//
// Run via:
//
//	mcp-gate wrap --service=github bin/smoke-helper
//
// It calls https://api.github.com/user using the env var $GITHUB_TOKEN
// (set by the wrapper to a mcpgate_... proxy token), respects $HTTPS_PROXY
// and $SSL_CERT_FILE the wrapper set, and emits a structured JSON line so
// the smoke script can grep for evidence.
//
// Output schema (stdout, one line):
//
//	{
//	  "github_token_prefix":  "mcpgate_",       // never "ghp_"
//	  "https_proxy":          "http://127...",
//	  "upstream_status":      200,
//	  "upstream_login":       "<your-handle>",
//	  "upstream_id":          12345,
//	  "real_pat_seen_in_env": false             // belt + suspenders
//	}
//
// Exit codes:
//
//	0  OK (200 from api.github.com with valid login)
//	1  setup error (missing env, can't reach proxy)
//	2  upstream returned non-200 (token rejected, network)
//	3  CRITICAL — real PAT was visible in our env (architecture broken)
package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

type result struct {
	GitHubTokenPrefix string `json:"github_token_prefix"`
	HTTPSProxy        string `json:"https_proxy"`
	SSLCertFile       string `json:"ssl_cert_file"`
	UpstreamStatus    int    `json:"upstream_status"`
	UpstreamLogin     string `json:"upstream_login,omitempty"`
	UpstreamID        int64  `json:"upstream_id,omitempty"`
	UpstreamError     string `json:"upstream_error,omitempty"`
	RealPATSeenInEnv  bool   `json:"real_pat_seen_in_env"`
}

func main() {
	tok := os.Getenv("GITHUB_TOKEN")
	proxyURL := os.Getenv("HTTPS_PROXY")
	caPath := os.Getenv("SSL_CERT_FILE")

	r := result{HTTPSProxy: proxyURL, SSLCertFile: caPath}

	switch {
	case strings.HasPrefix(tok, "mcpgate_"):
		r.GitHubTokenPrefix = "mcpgate_"
	case strings.HasPrefix(tok, "ghp_") || strings.HasPrefix(tok, "github_pat_"):
		// Architecture is broken — the real PAT made it into our env.
		r.GitHubTokenPrefix = "ghp_"
		r.RealPATSeenInEnv = true
		emit(r)
		os.Exit(3)
	default:
		r.GitHubTokenPrefix = firstN(tok, 8)
	}

	if proxyURL == "" || caPath == "" || tok == "" {
		r.UpstreamError = "missing required env: GITHUB_TOKEN, HTTPS_PROXY, or SSL_CERT_FILE"
		emit(r)
		os.Exit(1)
	}

	// Build a transport that:
	//  - explicitly uses $HTTPS_PROXY (Go's ProxyFromEnvironment auto-bypasses
	//    loopback, but production HTTPS_PROXY is non-loopback so this is
	//    only relevant in tests; we still go explicit for clarity)
	//  - trusts ONLY the CA mcp-gate handed us (so any real-PAT-bearing
	//    direct call to api.github.com would TLS-verify fail; this proves
	//    the wrapped child is forced through the proxy)
	pu, err := url.Parse(proxyURL)
	if err != nil {
		r.UpstreamError = "parse proxy URL: " + err.Error()
		emit(r)
		os.Exit(1)
	}
	pool := x509.NewCertPool()
	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		r.UpstreamError = "read CA: " + err.Error()
		emit(r)
		os.Exit(1)
	}
	if !pool.AppendCertsFromPEM(caPEM) {
		r.UpstreamError = "CA PEM had no usable certs"
		emit(r)
		os.Exit(1)
	}

	tr := &http.Transport{
		Proxy:             http.ProxyURL(pu),
		TLSClientConfig:   &tls.Config{RootCAs: pool},
		ForceAttemptHTTP2: true,
	}
	client := &http.Client{Transport: tr, Timeout: 15 * time.Second}

	req, _ := http.NewRequest(http.MethodGet, "https://api.github.com/user", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "mcp-gate-smoke/0.1")
	resp, err := client.Do(req)
	if err != nil {
		r.UpstreamError = err.Error()
		emit(r)
		os.Exit(2)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	r.UpstreamStatus = resp.StatusCode

	if resp.StatusCode == 200 {
		var u struct {
			Login string `json:"login"`
			ID    int64  `json:"id"`
		}
		if err := json.Unmarshal(body, &u); err == nil {
			r.UpstreamLogin = u.Login
			r.UpstreamID = u.ID
		}
	} else {
		r.UpstreamError = fmt.Sprintf("status %d body=%s", resp.StatusCode, truncate(string(body), 200))
	}

	emit(r)
	if resp.StatusCode != 200 {
		os.Exit(2)
	}
}

func emit(r result) {
	b, _ := json.Marshal(r)
	fmt.Println(string(b))
}

func firstN(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
