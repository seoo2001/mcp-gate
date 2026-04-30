package proxy

import (
	"net/http"
	"strings"

	"github.com/seoo2001/mcp-gate/internal/proxytoken"
)

// tokenHit records one proxy-token occurrence inside an http.Header so we can
// rewrite it in place after vault lookup.
type tokenHit struct {
	header   string
	valueIdx int    // index into header values slice
	start    int    // byte offset of token start in the value
	end      int    // byte offset of token end (exclusive)
	token    string // exact bytes of the matched token
}

// scanForTokens walks every header value and records each "mcpgate_..." span.
// Multiple matches in one request are allowed only if they're identical;
// the proxy enforces that in resolveToken.
func scanForTokens(h http.Header) []tokenHit {
	var hits []tokenHit
	for name, values := range h {
		for i, v := range values {
			tok, start, end := proxytoken.Find(v)
			if tok == "" {
				continue
			}
			hits = append(hits, tokenHit{
				header: name, valueIdx: i, start: start, end: end, token: tok,
			})
		}
	}
	return hits
}

// swapTokens replaces every recorded token hit with realToken.
func swapTokens(h http.Header, hits []tokenHit, realToken string) {
	for _, hit := range hits {
		vals, ok := h[hit.header]
		if !ok || hit.valueIdx >= len(vals) {
			continue
		}
		old := vals[hit.valueIdx]
		// Reslice safely: hit indices were captured before any rewrite.
		if hit.start > len(old) || hit.end > len(old) {
			continue
		}
		vals[hit.valueIdx] = old[:hit.start] + realToken + old[hit.end:]
		h[hit.header] = vals
	}
}

// hopByHop is the canonical RFC 7230 §6.1 set, plus Proxy-Connection
// (legacy but common in HTTP libraries).
var hopByHop = map[string]struct{}{
	"Connection":          {},
	"Proxy-Connection":    {},
	"Keep-Alive":          {},
	"Proxy-Authenticate":  {},
	"Proxy-Authorization": {},
	"Te":                  {},
	"Trailer":             {},
	"Transfer-Encoding":   {},
	"Upgrade":             {},
}

// stripHopByHop removes hop-by-hop headers from h. Also honours any extras
// listed in the request's Connection header (RFC 7230 §6.1 — clients can
// nominate headers as connection-scoped).
func stripHopByHop(h http.Header) {
	if conn := h.Get("Connection"); conn != "" {
		for _, name := range strings.Split(conn, ",") {
			h.Del(strings.TrimSpace(name))
		}
	}
	for name := range hopByHop {
		h.Del(name)
	}
}

