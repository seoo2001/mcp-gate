package proxy

import (
	"fmt"
	"io"
	"net/http"
)

// writeResponse writes resp (or a synthetic error if resp is nil) back onto
// the inner TLS connection of a CONNECT tunnel. The caller is responsible
// for flushing/closing the underlying conn.
//
// The synthetic-error branch matters when proxyOne short-circuits on auth
// failure: we still need to talk HTTP/1.1 to the wrapped child or it will
// hang forever waiting on a reply.
func writeResponse(w io.Writer, req *http.Request, resp *http.Response, status int) error {
	if resp == nil {
		body := http.StatusText(status)
		if body == "" {
			body = fmt.Sprintf("status %d", status)
		}
		_, err := fmt.Fprintf(w,
			"HTTP/1.1 %d %s\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
			status, http.StatusText(status), len(body)+1, body+"\n")
		return err
	}
	defer resp.Body.Close()
	// Strip hop-by-hop on the way back too.
	stripHopByHop(resp.Header)
	// resp.Write() writes status line, headers, and body. It honours
	// chunked transfer encoding for streaming responses.
	return resp.Write(w)
}
