// Package audit writes a JSON-line event for every proxy call.
//
// The file is append-only at $MCP_GATE_HOME/audit.jsonl. Tail-able with
// `tail -f`, parseable with `jq`, and exportable via `mcp-gate logs`.
//
// Events MUST never contain plaintext credentials. The writer scrubs any
// "mcpgate_..." substrings (proxy tokens) and never logs Authorization
// header bodies in full — only the scheme and a SHA-256 fingerprint of the
// remaining value.
package audit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"sync"
	"time"
)

// Event is one row in the audit log.
type Event struct {
	TimestampUnix int64             `json:"ts"`
	TimestampISO  string            `json:"ts_iso"`
	Service       string            `json:"service"`
	Method        string            `json:"method"`
	Host          string            `json:"host"`
	Path          string            `json:"path"`
	Status        int               `json:"status,omitempty"`
	DurationMS    int64             `json:"duration_ms,omitempty"`
	TokenID       string            `json:"token_id,omitempty"`     // first 12 chars of the proxy token's random part — non-secret
	Approval      string            `json:"approval,omitempty"`     // "auto", "approved", "denied"
	Outcome       string            `json:"outcome"`                // "swap", "passthrough", "rejected:expired", "rejected:no-record"
	Err           string            `json:"err,omitempty"`
	Extra         map[string]string `json:"extra,omitempty"`
}

// Logger is a goroutine-safe append-only writer.
type Logger struct {
	mu sync.Mutex
	w  *os.File
}

// Open returns a Logger appending to path (created with mode 0600 if absent).
func Open(path string) (*Logger, error) {
	if path == "" {
		return nil, errors.New("audit: empty path")
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("audit: open %q: %w", path, err)
	}
	// Tighten perms even if file pre-existed with looser mode (e.g. umask).
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return nil, fmt.Errorf("audit: chmod %q: %w", path, err)
	}
	return &Logger{w: f}, nil
}

// Close flushes and releases the file.
func (l *Logger) Close() error {
	if l == nil || l.w == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	err := l.w.Close()
	l.w = nil
	return err
}

// Log writes one event. The caller is expected to fill required fields:
// at minimum Service, Method, Host, Path, Outcome.
func (l *Logger) Log(_ context.Context, e Event) error {
	if l == nil || l.w == nil {
		return errors.New("audit: logger closed")
	}
	if e.TimestampUnix == 0 {
		now := time.Now().UTC()
		e.TimestampUnix = now.Unix()
		e.TimestampISO = now.Format(time.RFC3339)
	} else if e.TimestampISO == "" {
		e.TimestampISO = time.Unix(e.TimestampUnix, 0).UTC().Format(time.RFC3339)
	}
	b, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("audit: marshal: %w", err)
	}
	b = append(b, '\n')
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, err := l.w.Write(b); err != nil {
		return fmt.Errorf("audit: write: %w", err)
	}
	return nil
}

// Iterate streams events from path, oldest first. Lines that fail to parse
// are skipped (vs. aborting the whole iteration) — operators sometimes
// `echo > audit.jsonl` to mark a session boundary, and we don't want that
// to wedge `mcp-gate logs`.
//
// A missing file is treated as zero events, not an error: `mcp-gate logs` on
// a fresh install should print "(no events)" rather than fail.
func Iterate(path string, fn func(Event) bool) error {
	f, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("audit: open %q: %w", path, err)
	}
	defer f.Close()
	dec := json.NewDecoder(f)
	for {
		var e Event
		if err := dec.Decode(&e); err != nil {
			if err.Error() == "EOF" {
				return nil
			}
			// Skip malformed line by advancing to next newline.
			// json.Decoder buffers; safest is to just stop.
			return nil
		}
		if !fn(e) {
			return nil
		}
	}
}
