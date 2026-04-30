// Package rewriter rewrites mcp.json files in place so each server's
// command/args are wrapped by `mcp-gate wrap`, and the env section drops
// the now-vault-managed credential.
//
// Goals:
//
//	1. Atomic. Every rewrite produces a sibling .bak (timestamped on first
//	   touch, untouched on subsequent runs) and then atomically renames a
//	   tempfile over the original. No partial state on crash.
//	2. Idempotent. Running setup twice in a row is a no-op for already-
//	   wrapped servers. Detect-by-presence-of-our-marker, not by argv shape.
//	3. Faithful. We preserve unrelated keys verbatim — including arbitrary
//	   user metadata, comments-as-fields, or whatever else lives in the
//	   file. JSON round-trip preserves order via a tiny ordered-map shim.
//
// Out of scope (deliberately):
//
//	- Comments inside JSON. Claude Desktop's config is strict JSON; if the
//	  user has hand-edited in JSONC trailing-comma form, we say so and
//	  bail rather than silently strip.
//	- Reformatting beyond what json.MarshalIndent gives us. Two-space
//	  indent, sorted keys at the leaf — matches every editor's "format
//	  document" behaviour.
package rewriter

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/seoo2001/mcp-gate/internal/services"
)

// MarkerKey is set on every server we rewrite so we can recognise our own
// work on the next run and avoid double-wrapping.
const MarkerKey = "_mcpGate"

// MarkerValue carries our schema version. If the wrapping shape changes
// later, bump this and migrate based on the value seen.
const MarkerValue = "v1"

// Action enumerates what setup did to one server entry.
type Action int

const (
	// ActionSkipped means we left it alone (already wrapped, or no
	// matching credential).
	ActionSkipped Action = iota
	// ActionWrapped means we replaced command/args with `mcp-gate wrap ...`
	// and removed the credential from env.
	ActionWrapped
	// ActionRewrap means it was already wrapped but pointed at a stale
	// service or used a different binary path; we rewrote to current.
	ActionRewrap
)

// Result is the per-server outcome surfaced by Rewrite to the CLI.
type Result struct {
	ServerName string
	Action     Action
	Service    string // matched service name, if any
	Reason     string // human note (skipped: "already wrapped", "no matching credential", etc.)
}

// Options controls the rewrite.
type Options struct {
	// MCPGatePath is the absolute path to the mcp-gate binary the rewrite
	// should invoke. Required: this lives in argv, so a relative path or
	// "mcp-gate" alone is fragile when Claude Desktop spawns the child.
	MCPGatePath string
	// NodeShim, when true, adds --node-shim to every wrap invocation that
	// looks like a Node command (node, npx, bunx, deno run with .js/.mjs).
	// Heuristic only — users can edit afterwards.
	NodeShim bool
	// TTL is the proxy-token lifetime as a Go duration string ("5m"). If
	// empty, no --ttl flag is emitted (uses mcp-gate default).
	TTL string
	// Backup, if non-empty, is the path the original file is copied to
	// before rewriting. Empty means write a sibling .bak.<unix-ts>.
	Backup string
	// DryRun does everything except the final rename.
	DryRun bool
}

// Rewrite reads the mcp.json at path, transforms each server entry whose
// env section maps to a known service+credential, and writes the result.
//
// matchCredential is supplied by the caller; we don't open the vault here
// (this package is dependency-free of the vault to keep tests trivial).
// The function returns true when path's vault has a credential for service
// — that's the signal to actually wrap rather than skip.
func Rewrite(
	path string,
	reg *services.Registry,
	opts Options,
	matchCredential func(service string) bool,
) ([]Result, error) {
	if opts.MCPGatePath == "" {
		return nil, errors.New("rewriter: MCPGatePath is required")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %q: %w", path, err)
	}

	doc, err := parseOrdered(raw)
	if err != nil {
		return nil, fmt.Errorf("parse %q: %w (file may use JSONC; aborting to avoid corruption)", path, err)
	}
	servers, ok := doc.getMap("mcpServers")
	if !ok {
		return nil, fmt.Errorf("%s: no mcpServers section found", path)
	}

	results := make([]Result, 0, len(servers.keys))
	for _, name := range servers.keys {
		entry, ok := servers.getMap(name)
		if !ok {
			results = append(results, Result{ServerName: name, Action: ActionSkipped, Reason: "entry is not an object"})
			continue
		}
		r := rewriteOne(name, entry, reg, opts, matchCredential)
		results = append(results, r)
	}

	if opts.DryRun {
		return results, nil
	}

	if err := backupAndWrite(path, raw, doc, opts); err != nil {
		return results, err
	}
	return results, nil
}

func rewriteOne(
	name string,
	entry *orderedMap,
	reg *services.Registry,
	opts Options,
	matchCredential func(string) bool,
) Result {
	// Idempotency check — if we already wrapped, skip.
	if marker, ok := entry.getString(MarkerKey); ok {
		if marker == MarkerValue {
			return Result{ServerName: name, Action: ActionSkipped, Reason: "already wrapped (" + MarkerKey + "=" + marker + ")"}
		}
		// Different version → rewrap.
		return rewrapNow(name, entry, reg, opts, matchCredential, ActionRewrap)
	}
	return rewrapNow(name, entry, reg, opts, matchCredential, ActionWrapped)
}

func rewrapNow(
	name string,
	entry *orderedMap,
	reg *services.Registry,
	opts Options,
	matchCredential func(string) bool,
	action Action,
) Result {
	envMap, _ := entry.getMap("env")
	if envMap == nil {
		return Result{ServerName: name, Action: ActionSkipped, Reason: "no env section to extract credential from"}
	}
	// Identify the credential. Try each env entry against the registry;
	// first canonical/alias match wins. We also surface token-prefix
	// matches because users often use non-standard env-var names.
	var (
		matchedService string
		matchedEnvKey  string
	)
	for _, k := range envMap.keys {
		v, _ := envMap.getString(k)
		if v == "" {
			continue
		}
		if svc, ok := reg.ResolveByEnvVar(k); ok {
			matchedService = svc.Name
			matchedEnvKey = k
			break
		}
		if svc, ok := reg.ResolveByTokenPrefix(v); ok {
			matchedService = svc.Name
			matchedEnvKey = k
			break
		}
	}
	if matchedService == "" {
		return Result{ServerName: name, Action: ActionSkipped, Reason: "no env var maps to a known service"}
	}
	if !matchCredential(matchedService) {
		return Result{ServerName: name, Action: ActionSkipped, Service: matchedService,
			Reason: "vault has no credential for " + matchedService + " (run `mcp-gate import` first)"}
	}

	originalCmd, _ := entry.getString("command")
	originalArgs := entry.getStringArray("args")
	if originalCmd == "" {
		return Result{ServerName: name, Action: ActionSkipped, Service: matchedService,
			Reason: "missing command field"}
	}

	wrapArgs := []string{"wrap", "--service=" + matchedService}
	if opts.TTL != "" {
		wrapArgs = append(wrapArgs, "--ttl="+opts.TTL)
	}
	if opts.NodeShim && looksLikeNode(originalCmd, originalArgs) {
		wrapArgs = append(wrapArgs, "--node-shim")
	}
	wrapArgs = append(wrapArgs, "--", originalCmd)
	wrapArgs = append(wrapArgs, originalArgs...)

	entry.set("command", opts.MCPGatePath)
	entry.set("args", wrapArgs)
	envMap.delete(matchedEnvKey)
	if envMap.empty() {
		entry.delete("env")
	}
	entry.set(MarkerKey, MarkerValue)

	return Result{
		ServerName: name,
		Action:     action,
		Service:    matchedService,
		Reason:     "wrapped " + originalCmd + " (consumed env " + matchedEnvKey + ")",
	}
}

// looksLikeNode returns true when the wrapped command appears to be a
// Node.js process — used to default --node-shim on. Heuristic only:
// node/npx/bunx by name, or any *.{js,mjs,cjs} arg.
func looksLikeNode(cmd string, args []string) bool {
	base := filepath.Base(cmd)
	switch base {
	case "node", "npx", "bunx":
		return true
	}
	for _, a := range args {
		la := strings.ToLower(a)
		if strings.HasSuffix(la, ".js") || strings.HasSuffix(la, ".mjs") || strings.HasSuffix(la, ".cjs") {
			return true
		}
		if strings.HasPrefix(la, "@modelcontextprotocol/") {
			return true
		}
	}
	return false
}

func backupAndWrite(path string, original []byte, doc *orderedMap, opts Options) error {
	backup := opts.Backup
	if backup == "" {
		backup = path + ".bak." + fmt.Sprint(time.Now().Unix())
	}
	// Only create backup when one doesn't already exist for this exact
	// path+timestamp; protects against losing the *true* original on a
	// second setup run.
	if _, err := os.Stat(backup); errors.Is(err, fs.ErrNotExist) {
		if err := os.WriteFile(backup, original, 0o600); err != nil {
			return fmt.Errorf("write backup %q: %w", backup, err)
		}
	}
	out, err := doc.marshalIndent("", "  ")
	if err != nil {
		return fmt.Errorf("encode: %w", err)
	}
	// Atomic: write tempfile in same dir, rename over original.
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".mcp-gate-rewrite-*.json")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(out); err != nil {
		tmp.Close()
		return fmt.Errorf("write temp: %w", err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("chmod temp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("sync temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("rename: %w", err)
	}
	return nil
}

// orderedMap preserves JSON key order across read→edit→write so a user
// diffing the file before/after sees only meaningful changes (not all
// keys reshuffled by Go's map iteration). Implemented in ordered.go.

// helper for tests; kept here so ordered.go stays focused on JSON shaping.
func sortedKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// JSONShape is the input we tolerate. We use json.RawMessage everywhere
// non-mcpServers so unrelated keys round-trip verbatim.
type JSONShape struct {
	MCPServers map[string]json.RawMessage `json:"mcpServers"`
	Other      map[string]json.RawMessage `json:"-"`
}
