package rewriter

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/seoo2001/mcp-gate/internal/services"
)

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// alwaysHaveCredential is the matchCredential implementation used by tests
// that don't care about vault state — they just want to see what shape
// the rewrite produces when the vault has everything it needs.
func alwaysHaveCredential(string) bool { return true }

func TestRewrite_WrapsKnownService(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "claude.json")
	writeFile(t, path, `{
  "mcpServers": {
    "github": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-github"],
      "env": { "GITHUB_PERSONAL_ACCESS_TOKEN": "ghp_x" }
    }
  }
}`)
	results, err := Rewrite(path, services.NewRegistry(), Options{
		MCPGatePath: "/usr/local/bin/mcp-gate",
		NodeShim:    true,
		TTL:         "5m",
	}, alwaysHaveCredential)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0].Action != ActionWrapped || results[0].Service != "github" {
		t.Fatalf("unexpected result: %+v", results)
	}
	got := readFile(t, path)
	wantArgs := []string{"wrap", "--service=github", "--ttl=5m", "--node-shim", "--",
		"npx", "-y", "@modelcontextprotocol/server-github"}
	for _, w := range wantArgs {
		if !strings.Contains(got, `"`+w+`"`) {
			t.Fatalf("expected arg %q in output:\n%s", w, got)
		}
	}
	if !strings.Contains(got, `"command": "/usr/local/bin/mcp-gate"`) {
		t.Fatal("command was not rewritten")
	}
	if strings.Contains(got, "GITHUB_PERSONAL_ACCESS_TOKEN") {
		t.Fatal("env var should have been removed (vault holds it)")
	}
	if !strings.Contains(got, `"_mcpGate": "v1"`) {
		t.Fatal("idempotency marker missing")
	}
}

func TestRewrite_IsIdempotent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "claude.json")
	writeFile(t, path, `{
  "mcpServers": {
    "github": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-github"],
      "env": { "GITHUB_PERSONAL_ACCESS_TOKEN": "ghp_x" }
    }
  }
}`)
	opts := Options{MCPGatePath: "/usr/local/bin/mcp-gate", NodeShim: true}

	// First pass: wraps.
	r1, _ := Rewrite(path, services.NewRegistry(), opts, alwaysHaveCredential)
	if r1[0].Action != ActionWrapped {
		t.Fatalf("first pass should wrap, got %v", r1[0])
	}
	first := readFile(t, path)

	// Second pass: skip (idempotent).
	r2, _ := Rewrite(path, services.NewRegistry(), opts, alwaysHaveCredential)
	if r2[0].Action != ActionSkipped {
		t.Fatalf("second pass should skip, got %v", r2[0])
	}
	if !strings.Contains(r2[0].Reason, "already wrapped") {
		t.Fatalf("reason wrong: %q", r2[0].Reason)
	}
	second := readFile(t, path)
	if first != second {
		t.Fatalf("idempotent rewrite changed file:\nFIRST:\n%s\n\nSECOND:\n%s", first, second)
	}
}

func TestRewrite_SkipsServerWhenVaultMissingCredential(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "claude.json")
	writeFile(t, path, `{
  "mcpServers": {
    "slack": {
      "command": "node",
      "args": ["x.js"],
      "env": { "SLACK_BOT_TOKEN": "xoxb-x" }
    }
  }
}`)
	results, _ := Rewrite(path, services.NewRegistry(), Options{
		MCPGatePath: "/bin/mcp-gate",
	}, func(string) bool { return false }) // vault missing
	if results[0].Action != ActionSkipped {
		t.Fatalf("want skipped, got %+v", results[0])
	}
	if !strings.Contains(results[0].Reason, "vault has no credential") {
		t.Fatalf("reason: %q", results[0].Reason)
	}
}

func TestRewrite_SkipsUnknownEnvVar(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "claude.json")
	writeFile(t, path, `{
  "mcpServers": {
    "weird": {
      "command": "node",
      "args": ["x.js"],
      "env": { "MY_RANDOM_KEY": "no_known_prefix" }
    }
  }
}`)
	results, _ := Rewrite(path, services.NewRegistry(), Options{
		MCPGatePath: "/bin/mcp-gate",
	}, alwaysHaveCredential)
	if results[0].Action != ActionSkipped {
		t.Fatalf("want skipped, got %+v", results[0])
	}
	if !strings.Contains(results[0].Reason, "no env var maps") {
		t.Fatalf("reason: %q", results[0].Reason)
	}
}

func TestRewrite_PreservesUnrelatedKeys(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "claude.json")
	original := `{
  "globalShortcut": "Cmd+Shift+Space",
  "mcpServers": {
    "github": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-github"],
      "env": { "GITHUB_PERSONAL_ACCESS_TOKEN": "ghp_x" }
    }
  },
  "uiPreferences": {
    "theme": "dark",
    "fontSize": 14
  }
}`
	writeFile(t, path, original)
	_, err := Rewrite(path, services.NewRegistry(), Options{
		MCPGatePath: "/bin/mcp-gate",
	}, alwaysHaveCredential)
	if err != nil {
		t.Fatal(err)
	}
	got := readFile(t, path)
	for _, want := range []string{`"globalShortcut": "Cmd+Shift+Space"`, `"theme": "dark"`, `"fontSize": 14`} {
		if !strings.Contains(got, want) {
			t.Fatalf("lost unrelated key %q\n%s", want, got)
		}
	}
}

func TestRewrite_PreservesKeyOrder(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "claude.json")
	writeFile(t, path, `{
  "alpha": 1,
  "mcpServers": {},
  "zeta": 2,
  "middle": 3
}`)
	_, _ = Rewrite(path, services.NewRegistry(), Options{
		MCPGatePath: "/bin/mcp-gate",
	}, alwaysHaveCredential)
	got := readFile(t, path)
	idxA := strings.Index(got, `"alpha"`)
	idxM := strings.Index(got, `"mcpServers"`)
	idxZ := strings.Index(got, `"zeta"`)
	idxMid := strings.Index(got, `"middle"`)
	if !(idxA < idxM && idxM < idxZ && idxZ < idxMid) {
		t.Fatalf("key order changed:\n%s", got)
	}
}

func TestRewrite_BackupCreated(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "claude.json")
	original := `{"mcpServers":{"github":{"command":"node","args":["x.js"],"env":{"GITHUB_TOKEN":"ghp_x"}}}}`
	writeFile(t, path, original)
	bk := filepath.Join(dir, "claude.json.bak")
	_, err := Rewrite(path, services.NewRegistry(), Options{
		MCPGatePath: "/bin/mcp-gate",
		Backup:      bk,
	}, alwaysHaveCredential)
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(bk)
	if err != nil {
		t.Fatalf("backup not written: %v", err)
	}
	if string(got) != original {
		t.Fatalf("backup mismatch:\nwant: %s\ngot:  %s", original, got)
	}
}

func TestRewrite_DryRun(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "claude.json")
	original := `{"mcpServers":{"github":{"command":"node","args":["x.js"],"env":{"GITHUB_TOKEN":"ghp_x"}}}}`
	writeFile(t, path, original)
	r, err := Rewrite(path, services.NewRegistry(), Options{
		MCPGatePath: "/bin/mcp-gate", DryRun: true,
	}, alwaysHaveCredential)
	if err != nil {
		t.Fatal(err)
	}
	if r[0].Action != ActionWrapped {
		t.Fatalf("dry-run should still classify, got %+v", r[0])
	}
	got := readFile(t, path)
	if got != original {
		t.Fatalf("dry-run modified file:\n%s", got)
	}
}

func TestRewrite_OutputIsValidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "claude.json")
	writeFile(t, path, `{
  "mcpServers": {
    "a": { "command": "node", "args": ["a.js"], "env": { "GITHUB_TOKEN": "ghp_a" } },
    "b": { "command": "node", "args": ["b.js"], "env": { "SLACK_BOT_TOKEN": "xoxb-b" } }
  },
  "extra": [1, 2, 3]
}`)
	_, _ = Rewrite(path, services.NewRegistry(), Options{
		MCPGatePath: "/bin/mcp-gate", NodeShim: true,
	}, alwaysHaveCredential)
	got := readFile(t, path)
	var generic any
	if err := json.Unmarshal([]byte(got), &generic); err != nil {
		t.Fatalf("output is invalid JSON: %v\n%s", err, got)
	}
}

func TestRewrite_NodeShimHeuristic(t *testing.T) {
	cases := []struct {
		cmd   string
		args  []string
		want  bool
	}{
		{"node", []string{"x.js"}, true},
		{"npx", []string{"-y", "@modelcontextprotocol/server-github"}, true},
		{"bunx", []string{"foo"}, true},
		{"/usr/bin/node", []string{"y.js"}, true},
		{"python", []string{"app.py"}, false},
		{"deno", []string{"run", "thing.ts"}, false},
		{"deno", []string{"run", "thing.js"}, true}, // .js arg
		{"bash", []string{"@modelcontextprotocol/foo"}, true}, // npm pkg arg
	}
	for _, c := range cases {
		got := looksLikeNode(c.cmd, c.args)
		if got != c.want {
			t.Errorf("looksLikeNode(%q, %v) = %v, want %v", c.cmd, c.args, got, c.want)
		}
	}
}

func TestRewrite_RejectsJSONC(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	// trailing comma — invalid JSON, common in Cursor/VSCode-style configs
	writeFile(t, path, `{ "mcpServers": { "x": { "env": { "FOO": "BAR", } } } }`)
	if _, err := Rewrite(path, services.NewRegistry(), Options{
		MCPGatePath: "/bin/mcp-gate",
	}, alwaysHaveCredential); err == nil {
		t.Fatal("expected error on invalid JSON")
	}
}
