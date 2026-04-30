package wrapper

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/seoo2001/mcp-gate/internal/services"
)

func TestInstallNodeShim_WritesValidJS(t *testing.T) {
	dir := t.TempDir()
	path, err := installNodeShim(dir)
	if err != nil {
		t.Fatalf("install: %v", err)
	}
	if !strings.HasPrefix(path, dir) {
		t.Fatalf("shim path %q not under %q", path, dir)
	}
	if !strings.HasSuffix(path, ".cjs") {
		t.Fatalf("shim path lacks .cjs suffix: %q", path)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"HttpsProxyAgent",
		"connectThroughProxy",
		"globalThis.fetch",
		"keepAlive: false", // regression: keepAlive=true causes hang
	} {
		if !strings.Contains(string(body), want) {
			t.Fatalf("shim missing %q\n%s", want, string(body))
		}
	}
}

func TestInstallNodeShim_FreshFilePerCall(t *testing.T) {
	dir := t.TempDir()
	a, _ := installNodeShim(dir)
	b, _ := installNodeShim(dir)
	if a == b {
		t.Fatalf("two installs returned same path %q (must be fresh per wrap)", a)
	}
}

func TestBuildEnv_NodeShimAddsRequire(t *testing.T) {
	dir := t.TempDir()
	shim := filepath.Join(dir, "shim.cjs")
	_ = os.WriteFile(shim, []byte("// stub"), 0o600)

	cfg := Config{ProxyURL: "http://127.0.0.1:9", CACertPath: "/ca.pem"}
	env := buildEnv(cfg, fakeService(t), "mcpgate_x.y.1.z", shim)
	got := lookupEnv(env, "NODE_OPTIONS")
	want := "--require=" + shim
	if !strings.Contains(got, want) {
		t.Fatalf("NODE_OPTIONS = %q, want substring %q", got, want)
	}
}

func TestBuildEnv_PreservesUserNodeOptions(t *testing.T) {
	t.Setenv("NODE_OPTIONS", "--max-old-space-size=4096")
	dir := t.TempDir()
	shim := filepath.Join(dir, "shim.cjs")
	_ = os.WriteFile(shim, []byte("// stub"), 0o600)
	cfg := Config{ProxyURL: "http://127.0.0.1:9", CACertPath: "/ca.pem"}
	env := buildEnv(cfg, fakeService(t), "mcpgate_x.y.1.z", shim)
	got := lookupEnv(env, "NODE_OPTIONS")
	if !strings.Contains(got, "--max-old-space-size=4096") {
		t.Fatalf("user NODE_OPTIONS lost: %q", got)
	}
	if !strings.Contains(got, "--require="+shim) {
		t.Fatalf("shim require not appended: %q", got)
	}
}

func TestBuildEnv_NoShimMeansNoNodeOptions(t *testing.T) {
	t.Setenv("NODE_OPTIONS", "")
	cfg := Config{ProxyURL: "http://127.0.0.1:9", CACertPath: "/ca.pem"}
	env := buildEnv(cfg, fakeService(t), "mcpgate_x.y.1.z", "")
	if lookupEnv(env, "NODE_OPTIONS") != "" {
		t.Fatalf("NODE_OPTIONS set without shim: %q", lookupEnv(env, "NODE_OPTIONS"))
	}
}

func lookupEnv(env []string, key string) string {
	prefix := key + "="
	for _, e := range env {
		if strings.HasPrefix(e, prefix) {
			return e[len(prefix):]
		}
	}
	return ""
}

func fakeService(t *testing.T) services.Service {
	t.Helper()
	return services.Service{Name: "github", EnvVar: "GITHUB_TOKEN", Hosts: []string{"api.github.com"}}
}
