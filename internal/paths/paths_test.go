package paths

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveUsesEnvOverride(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(envHome, dir)
	got, err := Resolve()
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got.Home != dir {
		t.Fatalf("home = %q, want %q", got.Home, dir)
	}
	want := filepath.Join(dir, vaultFile)
	if got.Vault != want {
		t.Fatalf("vault = %q, want %q", got.Vault, want)
	}
	st, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if got, want := st.Mode().Perm(), os.FileMode(0o700); got != want {
		t.Fatalf("home perm = %v, want %v", got, want)
	}
}

func TestResolveCreatesMissingHome(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "home")
	t.Setenv(envHome, dir)
	if _, err := Resolve(); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("home not created: %v", err)
	}
}
