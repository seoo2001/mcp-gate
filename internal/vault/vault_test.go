package vault

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/seoo2001/mcp-gate/internal/keystore"
)

func newTestVault(t *testing.T) (*Vault, string) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("MCP_GATE_KEYSTORE", "file")
	ks, err := keystore.Auto(context.Background(), filepath.Join(dir, "master.key"))
	if err != nil {
		t.Fatal(err)
	}
	v, err := Open(context.Background(), filepath.Join(dir, "vault.json"), ks)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = v.Close() })
	return v, dir
}

func TestVault_AddGet(t *testing.T) {
	v, _ := newTestVault(t)
	if err := v.Add(context.Background(), "github", "ghp_secret_123"); err != nil {
		t.Fatal(err)
	}
	got, err := v.Get(context.Background(), "github")
	if err != nil {
		t.Fatal(err)
	}
	if got != "ghp_secret_123" {
		t.Fatalf("got %q, want ghp_secret_123", got)
	}
}

func TestVault_GetMissing(t *testing.T) {
	v, _ := newTestVault(t)
	if _, err := v.Get(context.Background(), "absent"); err != ErrNotFound {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestVault_Replace(t *testing.T) {
	v, _ := newTestVault(t)
	ctx := context.Background()
	if err := v.Add(ctx, "slack", "xoxb-old"); err != nil {
		t.Fatal(err)
	}
	if err := v.Add(ctx, "slack", "xoxb-new"); err != nil {
		t.Fatal(err)
	}
	got, _ := v.Get(ctx, "slack")
	if got != "xoxb-new" {
		t.Fatalf("got %q, want xoxb-new", got)
	}
	// CreatedUnix should be preserved across replace.
	v.mu.RLock()
	rec := v.records["slack"]
	v.mu.RUnlock()
	if rec.UpdatedUnix < rec.CreatedUnix {
		t.Fatalf("UpdatedUnix < CreatedUnix")
	}
}

func TestVault_Remove(t *testing.T) {
	v, _ := newTestVault(t)
	ctx := context.Background()
	_ = v.Add(ctx, "github", "tok")
	if err := v.Remove(ctx, "github"); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Get(ctx, "github"); err != ErrNotFound {
		t.Fatalf("expected ErrNotFound after Remove, got %v", err)
	}
	if err := v.Remove(ctx, "github"); err != ErrNotFound {
		t.Fatalf("expected ErrNotFound on second Remove, got %v", err)
	}
}

func TestVault_List(t *testing.T) {
	v, _ := newTestVault(t)
	ctx := context.Background()
	for _, s := range []string{"slack", "github", "notion"} {
		_ = v.Add(ctx, s, "x")
	}
	got, err := v.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"github", "notion", "slack"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("List = %v, want %v", got, want)
	}
}

func TestVault_PersistsAcrossOpens(t *testing.T) {
	t.Setenv("MCP_GATE_KEYSTORE", "file")
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "master.key")
	vaultPath := filepath.Join(dir, "vault.json")

	ks, _ := keystore.Auto(context.Background(), keyPath)
	v1, err := Open(context.Background(), vaultPath, ks)
	if err != nil {
		t.Fatal(err)
	}
	if err := v1.Add(context.Background(), "stripe", "sk_live_xxx"); err != nil {
		t.Fatal(err)
	}
	_ = v1.Close()

	// Reopen with same keystore (same on-disk key) — should still decrypt.
	ks2, _ := keystore.Auto(context.Background(), keyPath)
	v2, err := Open(context.Background(), vaultPath, ks2)
	if err != nil {
		t.Fatal(err)
	}
	got, err := v2.Get(context.Background(), "stripe")
	if err != nil {
		t.Fatal(err)
	}
	if got != "sk_live_xxx" {
		t.Fatalf("got %q after reopen", got)
	}
}

func TestVault_FilePermissionsTight(t *testing.T) {
	v, _ := newTestVault(t)
	if err := v.Add(context.Background(), "x", "y"); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(v.path)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := st.Mode().Perm(), os.FileMode(0o600); got != want {
		t.Fatalf("mode = %v, want %v", got, want)
	}
}

func TestVault_PlaintextNeverOnDisk(t *testing.T) {
	v, _ := newTestVault(t)
	const secret = "ghp_VERY_DISTINCT_TOKEN_VALUE_xyz123"
	if err := v.Add(context.Background(), "github", secret); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(v.path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), secret) {
		t.Fatalf("plaintext token appears in vault file at %s", v.path)
	}
}

func TestVault_TamperedRecordFailsAuth(t *testing.T) {
	v, _ := newTestVault(t)
	ctx := context.Background()
	if err := v.Add(ctx, "github", "tok"); err != nil {
		t.Fatal(err)
	}
	// Flip a bit in the value ciphertext on disk and reopen.
	b, _ := os.ReadFile(v.path)
	var ff fileFormat
	if err := json.Unmarshal(b, &ff); err != nil {
		t.Fatal(err)
	}
	if len(ff.Records) == 0 {
		t.Fatal("no records")
	}
	ff.Records[0].Value.Ciphertext[0] ^= 0xff
	out, _ := json.MarshalIndent(ff, "", "  ")
	_ = os.WriteFile(v.path, out, 0o600)

	// Force reload. Get must fail.
	if err := v.reload(); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Get(ctx, "github"); err == nil {
		t.Fatalf("expected auth failure on tampered ciphertext")
	}
}

func TestVault_OpenRejectsBadVersion(t *testing.T) {
	t.Setenv("MCP_GATE_KEYSTORE", "file")
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "master.key")
	vaultPath := filepath.Join(dir, "vault.json")
	bad := []byte(`{"version": 99, "records": []}`)
	if err := os.WriteFile(vaultPath, bad, 0o600); err != nil {
		t.Fatal(err)
	}
	ks, _ := keystore.Auto(context.Background(), keyPath)
	if _, err := Open(context.Background(), vaultPath, ks); err == nil {
		t.Fatalf("expected version error")
	}
}

func TestVault_AddRejectsEmpty(t *testing.T) {
	v, _ := newTestVault(t)
	ctx := context.Background()
	if err := v.Add(ctx, "", "x"); err == nil {
		t.Fatalf("empty service should error")
	}
	if err := v.Add(ctx, "x", ""); err == nil {
		t.Fatalf("empty token should error")
	}
}
