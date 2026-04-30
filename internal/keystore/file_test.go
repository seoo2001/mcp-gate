package keystore

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestFileKeystore_LoadGeneratesKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "master.key")
	ks := &FileKeystore{Path: path}
	key, err := ks.Load(context.Background())
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(key) != MasterKeyLen {
		t.Fatalf("len(key) = %d, want %d", len(key), MasterKeyLen)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if got, want := st.Mode().Perm(), os.FileMode(0o600); got != want {
		t.Fatalf("perm = %v, want %v", got, want)
	}
}

func TestFileKeystore_LoadIsStable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "master.key")
	ks := &FileKeystore{Path: path}
	a, err := ks.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	b, err := ks.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if string(a) != string(b) {
		t.Fatalf("subsequent load returned different key")
	}
}

func TestFileKeystore_Reset(t *testing.T) {
	path := filepath.Join(t.TempDir(), "master.key")
	ks := &FileKeystore{Path: path}
	if _, err := ks.Load(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := ks.Reset(context.Background()); err != nil {
		t.Fatalf("reset: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("expected file removed, got err=%v", err)
	}
	// idempotent
	if err := ks.Reset(context.Background()); err != nil {
		t.Fatalf("second reset: %v", err)
	}
}

func TestFileKeystore_RejectsCorruptKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "master.key")
	if err := os.WriteFile(path, []byte("not-base64@@@"), 0o600); err != nil {
		t.Fatal(err)
	}
	ks := &FileKeystore{Path: path}
	if _, err := ks.Load(context.Background()); err == nil {
		t.Fatalf("expected decode error, got nil")
	}
}

func TestFileKeystore_RejectsWrongLength(t *testing.T) {
	path := filepath.Join(t.TempDir(), "master.key")
	// 16 bytes encoded — half the right length
	if err := os.WriteFile(path, []byte("AAECAwQFBgcICQoLDA0ODw=="), 0o600); err != nil {
		t.Fatal(err)
	}
	ks := &FileKeystore{Path: path}
	if _, err := ks.Load(context.Background()); err == nil {
		t.Fatalf("expected length error, got nil")
	}
}

func TestFileKeystore_AutoOverrideToFile(t *testing.T) {
	t.Setenv(envOverride, "file")
	path := filepath.Join(t.TempDir(), "master.key")
	ks, err := Auto(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	if ks.Backend() != "file" {
		t.Fatalf("backend = %s, want file", ks.Backend())
	}
}
